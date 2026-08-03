use axum::{
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use binaris_core::{
    AnalysisId, AnalysisJob, AnalysisOptions, AnalysisReport, FileHashes, FileId, PipelineStage,
    ProjectId, StoredFile, UserId,
};
use binaris_pipeline::run_pipeline;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/projects/{project_id}/upload", post(upload))
        .route("/analyses/{id}", get(get_analysis))
        .route("/projects/{project_id}/analyses", get(list_analyses))
        .route("/analyses/{id}/functions", get(list_functions))
        .route("/analyses/{id}/annotations", post(create_annotation).get(list_annotations))
}

#[derive(Deserialize)]
pub struct UploadQueryOptions {
    pub enable_ai: Option<bool>,
}

async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<AnalysisReport>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    let user_id = UserId::from_uuid(
        Uuid::parse_str(&claims.sub).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?,
    );
    let project_id = ProjectId::from_uuid(project_id);
    state
        .store
        .get_project(project_id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))?;

    let mut filename = "upload.bin".to_string();
    let mut content_type = None;
    let mut data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" || name == "binary" || field.file_name().is_some() {
            if let Some(f) = field.file_name() {
                filename = f.to_string();
            }
            content_type = field.content_type().map(|c| c.to_string());
            data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                    .to_vec(),
            );
        }
    }

    let data = data.ok_or((StatusCode::BAD_REQUEST, "missing file field".into()))?;
    if data.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty file".into()));
    }
    if data.len() > 512 * 1024 * 1024 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "max upload size is 512MB".into()));
    }

    let file_id = FileId::new();
    let analysis_id = AnalysisId::new();
    let storage_key = format!("org/{}/project/{}/{}", claims.org_id, project_id, file_id);
    state
        .objects
        .put(&storage_key, &data)
        .await
        .map_err(internal)?;

    let hashes = binaris_analysis::hasher::hash_bytes(&data);
    let file = StoredFile {
        id: file_id,
        project_id,
        filename: filename.clone(),
        size_bytes: data.len() as u64,
        content_type,
        storage_key: storage_key.clone(),
        hashes: hashes.clone(),
        uploaded_by: user_id,
        created_at: Utc::now(),
    };
    state.store.create_file(&file).await.map_err(internal)?;

    let pending = AnalysisReport {
        id: analysis_id,
        file_id,
        project_id,
        stage: PipelineStage::Queued,
        progress: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        completed_at: None,
        error: None,
        filename: filename.clone(),
        size_bytes: data.len() as u64,
        hashes: hashes.clone(),
        identity: empty_identity(),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        network: vec![],
        crypto: vec![],
        packers: vec![],
        functions: vec![],
        security: vec![],
        malware: empty_malware(),
        signature: binaris_core::DigitalSignatureInfo {
            present: false,
            valid: None,
            subject: None,
            issuer: None,
            serial: None,
            not_before: None,
            not_after: None,
            algorithm: None,
        },
        resources: vec![],
        dependencies: vec![],
        call_graph: binaris_core::GraphPayload::default(),
        cfg_summary: binaris_core::GraphPayload::default(),
        import_graph: binaris_core::GraphPayload::default(),
        dfg: binaris_core::GraphPayload::default(),
        memory_graph: binaris_core::GraphPayload::default(),
        network_graph: binaris_core::GraphPayload::default(),
        network_intel: serde_json::json!({}),
        decomp_backends: serde_json::json!([]),
        language_structures: serde_json::json!([]),
        executive_summary: "Queued".into(),
        technical_summary: "Queued".into(),
        iocs: vec![],
        yara_rules: vec![],
        sbom: serde_json::json!({}),
    };
    state.store.save_analysis(&pending).await.map_err(internal)?;

    let job = AnalysisJob {
        analysis_id,
        file_id,
        project_id,
        storage_key,
        filename: filename.clone(),
        enqueued_at: Utc::now(),
        options: AnalysisOptions {
            enable_ai: true,
            enable_disassembly: true,
            deep_unpack: true,
            max_strings: 50_000,
            model_provider: None,
            model_name: None,
        },
    };

    if state.inline_analyze {
        let output = run_pipeline(
            analysis_id,
            file_id,
            project_id,
            filename,
            &data,
            job.options.clone(),
        )
        .await
        .map_err(internal)?;
        state
            .store
            .save_analysis(&output.report)
            .await
            .map_err(internal)?;
        state
            .store
            .save_reports(&output.documents)
            .await
            .map_err(internal)?;
        state
            .store
            .audit(
                None,
                Some(user_id),
                "analysis.completed",
                &analysis_id.to_string(),
            )
            .await
            .ok();
        return Ok(Json(output.report));
    }

    state.queue.enqueue(&job).await.map_err(internal)?;
    Ok(Json(pending))
}

async fn get_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AnalysisReport>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    state
        .store
        .get_analysis(AnalysisId::from_uuid(id))
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))
}

async fn list_analyses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<Uuid>,
) -> Result<Json<Vec<AnalysisReport>>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let items = state
        .store
        .list_analyses(ProjectId::from_uuid(project_id))
        .await
        .map_err(internal)?;
    Ok(Json(items))
}

async fn list_functions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let report = get_analysis(State(state), headers, Path(id)).await?.0;
    Ok(Json(serde_json::json!({ "functions": report.functions })))
}

#[derive(Deserialize)]
pub struct AnnotationBody {
    pub target_address: Option<u64>,
    pub target_kind: String,
    pub body: String,
    pub highlight_color: Option<String>,
}

async fn create_annotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<AnnotationBody>,
) -> Result<Json<binaris_core::Annotation>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    let user_id = UserId::from_uuid(
        Uuid::parse_str(&claims.sub).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?,
    );
    let ann = binaris_core::Annotation {
        id: binaris_core::AnnotationId::new(),
        analysis_id: AnalysisId::from_uuid(id),
        author_id: user_id,
        target_address: req.target_address,
        target_kind: req.target_kind,
        body: req.body,
        highlight_color: req.highlight_color,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    state.store.save_annotation(&ann).await.map_err(internal)?;
    Ok(Json(ann))
}

async fn list_annotations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<binaris_core::Annotation>>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let items = state
        .store
        .list_annotations(AnalysisId::from_uuid(id))
        .await
        .map_err(internal)?;
    Ok(Json(items))
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn empty_identity() -> binaris_core::BinaryIdentity {
    binaris_core::BinaryIdentity {
        format: binaris_core::BinaryFormat::Unknown,
        architecture: binaris_core::Architecture::Unknown,
        endianness: "unknown".into(),
        bits: 0,
        os: binaris_core::OperatingSystem::Unknown,
        is_dll: false,
        is_driver: false,
        is_shared_object: false,
        entry_point: None,
        image_base: None,
        compiler: None,
        compiler_version: None,
        language: None,
        build_system: None,
        framework: None,
        linker: None,
        packed: false,
        packer: None,
        obfuscated: false,
        obfuscation: vec![],
        encrypted_sections: vec![],
        compressed: false,
        has_debug_symbols: false,
        has_signature: false,
        mime: None,
    }
}

fn empty_malware() -> binaris_core::MalwareClassification {
    binaris_core::MalwareClassification {
        family: binaris_core::MalwareFamily::Unknown,
        confidence: 0.0,
        malware_probability: 0.0,
        reasoning: "pending".into(),
        evidence: vec![],
        suspicious_apis: vec![],
        suspicious_strings: vec![],
        behaviors: vec![],
        persistence: vec![],
        privilege_escalation: vec![],
        process_injection: vec![],
        anti_analysis: vec![],
    }
}

#[allow(dead_code)]
fn _hashes() -> FileHashes {
    binaris_analysis::hasher::hash_bytes(b"")
}
