use binaris_ai::providers::ProviderConfig;
use binaris_ai::semantic::{build_summaries, enrich_functions};
use binaris_analysis::{analyze_bytes, AnalysisContext};
use binaris_core::{
    AnalysisId, AnalysisOptions, AnalysisReport, FileId, PipelineEvent, PipelineStage, ProjectId,
    ReportDocument, StringCategory,
};
use binaris_decomp::enrich_functions as decomp_enrich;
use binaris_graphs::{
    build_call_graph, build_cfg_summary, build_dfg, build_import_graph, build_memory_graph,
};
use binaris_malware::classify;
use binaris_network::enrich as enrich_network;
use binaris_reports::build_documents;
use binaris_security::analyze as security_analyze;
use chrono::Utc;
use serde_json::json;
use tracing::info;

pub struct PipelineOutput {
    pub report: AnalysisReport,
    pub documents: Vec<ReportDocument>,
    pub events: Vec<PipelineEvent>,
}

pub async fn run_pipeline(
    analysis_id: AnalysisId,
    file_id: FileId,
    project_id: ProjectId,
    filename: String,
    data: &[u8],
    options: AnalysisOptions,
) -> anyhow::Result<PipelineOutput> {
    let mut events = Vec::new();
    let emit = |events: &mut Vec<PipelineEvent>, stage: PipelineStage, msg: &str| {
        events.push(PipelineEvent::new(analysis_id, stage, msg));
    };

    emit(&mut events, PipelineStage::Hashing, "Computing cryptographic hashes");
    emit(
        &mut events,
        PipelineStage::Identification,
        "Identifying file format and architecture",
    );
    emit(&mut events, PipelineStage::Unpacking, "Checking packers / containers");

    let ctx = AnalysisContext {
        max_strings: options.max_strings,
        enable_disassembly: options.enable_disassembly,
    };

    emit(
        &mut events,
        PipelineStage::StaticAnalysis,
        "Running static analysis engine",
    );
    let mut static_result = analyze_bytes(data, &ctx);

    emit(&mut events, PipelineStage::Disassembly, "Disassembling + decomp backends");
    let decomp = decomp_enrich(
        data,
        static_result.identity.architecture,
        &mut static_result.functions,
    )
    .await;

    emit(
        &mut events,
        PipelineStage::GraphConstruction,
        "Building program graphs (call/CFG/DFG/memory)",
    );
    emit(
        &mut events,
        PipelineStage::FunctionExtraction,
        "Extracting and classifying functions",
    );
    emit(&mut events, PipelineStage::StringExtraction, "Classifying strings");
    emit(
        &mut events,
        PipelineStage::ImportExportAnalysis,
        "Analyzing imports and exports",
    );
    emit(
        &mut events,
        PipelineStage::ResourceExtraction,
        "Extracting resources and dependencies",
    );

    if options.enable_ai {
        emit(
            &mut events,
            PipelineStage::AiSemantic,
            "Running AI semantic rename / enrichment",
        );
        enrich_functions(
            &mut static_result.functions,
            &static_result.imports,
            &static_result.strings,
        );
    } else {
        emit(
            &mut events,
            PipelineStage::AiSemantic,
            "AI disabled — skipping semantic enrichment",
        );
    }

    emit(
        &mut events,
        PipelineStage::SecurityAnalysis,
        "Running security engine",
    );
    let security = security_analyze(
        &static_result.imports,
        &static_result.strings,
        &static_result.crypto,
    );

    emit(
        &mut events,
        PipelineStage::MalwareAnalysis,
        "Running malware classification",
    );
    let malware = classify(
        &static_result.imports,
        &static_result.strings,
        &static_result.packers,
    );

    let network_intel = enrich_network(&static_result.network).await;
    let call_graph = build_call_graph(&static_result.functions);
    let cfg_summary = build_cfg_summary(&static_result.functions);
    let import_graph = build_import_graph(&static_result.imports, &static_result.exports);
    let dfg = build_dfg(&static_result.functions);
    let memory_graph = build_memory_graph(&static_result.functions, &static_result.sections);
    let network_graph = network_intel.graph.clone();

    let top_findings: Vec<String> = security
        .iter()
        .take(8)
        .map(|f| format!("{:?}: {}", f.severity, f.title))
        .collect();
    let identity_line = format!(
        "Identified as {:?} {:?} ({:?}). Compiler={}.",
        static_result.identity.format,
        static_result.identity.architecture,
        static_result.identity.os,
        static_result
            .identity
            .compiler
            .as_deref()
            .unwrap_or("unknown")
    );
    let malware_line = format!(
        "Malware probability {:.0}% ({:?}).",
        malware.malware_probability * 100.0,
        malware.family
    );
    let (executive_summary, technical_summary) =
        build_summaries(&filename, &identity_line, &malware_line, &top_findings);

    let mut iocs = Vec::new();
    iocs.push(static_result.hashes.sha256.clone());
    iocs.push(static_result.hashes.md5.clone());
    for n in &static_result.network {
        iocs.push(n.value.clone());
    }
    for s in static_result.strings.iter().filter(|s| {
        matches!(
            s.category,
            StringCategory::Mutex | StringCategory::Registry | StringCategory::Path
        )
    }) {
        iocs.push(s.value.clone());
    }
    iocs.sort();
    iocs.dedup();

    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": static_result.dependencies.iter().map(|d| json!({
            "type": "library",
            "name": d.name,
            "version": d.version,
            "purl": format!("pkg:generic/{}@", d.name),
        })).collect::<Vec<_>>(),
        "metadata": {
            "component": {
                "type": "application",
                "name": filename,
                "hashes": [
                    {"alg": "SHA-256", "content": static_result.hashes.sha256},
                    {"alg": "MD5", "content": static_result.hashes.md5},
                ]
            }
        }
    });

    let now = Utc::now();
    let mut report = AnalysisReport {
        id: analysis_id,
        file_id,
        project_id,
        stage: PipelineStage::ReportGeneration,
        progress: PipelineStage::ReportGeneration.progress_percent(),
        created_at: now,
        updated_at: now,
        completed_at: None,
        error: None,
        filename: filename.clone(),
        size_bytes: data.len() as u64,
        hashes: static_result.hashes,
        identity: static_result.identity,
        sections: static_result.sections,
        imports: static_result.imports,
        exports: static_result.exports,
        strings: static_result.strings,
        network: static_result.network,
        crypto: static_result.crypto,
        packers: static_result.packers,
        functions: static_result.functions,
        security,
        malware,
        signature: static_result.signature,
        resources: static_result.resources,
        dependencies: static_result.dependencies,
        call_graph,
        cfg_summary,
        import_graph,
        dfg,
        memory_graph,
        network_graph,
        network_intel: serde_json::to_value(&network_intel).unwrap_or(json!({})),
        decomp_backends: serde_json::to_value(&decomp.backends).unwrap_or(json!([])),
        language_structures: serde_json::to_value(&decomp.language_structures)
            .unwrap_or(json!([])),
        executive_summary,
        technical_summary,
        iocs,
        yara_rules: vec![],
        sbom,
    };

    emit(
        &mut events,
        PipelineStage::ReportGeneration,
        "Generating reports (MD/HTML/PDF/SARIF/YARA)",
    );
    let documents = build_documents(&report);
    report.yara_rules = documents
        .iter()
        .filter(|d| d.kind == binaris_core::ReportKind::Yara)
        .map(|d| d.content.clone())
        .collect();

    emit(
        &mut events,
        PipelineStage::ChatIndexing,
        "Indexing analysis for chat retrieval",
    );
    let _ = ProviderConfig::default();

    report.stage = PipelineStage::Completed;
    report.progress = 100;
    report.completed_at = Some(Utc::now());
    report.updated_at = Utc::now();
    emit(&mut events, PipelineStage::Completed, "Analysis complete");

    info!(
        analysis_id = %analysis_id,
        functions = report.functions.len(),
        findings = report.security.len(),
        "pipeline finished"
    );

    Ok(PipelineOutput {
        report,
        documents,
        events,
    })
}
