//! GraphQL query endpoint covering projects, analysis, network, and malware fields.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;
use binaris_core::AnalysisId;

pub fn routes() -> Router<AppState> {
    Router::new().route("/graphql", post(graphql))
}

#[derive(Deserialize)]
pub struct GraphqlRequest {
    pub query: String,
    pub variables: Option<Value>,
}

async fn graphql(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GraphqlRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    let q = req.query.to_ascii_lowercase();
    let vars = req.variables.unwrap_or_else(|| json!({}));

    if q.contains("providers") {
        return Ok(Json(json!({
            "data": {
                "oauthProviders": binaris_auth::oauth::list_configured_providers()
            }
        })));
    }

    if q.contains("projects") && !q.contains("analysis") {
        let org_id = binaris_core::OrgId::from_uuid(
            Uuid::parse_str(&claims.org_id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        );
        let projects = state.store.list_projects(org_id).await.map_err(internal)?;
        return Ok(Json(json!({
            "data": {
                "projects": projects.iter().map(|p| json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                })).collect::<Vec<_>>()
            }
        })));
    }

    let id = vars
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| extract_id_literal(&req.query))
        .ok_or((StatusCode::BAD_REQUEST, "analysis id required".into()))?;
    let id = Uuid::parse_str(id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let report = state
        .store
        .get_analysis(AnalysisId::from_uuid(id))
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))?;

    Ok(Json(json!({
        "data": {
            "analysis": {
                "id": report.id,
                "filename": report.filename,
                "stage": report.stage,
                "progress": report.progress,
                "executiveSummary": report.executive_summary,
                "malwareProbability": report.malware.malware_probability,
                "family": report.malware.family,
                "sha256": report.hashes.sha256,
                "imports": report.imports.len(),
                "functions": report.functions.len(),
                "securityFindings": report.security.len(),
                "networkEndpoints": report.network.len(),
                "networkIntel": report.network_intel,
                "decompBackends": report.decomp_backends,
            }
        }
    })))
}

fn extract_id_literal(q: &str) -> Option<&str> {
    let marker = "analysis(id:";
    let idx = q.to_ascii_lowercase().find(marker)?;
    let rest = &q[idx + marker.len()..];
    let rest = rest.trim_start().trim_start_matches(['"', '\'']);
    let end = rest.find(['"', '\'', ')', ' ', ','])?;
    Some(&rest[..end])
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
