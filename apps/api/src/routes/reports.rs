use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;
use binaris_core::AnalysisId;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/analyses/{id}/reports", get(list_reports))
        .route("/analyses/{id}/graphs/{kind}", get(get_graph))
}

async fn list_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let docs = state
        .store
        .list_reports(AnalysisId::from_uuid(id))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({ "reports": docs })))
}

async fn get_graph(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, kind)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let report = state
        .store
        .get_analysis(AnalysisId::from_uuid(id))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))?;

    let graph = match kind.as_str() {
        "call" => report.call_graph,
        "cfg" => report.cfg_summary,
        "imports" => report.import_graph,
        "dfg" => report.dfg,
        "memory" => report.memory_graph,
        "network" => report.network_graph,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "unknown graph kind (call|cfg|imports|dfg|memory|network)".into(),
            ));
        }
    };
    Ok(Json(serde_json::json!({ "kind": kind, "graph": graph })))
}
