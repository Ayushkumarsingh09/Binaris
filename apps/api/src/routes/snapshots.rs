use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use binaris_core::{AnalysisId, SnapshotId};
use binaris_diff::{diff_reports, snapshot};
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/analyses/{id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route("/snapshots/{id}/restore", post(restore_snapshot))
        .route("/analyses/{left}/diff/{right}", get(diff_analyses))
}

#[derive(Deserialize)]
pub struct SnapshotBody {
    pub label: Option<String>,
}

async fn create_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<SnapshotBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let report = state
        .store
        .get_analysis(AnalysisId::from_uuid(id))
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))?;
    let snap = snapshot(&report, body.label.unwrap_or_else(|| "manual".into()));
    state.store.save_snapshot(&snap).await.map_err(internal)?;
    Ok(Json(serde_json::json!({
        "id": snap.id,
        "label": snap.label,
        "created_at": snap.created_at,
    })))
}

async fn list_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let items = state
        .store
        .list_snapshots(AnalysisId::from_uuid(id))
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "snapshots": items.iter().map(|s| serde_json::json!({
            "id": s.id,
            "label": s.label,
            "created_at": s.created_at,
            "sha256": s.report.hashes.sha256,
        })).collect::<Vec<_>>()
    })))
}

async fn restore_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let report = state
        .store
        .restore_snapshot(SnapshotId::from_uuid(id))
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "snapshot not found".into()))?;
    Ok(Json(serde_json::json!({ "restored": true, "report": report })))
}

async fn diff_analyses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((left, right)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let l = state
        .store
        .get_analysis(AnalysisId::from_uuid(left))
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "left analysis not found".into()))?;
    let r = state
        .store
        .get_analysis(AnalysisId::from_uuid(right))
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "right analysis not found".into()))?;
    Ok(Json(serde_json::to_value(diff_reports(&l, &r)).map_err(internal)?))
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
