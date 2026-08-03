use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "binaris-api", "version": env!("CARGO_PKG_VERSION") }))
}

async fn readyz() -> Json<Value> {
    Json(json!({ "status": "ready" }))
}

async fn metrics() -> String {
    format!(
        "# HELP binaris_up API up\n# TYPE binaris_up gauge\nbinaris_up 1\n# HELP binaris_build_info Build info\nbinaris_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    )
}
