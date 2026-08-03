use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;
use binaris_core::AnalysisId;

pub fn routes() -> Router<AppState> {
    Router::new().route("/analyses/{id}/search", get(search))
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub kind: Option<String>,
}

async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    let report = state
        .store
        .get_analysis(AnalysisId::from_uuid(id))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))?;

    let needle = q.q.to_ascii_lowercase();
    let kind = q.kind.as_deref().unwrap_or("all");

    let mut functions = vec![];
    let mut imports = vec![];
    let mut exports = vec![];
    let mut strings = vec![];
    let mut crypto = vec![];
    let mut network = vec![];

    if kind == "all" || kind == "functions" {
        for f in &report.functions {
            let hay = format!(
                "{} {} {}",
                f.name,
                f.suggested_name.as_deref().unwrap_or(""),
                f.description.as_deref().unwrap_or("")
            )
            .to_ascii_lowercase();
            if hay.contains(&needle) {
                functions.push(f);
            }
        }
    }
    if kind == "all" || kind == "imports" {
        for i in &report.imports {
            if i.symbol.to_ascii_lowercase().contains(&needle)
                || i.module.to_ascii_lowercase().contains(&needle)
            {
                imports.push(i);
            }
        }
    }
    if kind == "all" || kind == "exports" {
        for e in &report.exports {
            if e.symbol.to_ascii_lowercase().contains(&needle) {
                exports.push(e);
            }
        }
    }
    if kind == "all" || kind == "strings" {
        for s in &report.strings {
            if s.value.to_ascii_lowercase().contains(&needle) {
                strings.push(s);
            }
        }
    }
    if kind == "all" || kind == "crypto" {
        for c in &report.crypto {
            if c.algorithm.to_ascii_lowercase().contains(&needle) {
                crypto.push(c);
            }
        }
    }
    if kind == "all" || kind == "network" {
        for n in &report.network {
            if n.value.to_ascii_lowercase().contains(&needle) {
                network.push(n);
            }
        }
    }

    Ok(Json(serde_json::json!({
        "query": q.q,
        "functions": functions,
        "imports": imports,
        "exports": exports,
        "strings": strings.into_iter().take(100).collect::<Vec<_>>(),
        "crypto": crypto,
        "network": network,
    })))
}
