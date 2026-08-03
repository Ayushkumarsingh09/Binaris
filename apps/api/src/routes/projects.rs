use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use binaris_core::{Project, ProjectId, Role, UserId};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route("/{id}", get(get_project))
}

#[derive(Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub description: Option<String>,
    pub org_id: Uuid,
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Project>>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    let org_id = binaris_core::OrgId::from_uuid(
        Uuid::parse_str(&claims.org_id).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?,
    );
    let items = state.store.list_projects(org_id).await.map_err(internal)?;
    Ok(Json(items))
}

async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateProject>,
) -> Result<Json<Project>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    if !binaris_auth::role_allows(claims.role, "project:write") {
        return Err((StatusCode::FORBIDDEN, "insufficient role".into()));
    }
    let user_id = UserId::from_uuid(
        Uuid::parse_str(&claims.sub).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?,
    );
    let project = Project {
        id: ProjectId::new(),
        org_id: binaris_core::OrgId::from_uuid(req.org_id),
        name: req.name,
        description: req.description,
        created_by: user_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    state.store.create_project(&project).await.map_err(internal)?;
    Ok(Json(project))
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Project>, (StatusCode, String)> {
    let _ = require_auth(&state, &headers)?;
    state
        .store
        .get_project(ProjectId::from_uuid(id))
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))
}

pub fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<binaris_auth::Claims, (StatusCode, String)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing authorization".into()))?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer token".into()))?;
    state
        .jwt
        .verify(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// silence unused Role import warning in some cfgs
#[allow(dead_code)]
fn _role() -> Role {
    Role::Viewer
}
