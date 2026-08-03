use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use binaris_auth::{hash_password, verify_password};
use binaris_core::{OrgId, Organization, Role, User, UserId};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub org_name: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
    pub org_id: OrgId,
    pub role: Role,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    if req.password.len() < 8 {
        return Err((StatusCode::BAD_REQUEST, "password must be at least 8 characters".into()));
    }
    if state
        .store
        .get_user_by_email(&req.email)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err((StatusCode::CONFLICT, "email already registered".into()));
    }
    let user = User {
        id: UserId::new(),
        email: req.email.clone(),
        name: req.name.clone(),
        avatar_url: None,
        created_at: Utc::now(),
    };
    let hash = hash_password(&req.password).map_err(internal)?;
    state
        .store
        .upsert_user(&user, Some(&hash))
        .await
        .map_err(internal)?;
    let org = Organization {
        id: OrgId::new(),
        name: req.org_name.unwrap_or_else(|| format!("{}'s Org", req.name)),
        slug: slugify(&req.email),
        created_at: Utc::now(),
    };
    state.store.upsert_org(&org).await.map_err(internal)?;
    state
        .store
        .set_membership(org.id, user.id, Role::Owner)
        .await
        .map_err(internal)?;
    let token = state
        .jwt
        .issue(user.id, &user.email, org.id, Role::Owner)
        .map_err(internal)?;
    state
        .store
        .audit(Some(org.id), Some(user.id), "auth.register", &user.email)
        .await
        .ok();
    Ok(Json(AuthResponse {
        token,
        user,
        org_id: org.id,
        role: Role::Owner,
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let (user, hash) = state
        .store
        .get_user_by_email(&req.email)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    let hash = hash.ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;
    if !verify_password(&req.password, &hash).map_err(internal)? {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into()));
    }
    let (org_id, role) = state
        .store
        .find_org_for_user(user.id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::UNAUTHORIZED, "no organization membership".into()))?;

    let token = state
        .jwt
        .issue(user.id, &user.email, org_id, role)
        .map_err(internal)?;
    Ok(Json(AuthResponse {
        token,
        user,
        org_id,
        role,
    }))
}

fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .take(48)
        .collect()
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
