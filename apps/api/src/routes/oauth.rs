use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
    Json, Router,
};
use binaris_auth::oauth::{list_configured_providers, OAuthProviderConfig};
use binaris_core::{OrgId, Organization, Role, User, UserId};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/providers", get(providers))
        .route("/oauth/{provider}/start", get(start))
        .route("/oauth/{provider}/callback", get(callback))
}

async fn providers() -> Json<serde_json::Value> {
    Json(json!({ "providers": list_configured_providers() }))
}

async fn start(Path(provider): Path<String>) -> Result<Redirect, (StatusCode, String)> {
    let cfg = OAuthProviderConfig::from_env(&provider)
        .ok_or((StatusCode::NOT_FOUND, format!("oauth provider {provider} not configured")))?;
    let state = Uuid::now_v7().to_string();
    Ok(Redirect::temporary(&cfg.authorize_url(&state)))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(err) = q.error {
        return Err((StatusCode::BAD_REQUEST, err));
    }
    let code = q
        .code
        .ok_or((StatusCode::BAD_REQUEST, "missing code".into()))?;
    let cfg = OAuthProviderConfig::from_env(&provider)
        .ok_or((StatusCode::NOT_FOUND, "provider not configured".into()))?;

    let client = reqwest::Client::new();
    let token_res = client
        .post(&cfg.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", cfg.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let token_json: serde_json::Value = token_res
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let access = token_json["access_token"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "no access_token".into()))?;

    let user_res = client
        .get(&cfg.userinfo_url)
        .header("Authorization", format!("Bearer {access}"))
        .header("User-Agent", "binaris")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let user_json: serde_json::Value = user_res
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let email = user_json["email"]
        .as_str()
        .or_else(|| user_json["login"].as_str())
        .unwrap_or("unknown@oauth.local")
        .to_string();
    let name = user_json["name"]
        .as_str()
        .or_else(|| user_json["login"].as_str())
        .unwrap_or(&email)
        .to_string();
    let avatar = user_json["picture"]
        .as_str()
        .or_else(|| user_json["avatar_url"].as_str())
        .map(|s| s.to_string());

    let (user, org_id, role) = if let Some((existing, _)) = state
        .store
        .get_user_by_email(&email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        let (org_id, role) = state
            .store
            .find_org_for_user(existing.id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or((OrgId::new(), Role::Analyst));
        (existing, org_id, role)
    } else {
        let user = User {
            id: UserId::new(),
            email: email.clone(),
            name,
            avatar_url: avatar,
            created_at: Utc::now(),
        };
        state
            .store
            .upsert_user(&user, None)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let org = Organization {
            id: OrgId::new(),
            name: format!("{} Org", user.name),
            slug: format!("oauth-{}", &user.id.to_string()[..8]),
            created_at: Utc::now(),
        };
        state
            .store
            .upsert_org(&org)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .store
            .set_membership(org.id, user.id, Role::Owner)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (user, org.id, Role::Owner)
    };

    let token = state
        .jwt
        .issue(user.id, &user.email, org_id, role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .store
        .audit(Some(org_id), Some(user.id), "auth.oauth", &provider)
        .await
        .ok();

    Ok(Json(json!({
        "token": token,
        "user": user,
        "org_id": org_id,
        "role": role,
        "provider": provider,
        "state": q.state,
    })))
}
