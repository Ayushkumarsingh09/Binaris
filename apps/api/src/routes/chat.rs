use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use binaris_ai::answer_question;
use binaris_ai::providers::ProviderConfig;
use binaris_core::{AnalysisId, ChatMessage, ChatSession, ChatSessionId, UserId};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::projects::require_auth;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/analyses/{id}/chat", post(chat))
}

#[derive(Deserialize)]
pub struct ChatRequest {
    pub message: String,
    pub session_id: Option<Uuid>,
}

async fn chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ChatRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let claims = require_auth(&state, &headers)?;
    let user_id = UserId::from_uuid(
        Uuid::parse_str(&claims.sub).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?,
    );
    let analysis_id = AnalysisId::from_uuid(id);
    let report = state
        .store
        .get_analysis(analysis_id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "analysis not found".into()))?;

    let session_id = if let Some(sid) = req.session_id {
        ChatSessionId::from_uuid(sid)
    } else {
        let session = ChatSession {
            id: ChatSessionId::new(),
            analysis_id,
            user_id,
            title: req.message.chars().take(64).collect(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state
            .store
            .create_chat_session(&session)
            .await
            .map_err(internal)?;
        session.id
    };

    let user_msg = ChatMessage {
        id: Uuid::now_v7().to_string(),
        session_id,
        role: "user".into(),
        content: req.message.clone(),
        citations: vec![],
        created_at: Utc::now(),
    };
    state
        .store
        .add_chat_message(&user_msg)
        .await
        .map_err(internal)?;

    let answer = answer_question(&report, &req.message, &ProviderConfig::default())
        .await
        .map_err(internal)?;

    let assistant = ChatMessage {
        id: Uuid::now_v7().to_string(),
        session_id,
        role: "assistant".into(),
        content: answer.content.clone(),
        citations: answer.citations.clone(),
        created_at: Utc::now(),
    };
    state
        .store
        .add_chat_message(&assistant)
        .await
        .map_err(internal)?;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "message": assistant,
        "provider": answer.provider,
    })))
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
