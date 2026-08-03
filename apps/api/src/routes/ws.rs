use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use uuid::Uuid;

use crate::state::AppState;
use binaris_core::AnalysisId;

pub fn routes() -> Router<AppState> {
    Router::new().route("/analyses/{id}/ws", get(ws_handler))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, AnalysisId::from_uuid(id)))
}

async fn handle_socket(socket: WebSocket, state: AppState, id: AnalysisId) {
    let (mut sender, mut receiver) = socket.split();
    // Push current analysis snapshot, then poll for completion updates.
    for _ in 0..120 {
        if let Ok(Some(report)) = state.store.get_analysis(id).await {
            let payload = serde_json::json!({
                "type": "progress",
                "analysis_id": id,
                "stage": report.stage,
                "progress": report.progress,
                "completed": report.completed_at.is_some(),
                "error": report.error,
            });
            if sender
                .send(Message::Text(payload.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
            if report.completed_at.is_some() || report.stage == binaris_core::PipelineStage::Failed {
                let full = serde_json::json!({ "type": "report", "report": report });
                let _ = sender
                    .send(Message::Text(full.to_string().into()))
                    .await;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // Drain client pings/close
        while let Ok(Some(Ok(msg))) =
            tokio::time::timeout(std::time::Duration::from_millis(1), receiver.next()).await
        {
            if matches!(msg, Message::Close(_)) {
                return;
            }
        }
    }
}
