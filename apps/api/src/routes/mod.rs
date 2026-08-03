mod auth;
mod health;
mod projects;
mod analysis;
mod chat;
mod search;
mod reports;
mod ws;
mod graphql;
mod oauth;
mod snapshots;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .nest("/v1/auth", auth::routes())
        .nest("/v1/auth", oauth::routes())
        .nest("/v1/projects", projects::routes())
        .nest("/v1", analysis::routes())
        .nest("/v1", chat::routes())
        .nest("/v1", search::routes())
        .nest("/v1", reports::routes())
        .nest("/v1", ws::routes())
        .nest("/v1", graphql::routes())
        .nest("/v1", snapshots::routes())
        .with_state(state)
}
