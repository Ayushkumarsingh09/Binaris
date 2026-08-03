mod routes;
mod state;
mod queue;

use clap::Parser;
use state::AppState;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "binaris-api", about = "Binaris API server")]
struct Args {
    #[arg(long, env = "BINARIS_API_HOST", default_value = "0.0.0.0")]
    host: String,
    #[arg(long, env = "BINARIS_API_PORT", default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "binaris_api=info,binaris_pipeline=info,binaris_analysis=info,tower_http=info".into()
        }))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let args = Args::parse();
    let state = AppState::from_env().await?;

    // Ensure demo tenant exists for zero-config local use
    state.bootstrap_demo().await?;

    let app = routes::router(state).layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    ).layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!(%addr, "Binaris API listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
