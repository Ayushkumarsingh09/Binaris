use binaris_core::PipelineStage;
use binaris_db::{PgStore, Store};
use binaris_pipeline::run_pipeline;
use binaris_storage::{build_store_from_env, ObjectStore};
use clap::Parser;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "binaris-worker")]
struct Args {
    #[arg(long, env = "BINARIS_WORKER_POLL_MS", default_value_t = 500)]
    poll_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "binaris_worker=info,binaris_pipeline=info".into()
        }))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let args = Args::parse();
    let store: Arc<dyn Store> = if let Ok(url) = std::env::var("DATABASE_URL") {
        let pg = PgStore::connect(&url).await?;
        let _ = pg.migrate().await;
        Arc::new(pg)
    } else {
        anyhow::bail!("worker requires DATABASE_URL (use API inline mode for memory store)");
    };
    let objects: Arc<dyn ObjectStore> = Arc::from(build_store_from_env()?);

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = redis::Client::open(redis_url)?;
    let mut conn = ConnectionManager::new(client).await?;
    info!("Binaris worker online");

    loop {
        let item: Option<String> = conn.rpop("binaris:jobs:analyze", None).await?;
        if let Some(payload) = item {
            match serde_json::from_str::<binaris_core::AnalysisJob>(&payload) {
                Ok(job) => {
                    info!(analysis_id = %job.analysis_id, "picked job");
                    let _ = store
                        .update_analysis_stage(
                            job.analysis_id,
                            PipelineStage::Hashing,
                            5,
                            None,
                        )
                        .await;
                    match objects.get(&job.storage_key).await {
                        Ok(data) => match run_pipeline(
                            job.analysis_id,
                            job.file_id,
                            job.project_id,
                            job.filename.clone(),
                            &data,
                            job.options,
                        )
                        .await
                        {
                            Ok(out) => {
                                store.save_analysis(&out.report).await?;
                                store.save_reports(&out.documents).await?;
                                info!(analysis_id = %job.analysis_id, "job completed");
                            }
                            Err(e) => {
                                error!(error = %e, "pipeline failed");
                                let _ = store
                                    .update_analysis_stage(
                                        job.analysis_id,
                                        PipelineStage::Failed,
                                        100,
                                        Some(e.to_string()),
                                    )
                                    .await;
                            }
                        },
                        Err(e) => {
                            error!(error = %e, "failed to load object");
                        }
                    }
                }
                Err(e) => error!(error = %e, "invalid job payload"),
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(args.poll_ms)).await;
        }
    }
}
