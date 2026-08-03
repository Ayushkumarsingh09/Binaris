use binaris_core::AnalysisJob;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::{info, warn};

const QUEUE_KEY: &str = "binaris:jobs:analyze";

#[derive(Clone)]
pub struct JobQueue {
    redis: Option<ConnectionManager>,
    local: std::sync::Arc<tokio::sync::Mutex<Vec<AnalysisJob>>>,
}

impl JobQueue {
    pub async fn from_env() -> anyhow::Result<Self> {
        let local = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        if let Ok(url) = std::env::var("REDIS_URL") {
            match redis::Client::open(url) {
                Ok(client) => match ConnectionManager::new(client).await {
                    Ok(conn) => {
                        info!("connected to Redis job queue");
                        return Ok(Self {
                            redis: Some(conn),
                            local,
                        });
                    }
                    Err(e) => warn!(error = %e, "redis connection failed; using local queue"),
                },
                Err(e) => warn!(error = %e, "redis client failed; using local queue"),
            }
        } else {
            warn!("REDIS_URL not set — using in-process job queue");
        }
        Ok(Self {
            redis: None,
            local,
        })
    }

    pub async fn enqueue(&self, job: &AnalysisJob) -> anyhow::Result<()> {
        let payload = serde_json::to_string(job)?;
        if let Some(mut conn) = self.redis.clone() {
            let _: () = conn.lpush(QUEUE_KEY, payload).await?;
        } else {
            self.local.lock().await.push(job.clone());
        }
        Ok(())
    }

    pub async fn dequeue(&self) -> anyhow::Result<Option<AnalysisJob>> {
        if let Some(mut conn) = self.redis.clone() {
            let item: Option<String> = conn.rpop(QUEUE_KEY, None).await?;
            return Ok(item.and_then(|s| serde_json::from_str(&s).ok()));
        }
        Ok(self.local.lock().await.pop())
    }
}
