use binaris_auth::JwtService;
use binaris_core::{OrgId, Organization, Project, ProjectId, Role, User, UserId};
use binaris_db::{MemoryStore, PgStore, Store};
use binaris_storage::{build_store_from_env, ObjectStore};
use chrono::Utc;
use std::sync::Arc;

use crate::queue::JobQueue;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub objects: Arc<dyn ObjectStore>,
    pub jwt: JwtService,
    pub queue: JobQueue,
    pub inline_analyze: bool,
}

impl AppState {
    pub async fn from_env() -> anyhow::Result<Self> {
        let jwt_secret = std::env::var("BINARIS_JWT_SECRET")
            .unwrap_or_else(|_| "binaris-dev-secret-change-me-in-production-32b".into());
        let jwt = JwtService::from_secret(&jwt_secret);

        let store: Arc<dyn Store> = if let Ok(url) = std::env::var("DATABASE_URL") {
            let pg = PgStore::connect(&url).await?;
            let _ = pg.migrate().await;
            Arc::new(pg)
        } else {
            tracing::warn!("DATABASE_URL not set — using in-memory store");
            Arc::new(MemoryStore::new())
        };

        let objects = Arc::from(build_store_from_env()?);
        let queue = JobQueue::from_env().await?;
        let inline_analyze = std::env::var("BINARIS_INLINE_ANALYZE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        Ok(Self {
            store,
            objects,
            jwt,
            queue,
            inline_analyze,
        })
    }

    pub async fn bootstrap_demo(&self) -> anyhow::Result<()> {
        let email = "demo@binaris.dev";
        if self.store.get_user_by_email(email).await?.is_some() {
            return Ok(());
        }
        let user_id = UserId::from_uuid(uuid::Uuid::parse_str(
            "01900000-0000-7000-8000-000000000001",
        )?);
        let org_id = OrgId::from_uuid(uuid::Uuid::parse_str(
            "01900000-0000-7000-8000-000000000002",
        )?);
        let project_id = ProjectId::from_uuid(uuid::Uuid::parse_str(
            "01900000-0000-7000-8000-000000000003",
        )?);
        let user = User {
            id: user_id,
            email: email.into(),
            name: "Binaris Demo".into(),
            avatar_url: None,
            created_at: Utc::now(),
        };
        let hash = binaris_auth::hash_password("demo-password-change-me")?;
        self.store.upsert_user(&user, Some(&hash)).await?;
        let org = Organization {
            id: org_id,
            name: "Binaris Lab".into(),
            slug: "binaris-lab".into(),
            created_at: Utc::now(),
        };
        self.store.upsert_org(&org).await?;
        self.store
            .set_membership(org.id, user.id, Role::Owner)
            .await?;
        let project = Project {
            id: project_id,
            org_id: org.id,
            name: "Default Project".into(),
            description: Some("Auto-created workspace".into()),
            created_by: user.id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.store.create_project(&project).await?;
        tracing::info!(user = email, project = %project.id, "bootstrapped demo tenant");
        Ok(())
    }
}
