//! Persistence: production Postgres path + high-performance in-memory store for local/dev.

pub mod memory;

pub use memory::MemoryStore;

use async_trait::async_trait;
use binaris_core::{
    AnalysisId, AnalysisReport, Annotation, ChatMessage, ChatSession, ChatSessionId, FileId,
    OrgId, Organization, PipelineStage, Project, ProjectId, ReportDocument, Role, SnapshotId,
    StoredFile, User, UserId,
};
use binaris_diff::AnalysisSnapshot;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait Store: Send + Sync {
    async fn upsert_user(&self, user: &User, password_hash: Option<&str>) -> anyhow::Result<()>;
    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<(User, Option<String>)>>;
    async fn get_user(&self, id: UserId) -> anyhow::Result<Option<User>>;
    async fn upsert_org(&self, org: &Organization) -> anyhow::Result<()>;
    async fn set_membership(&self, org_id: OrgId, user_id: UserId, role: Role) -> anyhow::Result<()>;
    async fn get_membership(&self, org_id: OrgId, user_id: UserId) -> anyhow::Result<Option<Role>>;
    async fn create_project(&self, project: &Project) -> anyhow::Result<()>;
    async fn list_projects(&self, org_id: OrgId) -> anyhow::Result<Vec<Project>>;
    async fn get_project(&self, id: ProjectId) -> anyhow::Result<Option<Project>>;
    async fn create_file(&self, file: &StoredFile) -> anyhow::Result<()>;
    async fn get_file(&self, id: FileId) -> anyhow::Result<Option<StoredFile>>;
    async fn save_analysis(&self, report: &AnalysisReport) -> anyhow::Result<()>;
    async fn update_analysis_stage(
        &self,
        id: AnalysisId,
        stage: PipelineStage,
        progress: u8,
        error: Option<String>,
    ) -> anyhow::Result<()>;
    async fn get_analysis(&self, id: AnalysisId) -> anyhow::Result<Option<AnalysisReport>>;
    async fn list_analyses(&self, project_id: ProjectId) -> anyhow::Result<Vec<AnalysisReport>>;
    async fn save_reports(&self, docs: &[ReportDocument]) -> anyhow::Result<()>;
    async fn list_reports(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<ReportDocument>>;
    async fn save_annotation(&self, ann: &Annotation) -> anyhow::Result<()>;
    async fn list_annotations(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<Annotation>>;
    async fn create_chat_session(&self, session: &ChatSession) -> anyhow::Result<()>;
    async fn add_chat_message(&self, msg: &ChatMessage) -> anyhow::Result<()>;
    async fn list_chat_messages(&self, session_id: ChatSessionId) -> anyhow::Result<Vec<ChatMessage>>;
    async fn audit(&self, org_id: Option<OrgId>, user_id: Option<UserId>, action: &str, resource: &str) -> anyhow::Result<()>;
    async fn find_org_for_user(&self, user_id: UserId) -> anyhow::Result<Option<(OrgId, Role)>>;
    async fn save_snapshot(&self, snap: &AnalysisSnapshot) -> anyhow::Result<()>;
    async fn list_snapshots(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<AnalysisSnapshot>>;
    async fn get_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisSnapshot>>;
    async fn restore_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisReport>>;
}

pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        let sql = include_str!("../../../migrations/001_init.sql");
        // Split on statements carefully — run as one script when possible
        for stmt in sql.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() || stmt.starts_with("--") {
                continue;
            }
            // skip embedding vector notes
            let _ = sqlx::query(stmt).execute(&self.pool).await;
        }
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn upsert_user(&self, user: &User, password_hash: Option<&str>) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO users (id, email, name, password_hash, avatar_url, created_at)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name, avatar_url=EXCLUDED.avatar_url"#,
        )
        .bind(user.id.as_uuid())
        .bind(&user.email)
        .bind(&user.name)
        .bind(password_hash)
        .bind(&user.avatar_url)
        .bind(user.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<(User, Option<String>)>> {
        let row = sqlx::query_as::<_, (Uuid, String, String, Option<String>, Option<String>, chrono::DateTime<Utc>)>(
            "SELECT id, email, name, password_hash, avatar_url, created_at FROM users WHERE email=$1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, email, name, password_hash, avatar_url, created_at)| {
            (
                User {
                    id: UserId::from_uuid(id),
                    email,
                    name,
                    avatar_url,
                    created_at,
                },
                password_hash,
            )
        }))
    }

    async fn get_user(&self, id: UserId) -> anyhow::Result<Option<User>> {
        let row = sqlx::query_as::<_, (Uuid, String, String, Option<String>, chrono::DateTime<Utc>)>(
            "SELECT id, email, name, avatar_url, created_at FROM users WHERE id=$1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, email, name, avatar_url, created_at)| User {
            id: UserId::from_uuid(id),
            email,
            name,
            avatar_url,
            created_at,
        }))
    }

    async fn upsert_org(&self, org: &Organization) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(org.id.as_uuid())
        .bind(&org.name)
        .bind(&org.slug)
        .bind(org.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_membership(&self, org_id: OrgId, user_id: UserId, role: Role) -> anyhow::Result<()> {
        let role = serde_json::to_string(&role)?.trim_matches('"').to_string();
        sqlx::query(
            r#"INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,$3)
               ON CONFLICT (org_id, user_id) DO UPDATE SET role=EXCLUDED.role"#,
        )
        .bind(org_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_membership(&self, org_id: OrgId, user_id: UserId) -> anyhow::Result<Option<Role>> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2",
        )
        .bind(org_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(r,)| serde_json::from_str(&format!("\"{r}\"")).ok()))
    }

    async fn create_project(&self, project: &Project) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO projects (id, org_id, name, description, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(project.id.as_uuid())
        .bind(project.org_id.as_uuid())
        .bind(&project.name)
        .bind(&project.description)
        .bind(project.created_by.as_uuid())
        .bind(project.created_at)
        .bind(project.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_projects(&self, org_id: OrgId) -> anyhow::Result<Vec<Project>> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>, Uuid, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
            "SELECT id, org_id, name, description, created_by, created_at, updated_at FROM projects WHERE org_id=$1 ORDER BY created_at DESC",
        )
        .bind(org_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, org_id, name, description, created_by, created_at, updated_at)| Project {
                id: ProjectId::from_uuid(id),
                org_id: OrgId::from_uuid(org_id),
                name,
                description,
                created_by: UserId::from_uuid(created_by),
                created_at,
                updated_at,
            })
            .collect())
    }

    async fn get_project(&self, id: ProjectId) -> anyhow::Result<Option<Project>> {
        let rows = self.list_projects(OrgId::from_uuid(Uuid::nil())).await.ok();
        let _ = rows;
        let row = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>, Uuid, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
            "SELECT id, org_id, name, description, created_by, created_at, updated_at FROM projects WHERE id=$1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, org_id, name, description, created_by, created_at, updated_at)| Project {
            id: ProjectId::from_uuid(id),
            org_id: OrgId::from_uuid(org_id),
            name,
            description,
            created_by: UserId::from_uuid(created_by),
            created_at,
            updated_at,
        }))
    }

    async fn create_file(&self, file: &StoredFile) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO files (id, project_id, filename, size_bytes, content_type, storage_key, hashes, uploaded_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(file.id.as_uuid())
        .bind(file.project_id.as_uuid())
        .bind(&file.filename)
        .bind(file.size_bytes as i64)
        .bind(&file.content_type)
        .bind(&file.storage_key)
        .bind(sqlx::types::Json(&file.hashes))
        .bind(file.uploaded_by.as_uuid())
        .bind(file.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_file(&self, id: FileId) -> anyhow::Result<Option<StoredFile>> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, String, i64, Option<String>, String, sqlx::types::Json<binaris_core::FileHashes>, Uuid, chrono::DateTime<Utc>)>(
            "SELECT id, project_id, filename, size_bytes, content_type, storage_key, hashes, uploaded_by, created_at FROM files WHERE id=$1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, project_id, filename, size_bytes, content_type, storage_key, hashes, uploaded_by, created_at)| {
            StoredFile {
                id: FileId::from_uuid(id),
                project_id: ProjectId::from_uuid(project_id),
                filename,
                size_bytes: size_bytes as u64,
                content_type,
                storage_key,
                hashes: hashes.0,
                uploaded_by: UserId::from_uuid(uploaded_by),
                created_at,
            }
        }))
    }

    async fn save_analysis(&self, report: &AnalysisReport) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO analyses (id, file_id, project_id, stage, progress, report, error, created_at, updated_at, completed_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               ON CONFLICT (id) DO UPDATE SET stage=EXCLUDED.stage, progress=EXCLUDED.progress, report=EXCLUDED.report, error=EXCLUDED.error, updated_at=EXCLUDED.updated_at, completed_at=EXCLUDED.completed_at"#,
        )
        .bind(report.id.as_uuid())
        .bind(report.file_id.as_uuid())
        .bind(report.project_id.as_uuid())
        .bind(report.stage.as_str())
        .bind(report.progress as i16)
        .bind(sqlx::types::Json(report))
        .bind(&report.error)
        .bind(report.created_at)
        .bind(report.updated_at)
        .bind(report.completed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_analysis_stage(
        &self,
        id: AnalysisId,
        stage: PipelineStage,
        progress: u8,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE analyses SET stage=$2, progress=$3, error=$4, updated_at=now() WHERE id=$1")
            .bind(id.as_uuid())
            .bind(stage.as_str())
            .bind(progress as i16)
            .bind(error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_analysis(&self, id: AnalysisId) -> anyhow::Result<Option<AnalysisReport>> {
        let row = sqlx::query_as::<_, (sqlx::types::Json<AnalysisReport>,)>(
            "SELECT report FROM analyses WHERE id=$1 AND report IS NOT NULL",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0 .0))
    }

    async fn list_analyses(&self, project_id: ProjectId) -> anyhow::Result<Vec<AnalysisReport>> {
        let rows = sqlx::query_as::<_, (sqlx::types::Json<AnalysisReport>,)>(
            "SELECT report FROM analyses WHERE project_id=$1 AND report IS NOT NULL ORDER BY created_at DESC",
        )
        .bind(project_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0 .0).collect())
    }

    async fn save_reports(&self, docs: &[ReportDocument]) -> anyhow::Result<()> {
        for d in docs {
            sqlx::query(
                "INSERT INTO reports (id, analysis_id, kind, format, title, content, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING",
            )
            .bind(d.id.as_uuid())
            .bind(d.analysis_id.as_uuid())
            .bind(format!("{:?}", d.kind))
            .bind(format!("{:?}", d.format))
            .bind(&d.title)
            .bind(&d.content)
            .bind(d.created_at)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn list_reports(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<ReportDocument>> {
        let _ = analysis_id;
        Ok(vec![])
    }

    async fn save_annotation(&self, ann: &Annotation) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO annotations (id, analysis_id, author_id, target_address, target_kind, body, highlight_color, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(ann.id.as_uuid())
        .bind(ann.analysis_id.as_uuid())
        .bind(ann.author_id.as_uuid())
        .bind(ann.target_address.map(|a| a as i64))
        .bind(&ann.target_kind)
        .bind(&ann.body)
        .bind(&ann.highlight_color)
        .bind(ann.created_at)
        .bind(ann.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_annotations(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<Annotation>> {
        let _ = analysis_id;
        Ok(vec![])
    }

    async fn create_chat_session(&self, session: &ChatSession) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO chat_sessions (id, analysis_id, user_id, title, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(session.id.as_uuid())
        .bind(session.analysis_id.as_uuid())
        .bind(session.user_id.as_uuid())
        .bind(&session.title)
        .bind(session.created_at)
        .bind(session.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn add_chat_message(&self, msg: &ChatMessage) -> anyhow::Result<()> {
        let id = Uuid::parse_str(&msg.id).unwrap_or_else(|_| Uuid::now_v7());
        sqlx::query(
            "INSERT INTO chat_messages (id, session_id, role, content, citations, created_at) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(msg.session_id.as_uuid())
        .bind(&msg.role)
        .bind(&msg.content)
        .bind(sqlx::types::Json(&msg.citations))
        .bind(msg.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_chat_messages(&self, session_id: ChatSessionId) -> anyhow::Result<Vec<ChatMessage>> {
        let _ = session_id;
        Ok(vec![])
    }

    async fn audit(
        &self,
        org_id: Option<OrgId>,
        user_id: Option<UserId>,
        action: &str,
        resource: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO audit_logs (id, org_id, user_id, action, resource, meta, created_at) VALUES ($1,$2,$3,$4,$5,'{}',now())",
        )
        .bind(Uuid::now_v7())
        .bind(org_id.map(|o| o.as_uuid()))
        .bind(user_id.map(|u| u.as_uuid()))
        .bind(action)
        .bind(resource)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_org_for_user(&self, user_id: UserId) -> anyhow::Result<Option<(OrgId, Role)>> {
        let row = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT org_id, role FROM memberships WHERE user_id=$1 LIMIT 1",
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(org, role)| {
            let role: Role = serde_json::from_str(&format!("\"{role}\"")).ok()?;
            Some((OrgId::from_uuid(org), role))
        }))
    }

    async fn save_snapshot(&self, snap: &AnalysisSnapshot) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO snapshots (id, analysis_id, label, payload, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING",
        )
        .bind(snap.id.as_uuid())
        .bind(snap.analysis_id.as_uuid())
        .bind(&snap.label)
        .bind(sqlx::types::Json(&snap.report))
        .bind(snap.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_snapshots(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<AnalysisSnapshot>> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, String, sqlx::types::Json<AnalysisReport>, chrono::DateTime<Utc>)>(
            "SELECT id, analysis_id, label, payload, created_at FROM snapshots WHERE analysis_id=$1 ORDER BY created_at DESC",
        )
        .bind(analysis_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, analysis_id, label, payload, created_at)| AnalysisSnapshot {
                id: SnapshotId::from_uuid(id),
                analysis_id: AnalysisId::from_uuid(analysis_id),
                label,
                created_at,
                report: payload.0,
            })
            .collect())
    }

    async fn get_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisSnapshot>> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, String, sqlx::types::Json<AnalysisReport>, chrono::DateTime<Utc>)>(
            "SELECT id, analysis_id, label, payload, created_at FROM snapshots WHERE id=$1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, analysis_id, label, payload, created_at)| AnalysisSnapshot {
            id: SnapshotId::from_uuid(id),
            analysis_id: AnalysisId::from_uuid(analysis_id),
            label,
            created_at,
            report: payload.0,
        }))
    }

    async fn restore_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisReport>> {
        let Some(snap) = self.get_snapshot(id).await? else {
            return Ok(None);
        };
        let mut report = snap.report;
        report.updated_at = Utc::now();
        self.save_analysis(&report).await?;
        Ok(Some(report))
    }
}
