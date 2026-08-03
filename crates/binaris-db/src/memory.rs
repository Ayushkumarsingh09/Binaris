use async_trait::async_trait;
use binaris_core::{
    AnalysisId, AnalysisReport, Annotation, ChatMessage, ChatSession, ChatSessionId, FileId, OrgId,
    Organization, PipelineStage, Project, ProjectId, ReportDocument, Role, SnapshotId, StoredFile,
    User, UserId,
};
use binaris_diff::AnalysisSnapshot;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;

use crate::Store;

#[derive(Default)]
struct Inner {
    password_hashes: DashMap<String, String>,
    memberships: DashMap<(OrgId, UserId), Role>,
    projects: DashMap<ProjectId, Project>,
    files: DashMap<FileId, StoredFile>,
    analyses: DashMap<AnalysisId, AnalysisReport>,
    reports: DashMap<AnalysisId, Vec<ReportDocument>>,
    annotations: DashMap<AnalysisId, Vec<Annotation>>,
    chat_sessions: DashMap<ChatSessionId, ChatSession>,
    chat_messages: DashMap<ChatSessionId, Vec<ChatMessage>>,
    users: DashMap<UserId, User>,
    users_by_email: DashMap<String, UserId>,
    orgs: DashMap<OrgId, Organization>,
    audit: RwLock<Vec<String>>,
    snapshots: DashMap<SnapshotId, AnalysisSnapshot>,
}

#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn upsert_user(&self, user: &User, password_hash: Option<&str>) -> anyhow::Result<()> {
        self.inner.users.insert(user.id, user.clone());
        self.inner
            .users_by_email
            .insert(user.email.to_ascii_lowercase(), user.id);
        if let Some(hash) = password_hash {
            self.inner
                .password_hashes
                .insert(user.email.to_ascii_lowercase(), hash.to_string());
        }
        Ok(())
    }

    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<(User, Option<String>)>> {
        let key = email.to_ascii_lowercase();
        let Some(id) = self.inner.users_by_email.get(&key).map(|v| *v) else {
            return Ok(None);
        };
        let user = self.inner.users.get(&id).map(|u| u.clone());
        let hash = self.inner.password_hashes.get(&key).map(|h| h.clone());
        Ok(user.map(|u| (u, hash)))
    }

    async fn get_user(&self, id: UserId) -> anyhow::Result<Option<User>> {
        Ok(self.inner.users.get(&id).map(|u| u.clone()))
    }

    async fn upsert_org(&self, org: &Organization) -> anyhow::Result<()> {
        self.inner.orgs.insert(org.id, org.clone());
        Ok(())
    }

    async fn set_membership(&self, org_id: OrgId, user_id: UserId, role: Role) -> anyhow::Result<()> {
        self.inner.memberships.insert((org_id, user_id), role);
        Ok(())
    }

    async fn get_membership(&self, org_id: OrgId, user_id: UserId) -> anyhow::Result<Option<Role>> {
        Ok(self.inner.memberships.get(&(org_id, user_id)).map(|r| *r))
    }

    async fn create_project(&self, project: &Project) -> anyhow::Result<()> {
        self.inner.projects.insert(project.id, project.clone());
        Ok(())
    }

    async fn list_projects(&self, org_id: OrgId) -> anyhow::Result<Vec<Project>> {
        let mut items: Vec<_> = self
            .inner
            .projects
            .iter()
            .filter(|p| p.org_id == org_id)
            .map(|p| p.clone())
            .collect();
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
    }

    async fn get_project(&self, id: ProjectId) -> anyhow::Result<Option<Project>> {
        Ok(self.inner.projects.get(&id).map(|p| p.clone()))
    }

    async fn create_file(&self, file: &StoredFile) -> anyhow::Result<()> {
        self.inner.files.insert(file.id, file.clone());
        Ok(())
    }

    async fn get_file(&self, id: FileId) -> anyhow::Result<Option<StoredFile>> {
        Ok(self.inner.files.get(&id).map(|f| f.clone()))
    }

    async fn save_analysis(&self, report: &AnalysisReport) -> anyhow::Result<()> {
        self.inner.analyses.insert(report.id, report.clone());
        Ok(())
    }

    async fn update_analysis_stage(
        &self,
        id: AnalysisId,
        stage: PipelineStage,
        progress: u8,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        if let Some(mut r) = self.inner.analyses.get_mut(&id) {
            r.stage = stage;
            r.progress = progress;
            r.error = error;
            r.updated_at = chrono::Utc::now();
        }
        Ok(())
    }

    async fn get_analysis(&self, id: AnalysisId) -> anyhow::Result<Option<AnalysisReport>> {
        Ok(self.inner.analyses.get(&id).map(|a| a.clone()))
    }

    async fn list_analyses(&self, project_id: ProjectId) -> anyhow::Result<Vec<AnalysisReport>> {
        let mut items: Vec<_> = self
            .inner
            .analyses
            .iter()
            .filter(|a| a.project_id == project_id)
            .map(|a| a.clone())
            .collect();
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
    }

    async fn save_reports(&self, docs: &[ReportDocument]) -> anyhow::Result<()> {
        for d in docs {
            self.inner
                .reports
                .entry(d.analysis_id)
                .or_default()
                .push(d.clone());
        }
        Ok(())
    }

    async fn list_reports(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<ReportDocument>> {
        Ok(self
            .inner
            .reports
            .get(&analysis_id)
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    async fn save_annotation(&self, ann: &Annotation) -> anyhow::Result<()> {
        self.inner
            .annotations
            .entry(ann.analysis_id)
            .or_default()
            .push(ann.clone());
        Ok(())
    }

    async fn list_annotations(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<Annotation>> {
        Ok(self
            .inner
            .annotations
            .get(&analysis_id)
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    async fn create_chat_session(&self, session: &ChatSession) -> anyhow::Result<()> {
        self.inner.chat_sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn add_chat_message(&self, msg: &ChatMessage) -> anyhow::Result<()> {
        self.inner
            .chat_messages
            .entry(msg.session_id)
            .or_default()
            .push(msg.clone());
        Ok(())
    }

    async fn list_chat_messages(&self, session_id: ChatSessionId) -> anyhow::Result<Vec<ChatMessage>> {
        Ok(self
            .inner
            .chat_messages
            .get(&session_id)
            .map(|v| v.clone())
            .unwrap_or_default())
    }

    async fn audit(
        &self,
        org_id: Option<OrgId>,
        user_id: Option<UserId>,
        action: &str,
        resource: &str,
    ) -> anyhow::Result<()> {
        self.inner.audit.write().push(format!(
            "{} org={:?} user={:?} action={action} resource={resource}",
            chrono::Utc::now(),
            org_id,
            user_id
        ));
        Ok(())
    }

    async fn find_org_for_user(&self, user_id: UserId) -> anyhow::Result<Option<(OrgId, Role)>> {
        for entry in self.inner.memberships.iter() {
            let ((org_id, uid), role) = (entry.key(), entry.value());
            if *uid == user_id {
                return Ok(Some((*org_id, *role)));
            }
        }
        Ok(None)
    }

    async fn save_snapshot(&self, snap: &AnalysisSnapshot) -> anyhow::Result<()> {
        self.inner.snapshots.insert(snap.id, snap.clone());
        Ok(())
    }

    async fn list_snapshots(&self, analysis_id: AnalysisId) -> anyhow::Result<Vec<AnalysisSnapshot>> {
        let mut items: Vec<_> = self
            .inner
            .snapshots
            .iter()
            .filter(|s| s.analysis_id == analysis_id)
            .map(|s| s.clone())
            .collect();
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(items)
    }

    async fn get_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisSnapshot>> {
        Ok(self.inner.snapshots.get(&id).map(|s| s.clone()))
    }

    async fn restore_snapshot(&self, id: SnapshotId) -> anyhow::Result<Option<AnalysisReport>> {
        let Some(snap) = self.get_snapshot(id).await? else {
            return Ok(None);
        };
        let mut report = snap.report;
        report.updated_at = chrono::Utc::now();
        self.save_analysis(&report).await?;
        Ok(Some(report))
    }
}
