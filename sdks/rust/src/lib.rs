//! Official Binaris Rust SDK.

use binaris_core::{AnalysisReport, Project};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("{0}")]
    Api(String),
}

#[derive(Clone)]
pub struct BinarisClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl BinarisClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
        }
    }

    pub async fn list_projects(&self) -> Result<Vec<Project>, SdkError> {
        let res = self
            .http
            .get(format!("{}/v1/projects", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(SdkError::Api(res.text().await.unwrap_or_default()));
        }
        Ok(res.json().await?)
    }

    pub async fn get_analysis(&self, id: Uuid) -> Result<AnalysisReport, SdkError> {
        let res = self
            .http
            .get(format!("{}/v1/analyses/{id}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(SdkError::Api(res.text().await.unwrap_or_default()));
        }
        Ok(res.json().await?)
    }

    pub async fn upload(
        &self,
        project_id: Uuid,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<AnalysisReport, SdkError> {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| SdkError::Api(e.to_string()))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let res = self
            .http
            .post(format!(
                "{}/v1/projects/{project_id}/upload",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .multipart(form)
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(SdkError::Api(res.text().await.unwrap_or_default()));
        }
        Ok(res.json().await?)
    }

    pub async fn chat(
        &self,
        analysis_id: Uuid,
        message: impl Serialize,
    ) -> Result<serde_json::Value, SdkError> {
        let res = self
            .http
            .post(format!("{}/v1/analyses/{analysis_id}/chat", self.base_url))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "message": message }))
            .send()
            .await?;
        if !res.status().is_success() {
            return Err(SdkError::Api(res.text().await.unwrap_or_default()));
        }
        Ok(res.json().await?)
    }
}
