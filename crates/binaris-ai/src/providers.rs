use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            provider: std::env::var("BINARIS_AI_PROVIDER").unwrap_or_else(|_| "local".into()),
            model: std::env::var("BINARIS_AI_MODEL").unwrap_or_else(|_| "binaris-local".into()),
            api_key: std::env::var("BINARIS_AI_API_KEY")
                .ok()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok()),
            base_url: std::env::var("BINARIS_AI_BASE_URL").ok(),
        }
    }
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, messages: &[AiMessage]) -> anyhow::Result<String>;
}

pub struct LocalProvider;

#[async_trait]
impl LlmProvider for LocalProvider {
    async fn complete(&self, messages: &[AiMessage]) -> anyhow::Result<String> {
        let user = messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("");
        Ok(format!(
            "Local evidence-bound response (no external model configured).\n\n{}",
            user.chars().take(4000).collect::<String>()
        ))
    }
}

pub struct OpenAiCompatible {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
    client: reqwest::Client,
}

impl OpenAiCompatible {
    pub fn new(api_key: String, base_url: String, model: String) -> Self {
        Self {
            api_key,
            base_url,
            model,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatible {
    async fn complete(&self, messages: &[AiMessage]) -> anyhow::Result<String> {
        let url = format!(
            "{}/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
        });
        let res = self
            .client
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("provider error {status}: {text}");
        }
        let v: serde_json::Value = res.json().await?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(content)
    }
}

pub fn build_provider(cfg: &ProviderConfig) -> Box<dyn LlmProvider> {
    match cfg.provider.as_str() {
        "openai" | "openrouter" | "ollama" | "gemini" | "claude" => {
            if let Some(key) = &cfg.api_key {
                let base = cfg.base_url.clone().unwrap_or_else(|| match cfg.provider.as_str() {
                    "openrouter" => "https://openrouter.ai/api/v1".into(),
                    "ollama" => "http://127.0.0.1:11434/v1".into(),
                    "gemini" => "https://generativelanguage.googleapis.com/v1beta/openai".into(),
                    "claude" => "https://api.anthropic.com/v1".into(),
                    _ => "https://api.openai.com/v1".into(),
                });
                Box::new(OpenAiCompatible::new(key.clone(), base, cfg.model.clone()))
            } else {
                warn!("AI provider requested but no API key; using local engine");
                Box::new(LocalProvider)
            }
        }
        _ => Box::new(LocalProvider),
    }
}
