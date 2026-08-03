//! OAuth / OIDC helpers for Google, GitHub, and generic OIDC providers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub subject: String,
    pub email: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub provider: String,
}

impl OAuthProviderConfig {
    pub fn from_env(provider: &str) -> Option<Self> {
        let upper = provider.to_ascii_uppercase();
        let client_id = std::env::var(format!("BINARIS_OAUTH_{upper}_CLIENT_ID")).ok()?;
        let client_secret = std::env::var(format!("BINARIS_OAUTH_{upper}_CLIENT_SECRET")).ok()?;
        let redirect_uri = std::env::var(format!("BINARIS_OAUTH_{upper}_REDIRECT_URI")).unwrap_or_else(|_| {
            format!("http://127.0.0.1:8080/v1/auth/oauth/{provider}/callback")
        });
        let (auth_url, token_url, userinfo_url, scopes) = match provider {
            "google" => (
                "https://accounts.google.com/o/oauth2/v2/auth".into(),
                "https://oauth2.googleapis.com/token".into(),
                "https://openidconnect.googleapis.com/v1/userinfo".into(),
                vec!["openid".into(), "email".into(), "profile".into()],
            ),
            "github" => (
                "https://github.com/login/oauth/authorize".into(),
                "https://github.com/login/oauth/access_token".into(),
                "https://api.github.com/user".into(),
                vec!["read:user".into(), "user:email".into()],
            ),
            "oidc" => (
                std::env::var("BINARIS_OIDC_AUTH_URL").unwrap_or_default(),
                std::env::var("BINARIS_OIDC_TOKEN_URL").unwrap_or_default(),
                std::env::var("BINARIS_OIDC_USERINFO_URL").unwrap_or_default(),
                vec!["openid".into(), "email".into(), "profile".into()],
            ),
            _ => return None,
        };
        if auth_url.is_empty() || token_url.is_empty() {
            return None;
        }
        Some(Self {
            provider: provider.into(),
            client_id,
            client_secret,
            redirect_uri,
            auth_url,
            token_url,
            userinfo_url,
            scopes,
        })
    }

    pub fn authorize_url(&self, state: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            self.auth_url,
            urlencoding(&self.client_id),
            urlencoding(&self.redirect_uri),
            urlencoding(&self.scopes.join(" ")),
            urlencoding(state)
        )
    }
}

pub fn list_configured_providers() -> Vec<String> {
    ["google", "github", "oidc"]
        .into_iter()
        .filter(|p| OAuthProviderConfig::from_env(p).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
