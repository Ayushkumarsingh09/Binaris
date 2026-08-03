pub mod oauth;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use binaris_core::{ApiKeyId, OrgId, Role, UserId};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub role: Role,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

#[derive(Clone)]
pub struct JwtService {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    ttl_hours: i64,
}

impl JwtService {
    pub fn from_secret(secret: &str) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            issuer: "binaris".into(),
            ttl_hours: 24,
        }
    }

    pub fn issue(&self, user_id: UserId, email: &str, org_id: OrgId, role: Role) -> anyhow::Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            org_id: org_id.to_string(),
            role,
            exp: (now + Duration::hours(self.ttl_hours)).timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };
        Ok(encode(&Header::default(), &claims, &self.encoding)?)
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        let data = decode::<Claims>(token, &self.decoding, &validation)?;
        Ok(data.claims)
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMaterial {
    pub id: ApiKeyId,
    pub prefix: String,
    pub secret: String,
    pub hash: String,
}

pub fn generate_api_key() -> ApiKeyMaterial {
    let id = ApiKeyId::new();
    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut raw);
    let secret = format!("bnr_{}", hex::encode(raw));
    let prefix = secret.chars().take(12).collect();
    let hash = hex::encode(Sha256::digest(secret.as_bytes()));
    ApiKeyMaterial {
        id,
        prefix,
        secret,
        hash,
    }
}

pub fn hash_api_key(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

pub fn role_allows(role: Role, action: &str) -> bool {
    match action {
        "project:read" | "analysis:read" | "report:read" | "chat:read" => true,
        "project:write" | "analysis:write" | "annotation:write" | "chat:write" => {
            matches!(role, Role::Owner | Role::Admin | Role::Analyst)
        }
        "org:admin" | "api_key:manage" | "member:manage" => {
            matches!(role, Role::Owner | Role::Admin)
        }
        "org:delete" => matches!(role, Role::Owner),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn jwt_roundtrip() {
        let jwt = JwtService::from_secret("test-secret-key-32-bytes-minimum!!");
        let token = jwt
            .issue(UserId::new(), "a@b.co", OrgId::new(), Role::Analyst)
            .unwrap();
        let claims = jwt.verify(&token).unwrap();
        assert_eq!(claims.email, "a@b.co");
    }
}
