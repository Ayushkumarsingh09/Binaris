use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::info;

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
    async fn exists(&self, key: &str) -> anyhow::Result<bool>;
}

#[derive(Clone)]
pub struct LocalObjectStore {
    root: PathBuf,
}

impl LocalObjectStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let safe = key.replace("..", "_");
        self.root.join(safe)
    }
}

#[async_trait]
impl ObjectStore for LocalObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, bytes).await?;
        info!(key, bytes = bytes.len(), "stored object locally");
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.path_for(key);
        Ok(fs::read(path).await?)
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            fs::remove_file(path).await?;
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self.path_for(key).exists())
    }
}

/// Minimal S3-compatible PUT/GET via HTTP (path-style). For production, wire AWS SigV4.
#[derive(Clone)]
pub struct S3HttpStore {
    endpoint: String,
    bucket: String,
    client: reqwest::Client,
}

impl S3HttpStore {
    pub fn new(endpoint: String, bucket: String) -> Self {
        Self {
            endpoint,
            bucket,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.bucket,
            key
        )
    }
}

#[async_trait]
impl ObjectStore for S3HttpStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let res = self.client.put(self.url(key)).body(bytes.to_vec()).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("s3 put failed: {}", res.status());
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let res = self.client.get(self.url(key)).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("s3 get failed: {}", res.status());
        }
        Ok(res.bytes().await?.to_vec())
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let res = self.client.delete(self.url(key)).send().await?;
        if !res.status().is_success() && res.status().as_u16() != 404 {
            anyhow::bail!("s3 delete failed: {}", res.status());
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        let res = self.client.head(self.url(key)).send().await?;
        Ok(res.status().is_success())
    }
}

pub fn build_store_from_env() -> anyhow::Result<Box<dyn ObjectStore>> {
    let backend = std::env::var("BINARIS_STORAGE_BACKEND").unwrap_or_else(|_| "local".into());
    match backend.as_str() {
        "s3" => {
            let endpoint = std::env::var("BINARIS_S3_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:9000".into());
            let bucket = std::env::var("BINARIS_S3_BUCKET").unwrap_or_else(|_| "binaris".into());
            Ok(Box::new(S3HttpStore::new(endpoint, bucket)))
        }
        _ => {
            let root = std::env::var("BINARIS_STORAGE_PATH")
                .unwrap_or_else(|_| "./data/objects".into());
            std::fs::create_dir_all(&root)?;
            Ok(Box::new(LocalObjectStore::new(root)))
        }
    }
}
