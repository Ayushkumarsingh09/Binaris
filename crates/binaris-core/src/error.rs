use thiserror::Error;

pub type Result<T> = std::result::Result<T, BinarisError>;

#[derive(Debug, Error)]
pub enum BinarisError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("unsupported binary format: {0}")]
    UnsupportedFormat(String),

    #[error("analysis failed: {0}")]
    Analysis(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("queue error: {0}")]
    Queue(String),

    #[error("AI provider error: {0}")]
    Ai(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl BinarisError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotFound(_) => 404,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::Validation(_) | Self::UnsupportedFormat(_) => 400,
            Self::Conflict(_) => 409,
            Self::RateLimited(_) => 429,
            _ => 500,
        }
    }
}
