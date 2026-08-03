//! Binaris core domain types shared across API, workers, and SDKs.

pub mod error;
pub mod evidence;
pub mod ids;
pub mod models;
pub mod pipeline;

pub use error::{BinarisError, Result};
pub use evidence::Evidence;
pub use ids::*;
pub use models::*;
pub use pipeline::*;
