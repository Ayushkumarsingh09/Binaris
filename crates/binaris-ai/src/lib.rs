//! Multi-provider AI layer with mandatory evidence grounding.
//! When no API key is configured, a deterministic local semantic engine is used.

pub mod chat;
pub mod providers;
pub mod rename;
pub mod semantic;

pub use chat::{answer_question, ChatAnswer};
pub use rename::suggest_names;
pub use semantic::enrich_functions;
