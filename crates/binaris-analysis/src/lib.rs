//! Static analysis engine: hashing, identification, unpacking hooks,
//! strings, imports/exports, sections, crypto/packer heuristics, disassembly.

pub mod compiler;
pub mod crypto_detect;
pub mod disasm;
pub mod entropy;
pub mod format;
pub mod hasher;
pub mod indicators;
pub mod packer;
pub mod pe_signature;
pub mod strings;
pub mod engine;

pub use engine::{analyze_bytes, AnalysisContext, StaticAnalysisResult};
