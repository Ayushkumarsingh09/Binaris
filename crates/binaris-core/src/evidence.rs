use serde::{Deserialize, Serialize};

/// Evidence citation that AI and engines must attach to claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Function {
        address: String,
        name: Option<String>,
        note: String,
    },
    Import {
        module: String,
        symbol: String,
        note: String,
    },
    Export {
        symbol: String,
        note: String,
    },
    String {
        value: String,
        offset: Option<u64>,
        note: String,
    },
    Section {
        name: String,
        note: String,
    },
    Hash {
        algorithm: String,
        value: String,
        note: String,
    },
    Signature {
        subject: String,
        note: String,
    },
    Entropy {
        region: String,
        value: f64,
        note: String,
    },
    Constant {
        value: String,
        address: Option<String>,
        note: String,
    },
    Resource {
        name: String,
        note: String,
    },
    NetworkIndicator {
        indicator: String,
        note: String,
    },
    Heuristic {
        rule: String,
        note: String,
    },
}

impl Evidence {
    pub fn note(&self) -> &str {
        match self {
            Self::Function { note, .. }
            | Self::Import { note, .. }
            | Self::Export { note, .. }
            | Self::String { note, .. }
            | Self::Section { note, .. }
            | Self::Hash { note, .. }
            | Self::Signature { note, .. }
            | Self::Entropy { note, .. }
            | Self::Constant { note, .. }
            | Self::Resource { note, .. }
            | Self::NetworkIndicator { note, .. }
            | Self::Heuristic { note, .. } => note,
        }
    }
}
