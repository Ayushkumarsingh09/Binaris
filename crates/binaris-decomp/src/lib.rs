//! Multi-backend decompilation and language structure analysis.
//!
//! Backends are invoked when their CLI tools are installed; otherwise the
//! built-in Capstone-driven pseudocode engine always runs.

pub mod ghidra;
pub mod keystone;
pub mod pseudocode;
pub mod rizin;
pub mod treesitter;

use binaris_core::{Architecture, FunctionAnalysis};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompBackendResult {
    pub backend: String,
    pub available: bool,
    pub pseudocode: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompEnrichment {
    pub backends: Vec<DecompBackendResult>,
    pub language_structures: Vec<treesitter::LanguageHit>,
}

pub async fn enrich_functions(
    data: &[u8],
    arch: Architecture,
    functions: &mut [FunctionAnalysis],
) -> DecompEnrichment {
    // Always apply built-in pseudocode
    for f in functions.iter_mut() {
        if f.pseudocode_summary.is_none() || f.assembly_preview.is_some() {
            let pc = pseudocode::from_assembly_preview(
                f.assembly_preview.as_deref().unwrap_or(""),
                f.suggested_name.as_deref().unwrap_or(&f.name),
            );
            if f.pseudocode_summary.is_none() {
                f.pseudocode_summary = Some(pc.clone());
            }
            if f.description.is_none() {
                f.description = Some(pc);
            }
        }
    }

    let mut backends = vec![DecompBackendResult {
        backend: "binaris-pseudocode".into(),
        available: true,
        pseudocode: functions
            .first()
            .and_then(|f| f.pseudocode_summary.clone()),
        notes: vec!["Deterministic Capstone-derived pseudocode".into()],
    }];

    if let Some(r) = ghidra::try_decompile(data, arch).await {
        apply_backend_pseudocode(functions, &r);
        backends.push(r);
    } else {
        backends.push(DecompBackendResult {
            backend: "ghidra".into(),
            available: false,
            pseudocode: None,
            notes: vec!["GHIDRA_HOME / analyzeHeadless not found".into()],
        });
    }

    if let Some(r) = rizin::try_decompile(data, "rizin").await {
        apply_backend_pseudocode(functions, &r);
        backends.push(r);
    } else {
        backends.push(DecompBackendResult {
            backend: "rizin".into(),
            available: false,
            pseudocode: None,
            notes: vec!["rizin binary not on PATH".into()],
        });
    }

    if let Some(r) = rizin::try_decompile(data, "radare2").await {
        apply_backend_pseudocode(functions, &r);
        backends.push(r);
    } else {
        backends.push(DecompBackendResult {
            backend: "radare2".into(),
            available: false,
            pseudocode: None,
            notes: vec!["radare2 binary not on PATH".into()],
        });
    }

    let _ = keystone::probe();
    backends.push(DecompBackendResult {
        backend: "keystone".into(),
        available: keystone::probe(),
        pseudocode: None,
        notes: vec![if keystone::probe() {
            "kstool available for assemble/disassemble".into()
        } else {
            "kstool not on PATH".into()
        }],
    });

    let language_structures = treesitter::scan_binary_strings(data);

    DecompEnrichment {
        backends,
        language_structures,
    }
}

fn apply_backend_pseudocode(functions: &mut [FunctionAnalysis], result: &DecompBackendResult) {
    let Some(pc) = &result.pseudocode else {
        return;
    };
    if let Some(f) = functions.first_mut() {
        f.pseudocode_summary = Some(format!(
            "// via {}\n{}\n\n{}",
            result.backend,
            pc,
            f.pseudocode_summary.clone().unwrap_or_default()
        ));
        f.tags.push(format!("decomp:{}", result.backend));
        f.confidence = (f.confidence + 0.1).min(0.95);
    }
}
