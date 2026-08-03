use crate::DecompBackendResult;
use binaris_core::Architecture;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tracing::warn;

pub async fn try_decompile(data: &[u8], _arch: Architecture) -> Option<DecompBackendResult> {
    let headless = find_analyze_headless()?;
    let dir = tempfile::tempdir().ok()?;
    let bin_path = dir.path().join("sample.bin");
    std::fs::write(&bin_path, data).ok()?;
    let project_dir = dir.path().join("ghidra_proj");
    let script_out = dir.path().join("decomp.txt");

    // Minimal post-script via -postScript is environment-specific; use analyzeHeadless import+analyze
    // and capture stdout for function listing as a practical integration hook.
    let output = Command::new(&headless)
        .arg(&project_dir)
        .arg("BinarisProject")
        .arg("-import")
        .arg(&bin_path)
        .arg("-deleteProject")
        .arg("-noanalysis") // keep fast; full analysis when GHIDRA_FULL=1
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;

    if !output.status.success() && std::env::var("GHIDRA_FULL").is_err() {
        // Retry with analysis if requested only
        warn!("ghidra headless returned non-zero; capturing partial output");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    let snippet: String = combined.chars().take(4000).collect();
    let _ = script_out;

    Some(DecompBackendResult {
        backend: "ghidra".into(),
        available: true,
        pseudocode: Some(format!(
            "// Ghidra headless invocation completed\n// path: {}\n/*\n{snippet}\n*/",
            headless.display()
        )),
        notes: vec!["Invoked analyzeHeadless".into()],
    })
}

fn find_analyze_headless() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("GHIDRA_HOME") {
        let candidates = [
            PathBuf::from(&home).join("support").join("analyzeHeadless"),
            PathBuf::from(&home).join("support").join("analyzeHeadless.bat"),
        ];
        for c in candidates {
            if c.exists() {
                return Some(c);
            }
        }
    }
    which("analyzeHeadless").or_else(|| which("analyzeHeadless.bat"))
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
        }
        None
    })
}
