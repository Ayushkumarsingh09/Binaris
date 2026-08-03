use crate::DecompBackendResult;
use std::process::Stdio;
use tokio::process::Command;

pub async fn try_decompile(data: &[u8], tool: &str) -> Option<DecompBackendResult> {
    if which(tool).is_none() {
        return None;
    }
    let dir = tempfile::tempdir().ok()?;
    let bin_path = dir.path().join("sample.bin");
    std::fs::write(&bin_path, data).ok()?;

    // rizin/radare2: print entry pdg/pdf style decompile when available (r2dec/pdc)
    let cmd = if tool == "rizin" {
        format!("aaa; s entry0; pdg 2>/dev/null || pdc 2>/dev/null || pdf")
    } else {
        format!("aaa; s entry0; pdc 2>/dev/null || pdf")
    };

    let output = Command::new(tool)
        .arg("-q")
        .arg("-c")
        .arg(&cmd)
        .arg(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    if text.trim().is_empty() && !output.status.success() {
        return Some(DecompBackendResult {
            backend: tool.into(),
            available: true,
            pseudocode: None,
            notes: vec![format!("tool failed: {}", err.chars().take(500).collect::<String>())],
        });
    }

    Some(DecompBackendResult {
        backend: tool.into(),
        available: true,
        pseudocode: Some(text.chars().take(8000).collect()),
        notes: vec![format!("Invoked {tool} quiet analysis")],
    })
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
            let bat = dir.join(format!("{name}.exe"));
            if bat.exists() {
                return Some(bat);
            }
        }
        None
    })
}
