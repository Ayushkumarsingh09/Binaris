use std::process::Command;

/// Probe for Keystone `kstool` CLI (official Keystone assembler frontend).
pub fn probe() -> bool {
    which("kstool").is_some() || which("kstool.exe").is_some()
}

/// Assemble a single instruction line when Keystone is available.
pub fn assemble(arch: &str, mode: &str, asm: &str) -> anyhow::Result<Vec<u8>> {
    let tool = which("kstool")
        .or_else(|| which("kstool.exe"))
        .ok_or_else(|| anyhow::anyhow!("kstool not found"))?;
    let out = Command::new(tool)
        .arg(format!("{arch}-{mode}"))
        .arg(asm)
        .output()?;
    if !out.status.success() {
        anyhow::bail!(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // kstool prints hex bytes
    let hex: String = text
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    Ok(hex::decode(hex)?)
}

fn which(name: &str) -> Option<std::path::PathBuf> {
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
