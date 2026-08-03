//! Security findings: unsafe APIs, secrets, weak crypto indicators.

use binaris_core::{
    CryptoFinding, Evidence, ExtractedString, ImportEntry, RiskLevel, SecurityFinding,
    StringCategory,
};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_GOOGLE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).expect("google key"));
static RE_AZURE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=%]{16,}"#).expect("azure")
});
static RE_GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"#)
        .expect("secret")
});

pub fn analyze(
    imports: &[ImportEntry],
    strings: &[ExtractedString],
    crypto: &[CryptoFinding],
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    for imp in imports {
        if let Some(f) = unsafe_api_finding(imp) {
            findings.push(f);
        }
    }

    for s in strings {
        match s.category {
            StringCategory::ApiKey | StringCategory::Credential | StringCategory::Jwt => {
                findings.push(SecurityFinding {
                    id: uuid::Uuid::now_v7().to_string(),
                    title: format!("Potential {:?} exposure", s.category),
                    category: "secrets".into(),
                    severity: RiskLevel::Critical,
                    confidence: s.score,
                    description: format!("Sensitive string category detected at offset {:#x}", s.offset),
                    cwe: Some("CWE-798".into()),
                    location: Some(format!("string@{:#x}", s.offset)),
                    evidence: vec![Evidence::String {
                        value: redact(&s.value),
                        offset: Some(s.offset),
                        note: "Hardcoded secret indicator".into(),
                    }],
                    remediation: Some("Remove secrets from binaries; use a secrets manager.".into()),
                });
            }
            _ => {}
        }
        if RE_GOOGLE.is_match(&s.value) {
            findings.push(secret_finding("Google API key", &s.value, s.offset, 0.95));
        }
        if RE_AZURE.is_match(&s.value) {
            findings.push(secret_finding("Azure key material", &s.value, s.offset, 0.9));
        }
        if RE_GENERIC_SECRET.is_match(&s.value) {
            findings.push(secret_finding("Hardcoded credential assignment", &s.value, s.offset, 0.8));
        }
    }

    for c in crypto {
        if c.strength == "weak" {
            findings.push(SecurityFinding {
                id: uuid::Uuid::now_v7().to_string(),
                title: format!("Weak cryptography: {}", c.algorithm),
                category: "weak_crypto".into(),
                severity: RiskLevel::High,
                confidence: c.confidence,
                description: c
                    .weakness
                    .clone()
                    .unwrap_or_else(|| format!("{} is considered weak", c.algorithm)),
                cwe: Some("CWE-327".into()),
                location: c.mode.clone(),
                evidence: c.evidence.clone(),
                remediation: Some("Migrate to modern algorithms (AES-GCM, ChaCha20-Poly1305, SHA-256+).".into()),
            });
        }
        if c.mode.as_deref() == Some("ECB") {
            findings.push(SecurityFinding {
                id: uuid::Uuid::now_v7().to_string(),
                title: "AES ECB mode detected".into(),
                category: "weak_crypto".into(),
                severity: RiskLevel::High,
                confidence: c.confidence,
                description: "ECB mode does not provide semantic security for repeated blocks.".into(),
                cwe: Some("CWE-327".into()),
                location: Some("crypto".into()),
                evidence: c.evidence.clone(),
                remediation: Some("Use AES-GCM or ChaCha20-Poly1305.".into()),
            });
        }
    }

    findings.sort_by(|a, b| severity_rank(b.severity).cmp(&severity_rank(a.severity)));
    findings
}

fn unsafe_api_finding(imp: &ImportEntry) -> Option<SecurityFinding> {
    let (title, category, severity, cwe, remediation) = match imp.symbol.as_str() {
        "strcpy" | "wcscpy" | "lstrcpyA" | "lstrcpyW" => (
            "Unsafe strcpy family",
            "buffer_overflow",
            RiskLevel::High,
            "CWE-120",
            "Use bounded string APIs",
        ),
        "gets" => (
            "Unsafe gets()",
            "buffer_overflow",
            RiskLevel::Critical,
            "CWE-242",
            "Never use gets; use fgets",
        ),
        "sprintf" | "vsprintf" => (
            "Unsafe sprintf",
            "format_string",
            RiskLevel::High,
            "CWE-134",
            "Use snprintf with bounds",
        ),
        "memcpy" => (
            "memcpy usage",
            "unsafe_memcpy",
            RiskLevel::Medium,
            "CWE-120",
            "Validate lengths; prefer safer wrappers",
        ),
        "scanf" | "sscanf" => (
            "Unbounded scanf",
            "buffer_overflow",
            RiskLevel::Medium,
            "CWE-120",
            "Use width specifiers",
        ),
        "system" | "WinExec" | "ShellExecuteA" | "ShellExecuteW" => (
            "Command execution API",
            "command_injection",
            RiskLevel::High,
            "CWE-78",
            "Avoid shelling out with untrusted input",
        ),
        "sqlite3_exec" => (
            "SQL exec API",
            "sql_injection",
            RiskLevel::Medium,
            "CWE-89",
            "Use parameterized queries",
        ),
        _ => return None,
    };

    Some(SecurityFinding {
        id: uuid::Uuid::now_v7().to_string(),
        title: title.into(),
        category: category.into(),
        severity,
        confidence: 0.7,
        description: format!("{}!{} can enable {}", imp.module, imp.symbol, category),
        cwe: Some(cwe.into()),
        location: Some(format!("{}!{}", imp.module, imp.symbol)),
        evidence: vec![Evidence::Import {
            module: imp.module.clone(),
            symbol: imp.symbol.clone(),
            note: title.into(),
        }],
        remediation: Some(remediation.into()),
    })
}

fn secret_finding(title: &str, value: &str, offset: u64, confidence: f32) -> SecurityFinding {
    SecurityFinding {
        id: uuid::Uuid::now_v7().to_string(),
        title: title.into(),
        category: "secrets".into(),
        severity: RiskLevel::Critical,
        confidence,
        description: format!("Possible secret material at offset {offset:#x}"),
        cwe: Some("CWE-798".into()),
        location: Some(format!("string@{offset:#x}")),
        evidence: vec![Evidence::String {
            value: redact(value),
            offset: Some(offset),
            note: title.into(),
        }],
        remediation: Some("Rotate exposed credentials immediately.".into()),
    }
}

fn redact(s: &str) -> String {
    if s.len() <= 8 {
        return "***".into();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 2..])
}

fn severity_rank(r: RiskLevel) -> u8 {
    match r {
        RiskLevel::Info => 0,
        RiskLevel::Low => 1,
        RiskLevel::Medium => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_strcpy() {
        let imports = vec![ImportEntry {
            module: "msvcrt.dll".into(),
            symbol: "strcpy".into(),
            ordinal: None,
            address: None,
            risk: RiskLevel::Info,
            tags: vec![],
        }];
        let findings = analyze(&imports, &[], &[]);
        assert!(findings.iter().any(|f| f.category == "buffer_overflow"));
    }
}
