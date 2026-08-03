use binaris_core::{ExtractedString, StringCategory};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>]{4,}"#).expect("url regex"));
static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"#).expect("email"));
static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"#)
        .expect("ipv4")
});
static RE_DOMAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|ru|cn|xyz|info|biz|co|us|uk|de|fr|jp|kr|in|ai|app|cloud|local)\b"#)
        .expect("domain")
});
static RE_REGISTRY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)\\[\\A-Za-z0-9 _.-]+"#)
        .expect("registry")
});
static RE_PATH_WIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#).expect("win path")
});
static RE_PATH_UNIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:^|[\s"'=])(/[\w./-]{3,})"#).expect("unix path"));
static RE_MUTEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:Global|Local)\\[A-Za-z0-9_.-]{4,}"#).expect("mutex")
});
static RE_JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#).expect("jwt")
});
static RE_AWS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"#).expect("aws"));
static RE_PRIVATE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#).expect("pkey"));

pub fn extract_strings(data: &[u8], max: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    extract_ascii(data, max, &mut out);
    if out.len() < max {
        extract_utf16le(data, max - out.len(), &mut out);
    }
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(max);
    out
}

fn extract_ascii(data: &[u8], max: usize, out: &mut Vec<ExtractedString>) {
    let mut start = 0usize;
    let mut i = 0usize;
    while i < data.len() && out.len() < max {
        let b = data[i];
        let printable = (0x20..=0x7e).contains(&b) || b == b'\t';
        if printable {
            if i == start && start == i {
                // continue
            }
        } else {
            if i - start >= 4 {
                push_string(&data[start..i], start as u64, "ascii", out);
            }
            start = i + 1;
        }
        i += 1;
        if !printable {
            start = i;
        }
    }
    if data.len() - start >= 4 && out.len() < max {
        push_string(&data[start..], start as u64, "ascii", out);
    }
}

fn extract_utf16le(data: &[u8], max: usize, out: &mut Vec<ExtractedString>) {
    let mut buf = String::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + 1 < data.len() && out.len() < max {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if (0x20..=0x7e).contains(&ch) {
            if buf.is_empty() {
                start = i;
            }
            buf.push(ch as u8 as char);
        } else {
            if buf.len() >= 4 {
                categorize_and_push(&buf, start as u64, "utf16le", out);
            }
            buf.clear();
        }
        i += 2;
    }
    if buf.len() >= 4 && out.len() < max {
        categorize_and_push(&buf, start as u64, "utf16le", out);
    }
}

fn push_string(bytes: &[u8], offset: u64, encoding: &str, out: &mut Vec<ExtractedString>) {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return;
    };
    categorize_and_push(s, offset, encoding, out);
}

fn categorize_and_push(s: &str, offset: u64, encoding: &str, out: &mut Vec<ExtractedString>) {
    let (category, score) = classify(s);
    out.push(ExtractedString {
        value: s.to_string(),
        offset,
        encoding: encoding.into(),
        category,
        score,
    });
}

fn classify(s: &str) -> (StringCategory, f32) {
    if RE_PRIVATE_KEY.is_match(s) {
        return (StringCategory::Credential, 1.0);
    }
    if RE_AWS.is_match(s) {
        return (StringCategory::ApiKey, 0.98);
    }
    if RE_JWT.is_match(s) {
        return (StringCategory::Jwt, 0.95);
    }
    if RE_URL.is_match(s) {
        return (StringCategory::Url, 0.95);
    }
    if RE_EMAIL.is_match(s) {
        return (StringCategory::Email, 0.9);
    }
    if RE_IPV4.is_match(s) {
        return (StringCategory::Ip, 0.9);
    }
    if RE_REGISTRY.is_match(s) {
        return (StringCategory::Registry, 0.92);
    }
    if RE_MUTEX.is_match(s) {
        return (StringCategory::Mutex, 0.85);
    }
    if RE_PATH_WIN.is_match(s) {
        return (StringCategory::Path, 0.8);
    }
    if RE_PATH_UNIX.is_match(s) {
        return (StringCategory::Path, 0.75);
    }
    if RE_DOMAIN.is_match(s) {
        return (StringCategory::Domain, 0.7);
    }
    let lower = s.to_ascii_lowercase();
    if lower.contains("password") || lower.contains("apikey") || lower.contains("secret") {
        return (StringCategory::Credential, 0.7);
    }
    if lower.contains("aes") || lower.contains("rsa") || lower.contains("sha256") {
        return (StringCategory::Crypto, 0.6);
    }
    if lower.starts_with("mozilla/") || lower.contains("user-agent") {
        return (StringCategory::UserAgent, 0.7);
    }
    (StringCategory::Generic, 0.2 + (s.len().min(40) as f32 / 100.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_url_and_ip() {
        let data = b"hello https://evil.example/c2 pad 10.0.0.5 trailer";
        let strings = extract_strings(data, 100);
        assert!(strings.iter().any(|s| s.category == StringCategory::Url));
        assert!(strings.iter().any(|s| s.category == StringCategory::Ip));
    }
}
