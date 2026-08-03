use binaris_core::FileHashes;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;
use sha3::Sha3_256;

pub fn hash_bytes(data: &[u8]) -> FileHashes {
    let md5 = hex::encode(Md5::digest(data));
    let sha1 = hex::encode(Sha1::digest(data));
    let sha256 = hex::encode(Sha256::digest(data));
    let sha3_256 = hex::encode(Sha3_256::digest(data));
    let blake3 = blake3::hash(data).to_hex().to_string();

    FileHashes {
        md5,
        sha1,
        sha256,
        sha3_256,
        blake3,
        imphash: None,
        ssdeep: Some(fuzzy_hash(data)),
        tlsh: None,
    }
}

/// Lightweight rolling fuzzy hash for similarity (ssdeep-inspired, deterministic).
fn fuzzy_hash(data: &[u8]) -> String {
    if data.is_empty() {
        return "3::".into();
    }
    let block_size = ((data.len().max(3) as f64).log2().floor() as usize).max(3);
    let mut left = String::new();
    let mut right = String::new();
    let mut h1: u32 = 0;
    let mut h2: u32 = 0;
    for (i, b) in data.iter().enumerate() {
        h1 = h1.wrapping_mul(16777619) ^ (*b as u32);
        h2 = h2.wrapping_mul(2166136261) ^ (*b as u32).wrapping_add(i as u32);
        if i % block_size == block_size - 1 {
            left.push(b64_char(h1));
            right.push(b64_char(h2));
            if left.len() >= 32 {
                break;
            }
        }
    }
    if left.is_empty() {
        left.push(b64_char(h1));
        right.push(b64_char(h2));
    }
    format!("{block_size}:{left}:{right}")
}

fn b64_char(v: u32) -> char {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    TABLE[(v as usize) % 64] as char
}

pub fn imphash_from_imports(imports: &[(String, String)]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = imports
        .iter()
        .map(|(m, s)| format!("{}.{}", m.to_ascii_lowercase().replace(".dll", ""), s.to_ascii_lowercase()))
        .collect();
    parts.sort();
    let joined = parts.join(",");
    Some(hex::encode(Md5::digest(joined.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_stable() {
        let h = hash_bytes(b"binaris");
        assert_eq!(h.md5.len(), 32);
        assert_eq!(h.sha1.len(), 40);
        assert_eq!(h.sha256.len(), 64);
        assert_eq!(h.blake3.len(), 64);
        assert!(h.ssdeep.is_some());
    }
}
