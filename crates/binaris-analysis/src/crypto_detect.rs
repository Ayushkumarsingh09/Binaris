use binaris_core::{CryptoFinding, Evidence};

/// Known cryptographic constants (S-boxes, IVs, magic, OIDs) for static detection.
pub fn detect_crypto(data: &[u8]) -> Vec<CryptoFinding> {
    let mut findings = Vec::new();

    // AES S-box first 16 bytes
    if find(data, &[
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
    ])
    .is_some()
    {
        findings.push(finding(
            "AES",
            "symmetric",
            Some("unknown"),
            "strong",
            None,
            0.9,
            "AES S-box constant",
        ));
    }

    // SHA256 initial hash values (H0.. first dwords little endian fragment)
    if find(data, &[0x67, 0xe6, 0x09, 0x6a]).is_some()
        && find(data, &[0x85, 0xae, 0x67, 0xbb]).is_some()
    {
        findings.push(finding(
            "SHA-256",
            "hash",
            None,
            "strong",
            None,
            0.75,
            "SHA-256 IV constants",
        ));
    }

    // MD5 init constants
    if find(data, &[0x01, 0x23, 0x45, 0x67]).is_some()
        && find(data, &[0x89, 0xab, 0xcd, 0xef]).is_some()
        && find(data, &[0xfe, 0xdc, 0xba, 0x98]).is_some()
    {
        findings.push(finding(
            "MD5",
            "hash",
            None,
            "weak",
            Some("MD5 is cryptographically broken"),
            0.7,
            "MD5 initialization constants",
        ));
    }

    // SHA1 constants
    if find(data, &[0x01, 0x23, 0x45, 0x67]).is_some()
        && find(data, &[0x89, 0xab, 0xcd, 0xef]).is_some()
        && contains_str(data, "SHA1")
    {
        findings.push(finding(
            "SHA-1",
            "hash",
            None,
            "weak",
            Some("SHA-1 collision attacks exist"),
            0.65,
            "SHA-1 related markers",
        ));
    }

    if contains_str(data, "ChaCha20") || contains_str(data, "chacha20") {
        findings.push(finding(
            "ChaCha20",
            "symmetric",
            None,
            "strong",
            None,
            0.8,
            "ChaCha20 string reference",
        ));
    }

    if contains_str(data, "Salsa20") {
        findings.push(finding(
            "Salsa20",
            "symmetric",
            None,
            "strong",
            None,
            0.8,
            "Salsa20 string reference",
        ));
    }

    if contains_str(data, "AES-ECB") || contains_str(data, "ECB") && contains_str(data, "AES") {
        findings.push(finding(
            "AES",
            "symmetric",
            Some("ECB"),
            "weak",
            Some("ECB mode leaks patterns"),
            0.85,
            "AES-ECB reference",
        ));
    }

    if contains_str(data, "RC4") || contains_str(data, "ARCFOUR") {
        findings.push(finding(
            "RC4",
            "symmetric",
            None,
            "weak",
            Some("RC4 is deprecated"),
            0.8,
            "RC4 reference",
        ));
    }

    if contains_str(data, "Blowfish") {
        findings.push(finding("Blowfish", "symmetric", None, "moderate", None, 0.75, "Blowfish"));
    }
    if contains_str(data, "Twofish") {
        findings.push(finding("Twofish", "symmetric", None, "strong", None, 0.75, "Twofish"));
    }
    if contains_str(data, "Serpent") {
        findings.push(finding("Serpent", "symmetric", None, "strong", None, 0.75, "Serpent"));
    }

    if contains_str(data, "BEGIN RSA PUBLIC KEY")
        || contains_str(data, "ssh-rsa")
        || contains_str(data, "RSACryptoServiceProvider")
    {
        findings.push(finding("RSA", "asymmetric", None, "strong", None, 0.85, "RSA markers"));
    }

    if contains_str(data, "secp256")
        || contains_str(data, "prime256v1")
        || contains_str(data, "ECDSA")
        || contains_str(data, "curve25519")
    {
        findings.push(finding("ECC", "asymmetric", None, "strong", None, 0.8, "ECC markers"));
    }

    if contains_str(data, "PBKDF2") {
        findings.push(finding(
            "PBKDF2",
            "kdf",
            None,
            "strong",
            None,
            0.85,
            "PBKDF2 reference",
        ));
    }
    if contains_str(data, "Argon2") {
        findings.push(finding("Argon2", "kdf", None, "strong", None, 0.9, "Argon2 reference"));
    }
    if contains_str(data, "bcrypt") {
        findings.push(finding("bcrypt", "kdf", None, "strong", None, 0.85, "bcrypt reference"));
    }
    if contains_str(data, "scrypt") {
        findings.push(finding("scrypt", "kdf", None, "strong", None, 0.85, "scrypt reference"));
    }
    if contains_str(data, "HMAC") {
        findings.push(finding("HMAC", "mac", None, "strong", None, 0.7, "HMAC reference"));
    }
    if contains_str(data, "DES") && !contains_str(data, "AES") {
        findings.push(finding(
            "DES",
            "symmetric",
            None,
            "weak",
            Some("DES key size is insufficient"),
            0.7,
            "DES reference",
        ));
    }
    if contains_str(data, "3DES") || contains_str(data, "TripleDES") {
        findings.push(finding(
            "3DES",
            "symmetric",
            None,
            "weak",
            Some("3DES is deprecated"),
            0.75,
            "3DES reference",
        ));
    }

    // DES S-box fragment
    if find(data, &[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]).is_some() {
        findings.push(finding(
            "DES",
            "symmetric",
            None,
            "weak",
            Some("DES S-box present"),
            0.8,
            "DES S-box constants",
        ));
    }

    findings
}

fn finding(
    algorithm: &str,
    category: &str,
    mode: Option<&str>,
    strength: &str,
    weakness: Option<&str>,
    confidence: f32,
    note: &str,
) -> CryptoFinding {
    CryptoFinding {
        algorithm: algorithm.into(),
        category: category.into(),
        mode: mode.map(|s| s.into()),
        strength: strength.into(),
        weakness: weakness.map(|s| s.into()),
        confidence,
        evidence: vec![Evidence::Constant {
            value: algorithm.into(),
            address: None,
            note: note.into(),
        }],
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains_str(hay: &[u8], s: &str) -> bool {
    find(hay, s.as_bytes()).is_some()
}
