use binaris_core::DigitalSignatureInfo;

/// Detect Authenticode directory presence (full cert chain validation is optional external).
pub fn detect_pe_signature(data: &[u8]) -> DigitalSignatureInfo {
    let present = pe_has_security_directory(data);
    DigitalSignatureInfo {
        present,
        valid: None,
        subject: None,
        issuer: None,
        serial: None,
        not_before: None,
        not_after: None,
        algorithm: if present {
            Some("Authenticode".into())
        } else {
            None
        },
    }
}

fn pe_has_security_directory(data: &[u8]) -> bool {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return false;
    }
    let opt_magic = if pe_offset + 24 + 2 <= data.len() {
        u16::from_le_bytes([data[pe_offset + 24], data[pe_offset + 25]])
    } else {
        return false;
    };
    // Data directory index 4 = SECURITY
    let dd_offset = match opt_magic {
        0x10b => pe_offset + 24 + 128, // PE32
        0x20b => pe_offset + 24 + 144, // PE32+
        _ => return false,
    };
    if dd_offset + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes([
        data[dd_offset],
        data[dd_offset + 1],
        data[dd_offset + 2],
        data[dd_offset + 3],
    ]);
    let size = u32::from_le_bytes([
        data[dd_offset + 4],
        data[dd_offset + 5],
        data[dd_offset + 6],
        data[dd_offset + 7],
    ]);
    rva != 0 && size != 0
}
