use binaris_core::{Architecture, BinaryFormat, BinaryIdentity, OperatingSystem};

#[derive(Debug, Clone)]
pub struct IdentifiedFile {
    pub identity: BinaryIdentity,
    pub magic: String,
}

pub fn identify(data: &[u8]) -> IdentifiedFile {
    let mime = infer::get(data).map(|t| t.mime_type().to_string());
    let magic = detect_magic(data);

    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        if looks_like_apk(data) {
            return IdentifiedFile {
                identity: BinaryIdentity {
                    format: BinaryFormat::Apk,
                    architecture: Architecture::Unknown,
                    endianness: "unknown".into(),
                    bits: 0,
                    os: OperatingSystem::Android,
                    is_dll: false,
                    is_driver: false,
                    is_shared_object: false,
                    entry_point: None,
                    image_base: None,
                    compiler: None,
                    compiler_version: None,
                    language: Some("Java/Kotlin".into()),
                    build_system: Some("Gradle/Android".into()),
                    framework: Some("Android".into()),
                    linker: None,
                    packed: false,
                    packer: None,
                    obfuscated: false,
                    obfuscation: vec![],
                    encrypted_sections: vec![],
                    compressed: true,
                    has_debug_symbols: false,
                    has_signature: false,
                    mime,
                },
                magic: "zip/apk".into(),
            };
        }
        if looks_like_jar(data) {
            return IdentifiedFile {
                identity: BinaryIdentity {
                    format: BinaryFormat::Jar,
                    architecture: Architecture::Unknown,
                    endianness: "unknown".into(),
                    bits: 0,
                    os: OperatingSystem::Unknown,
                    is_dll: false,
                    is_driver: false,
                    is_shared_object: false,
                    entry_point: None,
                    image_base: None,
                    compiler: Some("javac".into()),
                    compiler_version: None,
                    language: Some("Java".into()),
                    build_system: None,
                    framework: None,
                    linker: None,
                    packed: false,
                    packer: None,
                    obfuscated: false,
                    obfuscation: vec![],
                    encrypted_sections: vec![],
                    compressed: true,
                    has_debug_symbols: false,
                    has_signature: false,
                    mime,
                },
                magic: "zip/jar".into(),
            };
        }
    }

    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return IdentifiedFile {
            identity: BinaryIdentity {
                format: BinaryFormat::Pe,
                architecture: Architecture::Unknown,
                endianness: "little".into(),
                bits: 0,
                os: OperatingSystem::Windows,
                is_dll: false,
                is_driver: false,
                is_shared_object: false,
                entry_point: None,
                image_base: None,
                compiler: None,
                compiler_version: None,
                language: None,
                build_system: None,
                framework: None,
                linker: None,
                packed: false,
                packer: None,
                obfuscated: false,
                obfuscation: vec![],
                encrypted_sections: vec![],
                compressed: false,
                has_debug_symbols: false,
                has_signature: false,
                mime,
            },
            magic: "mz/pe".into(),
        };
    }

    if data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F'] {
        return IdentifiedFile {
            identity: BinaryIdentity {
                format: BinaryFormat::Elf,
                architecture: Architecture::Unknown,
                endianness: "unknown".into(),
                bits: 0,
                os: OperatingSystem::Linux,
                is_dll: false,
                is_driver: false,
                is_shared_object: false,
                entry_point: None,
                image_base: None,
                compiler: None,
                compiler_version: None,
                language: None,
                build_system: None,
                framework: None,
                linker: None,
                packed: false,
                packer: None,
                obfuscated: false,
                obfuscation: vec![],
                encrypted_sections: vec![],
                compressed: false,
                has_debug_symbols: false,
                has_signature: false,
                mime,
            },
            magic: "elf".into(),
        };
    }

    if data.len() >= 4
        && (data[0..4] == [0xfe, 0xed, 0xfa, 0xce]
            || data[0..4] == [0xce, 0xfa, 0xed, 0xfe]
            || data[0..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || data[0..4] == [0xcf, 0xfa, 0xed, 0xfe]
            || data[0..4] == [0xca, 0xfe, 0xba, 0xbe]
            || data[0..4] == [0xbe, 0xba, 0xfe, 0xca])
    {
        return IdentifiedFile {
            identity: BinaryIdentity {
                format: BinaryFormat::MachO,
                architecture: Architecture::Unknown,
                endianness: "unknown".into(),
                bits: 0,
                os: OperatingSystem::MacOs,
                is_dll: false,
                is_driver: false,
                is_shared_object: false,
                entry_point: None,
                image_base: None,
                compiler: None,
                compiler_version: None,
                language: None,
                build_system: None,
                framework: None,
                linker: None,
                packed: false,
                packer: None,
                obfuscated: false,
                obfuscation: vec![],
                encrypted_sections: vec![],
                compressed: false,
                has_debug_symbols: false,
                has_signature: false,
                mime,
            },
            magic: "macho".into(),
        };
    }

    if looks_like_msi(data) {
        return IdentifiedFile {
            identity: BinaryIdentity {
                format: BinaryFormat::Msi,
                architecture: Architecture::Unknown,
                endianness: "little".into(),
                bits: 0,
                os: OperatingSystem::Windows,
                is_dll: false,
                is_driver: false,
                is_shared_object: false,
                entry_point: None,
                image_base: None,
                compiler: None,
                compiler_version: None,
                language: None,
                build_system: Some("MSI".into()),
                framework: None,
                linker: None,
                packed: false,
                packer: None,
                obfuscated: false,
                obfuscation: vec![],
                encrypted_sections: vec![],
                compressed: true,
                has_debug_symbols: false,
                has_signature: false,
                mime,
            },
            magic: "msi/cfb".into(),
        };
    }

    IdentifiedFile {
        identity: BinaryIdentity {
            format: if looks_like_firmware(data) {
                BinaryFormat::Firmware
            } else {
                BinaryFormat::Raw
            },
            architecture: Architecture::Unknown,
            endianness: "unknown".into(),
            bits: 0,
            os: if looks_like_firmware(data) {
                OperatingSystem::Firmware
            } else {
                OperatingSystem::Unknown
            },
            is_dll: false,
            is_driver: false,
            is_shared_object: false,
            entry_point: None,
            image_base: None,
            compiler: None,
            compiler_version: None,
            language: None,
            build_system: None,
            framework: None,
            linker: None,
            packed: false,
            packer: None,
            obfuscated: false,
            obfuscation: vec![],
            encrypted_sections: vec![],
            compressed: false,
            has_debug_symbols: false,
            has_signature: false,
            mime,
        },
        magic,
    }
}

fn detect_magic(data: &[u8]) -> String {
    if data.len() < 4 {
        return "unknown".into();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        data[0], data[1], data[2], data[3]
    )
}

fn looks_like_apk(data: &[u8]) -> bool {
    zip_contains(data, &["AndroidManifest.xml", "classes.dex"])
}

fn looks_like_jar(data: &[u8]) -> bool {
    zip_contains(data, &["META-INF/MANIFEST.MF"])
}

fn zip_contains(data: &[u8], needles: &[&str]) -> bool {
    let Ok(mut reader) = zip::ZipArchive::new(std::io::Cursor::new(data)) else {
        return false;
    };
    let names: Vec<String> = (0..reader.len())
        .filter_map(|i| reader.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();
    needles.iter().any(|n| names.iter().any(|x| x.contains(n)))
}

fn looks_like_msi(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
}

fn looks_like_firmware(data: &[u8]) -> bool {
    data.len() >= 16
        && (data.windows(4).any(|w| w == b"UBI#")
            || data.windows(4).any(|w| w == b"hsqs")
            || data.starts_with(b"ANDROID!"))
}

pub fn map_machine(machine: u16, is_pe: bool) -> (Architecture, u8) {
    if is_pe {
        return match machine {
            0x014c => (Architecture::X86, 32),
            0x8664 => (Architecture::X64, 64),
            0x01c0 | 0x01c4 => (Architecture::Arm, 32),
            0xAA64 => (Architecture::Arm64, 64),
            0x0166 | 0x0266 => (Architecture::Mips, 32),
            0x01F0 => (Architecture::PowerPc, 32),
            0x5064 => (Architecture::RiscV, 64),
            _ => (Architecture::Unknown, 0),
        };
    }
    match machine {
        3 => (Architecture::X86, 32),
        62 => (Architecture::X64, 64),
        40 => (Architecture::Arm, 32),
        183 => (Architecture::Arm64, 64),
        8 | 10 => (Architecture::Mips, 32),
        20 | 21 => (Architecture::PowerPc, 32),
        243 => (Architecture::RiscV, 64),
        _ => (Architecture::Unknown, 0),
    }
}
