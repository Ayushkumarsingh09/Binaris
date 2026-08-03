use binaris_core::BinaryIdentity;

/// Infer language/compiler/toolchain from rich static signals.
pub fn enrich_toolchain(data: &[u8], identity: &mut BinaryIdentity, imports: &[String]) {
    let blob = String::from_utf8_lossy(data);

    if blob.contains("Go buildinf:") || blob.contains("runtime.main") || blob.contains("go.buildid")
    {
        identity.language = Some("Go".into());
        identity.compiler = Some("gc (Go toolchain)".into());
        identity.build_system = Some("go build".into());
    }

    if blob.contains("rust_eh_personality")
        || blob.contains(".rustc")
        || imports.iter().any(|i| i.contains("Rust"))
    {
        identity.language = Some("Rust".into());
        identity.compiler = Some("rustc".into());
        identity.build_system = identity.build_system.clone().or(Some("cargo".into()));
    }

    if blob.contains("MSVC") || blob.contains("Microsoft Visual C") || blob.contains("VCRUNTIME")
    {
        identity.compiler = Some("MSVC".into());
        identity.language = identity.language.clone().or(Some("C/C++".into()));
        if let Some(v) = capture_msvc_version(&blob) {
            identity.compiler_version = Some(v);
        }
    }

    if blob.contains("GCC:") || blob.contains("GNU C") || blob.contains("libgcc") {
        identity.compiler = Some(
            identity
                .compiler
                .clone()
                .unwrap_or_else(|| "GCC".into()),
        );
        identity.language = identity.language.clone().or(Some("C/C++".into()));
        if let Some(v) = capture_gcc_version(&blob) {
            identity.compiler_version = Some(v);
        }
    }

    if blob.contains("clang version") || blob.contains("Apple LLVM") {
        identity.compiler = Some("Clang/LLVM".into());
        identity.language = identity.language.clone().or(Some("C/C++/ObjC".into()));
    }

    if blob.contains("Borland") {
        identity.compiler = Some("Borland/Embarcadero".into());
    }

    if blob.contains("MinGW") {
        identity.compiler = Some("MinGW".into());
        identity.language = identity.language.clone().or(Some("C/C++".into()));
    }

    if blob.contains("dotnet") || blob.contains("mscoree.dll") || blob.contains("CLR.dll") {
        identity.language = Some(".NET/CIL".into());
        identity.framework = Some(".NET".into());
        identity.compiler = Some("csc/ilasm".into());
    }

    if blob.contains("Python") && (blob.contains("Py_") || blob.contains("python3")) {
        identity.language = Some("Python (embedded/frozen)".into());
        identity.framework = Some("CPython".into());
    }

    if blob.contains("Electron") || blob.contains("node.dll") {
        identity.framework = Some("Electron/Node".into());
        identity.language = Some("JavaScript/TypeScript".into());
    }

    if blob.contains("Qt5") || blob.contains("Qt6") || blob.contains("QObject") {
        identity.framework = Some("Qt".into());
    }

    if blob.contains("MFC") {
        identity.framework = Some("MFC".into());
    }

    if blob.contains("CMake") {
        identity.build_system = Some("CMake".into());
    } else if blob.contains("Ninja") {
        identity.build_system = Some("Ninja".into());
    } else if blob.contains("Autotools") || blob.contains("libtool") {
        identity.build_system = Some("Autotools".into());
    }

    if blob.contains(".pdb") || blob.contains("RSDS") || blob.contains(".debug_info") {
        identity.has_debug_symbols = true;
    }

    detect_obfuscation(data, identity);
}

fn capture_msvc_version(blob: &str) -> Option<String> {
    let idx = blob.find("MSVC")?;
    let slice = &blob[idx..blob.len().min(idx + 32)];
    Some(slice.chars().take_while(|c| c.is_ascii_graphic()).collect())
}

fn capture_gcc_version(blob: &str) -> Option<String> {
    let marker = "GCC: (";
    let idx = blob.find(marker)?;
    let rest = &blob[idx + marker.len()..];
    let end = rest.find(')')?;
    Some(rest[..end].to_string())
}

fn detect_obfuscation(data: &[u8], identity: &mut BinaryIdentity) {
    let mut techniques = Vec::new();
    if contains(data, b"VMProtect") || contains(data, b".vmp") {
        techniques.push("virtualization obfuscation".into());
    }
    if contains(data, b"Themida") {
        techniques.push("mutator/packer obfuscation".into());
    }
    if contains(data, b"Obfuscator-LLVM") || contains(data, b"ollvm") {
        techniques.push("OLLVM control-flow flattening".into());
    }
    if contains(data, b"ConfuserEx") || contains(data, b"Dotfuscator") {
        techniques.push(".NET obfuscation".into());
    }
    if contains(data, b"junk") && contains(data, b"opaque") {
        techniques.push("opaque predicates / junk code".into());
    }
    identity.obfuscated = !techniques.is_empty();
    identity.obfuscation = techniques;
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
