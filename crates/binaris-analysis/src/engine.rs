use binaris_core::{
    Architecture, BinaryFormat, DependencyInfo, ExportEntry, FileHashes, FunctionAnalysis,
    FunctionId, ImportEntry, OperatingSystem, ResourceEntry, SectionInfo,
};
use goblin::Object;
use tracing::{info, warn};

use crate::compiler::enrich_toolchain;
use crate::crypto_detect::detect_crypto;
use crate::disasm::{disassemble_entry, discover_functions_x86};
use crate::entropy::shannon_entropy;
use crate::format::{identify, map_machine};
use crate::hasher::{hash_bytes, imphash_from_imports};
use crate::indicators::{enrich_imports, network_from_strings};
use crate::packer::{detect_packers, encrypted_sections};
use crate::pe_signature::detect_pe_signature;
use crate::strings::extract_strings;
use binaris_core::{
    BinaryIdentity, CryptoFinding, DigitalSignatureInfo, ExtractedString, NetworkIndicator,
    PackerFinding,
};

#[derive(Debug, Clone)]
pub struct AnalysisContext {
    pub max_strings: usize,
    pub enable_disassembly: bool,
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self {
            max_strings: 50_000,
            enable_disassembly: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticAnalysisResult {
    pub hashes: FileHashes,
    pub identity: BinaryIdentity,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub strings: Vec<ExtractedString>,
    pub network: Vec<NetworkIndicator>,
    pub crypto: Vec<CryptoFinding>,
    pub packers: Vec<PackerFinding>,
    pub functions: Vec<FunctionAnalysis>,
    pub signature: DigitalSignatureInfo,
    pub resources: Vec<ResourceEntry>,
    pub dependencies: Vec<DependencyInfo>,
    pub code_slice_base: Option<u64>,
    pub code_slice: Vec<u8>,
}

pub fn analyze_bytes(data: &[u8], ctx: &AnalysisContext) -> StaticAnalysisResult {
    info!(size = data.len(), "starting static analysis");
    let mut hashes = hash_bytes(data);
    let identified = identify(data);
    let mut identity = identified.identity;

    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut resources = Vec::new();
    let mut dependencies = Vec::new();
    let mut code_slice = Vec::new();
    let mut code_slice_base = None;

    match Object::parse(data) {
        Ok(Object::PE(pe)) => {
            parse_pe(
                &pe,
                data,
                &mut identity,
                &mut sections,
                &mut imports,
                &mut exports,
                &mut resources,
                &mut dependencies,
                &mut code_slice,
                &mut code_slice_base,
            );
        }
        Ok(Object::Elf(elf)) => {
            parse_elf(
                &elf,
                data,
                &mut identity,
                &mut sections,
                &mut imports,
                &mut exports,
                &mut dependencies,
                &mut code_slice,
                &mut code_slice_base,
            );
        }
        Ok(Object::Mach(mach)) => {
            parse_mach(
                &mach,
                data,
                &mut identity,
                &mut sections,
                &mut imports,
                &mut exports,
                &mut code_slice,
                &mut code_slice_base,
            );
        }
        Ok(_) => {
            warn!("unhandled goblin object variant; using identity heuristics only");
        }
        Err(e) => {
            warn!(error = %e, "goblin parse failed; continuing with raw analysis");
            if identity.format == BinaryFormat::Raw || identity.format == BinaryFormat::Firmware {
                sections.push(SectionInfo {
                    name: ".raw".into(),
                    virtual_address: 0,
                    virtual_size: data.len() as u64,
                    raw_size: data.len() as u64,
                    entropy: shannon_entropy(data),
                    characteristics: vec![],
                    permissions: "rwx".into(),
                });
                code_slice = data.iter().take(4096).copied().collect();
                code_slice_base = Some(0);
            }
        }
    }

    enrich_imports(&mut imports);
    let import_pairs: Vec<(String, String)> = imports
        .iter()
        .map(|i| (i.module.clone(), i.symbol.clone()))
        .collect();
    hashes.imphash = imphash_from_imports(&import_pairs);

    let import_names: Vec<String> = imports.iter().map(|i| i.symbol.clone()).collect();
    enrich_toolchain(data, &mut identity, &import_names);

    let packers = detect_packers(data, &sections);
    identity.packed = !packers.is_empty();
    identity.packer = packers.first().map(|p| p.name.clone());
    identity.encrypted_sections = encrypted_sections(&sections);
    identity.compressed = identity.compressed
        || identity.encrypted_sections.iter().any(|_| false)
        || packers.iter().any(|p| p.name.contains("UPX"));

    let signature = if identity.format == BinaryFormat::Pe {
        let sig = detect_pe_signature(data);
        identity.has_signature = sig.present;
        sig
    } else {
        DigitalSignatureInfo {
            present: false,
            valid: None,
            subject: None,
            issuer: None,
            serial: None,
            not_before: None,
            not_after: None,
            algorithm: None,
        }
    };

    let strings = extract_strings(data, ctx.max_strings);
    let network = network_from_strings(&strings);
    let crypto = detect_crypto(data);

    let mut functions = Vec::new();
    if ctx.enable_disassembly && !code_slice.is_empty() {
        let base = code_slice_base.unwrap_or(0);
        let dis = disassemble_entry(&code_slice, base, identity.architecture, 256);
        functions.extend(dis.functions);

        if matches!(
            identity.architecture,
            Architecture::X86 | Architecture::X64 | Architecture::Unknown
        ) {
            let addrs = discover_functions_x86(&code_slice, base, identity.architecture);
            for (idx, addr) in addrs.into_iter().take(64).enumerate() {
                if functions.iter().any(|f| f.address == addr) {
                    continue;
                }
                let off = (addr - base) as usize;
                if off >= code_slice.len() {
                    continue;
                }
                let end = (off + 64).min(code_slice.len());
                let slice = &code_slice[off..end];
                let preview = slice
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                functions.push(FunctionAnalysis {
                    id: FunctionId::new(),
                    address: addr,
                    size: (end - off) as u64,
                    name: format!("sub_{addr:x}"),
                    suggested_name: None,
                    description: None,
                    purpose: None,
                    inputs: vec![],
                    outputs: vec![],
                    complexity: 1.0,
                    interesting_constants: vec![],
                    possible_vulnerabilities: vec![],
                    possible_crypto: false,
                    possible_networking: false,
                    possible_anti_debug: false,
                    possible_persistence: false,
                    possible_injection: false,
                    xrefs_from: vec![],
                    xrefs_to: vec![],
                    pseudocode_summary: None,
                    assembly_preview: Some(preview),
                    confidence: 0.35,
                    evidence: vec![],
                    tags: vec![if idx == 0 {
                        "discovered".into()
                    } else {
                        "heuristic".into()
                    }],
                });
            }
        }
    }

    StaticAnalysisResult {
        hashes,
        identity,
        sections,
        imports,
        exports,
        strings,
        network,
        crypto,
        packers,
        functions,
        signature,
        resources,
        dependencies,
        code_slice_base,
        code_slice,
    }
}

fn parse_pe(
    pe: &goblin::pe::PE,
    data: &[u8],
    identity: &mut BinaryIdentity,
    sections: &mut Vec<SectionInfo>,
    imports: &mut Vec<ImportEntry>,
    exports: &mut Vec<ExportEntry>,
    resources: &mut Vec<ResourceEntry>,
    dependencies: &mut Vec<DependencyInfo>,
    code_slice: &mut Vec<u8>,
    code_slice_base: &mut Option<u64>,
) {
    identity.format = BinaryFormat::Pe;
    identity.os = OperatingSystem::Windows;
    let (arch, bits) = map_machine(pe.header.coff_header.machine, true);
    identity.architecture = arch;
    identity.bits = bits;
    identity.endianness = "little".into();
    identity.is_dll = pe.is_lib;
    identity.entry_point = Some(pe.entry as u64);
    identity.image_base = Some(pe.image_base as u64);

    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches(char::from(0)).to_string();
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        let slice = if start < data.len() {
            &data[start..data.len().min(start + size)]
        } else {
            &[]
        };
        let chars = s.characteristics;
        let mut perms = String::new();
        if chars & 0x40000000 != 0 {
            perms.push('r');
        }
        if chars & 0x80000000 != 0 {
            perms.push('w');
        }
        if chars & 0x20000000 != 0 {
            perms.push('x');
        }
        let mut characteristics = Vec::new();
        if chars & 0x20 != 0 {
            characteristics.push("CODE".into());
        }
        if chars & 0x40 != 0 {
            characteristics.push("INITIALIZED_DATA".into());
        }
        if chars & 0x80 != 0 {
            characteristics.push("UNINITIALIZED_DATA".into());
        }
        sections.push(SectionInfo {
            name: name.clone(),
            virtual_address: s.virtual_address as u64,
            virtual_size: s.virtual_size as u64,
            raw_size: s.size_of_raw_data as u64,
            entropy: shannon_entropy(slice),
            characteristics,
            permissions: perms,
        });
        if code_slice.is_empty() && (name == ".text" || chars & 0x20000000 != 0) && !slice.is_empty()
        {
            *code_slice = slice.iter().take(8192).copied().collect();
            *code_slice_base = Some(pe.image_base as u64 + s.virtual_address as u64);
        }
    }

    for import in &pe.imports {
        imports.push(ImportEntry {
            module: import.dll.to_string(),
            symbol: import.name.to_string(),
            ordinal: None,
            address: Some(import.rva as u64),
            risk: binaris_core::RiskLevel::Info,
            tags: vec![],
        });
        if !dependencies.iter().any(|d| d.name.eq_ignore_ascii_case(&import.dll)) {
            dependencies.push(DependencyInfo {
                name: import.dll.to_string(),
                version: None,
                kind: "dll".into(),
            });
        }
    }

    for e in &pe.exports {
        if let Some(name) = e.name {
            exports.push(ExportEntry {
                symbol: name.to_string(),
                ordinal: None,
                address: e.rva as u64,
                forwarded: e.reexport.as_ref().map(|r| format!("{r:?}")),
            });
        }
    }

    // Resource directory size heuristic via sections
    if let Some(rsrc) = sections.iter().find(|s| s.name == ".rsrc") {
        resources.push(ResourceEntry {
            name: ".rsrc".into(),
            kind: "pe_resources".into(),
            size: rsrc.raw_size,
            language: None,
            entropy: Some(rsrc.entropy),
        });
    }

    // Driver heuristic
    if imports.iter().any(|i| {
        i.module.eq_ignore_ascii_case("ntoskrnl.exe") || i.symbol.contains("DriverEntry")
    }) {
        identity.is_driver = true;
    }
}

fn parse_elf(
    elf: &goblin::elf::Elf,
    data: &[u8],
    identity: &mut BinaryIdentity,
    sections: &mut Vec<SectionInfo>,
    imports: &mut Vec<ImportEntry>,
    exports: &mut Vec<ExportEntry>,
    dependencies: &mut Vec<DependencyInfo>,
    code_slice: &mut Vec<u8>,
    code_slice_base: &mut Option<u64>,
) {
    identity.format = BinaryFormat::Elf;
    identity.os = OperatingSystem::Linux;
    let (arch, bits) = map_machine(elf.header.e_machine, false);
    identity.architecture = arch;
    identity.bits = if elf.is_64 { 64 } else { bits.max(32) };
    identity.endianness = if elf.little_endian {
        "little".into()
    } else {
        "big".into()
    };
    identity.entry_point = Some(elf.entry);
    identity.is_shared_object = elf.header.e_type == goblin::elf::header::ET_DYN;
    identity.is_dll = identity.is_shared_object;

    for s in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(s.sh_name)
            .unwrap_or("")
            .to_string();
        let start = s.sh_offset as usize;
        let size = s.sh_size as usize;
        let slice = if start < data.len() {
            &data[start..data.len().min(start + size)]
        } else {
            &[]
        };
        let mut perms = String::new();
        if s.is_alloc() {
            perms.push('r');
        }
        if s.is_writable() {
            perms.push('w');
        }
        if s.is_executable() {
            perms.push('x');
        }
        sections.push(SectionInfo {
            name: name.clone(),
            virtual_address: s.sh_addr,
            virtual_size: s.sh_size,
            raw_size: s.sh_size,
            entropy: shannon_entropy(slice),
            characteristics: vec![],
            permissions: perms,
        });
        if code_slice.is_empty() && (name == ".text" || s.is_executable()) && !slice.is_empty() {
            *code_slice = slice.iter().take(8192).copied().collect();
            *code_slice_base = Some(s.sh_addr);
        }
    }

    for lib in &elf.libraries {
        dependencies.push(DependencyInfo {
            name: lib.to_string(),
            version: None,
            kind: "needed".into(),
        });
    }

    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        if sym.is_import() {
            imports.push(ImportEntry {
                module: "extern".into(),
                symbol: name,
                ordinal: None,
                address: Some(sym.st_value),
                risk: binaris_core::RiskLevel::Info,
                tags: vec![],
            });
        } else if sym.st_value != 0 {
            exports.push(ExportEntry {
                symbol: name,
                ordinal: None,
                address: sym.st_value,
                forwarded: None,
            });
        }
    }

    if identity.is_shared_object && sections.iter().any(|s| s.name.contains("modinfo")) {
        identity.format = BinaryFormat::KernelModule;
    }
}

fn parse_mach(
    mach: &goblin::mach::Mach,
    data: &[u8],
    identity: &mut BinaryIdentity,
    sections: &mut Vec<SectionInfo>,
    imports: &mut Vec<ImportEntry>,
    exports: &mut Vec<ExportEntry>,
    code_slice: &mut Vec<u8>,
    code_slice_base: &mut Option<u64>,
) {
    identity.format = BinaryFormat::MachO;
    identity.os = OperatingSystem::MacOs;
    match mach {
        goblin::mach::Mach::Binary(macho) => {
            fill_macho(
                macho,
                data,
                identity,
                sections,
                imports,
                exports,
                code_slice,
                code_slice_base,
            );
        }
        goblin::mach::Mach::Fat(fat) => {
            if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                fill_macho(
                    &macho,
                    data,
                    identity,
                    sections,
                    imports,
                    exports,
                    code_slice,
                    code_slice_base,
                );
            }
        }
    }
}

fn fill_macho(
    macho: &goblin::mach::MachO,
    data: &[u8],
    identity: &mut BinaryIdentity,
    sections: &mut Vec<SectionInfo>,
    imports: &mut Vec<ImportEntry>,
    exports: &mut Vec<ExportEntry>,
    code_slice: &mut Vec<u8>,
    code_slice_base: &mut Option<u64>,
) {
    identity.bits = if macho.is_64 { 64 } else { 32 };
    identity.endianness = if macho.little_endian {
        "little".into()
    } else {
        "big".into()
    };
    identity.entry_point = Some(macho.entry);
    identity.architecture = match macho.header.cputype() {
        7 => Architecture::X86,
        0x0100_0007 => Architecture::X64,
        12 => Architecture::Arm,
        0x0100_000c => Architecture::Arm64,
        _ => Architecture::Unknown,
    };

    for section in macho.segments.sections().flatten() {
        if let Ok((section, data_slice)) = section {
            let name = section.name().unwrap_or("").to_string();
            sections.push(SectionInfo {
                name: name.clone(),
                virtual_address: section.addr,
                virtual_size: section.size,
                raw_size: data_slice.len() as u64,
                entropy: shannon_entropy(data_slice),
                characteristics: vec![],
                permissions: "rwx".into(),
            });
            if code_slice.is_empty() && (name.contains("__text") || name.contains("text")) {
                *code_slice = data_slice.iter().take(8192).copied().collect();
                *code_slice_base = Some(section.addr);
            }
        }
    }

    if let Ok(exps) = macho.exports() {
        for e in exps {
            exports.push(ExportEntry {
                symbol: e.name,
                ordinal: None,
                address: e.offset,
                forwarded: None,
            });
        }
    }

    if let Ok(imps) = macho.imports() {
        for imp in imps {
            imports.push(ImportEntry {
                module: "".into(),
                symbol: imp.name.to_string(),
                ordinal: None,
                address: Some(imp.address),
                risk: binaris_core::RiskLevel::Info,
                tags: vec![],
            });
        }
    }

    let _ = data;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_raw_bytes() {
        let data = b"MZ\0\0raw test https://example.com/a 10.1.2.3 AES-ECB password=secret";
        let result = analyze_bytes(data, &AnalysisContext::default());
        assert!(!result.hashes.sha256.is_empty());
        assert!(!result.strings.is_empty());
    }
}
