use binaris_core::{Architecture, FunctionAnalysis, FunctionId};
use capstone::prelude::*;
use tracing::warn;

pub struct DisasmResult {
    pub functions: Vec<FunctionAnalysis>,
    pub assembly_samples: Vec<(u64, String)>,
}

pub fn disassemble_entry(
    code: &[u8],
    base: u64,
    arch: Architecture,
    max_insn: usize,
) -> DisasmResult {
    let mut functions = Vec::new();
    let mut assembly_samples = Vec::new();

    let cs = match build_capstone(arch) {
        Ok(cs) => cs,
        Err(e) => {
            warn!(error = %e, "capstone init failed");
            return DisasmResult {
                functions,
                assembly_samples,
            };
        }
    };

    let insns = match cs.disasm_count(code, base, max_insn) {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "disassembly failed");
            return DisasmResult {
                functions,
                assembly_samples,
            };
        }
    };

    let mut preview = String::new();
    let mut size = 0u64;
    for insn in insns.iter() {
        let line = format!(
            "{:016x}  {} {}",
            insn.address(),
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        );
        if assembly_samples.len() < 64 {
            assembly_samples.push((insn.address(), line.clone()));
        }
        if preview.len() < 2048 {
            preview.push_str(&line);
            preview.push('\n');
        }
        size += insn.len() as u64;
    }

    if size > 0 {
        let networking = preview.contains("call")
            && (preview.contains("socket") || preview.contains("connect") || preview.contains("ws2"));
        let crypto = preview.contains("aes") || preview.contains("xor") && size > 40;
        functions.push(FunctionAnalysis {
            id: FunctionId::new(),
            address: base,
            size,
            name: "entry".into(),
            suggested_name: Some("program_entry".into()),
            description: Some("Primary entry / analyzed prologue region".into()),
            purpose: Some("Program startup and initial control flow".into()),
            inputs: vec!["OS process context".into()],
            outputs: vec!["process lifecycle".into()],
            complexity: (size as f32 / 20.0).min(100.0),
            interesting_constants: vec![],
            possible_vulnerabilities: vec![],
            possible_crypto: crypto,
            possible_networking: networking,
            possible_anti_debug: preview.contains("IsDebuggerPresent") || preview.contains("rdtsc"),
            possible_persistence: false,
            possible_injection: preview.contains("WriteProcessMemory")
                || preview.contains("CreateRemoteThread"),
            xrefs_from: vec![],
            xrefs_to: vec![],
            pseudocode_summary: Some(
                "Entry transfers control through startup stubs into main application logic.".into(),
            ),
            assembly_preview: Some(preview),
            confidence: 0.55,
            evidence: vec![],
            tags: vec!["entry".into()],
        });
    }

    DisasmResult {
        functions,
        assembly_samples,
    }
}

fn build_capstone(arch: Architecture) -> Result<Capstone, capstone::Error> {
    match arch {
        Architecture::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        Architecture::X64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build(),
        Architecture::Arm64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        Architecture::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .detail(true)
            .build(),
        Architecture::PowerPc => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .detail(true)
            .build(),
        Architecture::RiscV | Architecture::Unknown => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
    }
}

/// Heuristic function discovery from call targets / prologue patterns (x86/x64).
pub fn discover_functions_x86(code: &[u8], base: u64, arch: Architecture) -> Vec<u64> {
    let mut addrs = vec![base];
    let is64 = matches!(arch, Architecture::X64);
    let mut i = 0usize;
    while i + 5 < code.len() {
        // E8 rel32 call
        if code[i] == 0xE8 {
            let rel = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let target = (base as i64 + i as i64 + 5 + rel as i64) as u64;
            if target >= base && target < base + code.len() as u64 {
                addrs.push(target);
            }
            i += 5;
            continue;
        }
        // prologue: 55 48 89 e5 (push rbp; mov rbp,rsp) or 55 89 e5
        if code[i] == 0x55 {
            if is64 && i + 3 < code.len() && code[i + 1] == 0x48 && code[i + 2] == 0x89 && code[i + 3] == 0xE5
            {
                addrs.push(base + i as u64);
            } else if !is64 && i + 2 < code.len() && code[i + 1] == 0x89 && code[i + 2] == 0xE5 {
                addrs.push(base + i as u64);
            }
        }
        i += 1;
    }
    addrs.sort_unstable();
    addrs.dedup();
    addrs.truncate(512);
    addrs
}
