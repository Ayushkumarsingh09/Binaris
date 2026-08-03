//! Built-in assembly → readable pseudocode translator.

use regex::Regex;
use once_cell::sync::Lazy;

static RE_INSN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^\s*([0-9a-f]+)?\s*([a-z]+)\s*(.*)$").expect("insn")
});

pub fn from_assembly_preview(asm: &str, fn_name: &str) -> String {
    let mut lines = vec![format!("void {fn_name}() {{")];
    let indent = "  ";
    for raw in asm.lines().take(80) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        // hex dump style "48 89 e5 ..." → comment
        if line
            .split_whitespace()
            .all(|t| t.len() == 2 && u8::from_str_radix(t, 16).is_ok())
        {
            lines.push(format!("{indent}// bytes: {line}"));
            continue;
        }
        if let Some(caps) = RE_INSN.captures(line) {
            let mnem = caps.get(2).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default();
            let ops = caps.get(3).map(|m| m.as_str().trim()).unwrap_or("");
            lines.push(format!("{indent}{}", translate(&mnem, ops)));
        } else {
            lines.push(format!("{indent}// {line}"));
        }
    }
    lines.push("}".into());
    lines.join("\n")
}

fn translate(mnem: &str, ops: &str) -> String {
    match mnem {
        "ret" | "retn" => "return;".into(),
        "call" => format!("call({ops});"),
        "jmp" => format!("goto {ops};"),
        "je" | "jz" => format!("if (ZF) goto {ops};"),
        "jne" | "jnz" => format!("if (!ZF) goto {ops};"),
        "ja" | "jg" => format!("if (greater) goto {ops};"),
        "jb" | "jl" => format!("if (less) goto {ops};"),
        "push" => format!("stack.push({ops});"),
        "pop" => format!("{ops} = stack.pop();"),
        "mov" | "movq" | "movd" | "lea" => {
            let mut parts = ops.splitn(2, ',');
            let dst = parts.next().unwrap_or("dst").trim();
            let src = parts.next().unwrap_or("src").trim();
            format!("{dst} = {src};")
        }
        "xor" => {
            let mut parts = ops.splitn(2, ',');
            let a = parts.next().unwrap_or("a").trim();
            let b = parts.next().unwrap_or("b").trim();
            if a == b {
                format!("{a} = 0;")
            } else {
                format!("{a} ^= {b};")
            }
        }
        "add" | "sub" | "and" | "or" | "shl" | "shr" | "imul" | "mul" | "div" => {
            let op = match mnem {
                "add" => "+=",
                "sub" => "-=",
                "and" => "&=",
                "or" => "|=",
                "shl" => "<<=",
                "shr" => ">>=",
                "imul" | "mul" => "*=",
                "div" => "/=",
                _ => "=",
            };
            let mut parts = ops.splitn(2, ',');
            let a = parts.next().unwrap_or("a").trim();
            let b = parts.next().unwrap_or("b").trim();
            format!("{a} {op} {b};")
        }
        "cmp" | "test" => format!("flags = compare({ops});"),
        "nop" => "/* nop */".into(),
        "int3" | "ud2" => "abort(); // trap".into(),
        "syscall" | "sysenter" | "svc" => "syscall();".into(),
        _ => format!("asm(\"{mnem} {ops}\");"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_mov_xor_ret() {
        let asm = "mov rax, rbx\nxor eax, eax\nret";
        let pc = from_assembly_preview(asm, "demo");
        assert!(pc.contains("rax = rbx"));
        assert!(pc.contains("eax = 0"));
        assert!(pc.contains("return"));
    }
}
