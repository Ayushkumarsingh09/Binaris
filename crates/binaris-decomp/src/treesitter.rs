//! Tree-sitter-style language structure detection over embedded source / scripts.
//! Uses grammar-inspired heuristics so the platform works without native grammar .so files.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageHit {
    pub language: String,
    pub confidence: f32,
    pub evidence: String,
}

pub fn scan_binary_strings(data: &[u8]) -> Vec<LanguageHit> {
    let text = String::from_utf8_lossy(data);
    let mut hits = Vec::new();

    push_if(
        &mut hits,
        "c",
        0.7,
        text.contains("#include <") || text.contains("int main("),
        "C markers",
    );
    push_if(
        &mut hits,
        "cpp",
        0.75,
        text.contains("std::") || text.contains("#include <iostream>"),
        "C++ markers",
    );
    push_if(
        &mut hits,
        "rust",
        0.8,
        text.contains("fn main(") || text.contains("impl ") && text.contains("pub "),
        "Rust markers",
    );
    push_if(
        &mut hits,
        "go",
        0.8,
        text.contains("package main") || text.contains("func main("),
        "Go markers",
    );
    push_if(
        &mut hits,
        "python",
        0.75,
        text.contains("def ") && text.contains("import ") || text.contains("PyObject"),
        "Python markers",
    );
    push_if(
        &mut hits,
        "javascript",
        0.7,
        text.contains("function(") || text.contains("=> {") || text.contains("node_modules"),
        "JavaScript markers",
    );
    push_if(
        &mut hits,
        "java",
        0.75,
        text.contains("public static void main") || text.contains("Ljava/"),
        "Java markers",
    );
    push_if(
        &mut hits,
        "kotlin",
        0.7,
        text.contains("fun main(") || text.contains("kotlin/"),
        "Kotlin markers",
    );
    push_if(
        &mut hits,
        "swift",
        0.7,
        text.contains("import Foundation") || text.contains("@objc"),
        "Swift markers",
    );
    push_if(
        &mut hits,
        "llvm_ir",
        0.85,
        text.contains("define ") && text.contains("i32 @") || text.contains("; ModuleID"),
        "LLVM IR markers",
    );

    hits.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits
}

fn push_if(out: &mut Vec<LanguageHit>, lang: &str, conf: f32, cond: bool, evidence: &str) {
    if cond {
        out.push(LanguageHit {
            language: lang.into(),
            confidence: conf,
            evidence: evidence.into(),
        });
    }
}
