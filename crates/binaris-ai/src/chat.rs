use binaris_core::{AnalysisReport, Evidence, StringCategory};
use serde::{Deserialize, Serialize};

use crate::providers::{build_provider, AiMessage, ProviderConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatAnswer {
    pub content: String,
    pub citations: Vec<Evidence>,
    pub provider: String,
}

pub async fn answer_question(
    report: &AnalysisReport,
    question: &str,
    cfg: &ProviderConfig,
) -> anyhow::Result<ChatAnswer> {
    let (local, citations) = grounded_answer(report, question);
    let provider = build_provider(cfg);

    if cfg.provider == "local" || cfg.api_key.is_none() {
        return Ok(ChatAnswer {
            content: local,
            citations,
            provider: "local".into(),
        });
    }

    let system = AiMessage {
        role: "system".into(),
        content: "You are Binaris, an expert reverse engineer. Only make claims supported by the provided evidence. Cite function addresses, imports, and strings. If evidence is insufficient, say so.".into(),
    };
    let context = AiMessage {
        role: "user".into(),
        content: format!(
            "Binary evidence pack:\n{}\n\nQuestion: {}\n\nDraft answer to refine (keep citations):\n{}",
            evidence_pack(report),
            question,
            local
        ),
    };

    match provider.complete(&[system, context]).await {
        Ok(content) => Ok(ChatAnswer {
            content,
            citations,
            provider: cfg.provider.clone(),
        }),
        Err(e) => Ok(ChatAnswer {
            content: format!("{local}\n\n_(External model unavailable: {e})_"),
            citations,
            provider: "local-fallback".into(),
        }),
    }
}

fn grounded_answer(report: &AnalysisReport, question: &str) -> (String, Vec<Evidence>) {
    let q = question.to_ascii_lowercase();
    let mut citations = Vec::new();

    if q.contains("summar") || q.contains("overview") {
        citations.push(Evidence::Hash {
            algorithm: "sha256".into(),
            value: report.hashes.sha256.clone(),
            note: "File identity".into(),
        });
        return (
            format!(
                "{}\n\nMalware: {:?} ({:.0}%).\n{}",
                report.executive_summary,
                report.malware.family,
                report.malware.malware_probability * 100.0,
                report.malware.reasoning
            ),
            citations,
        );
    }

    if q.contains("network") || q.contains("c2") || q.contains("url") || q.contains("domain") {
        let mut lines = vec!["Network-related evidence:".to_string()];
        for n in report.network.iter().take(30) {
            lines.push(format!("- {:?} `{}` suspicious={}", n.kind, n.value, n.suspicious));
            citations.extend(n.evidence.iter().cloned());
        }
        for imp in report.imports.iter().filter(|i| i.tags.iter().any(|t| t == "networking")).take(20) {
            lines.push(format!("- import {}!{}", imp.module, imp.symbol));
            citations.push(Evidence::Import {
                module: imp.module.clone(),
                symbol: imp.symbol.clone(),
                note: "Networking API".into(),
            });
        }
        if lines.len() == 1 {
            lines.push("No network indicators extracted.".into());
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("encrypt") || q.contains("crypto") || q.contains("decrypt") {
        let mut lines = vec!["Cryptography evidence:".to_string()];
        for c in &report.crypto {
            lines.push(format!(
                "- {} ({}) strength={} mode={:?}",
                c.algorithm, c.category, c.strength, c.mode
            ));
            citations.extend(c.evidence.iter().cloned());
        }
        for f in report.functions.iter().filter(|f| f.possible_crypto).take(15) {
            lines.push(format!(
                "- function {} @ {:#x} — {}",
                f.suggested_name.as_deref().unwrap_or(&f.name),
                f.address,
                f.description.as_deref().unwrap_or("crypto-related")
            ));
            citations.push(Evidence::Function {
                address: format!("{:#x}", f.address),
                name: f.suggested_name.clone().or(Some(f.name.clone())),
                note: "Marked possible_crypto".into(),
            });
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("license") {
        let mut lines = vec!["License-related evidence:".to_string()];
        for s in report.strings.iter().filter(|s| s.value.to_ascii_lowercase().contains("license")) {
            lines.push(format!("- string @ {:#x}: {}", s.offset, s.value));
            citations.push(Evidence::String {
                value: s.value.clone(),
                offset: Some(s.offset),
                note: "License string".into(),
            });
        }
        for f in report.functions.iter().filter(|f| {
            f.suggested_name
                .as_deref()
                .unwrap_or("")
                .contains("license")
                || f.name.contains("license")
        }) {
            lines.push(format!(
                "- {} @ {:#x}: {}",
                f.suggested_name.as_deref().unwrap_or(&f.name),
                f.address,
                f.description.as_deref().unwrap_or("candidate")
            ));
        }
        if lines.len() == 1 {
            lines.push("No explicit license checks found in extracted evidence.".into());
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("persist") {
        let mut lines = vec!["Persistence evidence:".to_string()];
        for p in &report.malware.persistence {
            lines.push(format!("- API/behavior: {p}"));
        }
        for s in report.strings.iter().filter(|s| {
            matches!(s.category, StringCategory::Registry | StringCategory::Service)
                || s.value.to_ascii_lowercase().contains("currentversion\\run")
        }) {
            lines.push(format!("- {}", s.value));
            citations.push(Evidence::String {
                value: s.value.clone(),
                offset: Some(s.offset),
                note: "Persistence indicator".into(),
            });
        }
        for f in report.functions.iter().filter(|f| f.possible_persistence) {
            lines.push(format!(
                "- {} @ {:#x}",
                f.suggested_name.as_deref().unwrap_or(&f.name),
                f.address
            ));
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("dangerous") || q.contains("api") {
        let mut lines = vec!["Higher-risk APIs:".to_string()];
        for imp in report
            .imports
            .iter()
            .filter(|i| {
                matches!(
                    i.risk,
                    binaris_core::RiskLevel::Medium
                        | binaris_core::RiskLevel::High
                        | binaris_core::RiskLevel::Critical
                )
            })
            .take(40)
        {
            lines.push(format!("- [{:?}] {}!{} {:?}", imp.risk, imp.module, imp.symbol, imp.tags));
            citations.push(Evidence::Import {
                module: imp.module.clone(),
                symbol: imp.symbol.clone(),
                note: format!("risk={:?}", imp.risk),
            });
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("malware") || q.contains("probability") {
        citations.extend(report.malware.evidence.iter().cloned());
        return (
            format!(
                "Malware probability is {:.0}% (confidence {:.0}%). Family: {:?}.\nReasoning: {}\nBehaviors: {}\n",
                report.malware.malware_probability * 100.0,
                report.malware.confidence * 100.0,
                report.malware.family,
                report.malware.reasoning,
                report.malware.behaviors.join(", ")
            ),
            citations,
        );
    }

    if q.contains("main") || q.contains("entry") {
        if let Some(f) = report.functions.iter().find(|f| {
            f.tags.iter().any(|t| t == "entry") || f.name == "entry" || f.name.contains("main")
        }) {
            citations.push(Evidence::Function {
                address: format!("{:#x}", f.address),
                name: f.suggested_name.clone().or(Some(f.name.clone())),
                note: "Entry/main candidate".into(),
            });
            return (
                format!(
                    "Entry candidate `{}` @ {:#x}\n{}\nPurpose: {}\nAssembly preview:\n{}",
                    f.suggested_name.as_deref().unwrap_or(&f.name),
                    f.address,
                    f.description.as_deref().unwrap_or("n/a"),
                    f.purpose.as_deref().unwrap_or("n/a"),
                    f.assembly_preview.as_deref().unwrap_or("n/a")
                ),
                citations,
            );
        }
    }

    if q.contains("credential") || q.contains("secret") || q.contains("password") {
        let mut lines = vec!["Credential/secret evidence:".to_string()];
        for f in report.security.iter().filter(|f| f.category == "secrets") {
            lines.push(format!("- [{:?}] {}", f.severity, f.title));
            citations.extend(f.evidence.iter().cloned());
        }
        for s in report.strings.iter().filter(|s| {
            matches!(
                s.category,
                StringCategory::Credential | StringCategory::ApiKey | StringCategory::Jwt
            )
        }) {
            lines.push(format!("- {:?} @ {:#x}", s.category, s.offset));
        }
        return (lines.join("\n"), citations);
    }

    if q.contains("dead code") {
        return (
            "Dead-code identification requires full CFG reachability from entry. Current static pass marks unreachable candidates only when call-graph coverage is complete; review functions with zero xrefs_to as candidates.".into(),
            citations,
        );
    }

    if q.contains("document") || q.contains("architecture diagram") {
        return (
            format!(
                "Architecture snapshot:\n- Format {:?}/{:?}\n- Dependencies: {}\n- Call-graph nodes: {}\n- Import modules: {}\n\nUse the Graphs panel for interactive diagrams. Generated reports are available via the Reports API.",
                report.identity.format,
                report.identity.architecture,
                report.dependencies.len(),
                report.call_graph.nodes.len(),
                report
                    .imports
                    .iter()
                    .map(|i| i.module.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            ),
            citations,
        );
    }

    // Default: search functions/imports/strings
    let mut hits = Vec::new();
    for f in report.functions.iter().filter(|f| {
        f.name.to_ascii_lowercase().contains(&q)
            || f.suggested_name
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&q)
            || f.description
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&q)
    }).take(10) {
        hits.push(format!(
            "- fn {} @ {:#x}: {}",
            f.suggested_name.as_deref().unwrap_or(&f.name),
            f.address,
            f.description.as_deref().unwrap_or("")
        ));
        citations.push(Evidence::Function {
            address: format!("{:#x}", f.address),
            name: Some(f.name.clone()),
            note: "Matched query".into(),
        });
    }
    for s in report.strings.iter().filter(|s| s.value.to_ascii_lowercase().contains(&q)).take(10) {
        hits.push(format!("- string @ {:#x}: {}", s.offset, s.value));
    }
    if hits.is_empty() {
        (
            format!(
                "No direct evidence matched `{question}`. Try: summarize binary, where is networking, show encryption, dangerous APIs, malware probability."
            ),
            citations,
        )
    } else {
        (format!("Evidence matches:\n{}", hits.join("\n")), citations)
    }
}

fn evidence_pack(report: &AnalysisReport) -> String {
    format!(
        "file={} sha256={} format={:?} arch={:?} malware={:?}/{:.2} imports={} strings={} findings={}",
        report.filename,
        report.hashes.sha256,
        report.identity.format,
        report.identity.architecture,
        report.malware.family,
        report.malware.malware_probability,
        report.imports.len(),
        report.strings.len(),
        report.security.len()
    )
}
