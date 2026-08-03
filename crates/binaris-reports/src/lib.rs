use binaris_core::{
    AnalysisReport, ReportDocument, ReportFormat, ReportId, ReportKind, RiskLevel,
};
use chrono::Utc;
use serde_json::json;

pub fn executive_summary(report: &AnalysisReport) -> String {
    format!(
        "## Executive Summary\n\n**File:** `{filename}`  \n**SHA-256:** `{sha}`  \n**Format:** {:?} / {:?} / {:?}  \n**Malware probability:** {:.0}% ({:?})  \n**Packer:** {packer}  \n**Critical findings:** {crit}  \n\n{summary}\n",
        report.identity.format,
        report.identity.architecture,
        report.identity.os,
        report.malware.malware_probability * 100.0,
        report.malware.family,
        filename = report.filename,
        sha = report.hashes.sha256,
        packer = report.identity.packer.as_deref().unwrap_or("none detected"),
        crit = report
            .security
            .iter()
            .filter(|f| matches!(f.severity, RiskLevel::Critical | RiskLevel::High))
            .count(),
        summary = report.malware.reasoning,
    )
}

pub fn technical_summary(report: &AnalysisReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("## Technical Summary — {}\n\n", report.filename));
    md.push_str("### Identity\n");
    md.push_str(&format!(
        "- Compiler: {}\n- Language: {}\n- Framework: {}\n- Entry: {:?}\n- Imports: {}\n- Exports: {}\n- Functions: {}\n- Strings: {}\n\n",
        report.identity.compiler.as_deref().unwrap_or("unknown"),
        report.identity.language.as_deref().unwrap_or("unknown"),
        report.identity.framework.as_deref().unwrap_or("unknown"),
        report.identity.entry_point,
        report.imports.len(),
        report.exports.len(),
        report.functions.len(),
        report.strings.len(),
    ));
    md.push_str("### Sections\n");
    for s in &report.sections {
        md.push_str(&format!(
            "- `{}` va={:#x} size={} entropy={:.2} perms={}\n",
            s.name, s.virtual_address, s.raw_size, s.entropy, s.permissions
        ));
    }
    md.push_str("\n### Crypto\n");
    for c in &report.crypto {
        md.push_str(&format!(
            "- {} ({}) strength={} conf={:.2}\n",
            c.algorithm, c.category, c.strength, c.confidence
        ));
    }
    md.push_str("\n### Network indicators\n");
    for n in report.network.iter().take(50) {
        md.push_str(&format!("- {:?} `{}` suspicious={}\n", n.kind, n.value, n.suspicious));
    }
    md.push_str("\n### Security findings\n");
    for f in report.security.iter().take(50) {
        md.push_str(&format!(
            "- [{:?}] {} — {}\n",
            f.severity, f.title, f.description
        ));
    }
    md
}

pub fn generate_yara(report: &AnalysisReport) -> String {
    let name = sanitize_ident(&report.filename);
    let mut strings = String::new();
    for (i, s) in report
        .strings
        .iter()
        .filter(|s| s.value.len() >= 8 && s.value.len() <= 64)
        .take(12)
        .enumerate()
    {
        let escaped = s.value.replace('\\', "\\\\").replace('"', "\\\"");
        strings.push_str(&format!("        $s{i} = \"{escaped}\" ascii wide\n"));
    }
    format!(
        "rule Binaris_{name}_{{\n    meta:\n        author = \"Binaris\"\n        sha256 = \"{}\"\n        generated = \"{}\"\n    strings:\n{strings}    condition:\n        uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or any of them\n}}\n",
        report.hashes.sha256,
        Utc::now().to_rfc3339(),
        name = name,
        strings = strings,
    )
}

pub fn generate_sigma(report: &AnalysisReport) -> String {
    format!(
        "title: Binaris Detection for {}\nstatus: experimental\ndescription: Generated from static analysis IOCs\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n{}  condition: selection\nfalsepositives:\n  - Unknown\nlevel: high\n",
        report.filename,
        report
            .iocs
            .iter()
            .take(10)
            .map(|i| format!("      - '{}'\n", i.replace('\'', "''")))
            .collect::<String>()
    )
}

pub fn generate_sarif(report: &AnalysisReport) -> String {
    let results: Vec<_> = report
        .security
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.category,
                "level": match f.severity {
                    RiskLevel::Critical | RiskLevel::High => "error",
                    RiskLevel::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": format!("{}: {}", f.title, f.description) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": report.filename },
                        "region": { "snippet": { "text": f.location.clone().unwrap_or_default() } }
                    }
                }]
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Binaris",
                    "informationUri": "https://binaris.dev",
                    "version": "0.1.0"
                }
            },
            "results": results
        }]
    }))
    .unwrap_or_else(|_| "{}".into())
}

pub fn generate_html(markdownish: &str, title: &str) -> String {
    let escaped = html_escape(markdownish);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{title}</title>
<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;background:#0b0f14;color:#e6edf3;margin:0;padding:2rem;line-height:1.55}}
pre{{white-space:pre-wrap;background:#111822;padding:1.25rem;border:1px solid #243041;border-radius:12px}}
h1{{color:#22d3ee}}
</style>
</head>
<body>
<h1>{title}</h1>
<pre>{escaped}</pre>
</body>
</html>"#
    )
}

pub fn build_documents(report: &AnalysisReport) -> Vec<ReportDocument> {
    let exec = executive_summary(report);
    let tech = technical_summary(report);
    let yara = generate_yara(report);
    let sigma = generate_sigma(report);
    let sarif = generate_sarif(report);
    let malware = format!(
        "{}\n\n## Malware Analysis\n\n{}\n\nSuspicious APIs:\n{}\n",
        exec,
        report.malware.reasoning,
        report
            .malware
            .suspicious_apis
            .iter()
            .map(|a| format!("- `{a}`"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let ioc = format!(
        "## IOC Report\n\n{}\n",
        report
            .iocs
            .iter()
            .map(|i| format!("- `{i}`"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let now = Utc::now();
    vec![
        doc(report, ReportKind::Executive, ReportFormat::Markdown, "Executive Summary", exec.clone(), now),
        doc(report, ReportKind::Technical, ReportFormat::Markdown, "Technical Summary", tech.clone(), now),
        doc(
            report,
            ReportKind::Executive,
            ReportFormat::Html,
            "Executive Summary HTML",
            generate_html(&exec, "Binaris Executive Summary"),
            now,
        ),
        doc(report, ReportKind::Malware, ReportFormat::Markdown, "Malware Report", malware, now),
        doc(report, ReportKind::Yara, ReportFormat::Markdown, "YARA Rules", yara, now),
        doc(report, ReportKind::Sigma, ReportFormat::Markdown, "Sigma Rules", sigma, now),
        doc(report, ReportKind::Ioc, ReportFormat::Markdown, "IOC Report", ioc, now),
        doc(report, ReportKind::Technical, ReportFormat::Sarif, "SARIF", sarif, now),
        doc(
            report,
            ReportKind::Sbom,
            ReportFormat::Json,
            "SBOM",
            serde_json::to_string_pretty(&report.sbom).unwrap_or_else(|_| "{}".into()),
            now,
        ),
        doc(
            report,
            ReportKind::ReverseEngineering,
            ReportFormat::Json,
            "Full Analysis JSON",
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into()),
            now,
        ),
        doc(
            report,
            ReportKind::Technical,
            ReportFormat::Pdf,
            "Technical Summary PDF",
            generate_pdf_bytes(&tech, "Binaris Technical Report"),
            now,
        ),
        doc(
            report,
            ReportKind::Dfir,
            ReportFormat::Markdown,
            "DFIR Report",
            format!(
                "{}\n\n## IOCs\n{}\n\n## Network\n{}\n",
                exec,
                report.iocs.iter().map(|i| format!("- `{i}`")).collect::<Vec<_>>().join("\n"),
                report
                    .network
                    .iter()
                    .map(|n| format!("- {:?} {}", n.kind, n.value))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            now,
        ),
        doc(
            report,
            ReportKind::ThreatIntelligence,
            ReportFormat::Markdown,
            "Threat Intelligence Report",
            format!(
                "## Threat Intel\n\nFamily: {:?}\nProbability: {:.0}%\n\n{}\n\nBehaviors:\n{}\n",
                report.malware.family,
                report.malware.malware_probability * 100.0,
                report.malware.reasoning,
                report
                    .malware
                    .behaviors
                    .iter()
                    .map(|b| format!("- {b}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            now,
        ),
    ]
}

/// Minimal valid PDF embedding the report text (no external PDF engine required).
pub fn generate_pdf_bytes(body: &str, title: &str) -> String {
    let content = format!("{title}\n\n{body}");
    // Escape PDF string literals
    let escaped = content
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .chars()
        .take(6000)
        .collect::<String>();
    let stream = format!("BT /F1 10 Tf 50 750 Td ({escaped}) Tj ET");
    let stream_len = stream.len();
    let pdf = format!(
        "%PDF-1.4\n\
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n\
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n\
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n\
4 0 obj<< /Length {stream_len} >>stream\n{stream}\nendstream endobj\n\
5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n\
xref\n0 6\n0000000000 65535 f \n\
trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
    );
    format!("data:application/pdf;base64,{}", base64_encode(pdf.as_bytes()))
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(T[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(T[(b2 & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn doc(
    report: &AnalysisReport,
    kind: ReportKind,
    format: ReportFormat,
    title: &str,
    content: String,
    created_at: chrono::DateTime<Utc>,
) -> ReportDocument {
    ReportDocument {
        id: ReportId::new(),
        analysis_id: report.id,
        kind,
        format,
        title: title.into(),
        content,
        created_at,
    }
}

fn sanitize_ident(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(48)
        .collect()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
