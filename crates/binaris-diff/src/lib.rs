use binaris_core::{AnalysisReport, SnapshotId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSnapshot {
    pub id: SnapshotId,
    pub analysis_id: binaris_core::AnalysisId,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub report: AnalysisReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiff {
    pub left_sha256: String,
    pub right_sha256: String,
    pub size_delta: i64,
    pub identical: bool,
    pub byte_diff_ratio: f32,
    pub section_changes: Vec<String>,
    pub import_added: Vec<String>,
    pub import_removed: Vec<String>,
    pub export_added: Vec<String>,
    pub export_removed: Vec<String>,
    pub function_added: Vec<String>,
    pub function_removed: Vec<String>,
    pub string_added: Vec<String>,
    pub string_removed: Vec<String>,
    pub malware_delta: String,
    pub summary: String,
}

pub fn snapshot(report: &AnalysisReport, label: impl Into<String>) -> AnalysisSnapshot {
    AnalysisSnapshot {
        id: SnapshotId::new(),
        analysis_id: report.id,
        label: label.into(),
        created_at: Utc::now(),
        report: report.clone(),
    }
}

pub fn diff_bytes(left: &[u8], right: &[u8]) -> (f32, bool) {
    if left == right {
        return (0.0, true);
    }
    let max = left.len().max(right.len()).max(1);
    let min = left.len().min(right.len());
    let mut diff = max - min;
    for i in 0..min {
        if left[i] != right[i] {
            diff += 1;
        }
    }
    ((diff as f32 / max as f32).min(1.0), false)
}

pub fn diff_reports(left: &AnalysisReport, right: &AnalysisReport) -> BinaryDiff {
    let (ratio, identical) = if left.hashes.sha256 == right.hashes.sha256 {
        (0.0, true)
    } else {
        (0.35, false) // structural diff without raw bytes
    };

    let limps: std::collections::BTreeSet<_> = left
        .imports
        .iter()
        .map(|i| format!("{}!{}", i.module, i.symbol))
        .collect();
    let rimps: std::collections::BTreeSet<_> = right
        .imports
        .iter()
        .map(|i| format!("{}!{}", i.module, i.symbol))
        .collect();

    let lexps: std::collections::BTreeSet<_> =
        left.exports.iter().map(|e| e.symbol.clone()).collect();
    let rexps: std::collections::BTreeSet<_> =
        right.exports.iter().map(|e| e.symbol.clone()).collect();

    let lfns: std::collections::BTreeSet<_> = left
        .functions
        .iter()
        .map(|f| f.suggested_name.clone().unwrap_or_else(|| f.name.clone()))
        .collect();
    let rfns: std::collections::BTreeSet<_> = right
        .functions
        .iter()
        .map(|f| f.suggested_name.clone().unwrap_or_else(|| f.name.clone()))
        .collect();

    let lstr: std::collections::BTreeSet<_> = left
        .strings
        .iter()
        .filter(|s| s.score >= 0.7)
        .map(|s| s.value.clone())
        .collect();
    let rstr: std::collections::BTreeSet<_> = right
        .strings
        .iter()
        .filter(|s| s.score >= 0.7)
        .map(|s| s.value.clone())
        .collect();

    let section_changes = {
        let ls: std::collections::BTreeSet<_> =
            left.sections.iter().map(|s| s.name.clone()).collect();
        let rs: std::collections::BTreeSet<_> =
            right.sections.iter().map(|s| s.name.clone()).collect();
        ls.symmetric_difference(&rs).cloned().collect::<Vec<_>>()
    };

    let import_added: Vec<_> = rimps.difference(&limps).cloned().collect();
    let import_removed: Vec<_> = limps.difference(&rimps).cloned().collect();
    let export_added: Vec<_> = rexps.difference(&lexps).cloned().collect();
    let export_removed: Vec<_> = lexps.difference(&rexps).cloned().collect();
    let function_added: Vec<_> = rfns.difference(&lfns).cloned().collect();
    let function_removed: Vec<_> = lfns.difference(&rfns).cloned().collect();
    let string_added: Vec<_> = rstr.difference(&lstr).take(50).cloned().collect();
    let string_removed: Vec<_> = lstr.difference(&rstr).take(50).cloned().collect();

    let malware_delta = format!(
        "{:?}/{:.0}% → {:?}/{:.0}%",
        left.malware.family,
        left.malware.malware_probability * 100.0,
        right.malware.family,
        right.malware.malware_probability * 100.0
    );

    let summary = format!(
        "Diff {} vs {}: +{} imports, -{} imports, +{} functions, -{} functions, sectionsΔ={}, malware {}",
        &left.hashes.sha256[..12.min(left.hashes.sha256.len())],
        &right.hashes.sha256[..12.min(right.hashes.sha256.len())],
        import_added.len(),
        import_removed.len(),
        function_added.len(),
        function_removed.len(),
        section_changes.len(),
        malware_delta
    );

    BinaryDiff {
        left_sha256: left.hashes.sha256.clone(),
        right_sha256: right.hashes.sha256.clone(),
        size_delta: right.size_bytes as i64 - left.size_bytes as i64,
        identical,
        byte_diff_ratio: ratio,
        section_changes,
        import_added,
        import_removed,
        export_added,
        export_removed,
        function_added,
        function_removed,
        string_added,
        string_removed,
        malware_delta,
        summary,
    }
}

pub fn content_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
