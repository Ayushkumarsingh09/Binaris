use binaris_core::{ExtractedString, FunctionAnalysis, ImportEntry};

use crate::rename::suggest_names;

pub fn enrich_functions(
    functions: &mut [FunctionAnalysis],
    imports: &[ImportEntry],
    strings: &[ExtractedString],
) {
    suggest_names(functions, imports, strings);

    for func in functions.iter_mut() {
        if func.inputs.is_empty() {
            func.inputs = vec!["machine state / arguments (inferred)".into()];
        }
        if func.outputs.is_empty() {
            func.outputs = vec!["side effects / return value (inferred)".into()];
        }
        if func.complexity <= 1.0 {
            func.complexity = (func.size as f32 / 16.0).clamp(1.0, 100.0);
        }
    }
}

pub fn build_summaries(
    filename: &str,
    identity_line: &str,
    malware_line: &str,
    top_findings: &[String],
) -> (String, String) {
    let executive = format!(
        "{filename} analyzed by Binaris. {identity_line} {malware_line} Key issues: {}.",
        if top_findings.is_empty() {
            "none critical".into()
        } else {
            top_findings.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
        }
    );
    let technical = format!(
        "Static pipeline completed for {filename}. {identity_line} Findings detail: {}",
        top_findings.join(" | ")
    );
    (executive, technical)
}
