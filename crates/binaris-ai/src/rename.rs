use binaris_core::{Evidence, FunctionAnalysis, ImportEntry, ExtractedString};

/// Deterministic semantic rename suggestions grounded in imports/strings/heuristics.
pub fn suggest_names(
    functions: &mut [FunctionAnalysis],
    imports: &[ImportEntry],
    strings: &[ExtractedString],
) {
    let import_blob = imports
        .iter()
        .map(|i| i.symbol.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let string_blob = strings
        .iter()
        .take(500)
        .map(|s| s.value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");

    for func in functions.iter_mut() {
        let preview = func
            .assembly_preview
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut score = 0.35f32;
        let mut name = None;
        let mut description = None;
        let mut purpose = None;
        let mut evidence = Vec::new();

        if func.tags.iter().any(|t| t == "entry") || func.name == "entry" {
            name = Some("program_entry".into());
            description = Some("Binary entry point / startup stub.".into());
            purpose = Some("Initialize runtime and transfer control to main logic.".into());
            score = 0.7;
        }

        if import_blob.contains("crypt") || preview.contains("xor") || func.possible_crypto {
            name = Some(name.unwrap_or_else(|| "crypto_routine".into()));
            description = Some(
                "Likely cryptographic or obfuscation routine based on crypto APIs/constants."
                    .into(),
            );
            purpose = Some("Encrypt, decrypt, or transform buffers.".into());
            func.possible_crypto = true;
            score = score.max(0.65);
            if let Some(imp) = imports.iter().find(|i| i.tags.iter().any(|t| t == "crypto")) {
                evidence.push(Evidence::Import {
                    module: imp.module.clone(),
                    symbol: imp.symbol.clone(),
                    note: "Crypto-related import".into(),
                });
            }
        }

        if import_blob.contains("wsastartup")
            || import_blob.contains("winhttp")
            || import_blob.contains("internetopen")
            || func.possible_networking
            || string_blob.contains("http://")
            || string_blob.contains("https://")
        {
            if name.is_none() || func.possible_networking {
                name = Some("network_communication".into());
                description = Some(
                    "Interacts with network APIs or contains network indicators.".into(),
                );
                purpose = Some("Establish outbound communication or fetch remote resources.".into());
                func.possible_networking = true;
                score = score.max(0.68);
            }
            if let Some(s) = strings.iter().find(|s| {
                matches!(
                    s.category,
                    binaris_core::StringCategory::Url | binaris_core::StringCategory::Domain
                )
            }) {
                evidence.push(Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "Network indicator string".into(),
                });
            }
        }

        if import_blob.contains("isdebuggerpresent") || func.possible_anti_debug {
            name = Some("anti_debug_check".into());
            description = Some("Checks for debugger / analysis environment.".into());
            purpose = Some("Evade dynamic analysis.".into());
            func.possible_anti_debug = true;
            score = score.max(0.75);
        }

        if import_blob.contains("writprocessmemory")
            || import_blob.contains("createremotethread")
            || import_blob.contains("virtualallocex")
            || func.possible_injection
        {
            name = Some("inject_into_process".into());
            description = Some("Uses classic process injection APIs.".into());
            purpose = Some("Inject code into a remote process.".into());
            func.possible_injection = true;
            score = score.max(0.8);
        }

        if import_blob.contains("regsetvalue")
            || import_blob.contains("createservice")
            || string_blob.contains("currentversion\\run")
        {
            if name.is_none() {
                name = Some("establish_persistence".into());
            }
            description = Some(
                description.unwrap_or_else(|| {
                    "Touches persistence mechanisms (registry/services).".into()
                }),
            );
            purpose = Some("Survive reboot / maintain foothold.".into());
            func.possible_persistence = true;
            score = score.max(0.72);
        }

        if string_blob.contains("license") && (preview.contains("cmp") || import_blob.contains("crypt"))
        {
            name = Some("validate_license".into());
            description =
                Some("Likely license or entitlement validation routine.".into());
            purpose = Some("Validate license material / signature.".into());
            score = score.max(0.6);
            if let Some(s) = strings.iter().find(|s| s.value.to_ascii_lowercase().contains("license"))
            {
                evidence.push(Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "License-related string".into(),
                });
            }
        }

        if let Some(n) = name {
            func.suggested_name = Some(n);
        }
        if description.is_some() {
            func.description = description;
        }
        if purpose.is_some() {
            func.purpose = purpose;
        }
        if func.pseudocode_summary.is_none() {
            if let Some(desc) = &func.description {
                func.pseudocode_summary = Some(desc.clone());
            }
        }
        func.confidence = score;
        func.evidence.extend(evidence);
    }
}
