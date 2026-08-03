use binaris_core::{
    Evidence, ExtractedString, ImportEntry, NetworkIndicator, NetworkKind, RiskLevel,
    StringCategory,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;

static DANGEROUS_APIS: Lazy<HashMap<&'static str, (&'static str, RiskLevel)>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let high = [
        ("VirtualAllocEx", "process_injection"),
        ("WriteProcessMemory", "process_injection"),
        ("CreateRemoteThread", "process_injection"),
        ("NtCreateThreadEx", "process_injection"),
        ("QueueUserAPC", "process_injection"),
        ("SetWindowsHookEx", "keylogger/hooks"),
        ("SetWindowsHookExA", "keylogger/hooks"),
        ("SetWindowsHookExW", "keylogger/hooks"),
        ("ReflectiveLoader", "reflective_loading"),
        ("AdjustTokenPrivileges", "token_manipulation"),
        ("DuplicateTokenEx", "token_manipulation"),
        ("RtlCreateUserThread", "process_injection"),
    ];
    for (api, tag) in high {
        m.insert(api, (tag, RiskLevel::High));
    }
    let critical = [
        ("CryptEncrypt", "crypto"),
        ("DeviceIoControl", "driver"),
        ("ZwMapViewOfSection", "injection"),
        ("NtMapViewOfSection", "injection"),
        ("MiniDumpWriteDump", "credential_access"),
    ];
    for (api, tag) in critical {
        m.insert(api, (tag, RiskLevel::Critical));
    }
    let medium = [
        ("InternetOpenUrlA", "networking"),
        ("InternetOpenUrlW", "networking"),
        ("URLDownloadToFileA", "dropper"),
        ("URLDownloadToFileW", "dropper"),
        ("WinHttpOpen", "networking"),
        ("HttpSendRequestA", "networking"),
        ("HttpSendRequestW", "networking"),
        ("socket", "networking"),
        ("connect", "networking"),
        ("send", "networking"),
        ("recv", "networking"),
        ("WSAStartup", "networking"),
        ("CreateServiceA", "persistence"),
        ("CreateServiceW", "persistence"),
        ("RegSetValueExA", "persistence"),
        ("RegSetValueExW", "persistence"),
        ("ShellExecuteA", "execution"),
        ("ShellExecuteW", "execution"),
        ("WinExec", "execution"),
        ("system", "execution"),
        ("IsDebuggerPresent", "anti_debug"),
        ("CheckRemoteDebuggerPresent", "anti_debug"),
        ("NtQueryInformationProcess", "anti_debug"),
        ("OutputDebugStringA", "anti_debug"),
        ("GetTickCount", "anti_sandbox"),
        ("GetCursorPos", "anti_sandbox"),
        ("Sleep", "anti_sandbox"),
        ("CreateToolhelp32Snapshot", "enumeration"),
        ("Process32FirstW", "enumeration"),
        ("OpenProcess", "process_access"),
        ("TerminateProcess", "process_kill"),
        ("LoadLibraryA", "dynamic_loading"),
        ("LoadLibraryW", "dynamic_loading"),
        ("GetProcAddress", "dynamic_loading"),
        ("VirtualProtect", "memory_protect"),
        ("VirtualAlloc", "memory_alloc"),
    ];
    for (api, tag) in medium {
        m.insert(api, (tag, RiskLevel::Medium));
    }
    m
});

pub fn classify_import(module: &str, symbol: &str) -> (RiskLevel, Vec<String>) {
    if let Some((tag, risk)) = DANGEROUS_APIS.get(symbol) {
        return (*risk, vec![(*tag).into()]);
    }
    let lower = symbol.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut risk = RiskLevel::Info;
    if lower.contains("crypt") {
        tags.push("crypto".into());
        risk = RiskLevel::Low;
    }
    if lower.contains("reg") {
        tags.push("registry".into());
    }
    if module.eq_ignore_ascii_case("ws2_32.dll") || module.eq_ignore_ascii_case("winhttp.dll") {
        tags.push("networking".into());
        risk = RiskLevel::Low;
    }
    (risk, tags)
}

pub fn enrich_imports(imports: &mut [ImportEntry]) {
    for imp in imports.iter_mut() {
        let (risk, tags) = classify_import(&imp.module, &imp.symbol);
        imp.risk = risk;
        imp.tags = tags;
    }
}

pub fn network_from_strings(strings: &[ExtractedString]) -> Vec<NetworkIndicator> {
    let mut out = Vec::new();
    for s in strings {
        match s.category {
            StringCategory::Url => out.push(NetworkIndicator {
                kind: NetworkKind::Url,
                value: s.value.clone(),
                port: parse_port_from_url(&s.value),
                protocol: protocol_from_url(&s.value),
                evidence: vec![Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "URL extracted from binary strings".into(),
                }],
                suspicious: is_suspicious_host(&s.value),
            }),
            StringCategory::Domain => out.push(NetworkIndicator {
                kind: NetworkKind::Domain,
                value: s.value.clone(),
                port: None,
                protocol: None,
                evidence: vec![Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "Domain extracted from binary strings".into(),
                }],
                suspicious: is_suspicious_host(&s.value),
            }),
            StringCategory::Ip => out.push(NetworkIndicator {
                kind: NetworkKind::Ip,
                value: s.value.clone(),
                port: None,
                protocol: None,
                evidence: vec![Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "IP extracted from binary strings".into(),
                }],
                suspicious: !s.value.starts_with("127.") && !s.value.starts_with("0."),
            }),
            StringCategory::Email => out.push(NetworkIndicator {
                kind: NetworkKind::Email,
                value: s.value.clone(),
                port: None,
                protocol: Some("smtp".into()),
                evidence: vec![Evidence::String {
                    value: s.value.clone(),
                    offset: Some(s.offset),
                    note: "Email indicator".into(),
                }],
                suspicious: false,
            }),
            _ => {}
        }
    }
    out
}

fn parse_port_from_url(url: &str) -> Option<u16> {
    let after = url.split("://").nth(1)?;
    let hostport = after.split('/').next()?;
    let port = hostport.split(':').nth(1)?;
    port.parse().ok()
}

fn protocol_from_url(url: &str) -> Option<String> {
    url.split("://").next().map(|s| s.to_ascii_lowercase())
}

fn is_suspicious_host(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.contains("pastebin")
        || v.contains("ngrok")
        || v.contains("duckdns")
        || v.contains("raw.githubusercontent")
        || v.contains("tor2web")
        || v.contains(".onion")
        || v.contains("discord.com/api/webhooks")
}
