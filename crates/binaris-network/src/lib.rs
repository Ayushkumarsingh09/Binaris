//! Enrich network indicators with GeoIP / ASN / WHOIS / protocol heuristics.

use binaris_core::{Evidence, GraphEdge, GraphNode, GraphPayload, NetworkIndicator, NetworkKind};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEndpoint {
    pub indicator: String,
    pub kind: NetworkKind,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub as_org: Option<String>,
    pub whois_summary: Option<String>,
    pub protocol: Option<String>,
    pub possible_c2: bool,
    pub beacon_interval_hint: Option<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkIntelligence {
    pub endpoints: Vec<EnrichedEndpoint>,
    pub graph: GraphPayload,
    pub destination_summary: Vec<String>,
}

pub async fn enrich(indicators: &[NetworkIndicator]) -> NetworkIntelligence {
    let mut endpoints = Vec::new();
    for ind in indicators.iter().take(40) {
        let mut ep = EnrichedEndpoint {
            indicator: ind.value.clone(),
            kind: ind.kind,
            ip: matches!(ind.kind, NetworkKind::Ip).then(|| ind.value.clone()),
            country: None,
            city: None,
            asn: None,
            as_org: None,
            whois_summary: None,
            protocol: ind.protocol.clone().or_else(|| protocol_guess(&ind.value)),
            possible_c2: ind.suspicious || looks_like_c2(&ind.value),
            beacon_interval_hint: beacon_hint(&ind.value),
            evidence: ind.evidence.clone(),
        };

        if let Some(host) = extract_host(&ind.value) {
            if let Some(geo) = lookup_ip_api(&host).await {
                ep.ip = geo.ip.or(ep.ip);
                ep.country = geo.country;
                ep.city = geo.city;
                ep.asn = geo.asn;
                ep.as_org = geo.as_org;
                ep.evidence.push(Evidence::NetworkIndicator {
                    indicator: host.clone(),
                    note: "GeoIP/ASN enrichment".into(),
                });
            }
            if let Some(whois) = whois_summary(&host).await {
                ep.whois_summary = Some(whois);
            }
        }
        endpoints.push(ep);
    }

    let graph = build_network_graph(&endpoints);
    let destination_summary = endpoints
        .iter()
        .map(|e| {
            format!(
                "{} [{}] {}{}{}",
                e.indicator,
                e.protocol.as_deref().unwrap_or("?"),
                e.country.as_deref().unwrap_or("??"),
                e.asn
                    .as_ref()
                    .map(|a| format!("/{a}"))
                    .unwrap_or_default(),
                if e.possible_c2 { " C2?" } else { "" }
            )
        })
        .collect();

    NetworkIntelligence {
        endpoints,
        graph,
        destination_summary,
    }
}

#[derive(Default)]
struct Geo {
    ip: Option<String>,
    country: Option<String>,
    city: Option<String>,
    asn: Option<String>,
    as_org: Option<String>,
}

async fn lookup_ip_api(host: &str) -> Option<Geo> {
    // Uses public ip-api.com (no key) when network available; fails soft offline.
    let url = format!("http://ip-api.com/json/{host}?fields=status,message,country,city,query,as,org");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let res = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "geoip lookup failed");
            return None;
        }
    };
    let v: serde_json::Value = res.json().await.ok()?;
    if v["status"].as_str() != Some("success") {
        return None;
    }
    Some(Geo {
        ip: v["query"].as_str().map(|s| s.to_string()),
        country: v["country"].as_str().map(|s| s.to_string()),
        city: v["city"].as_str().map(|s| s.to_string()),
        asn: v["as"].as_str().map(|s| s.to_string()),
        as_org: v["org"].as_str().map(|s| s.to_string()),
    })
}

async fn whois_summary(host: &str) -> Option<String> {
    // Lightweight RDAP via rdap.org bootstrap when available.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .ok()?;
    let url = format!("https://rdap.org/domain/{host}");
    let res = client.get(&url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let v: serde_json::Value = res.json().await.ok()?;
    let name = v["ldhName"].as_str().unwrap_or(host);
    let status = v["status"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Some(format!("RDAP {name} status={status}"))
}

fn extract_host(value: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(value) {
        return u.host_str().map(|s| s.to_string());
    }
    if value.contains('.') && !value.contains(' ') {
        return Some(
            value
                .split(['/', ':'])
                .next()
                .unwrap_or(value)
                .trim()
                .to_string(),
        );
    }
    None
}

fn protocol_guess(v: &str) -> Option<String> {
    let l = v.to_ascii_lowercase();
    if l.starts_with("https://") {
        Some("https".into())
    } else if l.starts_with("http://") {
        Some("http".into())
    } else if l.starts_with("ws://") || l.starts_with("wss://") {
        Some("websocket".into())
    } else if l.contains("mqtt") {
        Some("mqtt".into())
    } else if l.contains("ftp://") {
        Some("ftp".into())
    } else if l.contains("smtp") {
        Some("smtp".into())
    } else if l.contains("\\\\.\\pipe") || l.contains("\\\\") {
        Some("named_pipe".into())
    } else {
        None
    }
}

fn looks_like_c2(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    l.contains("ngrok")
        || l.contains("duckdns")
        || l.contains(".onion")
        || l.contains("pastebin")
        || l.contains("discord.com/api/webhooks")
        || l.contains("/gate")
        || l.contains("/panel")
}

fn beacon_hint(v: &str) -> Option<String> {
    let l = v.to_ascii_lowercase();
    if l.contains("sleep") || l.contains("beacon") || l.contains("jitter") {
        Some("Static strings suggest sleep/jitter-based beaconing; confirm dynamically".into())
    } else {
        None
    }
}

fn build_network_graph(endpoints: &[EnrichedEndpoint]) -> GraphPayload {
    let mut nodes = vec![GraphNode {
        id: "binary".into(),
        label: "binary".into(),
        kind: "binary".into(),
        address: None,
        meta: json!({}),
    }];
    let mut edges = Vec::new();
    for (i, ep) in endpoints.iter().enumerate() {
        let id = format!("ep_{i}");
        nodes.push(GraphNode {
            id: id.clone(),
            label: ep.indicator.clone(),
            kind: "endpoint".into(),
            address: None,
            meta: json!({
                "country": ep.country,
                "asn": ep.asn,
                "c2": ep.possible_c2,
            }),
        });
        edges.push(GraphEdge {
            id: format!("e_{i}"),
            source: "binary".into(),
            target: id,
            kind: if ep.possible_c2 { "possible_c2" } else { "connects" }.into(),
            label: ep.protocol.clone(),
        });
    }
    GraphPayload { nodes, edges }
}
