use binaris_core::{Evidence, PackerFinding, SectionInfo};

use crate::entropy::is_high_entropy;

pub fn detect_packers(data: &[u8], sections: &[SectionInfo]) -> Vec<PackerFinding> {
    let mut findings = Vec::new();

    check_upx(data, sections, &mut findings);
    check_section_names(sections, &mut findings);
    check_entropy_packer(sections, &mut findings);
    check_themida(data, sections, &mut findings);
    check_vmprotect(data, sections, &mut findings);
    check_aspack(sections, &mut findings);
    check_fsg(data, &mut findings);
    check_pecompact(sections, &mut findings);

    findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings
}

fn check_upx(data: &[u8], sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    let has_upx_magic = contains(data, b"UPX!") || contains(data, b"UPX0") || contains(data, b"UPX1");
    let has_upx_sections = sections.iter().any(|s| s.name.contains("UPX"));
    if has_upx_magic || has_upx_sections {
        out.push(PackerFinding {
            name: "UPX".into(),
            confidence: if has_upx_magic && has_upx_sections {
                0.98
            } else {
                0.85
            },
            evidence: vec![Evidence::Heuristic {
                rule: "upx_signature".into(),
                note: "UPX section names or magic detected".into(),
            }],
        });
    }
}

fn check_themida(data: &[u8], sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    let hit = sections.iter().any(|s| {
        s.name.contains("themida") || s.name.contains(".yP") || s.name.contains(".winlice")
    }) || contains(data, b"Themida")
        || contains(data, b"WinLicense");
    if hit {
        out.push(PackerFinding {
            name: "Themida/WinLicense".into(),
            confidence: 0.9,
            evidence: vec![Evidence::Heuristic {
                rule: "themida_signature".into(),
                note: "Themida/WinLicense markers found".into(),
            }],
        });
    }
}

fn check_vmprotect(data: &[u8], sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    let hit = sections.iter().any(|s| s.name.contains(".vmp"))
        || contains(data, b"VMProtect")
        || contains(data, b".vmp0");
    if hit {
        out.push(PackerFinding {
            name: "VMProtect".into(),
            confidence: 0.92,
            evidence: vec![Evidence::Heuristic {
                rule: "vmprotect_signature".into(),
                note: "VMProtect markers found".into(),
            }],
        });
    }
}

fn check_aspack(sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    if sections.iter().any(|s| s.name.contains(".aspack") || s.name.contains(".adata")) {
        out.push(PackerFinding {
            name: "ASPack".into(),
            confidence: 0.88,
            evidence: vec![Evidence::Section {
                name: ".aspack/.adata".into(),
                note: "ASPack section naming pattern".into(),
            }],
        });
    }
}

fn check_fsg(data: &[u8], out: &mut Vec<PackerFinding>) {
    if contains(data, b"FSG!") || contains(data, b"FSG1") {
        out.push(PackerFinding {
            name: "FSG".into(),
            confidence: 0.86,
            evidence: vec![Evidence::Heuristic {
                rule: "fsg_magic".into(),
                note: "FSG packer magic".into(),
            }],
        });
    }
}

fn check_pecompact(sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    if sections
        .iter()
        .any(|s| s.name.contains("PEC2") || s.name.contains("pecompact"))
    {
        out.push(PackerFinding {
            name: "PECompact".into(),
            confidence: 0.84,
            evidence: vec![Evidence::Section {
                name: "PEC2".into(),
                note: "PECompact section marker".into(),
            }],
        });
    }
}

fn check_section_names(sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    for s in sections {
        let n = s.name.to_ascii_lowercase();
        if n.contains("packed") || n.contains("crypt") {
            out.push(PackerFinding {
                name: "Custom/Generic packer".into(),
                confidence: 0.55,
                evidence: vec![Evidence::Section {
                    name: s.name.clone(),
                    note: format!("Suspicious section name with entropy {:.2}", s.entropy),
                }],
            });
        }
    }
}

fn check_entropy_packer(sections: &[SectionInfo], out: &mut Vec<PackerFinding>) {
    let high = sections
        .iter()
        .filter(|s| is_high_entropy(s.entropy) && s.raw_size > 1024)
        .count();
    let executable_high = sections.iter().any(|s| {
        is_high_entropy(s.entropy) && s.permissions.contains('x') && s.raw_size > 2048
    });
    if high >= 2 || executable_high {
        out.push(PackerFinding {
            name: "High-entropy packing/encryption".into(),
            confidence: if executable_high { 0.7 } else { 0.55 },
            evidence: vec![Evidence::Entropy {
                region: "sections".into(),
                value: sections.iter().map(|s| s.entropy).fold(0.0, f64::max),
                note: format!("{high} high-entropy sections; possible custom packer"),
            }],
        });
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn encrypted_sections(sections: &[SectionInfo]) -> Vec<String> {
    sections
        .iter()
        .filter(|s| s.entropy >= 7.5 && s.raw_size > 512)
        .map(|s| s.name.clone())
        .collect()
}
