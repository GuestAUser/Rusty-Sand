use super::capabilities::import_findings;
use super::model::*;
use super::push_finding;

pub(super) fn obfuscation_findings(report: &mut StaticReport) {
    /*
     * Retained strings and their lengths are already bounded by extraction.
     * Reject truncated runs rather than treating a retained prefix as a
     * complete command. Matching observes syntax only, never decoded behavior.
     */
    for index in 0..report.strings.len() {
        let string = &report.strings[index];
        let reaches_scan_boundary = string.offset + string.byte_length
            == report.coverage.string_scan_bytes
            && report.size_bytes > report.coverage.string_scan_bytes;

        if string.truncated || reaches_scan_boundary || !encoded_powershell_command(&string.value) {
            continue;
        }

        let finding = Finding {
            id: "obfuscation.powershell_encoded_command".into(),
            category: FindingCategory::EmbeddedIndicator,
            severity: Severity::Low,
            confidence: Confidence::Low,
            summary: "PowerShell encoded-execution syntax; may be legitimate administration, not a malware verdict"
                .into(),
            evidence: vec![Evidence {
                offset: Some(string.offset),
                length: Some(string.byte_length),
                detail: string.value.clone(),
            }],
        };

        push_finding(report, finding);
    }
}

fn encoded_powershell_command(value: &str) -> bool {
    let mut arguments = value.split_ascii_whitespace();
    let Some(launcher) = arguments.next() else {
        return false;
    };

    if !["powershell", "powershell.exe", "pwsh", "pwsh.exe"]
        .iter()
        .any(|candidate| launcher.eq_ignore_ascii_case(candidate))
    {
        return false;
    }

    /*
     * This is deliberately not a shell or PowerShell argument parser.
     * In particular, -Command/-File must not turn later string literals into
     * apparent launcher options. Only these argument-free switches may precede
     * the encoded-command switch, and no trailing arguments are interpreted.
     */
    while let Some(option) = arguments.next() {
        if option.eq_ignore_ascii_case("-EncodedCommand") || option.eq_ignore_ascii_case("-enc") {
            return arguments.next().is_some_and(plausible_encoded_argument)
                && arguments.next().is_none();
        }

        if !["-NoProfile", "-NonInteractive", "-NoLogo"]
            .iter()
            .any(|candidate| option.eq_ignore_ascii_case(candidate))
        {
            return false;
        }
    }

    false
}

fn plausible_encoded_argument(argument: &str) -> bool {
    if !(8..=256).contains(&argument.len()) || !argument.len().is_multiple_of(4) {
        return false;
    }

    let content = argument.trim_end_matches('=');
    let padding = argument.len() - content.len();

    if padding > 2
        || !content
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return false;
    }

    /*
     * EncodedCommand expects UTF-16LE: its implied byte count must be even.
     * This checks only length and alphabet plausibility, not decoded content.
     */
    let implied_bytes = argument.len() / 4 * 3 - padding;

    implied_bytes.is_multiple_of(2)
}

fn section_finding(
    section: &Section,
    id: &str,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    summary: &str,
) -> Finding {
    Finding {
        id: id.into(),
        category,
        severity,
        confidence,
        summary: summary.into(),
        evidence: vec![Evidence {
            offset: Some(section.header_offset),
            length: Some(40),
            detail: format!(
                "section={:?}; raw_offset={}; raw_size={}; characteristics=0x{:08x}; entropy={:?}",
                section.name,
                section.raw_offset,
                section.raw_size,
                section.characteristics,
                section.entropy
            ),
        }],
    }
}

pub(super) fn pe_findings(metadata: &PeMetadata, report: &mut StaticReport) {
    for section in &metadata.sections {
        if section.writable && section.executable {
            push_finding(
                report,
                section_finding(
                    section,
                    "pe.section_writable_executable",
                    FindingCategory::Structure,
                    Severity::Medium,
                    Confidence::High,
                    "Section requests writable and executable memory; this is not proof of malware",
                ),
            );
        }

        let normalized_name = section.name.to_ascii_lowercase();

        if matches!(
            normalized_name.as_str(),
            "upx0"
                | "upx1"
                | "upx2"
                | ".aspack"
                | ".petite"
                | ".themida"
                | ".vmp0"
                | ".vmp1"
                | ".vmp2"
                | "mpress1"
                | "mpress2"
        ) {
            push_finding(
                report,
                section_finding(
                    section,
                    "packing.section_marker",
                    FindingCategory::Packing,
                    Severity::Low,
                    Confidence::Medium,
                    "Exact known packer section-name marker; names can be imitated and packing can be benign",
                ),
            );
        }

        if section.executable
            && section.raw_size >= 1024
            && section.entropy.is_some_and(|value| value >= 7.2)
        {
            push_finding(
                report,
                section_finding(
                    section,
                    "packing.high_entropy_executable",
                    FindingCategory::Packing,
                    Severity::Low,
                    Confidence::Low,
                    "High-entropy executable content may be packed, encrypted, or ordinary data; no malware inference",
                ),
            );
        }
    }

    if metadata.entry_point_rva != 0 {
        let executable_entry = metadata.sections.iter().any(|section| {
            let start = u64::from(section.virtual_address);
            let end = start + u64::from(section.virtual_size.max(section.raw_size));
            let entry = u64::from(metadata.entry_point_rva);

            section.executable && entry >= start && entry < end
        });

        if metadata.entry_point_offset.is_none() || !executable_entry {
            push_finding(
                report,
                Finding {
                    id: "pe.entry_point_anomaly".into(),
                    category: FindingCategory::Structure,
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    summary: "Entry point is not file-backed executable section content".into(),
                    evidence: vec![Evidence {
                        offset: metadata.entry_point_offset,
                        length: None,
                        detail: format!("entry_point_rva=0x{:08x}", metadata.entry_point_rva),
                    }],
                },
            );
        }
    }

    for range in &metadata.overlay {
        push_finding(
            report,
            Finding {
                id: "pe.overlay".into(),
                category: FindingCategory::Structure,
                severity: Severity::Informational,
                confidence: Confidence::High,
                summary:
                    "Trailing bytes outside headers, sections, and certificate table; often benign"
                        .into(),
                evidence: vec![Evidence {
                    offset: Some(range.offset),
                    length: Some(range.size),
                    detail: "Overlay range; no content classification or execution".into(),
                }],
            },
        );
    }

    if let Some(tls) = &metadata.tls {
        if !tls.callbacks.is_empty() {
            push_finding(
                report,
                Finding {
                    id: "pe.tls_callbacks".into(),
                    category: FindingCategory::Structure,
                    severity: Severity::Informational,
                    confidence: Confidence::High,
                    summary: "TLS callback addresses are present; callbacks also occur in benign software"
                        .into(),
                    evidence: vec![Evidence {
                        offset: metadata.directories.get(9).and_then(|entry| entry.file_offset),
                        length: metadata.directories.get(9).map(|entry| u64::from(entry.size)),
                        detail: format!(
                            "callbacks_va=0x{:x}; callback_count={}",
                            tls.callbacks_va,
                            tls.callbacks.len()
                        ),
                    }],
                },
            );
        }
    }

    import_findings(metadata, report);
}
