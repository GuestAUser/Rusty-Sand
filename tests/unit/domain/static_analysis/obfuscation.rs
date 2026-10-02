use super::*;

const FINDING_ID: &str = "obfuscation.powershell_encoded_command";

#[test]
fn encoded_execution_syntax_preserves_ascii_and_utf16_evidence() {
    /*
     * The constant argument encodes the benign text Get-Date as UTF-16LE.
     * Tests only analyze bytes; no command is decoded or executed.
     */
    for command in [
        "powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA==",
        "PoWeRsHeLl.ExE -NoProfile -NonInteractive -ENC RwBlAHQALQBEAGEAdABlAA==",
        "pwsh -NoLogo -enc RwBlAHQALQBEAGEAdABlAA==",
        "pwsh.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA==",
    ] {
        for wide in [false, true] {
            let mut bytes = vec![0, 1, 0];
            let stride = if wide { 2 } else { 1 };

            if wide {
                for unit in command.encode_utf16() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
            } else {
                bytes.extend_from_slice(command.as_bytes());
            }

            bytes.extend_from_slice(&[0, 0]);

            let report = analyze_bytes(&bytes).unwrap();
            let matches: Vec<_> = report
                .findings
                .iter()
                .filter(|finding| finding.id == FINDING_ID)
                .collect();

            assert_eq!(matches.len(), 1);

            let finding = matches[0];

            assert_eq!(finding.category, FindingCategory::EmbeddedIndicator);
            assert_eq!(finding.severity, Severity::Low);
            assert_eq!(finding.confidence, Confidence::Low);
            assert_eq!(finding.evidence.len(), 1);
            assert_eq!(finding.evidence[0].offset, Some(3));
            assert_eq!(
                finding.evidence[0].length,
                Some((command.len() * stride) as u64)
            );
            assert_eq!(finding.evidence[0].detail, command);
            assert_eq!(report.coverage.pe_status, PeStatus::NotPe);
        }
    }
}

#[test]
fn ordinary_encoded_data_and_unencoded_administration_are_not_obfuscation_findings() {
    for text in [
        "RwBlAHQALQBEAGEAdABlAA==",
        "payload=RwBlAHQALQBEAGEAdABlAA==",
        "powershell.exe -Command Get-Date",
        "powershell.exe -NoProfile -File maintenance.ps1",
        "powershell.exe -Command Write-Output RwBlAHQALQBEAGEAdABlAA==",
        "powershell.exe -Command Write-Output -enc RwBlAHQALQBEAGEAdABlAA==",
        "echo powershell -enc RwBlAHQALQBEAGEAdABlAA==",
        "powershell.exe.config -enc RwBlAHQALQBEAGEAdABlAA==",
        "powershell -EncodedArguments RwBlAHQALQBEAGEAdABlAA==",
        "powershell -enc",
        "powershell -enc AAAA",
        "powershell -enc AAA$AAAA",
        "powershell -enc AA=AAAA=",
        "powershell -enc AAAAA===",
        "powershell -enc AAAAAAA=",
        "powershell -enc RwBlAHQALQBEAGEAdABlAA== trailing",
    ] {
        let report = analyze_bytes(text.as_bytes()).unwrap();

        assert!(!has_id(&report, FINDING_ID), "{text}");
    }
}

#[test]
fn encoded_argument_and_retained_string_lengths_are_bounded() {
    let at_limit = format!("powershell -enc {}", "A".repeat(256));
    let over_limit = format!("powershell -enc {}", "A".repeat(260));

    assert!(has_id(
        &analyze_bytes(at_limit.as_bytes()).unwrap(),
        FINDING_ID
    ));
    assert!(!has_id(
        &analyze_bytes(over_limit.as_bytes()).unwrap(),
        FINDING_ID
    ));

    let mut truncated = b"powershell -enc RwBlAHQALQBEAGEAdABlAA==".to_vec();

    truncated.resize(MAX_STRING_CHARS + 1, b' ');

    let report = analyze_bytes(&truncated).unwrap();

    assert!(report.coverage.strings_truncated);
    assert!(!has_id(&report, FINDING_ID));
}

#[test]
fn encoded_execution_does_not_use_omitted_or_scan_truncated_strings() {
    let command = b"powershell -enc RwBlAHQALQBEAGEAdABlAA==";
    let mut omitted = b"data\0".repeat(MAX_STRINGS);

    omitted.extend_from_slice(command);

    let report = analyze_bytes(&omitted).unwrap();

    assert!(report.coverage.strings_truncated);
    assert!(!has_id(&report, FINDING_ID));

    let mut outside = vec![0; MAX_STRING_SCAN_BYTES];

    outside.extend_from_slice(command);

    let report = analyze_bytes(&outside).unwrap();

    assert!(report.coverage.strings_truncated);
    assert!(!has_id(&report, FINDING_ID));

    let mut partial = vec![0; MAX_STRING_SCAN_BYTES - command.len()];

    partial.extend_from_slice(command);
    partial.push(b'!');

    let report = analyze_bytes(&partial).unwrap();

    assert!(report.coverage.strings_truncated);
    assert!(!has_id(&report, FINDING_ID));
}

#[test]
fn encoded_execution_findings_share_the_report_output_bound() {
    let bytes = b"powershell -enc RwBlAHQALQBEAGEAdABlAA==\0".repeat(MAX_FINDINGS + 10);
    let report = analyze_bytes(&bytes).unwrap();

    assert_eq!(report.findings.len(), MAX_FINDINGS);
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.id == FINDING_ID));
    assert!(report.coverage.findings_truncated);
    assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_REPORT_BYTES);
}
