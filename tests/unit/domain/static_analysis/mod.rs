use super::*;

mod obfuscation;

const OPTIONAL: usize = 0x98;
const RAW: usize = 0x200;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_name(bytes: &mut [u8], offset: usize, name: &str) {
    bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    bytes[offset + name.len()] = 0;
}

fn directory_table(is_64: bool) -> usize {
    OPTIONAL + if is_64 { 112 } else { 96 }
}

fn section_table(is_64: bool) -> usize {
    OPTIONAL + if is_64 { 240 } else { 224 }
}

fn set_directory(bytes: &mut [u8], is_64: bool, index: usize, address: u32, size: u32) {
    let offset = directory_table(is_64) + index * 8;

    put_u32(bytes, offset, address);
    put_u32(bytes, offset + 4, size);
}

fn image_base(is_64: bool) -> u64 {
    if is_64 {
        0x0001_4000_0000
    } else {
        0x0040_0000
    }
}

fn put_pointer(bytes: &mut [u8], offset: usize, value: u64, is_64: bool) {
    if is_64 {
        put_u64(bytes, offset, value);
    } else {
        put_u32(bytes, offset, value as u32);
    }
}

fn fixture(is_64: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x1200];

    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, if is_64 { 0x8664 } else { 0x14c });
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x88, 123);
    put_u16(&mut bytes, 0x94, if is_64 { 240 } else { 224 });
    put_u16(&mut bytes, 0x96, 0x22);
    put_u16(&mut bytes, OPTIONAL, if is_64 { 0x20b } else { 0x10b });
    put_u32(&mut bytes, OPTIONAL + 16, 0x1000);

    if is_64 {
        put_u64(&mut bytes, OPTIONAL + 24, image_base(true));
    } else {
        put_u32(&mut bytes, OPTIONAL + 28, image_base(false) as u32);
    }

    put_u32(&mut bytes, OPTIONAL + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL + 36, 0x200);
    put_u32(&mut bytes, OPTIONAL + 56, 0x2000);
    put_u32(&mut bytes, OPTIONAL + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL + 68, 3);
    put_u16(&mut bytes, OPTIONAL + 70, 0x140);
    put_u32(&mut bytes, directory_table(is_64) - 4, 16);

    let section = section_table(is_64);

    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 0x1000);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x1000);
    put_u32(&mut bytes, section + 20, RAW as u32);
    put_u32(&mut bytes, section + 36, 0x6000_0020);

    bytes
}

fn add_imports(bytes: &mut [u8], is_64: bool, api: &str) {
    set_directory(bytes, is_64, 1, 0x1100, 40);
    put_u32(bytes, 0x300, 0x1200);
    put_u32(bytes, 0x30c, 0x1180);
    put_u32(bytes, 0x310, 0x1200);
    put_name(bytes, 0x380, "KERNEL32.dll");

    let width = if is_64 { 8 } else { 4 };
    let ordinal_flag = 1u64 << (width * 8 - 1);

    put_pointer(bytes, 0x400, 0x1300, is_64);
    put_pointer(bytes, 0x400 + width, ordinal_flag | 7, is_64);
    put_u16(bytes, 0x500, 19);
    put_name(bytes, 0x502, api);
}

fn add_exports(bytes: &mut [u8], is_64: bool) {
    set_directory(bytes, is_64, 0, 0x1400, 0x100);
    put_u32(bytes, 0x610, 1);
    put_u32(bytes, 0x614, 2);
    put_u32(bytes, 0x618, 1);
    put_u32(bytes, 0x61c, 0x1440);
    put_u32(bytes, 0x620, 0x1450);
    put_u32(bytes, 0x624, 0x1460);
    put_u32(bytes, 0x640, 0x1000);
    put_u32(bytes, 0x644, 0x1480);
    put_u32(bytes, 0x650, 0x1470);
    put_u16(bytes, 0x660, 0);
    put_name(bytes, 0x670, "DemoExport");
    put_name(bytes, 0x680, "KERNEL32.Sleep");
}

fn add_tls(bytes: &mut [u8], is_64: bool) {
    let width = if is_64 { 8 } else { 4 };
    let base = image_base(is_64);

    set_directory(bytes, is_64, 9, 0x1500, (width * 4 + 8) as u32);
    put_pointer(bytes, 0x700, base + 0x1600, is_64);
    put_pointer(bytes, 0x700 + width, base + 0x1604, is_64);
    put_pointer(bytes, 0x700 + width * 2, base + 0x1590, is_64);
    put_pointer(bytes, 0x700 + width * 3, base + 0x1580, is_64);
    put_pointer(bytes, 0x780, base + 0x1000, is_64);
}

fn has_id(report: &StaticReport, id: &str) -> bool {
    report.findings.iter().any(|finding| finding.id == id)
}

fn assert_status(bytes: &[u8], status: PeStatus) {
    let report = analyze_bytes(bytes).unwrap();

    assert_eq!(report.coverage.pe_status, status);
    assert!(report.pe.is_none());
    assert_eq!(report.size_bytes, bytes.len() as u64);
    assert_eq!(report.sha256.len(), 64);

    let id = match status {
        PeStatus::Malformed => "pe.malformed",
        PeStatus::Limited => "pe.parser_limit",
        PeStatus::Unsupported => "pe.unsupported",
        _ => panic!("Expected an unsuccessful PE parse status"),
    };

    assert!(has_id(&report, id));
}

#[test]
fn sha256_matches_known_vectors() {
    for (bytes, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        assert_eq!(analyze_bytes(bytes).unwrap().sha256, expected);
    }

    let million_a = vec![b'a'; 1_000_000];

    assert_eq!(
        analyze_bytes(&million_a).unwrap().sha256,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn entropy_is_measured_without_a_malware_verdict() {
    assert_eq!(analyze_bytes(b"").unwrap().entropy, 0.0);
    assert_eq!(analyze_bytes(&[42; 4096]).unwrap().entropy, 0.0);

    let all_values: Vec<u8> = (0..4096).map(|index| (index % 256) as u8).collect();
    let report = analyze_bytes(&all_values).unwrap();

    assert!((report.entropy - 8.0).abs() < 1e-12);
    assert_eq!(report.coverage.pe_status, PeStatus::NotPe);
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.category == FindingCategory::Packing));
    assert!(serde_json::to_value(&report)
        .unwrap()
        .get("verdict")
        .is_none());
}

#[test]
fn valid_pe32_and_pe32_plus_have_explicit_metadata() {
    for is_64 in [false, true] {
        let report = analyze_bytes(&fixture(is_64)).unwrap();
        let pe = report.pe.as_ref().unwrap();

        assert_eq!(report.coverage.pe_status, PeStatus::Parsed);
        assert_eq!(
            pe.kind,
            if is_64 {
                PeKind::Pe32Plus
            } else {
                PeKind::Pe32
            }
        );
        assert_eq!(pe.image_base, image_base(is_64));
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.entry_point_offset, Some(0x200));
        assert_eq!(pe.timestamp, 123);
        assert_eq!(pe.dll_characteristics, 0x140);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].entropy, Some(0.0));
        assert!(pe.sections[0].readable);
        assert!(pe.sections[0].executable);
        assert!(!pe.sections[0].writable);
        assert_eq!(pe.directories.len(), 16);
        assert!(pe.overlay.is_empty());
        assert!(report.findings.is_empty());
    }
}

#[test]
fn named_and_ordinal_imports_preserve_offsets_and_hint() {
    for is_64 in [false, true] {
        let mut bytes = fixture(is_64);

        add_imports(&mut bytes, is_64, "WriteProcessMemory");

        let report = analyze_bytes(&bytes).unwrap();
        let imports = &report.pe.as_ref().unwrap().imports;

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].library, "KERNEL32.dll");
        assert_eq!(imports[0].name.as_deref(), Some("WriteProcessMemory"));
        assert_eq!(imports[0].hint, Some(19));
        assert_eq!(imports[0].ordinal, None);
        assert_eq!(imports[0].thunk_offset, 0x400);
        assert_eq!(imports[1].ordinal, Some(7));
        assert_eq!(imports[1].name, None);
        assert_eq!(imports[1].hint, None);
        assert!(has_id(&report, "capability.injection"));

        put_u32(&mut bytes, 0x300, 0);

        let fallback = analyze_bytes(&bytes).unwrap();

        assert_eq!(fallback.pe.unwrap().imports, *imports);
    }
}

#[test]
fn capability_categories_match_exact_names_not_substrings() {
    for (name, id) in [
        ("CredReadW", "capability.credentials"),
        ("CreateServiceW", "capability.persistence"),
        ("WinHttpConnect", "capability.networking"),
        ("IsDebuggerPresent", "capability.anti_debug"),
    ] {
        let mut bytes = fixture(true);

        add_imports(&mut bytes, true, name);

        assert!(has_id(&analyze_bytes(&bytes).unwrap(), id));
    }

    let mut bytes = fixture(true);

    add_imports(&mut bytes, true, "NotWriteProcessMemory");

    assert!(!has_id(
        &analyze_bytes(&bytes).unwrap(),
        "capability.injection"
    ));
}

#[test]
fn exports_and_tls_are_decoded_for_both_pointer_widths() {
    for is_64 in [false, true] {
        let mut bytes = fixture(is_64);

        add_exports(&mut bytes, is_64);
        add_tls(&mut bytes, is_64);

        let report = analyze_bytes(&bytes).unwrap();
        let pe = report.pe.as_ref().unwrap();

        assert_eq!(pe.exports.len(), 2);
        assert_eq!(pe.exports[0].ordinal, 1);
        assert_eq!(pe.exports[0].names, ["DemoExport"]);
        assert_eq!(pe.exports[0].file_offset, Some(0x200));
        assert_eq!(pe.exports[1].forwarder.as_deref(), Some("KERNEL32.Sleep"));
        assert_eq!(
            pe.tls.as_ref().unwrap().callbacks,
            [image_base(is_64) + 0x1000]
        );
        assert!(has_id(&report, "pe.tls_callbacks"));
    }
}

#[test]
fn certificate_metadata_is_not_overlay_or_signature_validation() {
    let mut bytes = fixture(true);

    bytes.extend_from_slice(b"before!!");

    let certificate_offset = bytes.len();

    bytes.resize(certificate_offset + 16, 0);
    put_u32(&mut bytes, certificate_offset, 12);
    put_u16(&mut bytes, certificate_offset + 4, 0x200);
    put_u16(&mut bytes, certificate_offset + 6, 2);
    bytes.extend_from_slice(b"after!!!");
    set_directory(&mut bytes, true, 4, certificate_offset as u32, 16);

    let report = analyze_bytes(&bytes).unwrap();
    let pe = report.pe.unwrap();
    let security = pe.security.unwrap();

    assert_eq!(security.offset, 0x1208);
    assert_eq!(security.certificates.len(), 1);
    assert_eq!(security.certificates[0].length, 12);
    assert_eq!(security.certificates[0].revision, 0x200);
    assert_eq!(security.certificates[0].certificate_type, 2);
    assert!(pe.directories[4].is_file_offset);
    assert_eq!(
        pe.overlay,
        [
            FileRange {
                offset: 0x1200,
                size: 8
            },
            FileRange {
                offset: 0x1218,
                size: 8
            },
        ]
    );

    put_u32(&mut bytes, certificate_offset, 0);
    assert_status(&bytes, PeStatus::Malformed);
}

#[test]
fn packing_markers_and_entropy_have_false_positive_controls() {
    for marker in ["UPX1", ".aspack", ".vmp0", "MPRESS1"] {
        let mut bytes = fixture(false);
        let section = section_table(false);

        bytes[section..section + 8].fill(0);
        bytes[section..section + marker.len()].copy_from_slice(marker.as_bytes());

        let report = analyze_bytes(&bytes).unwrap();
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.id == "packing.section_marker")
            .unwrap();

        assert_eq!(finding.category, FindingCategory::Packing);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.evidence[0].offset, Some(section as u64));
    }

    for marker in [".text", ".upxtra", "NOTUPX1", ".adata"] {
        let mut bytes = fixture(false);
        let section = section_table(false);

        bytes[section..section + 8].fill(0);
        bytes[section..section + marker.len()].copy_from_slice(marker.as_bytes());

        assert!(!has_id(
            &analyze_bytes(&bytes).unwrap(),
            "packing.section_marker"
        ));
    }

    let mut bytes = fixture(true);

    for (index, byte) in bytes[RAW..].iter_mut().enumerate() {
        *byte = (index % 256) as u8;
    }

    let report = analyze_bytes(&bytes).unwrap();

    assert!(has_id(&report, "packing.high_entropy_executable"));
    assert_eq!(report.pe.unwrap().sections[0].entropy, Some(8.0));

    put_u32(&mut bytes, section_table(true) + 36, 0x4000_0040);

    assert!(!has_id(
        &analyze_bytes(&bytes).unwrap(),
        "packing.high_entropy_executable"
    ));
}

#[test]
fn writable_executable_sections_and_unbacked_entry_points_are_explicit() {
    let mut bytes = fixture(true);

    put_u32(&mut bytes, section_table(true) + 36, 0xe000_0020);

    assert!(has_id(
        &analyze_bytes(&bytes).unwrap(),
        "pe.section_writable_executable"
    ));

    put_u32(&mut bytes, OPTIONAL + 16, 0xffff_ffff);

    let report = analyze_bytes(&bytes).unwrap();

    assert_eq!(report.coverage.pe_status, PeStatus::Parsed);
    assert_eq!(report.pe.as_ref().unwrap().entry_point_offset, None);
    assert!(has_id(&report, "pe.entry_point_anomaly"));
}

#[test]
fn malformed_and_overflowing_ranges_never_become_clean_reports() {
    for bytes in [b"MZ".as_slice(), b"PE\0\0".as_slice()] {
        assert_status(bytes, PeStatus::Malformed);
    }

    for (offset, value) in [
        (0x3c, u32::MAX),
        (section_table(true) + 20, u32::MAX),
        (section_table(true) + 12, u32::MAX),
        (OPTIONAL + 60, u32::MAX),
    ] {
        let mut bytes = fixture(true);

        put_u32(&mut bytes, offset, value);
        assert_status(&bytes, PeStatus::Malformed);
    }

    let mut bytes = fixture(true);

    set_directory(&mut bytes, true, 1, u32::MAX - 4, 40);
    assert_status(&bytes, PeStatus::Malformed);

    let bytes = fixture(true);

    for end in [2, 63, 64, 127, 128, 150, 200, 400, 511, 512, 4096, 4607] {
        assert_status(&bytes[..end], PeStatus::Malformed);
    }
}

#[test]
fn overlapping_sections_and_virtual_only_directory_bytes_are_rejected() {
    let mut bytes = fixture(false);
    let section = section_table(false);
    let first = bytes[section..section + 40].to_vec();

    put_u16(&mut bytes, 0x86, 2);
    bytes[section + 40..section + 80].copy_from_slice(&first);
    assert_status(&bytes, PeStatus::Malformed);

    let mut bytes = fixture(false);

    put_u32(&mut bytes, section_table(false) + 16, 0x200);
    set_directory(&mut bytes, false, 1, 0x1400, 40);
    assert_status(&bytes, PeStatus::Malformed);
}

#[test]
fn optional_header_and_parser_count_limits_are_distinct() {
    let mut bytes = fixture(true);

    put_u16(&mut bytes, OPTIONAL, 0x107);
    assert_status(&bytes, PeStatus::Unsupported);

    let mut bytes = fixture(true);

    put_u16(&mut bytes, 0x86, (MAX_SECTIONS + 1) as u16);
    assert_status(&bytes, PeStatus::Limited);

    let mut bytes = fixture(true);

    put_u32(&mut bytes, directory_table(true) - 4, 17);
    assert_status(&bytes, PeStatus::Limited);

    let mut bytes = fixture(true);

    add_exports(&mut bytes, true);
    put_u32(&mut bytes, 0x614, u32::MAX);
    assert_status(&bytes, PeStatus::Limited);
}

#[test]
fn bad_import_ordinal_bits_and_unterminated_descriptors_are_rejected() {
    for is_64 in [false, true] {
        let mut bytes = fixture(is_64);

        add_imports(&mut bytes, is_64, "WriteProcessMemory");

        let width = if is_64 { 8 } else { 4 };

        put_pointer(
            &mut bytes,
            0x400 + width,
            (1u64 << (width * 8 - 1)) | 0x10007,
            is_64,
        );
        assert_status(&bytes, PeStatus::Malformed);

        let mut bytes = fixture(is_64);

        add_imports(&mut bytes, is_64, "WriteProcessMemory");
        set_directory(&mut bytes, is_64, 1, 0x1100, 20);
        assert_status(&bytes, PeStatus::Malformed);
    }
}

#[test]
fn import_and_tls_counts_are_bounded_before_large_outputs() {
    let mut bytes = fixture(true);

    add_imports(&mut bytes, true, "WriteProcessMemory");
    bytes.resize(0x9000, 0);
    put_u32(&mut bytes, section_table(true) + 8, 0x8e00);
    put_u32(&mut bytes, section_table(true) + 16, 0x8e00);
    put_u32(&mut bytes, OPTIONAL + 56, 0xa000);

    for index in 0..=MAX_IMPORTS {
        put_u64(&mut bytes, 0x400 + index * 8, (1u64 << 63) | 7);
    }

    assert_status(&bytes, PeStatus::Limited);

    let mut bytes = fixture(true);

    add_tls(&mut bytes, true);

    for index in 0..=MAX_TLS_CALLBACKS {
        put_u64(&mut bytes, 0x780 + index * 8, image_base(true) + 0x1000);
    }

    assert_status(&bytes, PeStatus::Limited);
}

#[test]
fn export_name_ordinals_and_forwarder_bounds_are_checked() {
    let mut bytes = fixture(true);

    add_exports(&mut bytes, true);
    put_u16(&mut bytes, 0x660, 2);
    assert_status(&bytes, PeStatus::Malformed);

    let mut bytes = fixture(true);

    add_exports(&mut bytes, true);
    put_u32(&mut bytes, 0x644, 0x14fe);
    put_name(&mut bytes, 0x6fe, "outside");
    assert_status(&bytes, PeStatus::Malformed);
}

#[test]
fn strings_keep_ascii_and_odd_aligned_utf16_offsets() {
    let bytes = b"\0hello\0";
    let report = analyze_bytes(bytes).unwrap();
    let ascii = report
        .strings
        .iter()
        .find(|string| string.encoding == StringEncoding::Ascii)
        .unwrap();

    assert_eq!(ascii.offset, 1);
    assert_eq!(ascii.byte_length, 5);
    assert_eq!(ascii.value, "hello");

    let mut bytes = vec![1];

    for unit in "https://example.invalid/path".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    bytes.extend_from_slice(&[0, 0]);

    let report = analyze_bytes(&bytes).unwrap();
    let wide = report
        .strings
        .iter()
        .find(|string| string.encoding == StringEncoding::Utf16Le)
        .unwrap();
    let url = report
        .findings
        .iter()
        .find(|finding| finding.id == "indicator.embedded_url")
        .unwrap();

    assert_eq!(wide.offset, 1);
    assert_eq!(wide.value, "https://example.invalid/path");
    assert_eq!(url.evidence[0].offset, Some(1));
    assert_eq!(url.evidence[0].length, Some(wide.byte_length));
}

#[test]
fn string_length_count_and_scan_bounds_are_visible() {
    let bytes = vec![b'A'; MAX_STRING_CHARS + 20];
    let report = analyze_bytes(&bytes).unwrap();

    assert_eq!(report.strings.len(), 1);
    assert_eq!(report.strings[0].value.len(), MAX_STRING_CHARS);
    assert_eq!(report.strings[0].byte_length, bytes.len() as u64);
    assert!(report.strings[0].truncated);
    assert!(report.coverage.strings_truncated);

    let report = analyze_bytes(&b"abcd\0".repeat(MAX_STRINGS + 1)).unwrap();

    assert_eq!(report.strings.len(), MAX_STRINGS);
    assert!(report.coverage.strings_truncated);

    let mut bytes = vec![0; MAX_STRING_SCAN_BYTES];

    bytes.extend_from_slice(b"https://outside.invalid");

    let report = analyze_bytes(&bytes).unwrap();

    assert_eq!(
        report.coverage.string_scan_bytes,
        MAX_STRING_SCAN_BYTES as u64
    );
    assert!(report.coverage.strings_truncated);
    assert!(!has_id(&report, "indicator.embedded_url"));
}

#[test]
fn findings_and_serialized_output_are_bounded() {
    let bytes = b"https://example.invalid\0".repeat(MAX_FINDINGS + 10);
    let report = analyze_bytes(&bytes).unwrap();

    assert_eq!(report.findings.len(), MAX_FINDINGS);
    assert!(report.coverage.findings_truncated);
    assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_REPORT_BYTES);
}

#[test]
fn eicar_is_only_an_exact_test_signature() {
    let report = analyze_bytes(EICAR).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id == "test.eicar")
        .unwrap();

    assert_eq!(finding.category, FindingCategory::TestSignature);
    assert_eq!(finding.severity, Severity::Informational);
    assert_eq!(finding.evidence[0].offset, Some(0));
    assert_eq!(finding.evidence[0].length, Some(68));

    let mut padded = EICAR.to_vec();

    padded.extend_from_slice(b" \t\r\n\x1a");
    assert!(has_id(&analyze_bytes(&padded).unwrap(), "test.eicar"));

    let mut embedded = b"prefix ".to_vec();

    embedded.extend_from_slice(EICAR);
    assert!(!has_id(&analyze_bytes(&embedded).unwrap(), "test.eicar"));

    let mut suffix = EICAR.to_vec();

    suffix.push(b'X');
    assert!(!has_id(&analyze_bytes(&suffix).unwrap(), "test.eicar"));

    padded.resize(129, b' ');
    assert!(!has_id(&analyze_bytes(&padded).unwrap(), "test.eicar"));
}

#[test]
fn file_surface_matches_bytes_and_report_round_trips() {
    use std::io::Write;

    let bytes = fixture(true);
    let mut file = tempfile::NamedTempFile::new().unwrap();

    file.write_all(&bytes).unwrap();
    file.flush().unwrap();

    let from_file = analyze_file(file.path()).unwrap();
    let from_bytes = analyze_bytes(&bytes).unwrap();

    assert_eq!(from_file, from_bytes);

    let serialized = serde_json::to_vec(&from_file).unwrap();
    let restored: StaticReport = serde_json::from_slice(&serialized).unwrap();

    assert_eq!(restored, from_file);
    assert_eq!(restored.coverage.limits, AnalysisLimits::default());
}

#[test]
fn oversized_inputs_and_non_files_return_errors() {
    let bytes = vec![0; MAX_FILE_BYTES + 1];

    assert!(analyze_bytes(&bytes).is_err());

    let file = tempfile::NamedTempFile::new().unwrap();

    file.as_file().set_len(MAX_FILE_BYTES as u64 + 1).unwrap();
    assert!(analyze_file(file.path()).is_err());

    let directory = tempfile::tempdir().unwrap();

    assert!(analyze_file(directory.path()).is_err());
    assert!(analyze_file(&directory.path().join("absent")).is_err());
}

#[test]
fn deterministic_header_mutations_return_reports_without_panics() {
    let original = fixture(true);
    let mut state = 0x1357_2468u32;

    for index in 0..256 {
        let mut bytes = original.clone();

        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;

        let offset = 2 + (index * 17 % 510);

        bytes[offset] = state as u8;

        let report = analyze_bytes(&bytes).unwrap();

        assert_eq!(report.size_bytes, bytes.len() as u64);
        assert!(report.entropy.is_finite());
        assert!(report.findings.len() <= MAX_FINDINGS);

        if report.coverage.pe_status != PeStatus::Parsed {
            assert!(report.pe.is_none());
            assert!(report.findings.iter().any(|finding| {
                matches!(
                    finding.id.as_str(),
                    "pe.malformed" | "pe.parser_limit" | "pe.unsupported"
                )
            }));
        }
    }
}
