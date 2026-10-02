//! Bounded, portable observations about file bytes, never a malware verdict.
//!
//! Parsing is deliberately conservative and does not emulate the Windows
//! loader. A failed or limited PE parse preserves basic analysis and records
//! its status explicitly; it never becomes an assertion that the file is clean.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

mod capabilities;
mod findings;
mod indicators;
mod model;
mod pe;
mod strings;

pub use model::*;

const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Read a regular file once, with both metadata and actual-read size bounds.
///
/// The hash describes the bytes actually read, not an atomic filesystem
/// snapshot. Inputs larger than `MAX_FILE_BYTES` are rejected, not sampled.
pub fn analyze_file(path: &Path) -> Result<StaticReport> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Cannot inspect {}", path.display()))?;

    ensure!(
        metadata.is_file(),
        "Static analysis requires a regular file"
    );
    ensure!(
        metadata.len() <= MAX_FILE_BYTES as u64,
        "File exceeds the static-analysis byte limit"
    );

    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let opened_metadata = file.metadata().context("Cannot inspect opened file")?;

    ensure!(
        opened_metadata.is_file(),
        "Static analysis requires a regular file"
    );
    ensure!(
        opened_metadata.len() <= MAX_FILE_BYTES as u64,
        "Opened file exceeds the static-analysis byte limit"
    );

    /*
     * A second size check after a bounded read handles growth after metadata
     * inspection without allowing an unbounded allocation.
     */
    let mut bytes = Vec::new();

    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read file for static analysis")?;

    analyze_bytes(&bytes)
}

/// Analyze owned-by-caller bytes without executing or modifying them.
pub fn analyze_bytes(bytes: &[u8]) -> Result<StaticReport> {
    ensure!(
        bytes.len() <= MAX_FILE_BYTES,
        "Input exceeds the static-analysis byte limit"
    );

    let (strings, strings_truncated) = strings::extract(bytes);
    let mut report = StaticReport {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
        entropy: entropy(bytes),
        pe: None,
        strings,
        findings: Vec::new(),
        coverage: Coverage {
            pe_status: PeStatus::NotPe,
            string_scan_bytes: bytes.len().min(MAX_STRING_SCAN_BYTES) as u64,
            strings_truncated,
            findings_truncated: false,
            limits: AnalysisLimits::default(),
            limitations: [
                "Static observations are not a malware verdict; absent indicators do not establish safety.",
                "No execution, unpacking, decryption, disassembly, or external reputation lookup.",
                "The conservative PE decoder is not a Windows loader validator; DOS/NE/LE images are not decoded.",
                "PE metadata is omitted on malformed, unsupported, or parser-limited input; basic analysis remains available.",
                "Only regular imports and exports are decoded. Delay/bound imports, resources, relocations, debug data, and load configuration have directory metadata only.",
                "Ordinal imports remain unresolved. Import capabilities are name matches, not observed calls or resolved API identities.",
                "Certificate records are structural metadata only; signatures, certificate chains, and publisher trust are not verified.",
                "Strings scan a bounded prefix: ASCII first, then ASCII-range UTF-16LE at both alignments. Other encodings and non-ASCII UTF-16 are not decoded.",
                "URL extraction retains the first HTTP(S) candidate per retained string. URLs are not contacted; truncated or omitted strings can hide indicators.",
                "Obfuscation checks only complete retained strings beginning with a bare powershell/pwsh launcher, optional -NoProfile/-NonInteractive/-NoLogo switches, and -EncodedCommand/-enc followed by one plausible 8-256 character Base64 argument. Paths, quoting, shell composition, and other obfuscation syntax are not interpreted. Encoded content is not decoded or executed.",
                "Capability evidence retains at most eight matching imports per category. All findings are bounded.",
                "File reads are not an atomic filesystem snapshot.",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
    };

    if bytes.starts_with(b"MZ") || bytes.starts_with(b"PE\0\0") {
        match pe::parse(bytes) {
            Ok(metadata) => {
                report.coverage.pe_status = PeStatus::Parsed;
                findings::pe_findings(&metadata, &mut report);
                report.pe = Some(metadata);
            }
            Err(error) => {
                report.coverage.pe_status = error.status;

                let id = match error.status {
                    PeStatus::Limited => "pe.parser_limit",
                    PeStatus::Unsupported => "pe.unsupported",
                    _ => "pe.malformed",
                };

                push_finding(
                    &mut report,
                    Finding {
                        id: id.into(),
                        category: FindingCategory::Structure,
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        summary:
                            "PE candidate was not fully decoded; do not interpret this as clean"
                                .into(),
                        evidence: vec![Evidence {
                            offset: error.offset,
                            length: None,
                            detail: error.message.into(),
                        }],
                    },
                );
            }
        }
    }

    if bytes.starts_with(EICAR)
        && bytes.len() <= 128
        && bytes[EICAR.len()..]
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x1a))
    {
        push_finding(
            &mut report,
            Finding {
                id: "test.eicar".into(),
                category: FindingCategory::TestSignature,
                severity: Severity::Informational,
                confidence: Confidence::High,
                summary: "EICAR antivirus test signature, not real malware".into(),
                evidence: vec![Evidence {
                    offset: Some(0),
                    length: Some(EICAR.len() as u64),
                    detail: "Exact EICAR test content with only permitted trailing whitespace"
                        .into(),
                }],
            },
        );
    }

    indicators::url_findings(&mut report);
    findings::obfuscation_findings(&mut report);

    /*
     * Count and string bounds already cap in-memory data. This final boundary
     * additionally guarantees a hard bound on the machine-consumed JSON form.
     */
    ensure!(
        serde_json::to_vec(&report)
            .context("Cannot serialize static-analysis report")?
            .len()
            <= MAX_REPORT_BYTES,
        "Static-analysis report exceeds the serialized-output limit"
    );

    Ok(report)
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];

    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }

    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / bytes.len() as f64;

            -probability * probability.log2()
        })
        .sum()
}

fn push_finding(report: &mut StaticReport, finding: Finding) {
    if report.findings.len() == MAX_FINDINGS {
        report.coverage.findings_truncated = true;
    } else {
        report.findings.push(finding);
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/static_analysis/mod.rs"]
mod tests;
