use anyhow::Result;
use rusty_sand::report::analysis::{AnalysisReport, Evidence};
use rusty_sand::ui::{self, Panel, Tone};

pub(super) fn analysis(report: &AnalysisReport) -> Result<()> {
    let mut fields = vec![
        ("Target".into(), report.executable.clone()),
        ("Mode".into(), format!("{:?}", report.mode)),
        ("Execution".into(), format!("{:?}", report.execution)),
    ];
    let mut notes = report.limitations.clone();

    match &report.static_analysis {
        Evidence::Collected { report } => {
            fields.extend([
                ("SHA-256".into(), report.sha256.clone()),
                ("Bytes".into(), report.size_bytes.to_string()),
                ("Entropy".into(), format!("{:.4}", report.entropy)),
                (
                    "PE coverage".into(),
                    format!("{:?}", report.coverage.pe_status),
                ),
                (
                    "Static indicators".into(),
                    report.findings.len().to_string(),
                ),
                (
                    "String scan".into(),
                    format!(
                        "{} bytes; strings truncated: {}; findings truncated: {}",
                        report.coverage.string_scan_bytes,
                        report.coverage.strings_truncated,
                        report.coverage.findings_truncated,
                    ),
                ),
            ]);
            notes.extend(report.coverage.limitations.iter().cloned());
            notes.extend(report.findings.iter().map(|finding| {
                format!(
                    "{} [{:?}, confidence {:?}]: {}",
                    finding.id, finding.severity, finding.confidence, finding.summary,
                )
            }));
        }
        Evidence::Failed { error } => {
            fields.push(("Static inspection failed".into(), error.clone()));
        }
        Evidence::Unavailable { reason } => {
            fields.push(("Static inspection unavailable".into(), reason.clone()));
        }
    }

    match &report.behavior {
        Evidence::Collected { report } => {
            fields.push((
                "Behavior coverage".into(),
                format!(
                    "{} input events; {} inspected; {} omitted; {} oversized",
                    report.coverage.input_events,
                    report.coverage.inspected_events,
                    report.coverage.omitted_events,
                    report.coverage.oversized_events,
                ),
            ));
            fields.push((
                "Behavior indicators".into(),
                report.findings.len().to_string(),
            ));
            notes.extend(report.coverage.limitations.iter().cloned());
            notes.extend(report.findings.iter().map(|finding| {
                let indices: Vec<_> = finding
                    .evidence
                    .iter()
                    .map(|evidence| evidence.event_index)
                    .collect();

                format!(
                    "{:?} [{:?}, {:?}, confidence {:?}], events {:?}: {}",
                    finding.rule,
                    finding.status,
                    finding.severity,
                    finding.confidence,
                    indices,
                    finding.summary,
                )
            }));
        }
        Evidence::Failed { error } => {
            fields.push(("Behavior assessment failed".into(), error.clone()));
        }
        Evidence::Unavailable { reason } => {
            fields.push(("Behavior assessment unavailable".into(), reason.clone()));
        }
    }

    ui::terminal().panel(&Panel {
        title: "Analysis evidence / bounded coverage".into(),
        tone: Tone::Warning,
        fields,
        notes,
    })?;

    Ok(())
}

#[cfg(windows)]
pub(super) fn debug(report: &rusty_sand::debugger::DebugReport) -> Result<()> {
    ui::terminal().panel(&Panel {
        title: "Native debugger evidence".into(),
        tone: Tone::Warning,
        fields: vec![
            ("Target PID".into(), report.target_pid.to_string()),
            ("Exit".into(), format!("{:?}", report.exit)),
            ("Timed out".into(), report.timed_out.to_string()),
            ("Cancelled".into(), report.cancelled.to_string()),
            ("Retained events".into(), report.events.len().to_string()),
            ("Coverage counters".into(), format!("{:?}", report.counters)),
        ],
        notes: report.limitations.clone(),
    })?;

    Ok(())
}
