//! Findings, bounded evidence and analyst-facing rule explanations.

use super::schema::{
    ActionStatus, BehaviorCategory, Confidence, Evidence, Finding, RuleId, Severity,
    MAX_EVIDENCE_PER_FINDING,
};
use crate::report::Event;
use std::collections::BTreeSet;

pub(super) fn finding(
    events: &[Event],
    rule: RuleId,
    status: ActionStatus,
    indices: BTreeSet<usize>,
) -> Finding {
    let (category, severity, confidence, summary) = rule.metadata();
    let matched_events = indices.len();
    let evidence: Vec<_> = indices
        .into_iter()
        .take(MAX_EVIDENCE_PER_FINDING)
        .map(|event_index| Evidence {
            event_index,
            timestamp: events[event_index].timestamp,
            event_type: events[event_index].event_type.clone(),
            status,
        })
        .collect();
    let omitted_evidence = matched_events - evidence.len();

    Finding {
        rule,
        category,
        severity,
        confidence,
        status,
        summary: summary.to_owned(),
        matched_events,
        evidence,
        omitted_evidence,
    }
}

impl RuleId {
    fn metadata(self) -> (BehaviorCategory, Severity, Confidence, &'static str) {
        use BehaviorCategory as Category;

        match self {
            Self::RansomwareLikeFileNames => (
                Category::RansomwareLike,
                Severity::High,
                Confidence::Low,
                "Multiple distinct paths use encryption-associated suffixes. \
                 This count-based indicator does not establish encryption; \
                 legitimate encrypted files and test fixtures can match.",
            ),
            Self::RansomNoteName => (
                Category::RansomwareLike,
                Severity::Medium,
                Confidence::Low,
                "A file name resembles a decryption note. Its contents and \
                 purpose are unknown, and a name alone is not a malware verdict.",
            ),
            Self::StartupRegistry => (
                Category::Persistence,
                Severity::Medium,
                Confidence::Low,
                "Activity involves a startup or service registry location. \
                 It does not establish an installed persistence mechanism; \
                 legitimate installers and unattributed changes can match.",
            ),
            Self::StartupFolder => (
                Category::Persistence,
                Severity::Medium,
                Confidence::Low,
                "An executable, script or shortcut path is in a Startup folder. \
                 Registration, future execution and malicious intent are unproven.",
            ),
            Self::CredentialStoreRead => (
                Category::CredentialAccess,
                Severity::Medium,
                Confidence::Low,
                "A read request names a credential-associated store. \
                 No returned data or credential extraction is established; \
                 browsers, backups and security tools may legitimately read it.",
            ),
            Self::RemoteMemoryWrite => (
                Category::ProcessInjection,
                Severity::Medium,
                Confidence::Low,
                "A nonempty memory-write request names another PID. \
                 Debuggers and instrumentation also do this; neither the write \
                 nor execution in the target is established.",
            ),
            Self::RemoteThread => (
                Category::ProcessInjection,
                Severity::Medium,
                Confidence::Low,
                "A remote-thread request names another PID. \
                 The requested thread is not an observed running thread, \
                 and legitimate instrumentation may use this API.",
            ),
            Self::WriteThenRemoteThread => (
                Category::ProcessInjection,
                Severity::High,
                Confidence::Medium,
                "A memory-write request precedes a remote-thread request with \
                 matching logged caller and target PIDs within the bounded \
                 order/time window. This is an injection-like request sequence, \
                 not proof that either API succeeded or that their addresses \
                 refer to the same payload.",
            ),
            Self::SuspiciousExecution => (
                Category::SuspiciousExecution,
                Severity::Medium,
                Confidence::Low,
                "A process request combines a script host or LOLBin with \
                 encoded-command, remote-content or inline-script indicators. \
                 Administrative use is possible; execution is not established.",
            ),
            Self::DefenseImpairment => (
                Category::DefenseImpairment,
                Severity::Medium,
                Confidence::Low,
                "A request involves recovery deletion, log clearing or a \
                 security-control setting. Command success is unknown. \
                 Registry value data is absent, so a setting change could \
                 strengthen rather than disable protection.",
            ),
            Self::NetworkActivity => (
                Category::NetworkActivity,
                Severity::Informational,
                Confidence::High,
                "Network-related telemetry is present. A request, denial, \
                 DNS query, endpoint or bound socket is not by itself malicious \
                 and does not establish transferred data.",
            ),
        }
    }
}
