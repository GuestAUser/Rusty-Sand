//! Coverage initialization and the limits of the supplied telemetry.

use super::schema::{
    Coverage, MAX_CORRELATION_EVENT_GAP, MAX_CORRELATION_SECONDS, MAX_DETAIL_BYTES, MAX_EVENTS,
    MAX_EVIDENCE_PER_FINDING, RANSOMWARE_PATH_THRESHOLD,
};

impl Coverage {
    pub(super) fn for_events(input_events: usize) -> Self {
        let inspected_events = input_events.min(MAX_EVENTS);

        Self {
            input_events,
            inspected_events,
            omitted_events: input_events - inspected_events,
            duplicate_events: 0,
            oversized_events: 0,
            unclassified_denial_records: 0,
            uncorrelatable_injection_events: 0,
            max_events: MAX_EVENTS,
            max_detail_bytes: MAX_DETAIL_BYTES,
            max_evidence_per_finding: MAX_EVIDENCE_PER_FINDING,
            correlation_event_gap: MAX_CORRELATION_EVENT_GAP,
            correlation_window_seconds: MAX_CORRELATION_SECONDS,
            ransomware_distinct_path_threshold: RANSOMWARE_PATH_THRESHOLD,
            limitations: [
                "Indicators are analyst leads, not verdicts. Legitimate administration, \
                 backups, security tools and ordinary applications can produce them.",
                "Allowed hook requests remain attempted. Denied requests are not \
                 completed actions. Observed means only the event's stated observation.",
                "Filesystem and registry observations do not identify the writer. \
                 Registry notifications do not identify the value or operation. \
                 No process attribution is inferred from nearby events.",
                "Network records may describe requests, DNS queries, TCP states or \
                 UDP bindings; they do not prove traffic, successful connections, \
                 command-and-control or exfiltration.",
                "Only memory-write then remote-thread requests with explicit matching \
                 caller and target PIDs are correlated. Both must be non-denied, in \
                 input order and within the stated event and timestamp bounds. \
                 PID lifetime, payload execution and API success are not established.",
                "Process snapshots lack command lines. Execution rules inspect \
                 intercepted process requests only. Registry value data, file \
                 contents, credential extraction and memory payloads are unavailable.",
                "Matching uses bounded ASCII-case-insensitive descriptive text, not \
                 canonical paths or a Windows command-line interpreter. Obfuscation, \
                 unresolved handles, alternate spellings and omitted data reduce coverage.",
                "The ransomware threshold counts distinct suspicious-suffix paths \
                 separately per action status across the inspected prefix; it is not \
                 a rate, entropy measurement or proof of encryption.",
                "Exact duplicate records are removed, but requests and observations \
                 are not assumed to describe different or identical operations. \
                 Generic HookBlocked and RegistryBlocked records are counted without \
                 inferring a technique or duplicating typed denial findings.",
                "Only supplied events are assessed. Missing findings do not establish \
                 safety or complete collection. Oversized descriptions are skipped \
                 whole, the event prefix is capped, and retained evidence is bounded.",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}
