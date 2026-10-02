//! Serialized assessment schema and collection limits.

use crate::report::EventType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const MAX_EVENTS: usize = 16_384;
pub const MAX_DETAIL_BYTES: usize = 4_096;
pub const MAX_EVIDENCE_PER_FINDING: usize = 16;
pub const MAX_CORRELATION_EVENT_GAP: usize = 32;
pub const MAX_CORRELATION_SECONDS: i64 = 30;
pub const RANSOMWARE_PATH_THRESHOLD: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorCategory {
    RansomwareLike,
    Persistence,
    CredentialAccess,
    ProcessInjection,
    SuspiciousExecution,
    DefenseImpairment,
    NetworkActivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Medium,
    High,
}

/// Confidence in the reported indicator, not in malicious intent or success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Attempted,
    Observed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    RansomwareLikeFileNames,
    RansomNoteName,
    StartupRegistry,
    StartupFolder,
    CredentialStoreRead,
    RemoteMemoryWrite,
    RemoteThread,
    WriteThenRemoteThread,
    SuspiciousExecution,
    DefenseImpairment,
    NetworkActivity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Zero-based index into the original input, including skipped records.
    pub event_index: usize,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub status: ActionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule: RuleId,
    pub category: BehaviorCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: ActionStatus,
    pub summary: String,
    /// Unique supporting event records, not unique completed operations.
    pub matched_events: usize,
    pub evidence: Vec<Evidence>,
    pub omitted_evidence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub input_events: usize,
    /// Prefix visited, including duplicate and oversized records.
    pub inspected_events: usize,
    pub omitted_events: usize,
    pub duplicate_events: usize,
    pub oversized_events: usize,
    /// Generic denial records are not assigned an inferred technique.
    pub unclassified_denial_records: usize,
    /// Memory/thread requests without usable caller and target identities.
    pub uncorrelatable_injection_events: usize,
    pub max_events: usize,
    pub max_detail_bytes: usize,
    pub max_evidence_per_finding: usize,
    pub correlation_event_gap: usize,
    pub correlation_window_seconds: i64,
    pub ransomware_distinct_path_threshold: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorAssessment {
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
}
