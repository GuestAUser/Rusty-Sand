//! Report-only indicators. This module does not make live policy decisions.

mod collection;
mod coverage;
mod matching;
mod presentation;
mod schema;

pub use collection::assess_events;
pub use schema::{
    ActionStatus, BehaviorAssessment, BehaviorCategory, Confidence, Coverage, Evidence, Finding,
    RuleId, Severity, MAX_CORRELATION_EVENT_GAP, MAX_CORRELATION_SECONDS, MAX_DETAIL_BYTES,
    MAX_EVENTS, MAX_EVIDENCE_PER_FINDING, RANSOMWARE_PATH_THRESHOLD,
};

#[cfg(test)]
use crate::report::{Event, EventType};
#[cfg(test)]
use chrono::{DateTime, Duration};

#[cfg(test)]
#[path = "../../../tests/unit/domain/behavior_assessment.rs"]
mod tests;
