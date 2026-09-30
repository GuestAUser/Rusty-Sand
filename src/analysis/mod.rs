//! Heuristic risk scoring for intercepted operations, not malware verdicts.

pub mod risk_scorer;

pub use risk_scorer::{analyze_operation, analyze_request, RiskScore, ThreatCategory};
