//! Heuristic risk scoring for intercepted operations, not malware verdicts.

pub mod risk_scorer;
pub mod static_analysis;

pub use risk_scorer::{analyze_operation, analyze_request, RiskScore, ThreatCategory};
