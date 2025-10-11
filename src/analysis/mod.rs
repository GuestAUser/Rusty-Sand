//! Threat analysis and risk scoring for hooked operations
//!
//! This module provides real-time risk assessment for intercepted operations,
//! helping users make informed decisions about allowing or blocking actions.

pub mod risk_scorer;

pub use risk_scorer::{RiskScore, ThreatCategory, analyze_operation};
