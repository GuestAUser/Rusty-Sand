//! Companion evidence, without changing the ordinary SandboxReport contract.
//!
//! Collection status describes available evidence, not maliciousness or safety.

use super::{Event, SandboxReport};
use crate::analysis::static_analysis::{analyze_file, StaticReport};
use crate::behavior::assessment::{assess_events, BehaviorAssessment};
use crate::config::SandboxConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    Static,
    Execute,
    Debug,
    Shell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Evidence<T> {
    Collected { report: T },
    Failed { error: String },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    NotRequested,
    Pending,
    Exited { code: u32 },
    Failed { error: String },
    ShellClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    pub executable: String,
    pub mode: AnalysisMode,
    pub requested_config: Option<SandboxConfig>,
    pub execution: ExecutionOutcome,
    pub static_analysis: Evidence<StaticReport>,
    pub behavior: Evidence<BehaviorAssessment>,
    /// Original records: behavior evidence indices refer directly to this list.
    pub events: Vec<Event>,
    pub limitations: Vec<String>,
}

impl AnalysisReport {
    pub fn inspect(executable: &str, mode: AnalysisMode) -> Self {
        let static_analysis = match analyze_file(Path::new(executable)) {
            Ok(report) => Evidence::Collected { report },
            Err(error) => Evidence::Failed {
                error: format!("{error:#}"),
            },
        };

        let reason = match mode {
            AnalysisMode::Static => "Static inspection does not execute the input.",
            AnalysisMode::Execute => "No hook/monitor event report has been returned.",
            AnalysisMode::Debug => {
                "Native debug events are separate evidence, not hook/monitor events."
            }
            AnalysisMode::Shell => {
                "Shell sessions own their live reports; closing a shell does not establish target execution."
            }
        };

        Self {
            schema_version: 1,
            created_at: Utc::now(),
            executable: executable.to_owned(),
            mode,
            requested_config: None,
            execution: if mode == AnalysisMode::Static {
                ExecutionOutcome::NotRequested
            } else {
                ExecutionOutcome::Pending
            },
            static_analysis,
            behavior: Evidence::Unavailable {
                reason: reason.into(),
            },
            events: Vec::new(),
            limitations: [
                "Bounded observations and detection indicators are not a clean or malicious guarantee.",
                "Consult each evidence report's coverage and limitations; collected does not mean complete analysis.",
                "Static bytes are inspected before execution and are not an atomic snapshot or a guarantee of the bytes later loaded.",
                "Behavior evidence refers only to returned events. Collection gaps and events unavailable after backend errors cannot be reconstructed.",
                "A process exit status describes execution, not whether the input is safe.",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }

    pub fn record_execution(&mut self, report: &SandboxReport) {
        self.execution = ExecutionOutcome::Exited {
            code: report.exit_code,
        };
        self.events.clone_from(&report.events);
        self.behavior = if report.config.enable_behavior_detection {
            Evidence::Collected {
                report: assess_events(&report.events),
            }
        } else {
            Evidence::Unavailable {
                reason: "Behavior assessment was disabled by the requested policy.".into(),
            }
        };
    }

    pub fn save_json(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;

        std::fs::write(path, bytes)
            .with_context(|| format!("Cannot write analysis report {}", path.display()))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/analysis_report.rs"]
mod tests;
