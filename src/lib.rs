//! Windows execution and monitoring, with portable configuration, reports,
//! behavior analysis, and hook operation scoring.
//!
//! Execution APIs are absent on non-Windows targets rather than exposing
//! substitutes that cannot provide the documented operating-system behavior.

pub mod analysis;
pub mod behavior;
pub mod config;
#[cfg(windows)]
pub mod control;
#[cfg(windows)]
pub mod injection;
pub mod ipc;
#[cfg(windows)]
pub mod monitor;
pub mod report;
#[cfg(windows)]
pub mod sandbox;
pub mod ui;

pub use config::SandboxConfig;
pub use report::SandboxReport;
#[cfg(windows)]
pub use sandbox::Sandbox;

#[cfg(windows)]
use anyhow::Result;

/// Execute a program in a sandboxed environment and return analysis report
#[cfg(windows)]
pub async fn execute_sandboxed(
    executable: &str,
    args: &[String],
    config: SandboxConfig,
) -> Result<SandboxReport> {
    let sandbox = Sandbox::new(config)?;
    sandbox.execute(executable, args).await
}
