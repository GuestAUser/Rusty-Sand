pub mod analysis;
pub mod behavior;
pub mod config;
pub mod control;
pub mod injection;  // DLL injection for API hooking
pub mod ipc;        // Inter-process communication for hooks
pub mod monitor;
pub mod report;
pub mod sandbox;

pub use config::SandboxConfig;
pub use report::SandboxReport;
pub use sandbox::Sandbox;

use anyhow::Result;

/// Execute a program in a sandboxed environment and return analysis report
pub async fn execute_sandboxed(
    executable: &str,
    args: &[String],
    config: SandboxConfig,
) -> Result<SandboxReport> {
    let sandbox = Sandbox::new(config)?;
    sandbox.execute(executable, args).await
}
