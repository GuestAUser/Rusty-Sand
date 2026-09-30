mod cleanup;
mod command_line;
pub mod deadline;
pub mod isolation;
pub mod process;
pub(crate) mod resource;
pub(crate) mod wait;

use crate::config::SandboxConfig;
use crate::monitor::MonitoringEngine;
use crate::report::SandboxReport;
use anyhow::{Context, Result};

pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.output_dir).context("create sandbox output directory")?;
        Ok(Self { config })
    }

    pub async fn execute(&self, executable: &str, args: &[String]) -> Result<SandboxReport> {
        let deadline = deadline::Deadline::after(self.config.timeout)?;
        let mut monitor = MonitoringEngine::new(self.config.clone())?;
        monitor.start().await?;
        deadline.check()?;
        let process = process::create_sandboxed_process(executable, args, &self.config)?;
        monitor.monitor_process_until(process, deadline).await
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox.rs"]
mod tests;
