pub mod isolation;
pub mod process;

use crate::config::SandboxConfig;
use crate::monitor::MonitoringEngine;
use crate::report::SandboxReport;
use anyhow::{Context, Result};
use log::{info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(&config.output_dir)
            .context("Failed to create output directory")?;

        Ok(Self { config })
    }

    pub async fn execute(&self, executable: &str, args: &[String]) -> Result<SandboxReport> {
        info!("Starting sandbox execution: {}", executable);
        info!("Internet access: {}", if self.config.allow_internet { "ENABLED" } else { "DISABLED" });

        if self.config.allow_internet {
            warn!("⚠️  Internet access is ENABLED - process can make network connections");
        } else {
            info!("🔒 Internet access is DISABLED (default secure mode)");
        }

        // Initialize monitoring engine
        let monitor = Arc::new(Mutex::new(MonitoringEngine::new(
            self.config.clone(),
        )?));

        // Start monitoring
        {
            let mut m = monitor.lock().await;
            m.start().await?;
        }

        // Create isolated process
        let proc_handle = process::create_sandboxed_process(
            executable,
            args,
            &self.config,
        )?;

        info!("Process started with PID: {:?}", proc_handle.process_id);

        // Monitor the process
        let report = {
            let mut m = monitor.lock().await;
            m.monitor_process(proc_handle).await?
        };

        info!("Sandbox execution completed");

        Ok(report)
    }
}
