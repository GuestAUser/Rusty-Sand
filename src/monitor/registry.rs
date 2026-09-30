use crate::config::SandboxConfig;
use crate::report::Event;
use anyhow::Result;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::Mutex;

/** Compatibility entry point for registry change notifications.

Start this monitor or `RealRegistryMonitor`, not both. The latter additionally
accepts the runtime owner's shutdown flag. Dropping either monitor future
cancels its notification worker; configuration never fabricates a denial.
*/
pub struct RegistryMonitor {
    events: Arc<Mutex<Vec<Event>>>,
}

impl RegistryMonitor {
    pub fn new(_config: SandboxConfig, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        Ok(Self { events })
    }

    pub async fn start(self) -> Result<()> {
        super::etw_registry::RealRegistryMonitor::new(self.events, Arc::new(AtomicBool::new(false)))
            .monitor()
            .await
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_registry.rs"]
mod tests;
