use crate::config::SandboxConfig;
use crate::report::{Event, EventType};
use anyhow::Result;
use log::debug;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct RegistryMonitor {
    config: SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
}

impl RegistryMonitor {
    pub fn new(config: SandboxConfig, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        Ok(Self { config, events })
    }

    pub async fn start(self) -> Result<()> {
        debug!("Starting registry monitor");

        if !self.config.allow_registry {
            self.log_event(
                EventType::RegistryBlocked,
                "Registry access disabled".to_string(),
            )
            .await;
            return Ok(());
        }

        // Note: Full registry monitoring requires a kernel driver or API hooking
        // This is a placeholder for basic monitoring [!]
        // Dev note: We could consider using Windows ETW (Event Tracing for Windows)

        // NOTE: This monitor is mostly a placeholder - real registry monitoring
        // happens via ETW in etw_registry.rs

        // Just exit immediately - no need to keep a dummy loop running
        Ok(())
    }

    async fn log_event(&self, event_type: EventType, details: String) {
        let event = Event {
            timestamp: chrono::Utc::now(),
            event_type,
            details,
        };

        if self.config.verbose {
            debug!("[REGISTRY] {:?}: {}", event.event_type, event.details);
        }

        self.events.lock().await.push(event);
    }
}
