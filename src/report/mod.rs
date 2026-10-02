use crate::config::SandboxConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub mod analysis;

mod classification;
mod summary;

#[cfg(test)]
#[path = "../../tests/unit/domain/report.rs"]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub executable: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
    pub events: Vec<Event>,
    pub exit_code: u32,
    pub config: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub details: String,
}

/**
Stable report tags for observations and intercepted requests.

Hook variants record requests regardless of their decision; HookBlocked records
an actual denial separately. A request is not proof of a completed operation.
*/
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    SandboxStarted,
    SandboxStopped,
    ProcessCreated,
    ProcessTerminated,
    FileCreated,
    FileModified,
    FileDeleted,
    FolderCreated,
    FolderDeleted,
    NetworkConnection,
    NetworkBlocked,
    RegistryAccess,
    RegistryBlocked,
    DnsQuery,
    ApiCall,
    Suspicious,
    HighMemoryUsage,
    HighCpuUsage,
    ResourceLimitReached,
    HookFileCreate,
    HookFileWrite,
    HookFileDelete,
    HookFileRead,
    HookFileMove,
    HookFileCopy,
    HookFileAttributeChange,
    HookFolderCreate,
    HookFolderDelete,
    HookRegistrySet,
    HookRegistryDelete,
    HookRegistryRead,
    HookRegistryOpen,
    HookNetworkConnect,
    HookNetworkSend,
    HookNetworkReceive,
    HookProcessCreate,
    HookThreadCreate,
    HookThreadCreateRemote,
    HookDllLoad,
    HookMemoryAllocate,
    HookMemoryProtect,
    HookMemoryWrite,
    HookBlocked,
}

impl SandboxReport {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn get_suspicious_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    EventType::Suspicious | EventType::NetworkBlocked
                )
            })
            .collect()
    }

    pub fn get_network_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|event| event.event_type.is_network())
            .collect()
    }

    pub fn get_file_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|event| event.event_type.is_file())
            .collect()
    }
}
