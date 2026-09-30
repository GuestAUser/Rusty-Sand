use super::review::ReviewClient;
use crate::config::SandboxConfig;
use crate::control::UserDecision;
use crate::ipc::{HookIpcServer, HookOperation, HookResponse};
use crate::report::{Event, EventType};
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(super) async fn serve(
    server: Option<&mut HookIpcServer>,
    reviews: &ReviewClient,
    config: &SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<()> {
    let Some(server) = server else {
        return std::future::pending().await;
    };
    let mut allowed_types = HashSet::new();
    let mut denied_types = HashSet::new();
    loop {
        let request = server.read_request().await?;
        let kind = std::mem::discriminant(&request.operation);
        let description = request.operation.short_description();
        let (allowed, terminate, reason) =
            if let Some(reason) = policy_denial(config, &request.operation) {
                (false, false, reason)
            } else if !config.interactive_mode || allowed_types.contains(&kind) {
                (true, false, "configured policy permits operation")
            } else if denied_types.contains(&kind) {
                (false, false, "user denied this operation type")
            } else if request.operation.is_read_only() {
                (true, false, "read-only operation permitted by policy")
            } else {
                let risk = crate::analysis::analyze_request(&request);
                match reviews.hook(description.clone(), risk).await? {
                    UserDecision::Allow => (true, false, "user approved operation"),
                    UserDecision::AllowAll => {
                        allowed_types.insert(kind);
                        (true, false, "user approved this operation type")
                    }
                    UserDecision::BlockAll => {
                        denied_types.insert(kind);
                        (false, false, "user denied this operation type")
                    }
                    UserDecision::Terminate => (false, true, "user requested termination"),
                    UserDecision::Block | UserDecision::Continue => {
                        (false, false, "user did not approve operation")
                    }
                }
            };
        /*
         * Persist the decision before a reply can release the target. A fast
         * process may exit immediately after receiving it, cancelling this
         * service future before any later event-log lock is acquired.
         */
        let mut events = events.lock().await;
        events.push(Event {
            timestamp: chrono::Utc::now(),
            event_type: event_type(&request.operation),
            details: format!(
                "{} hook request from PID {}: {description} ({reason})",
                if allowed { "Allowed" } else { "Denied" },
                request.pid
            ),
        });
        if !allowed {
            events.push(Event {
                timestamp: chrono::Utc::now(),
                event_type: EventType::HookBlocked,
                details: format!("Denied {description}: {reason}"),
            });
        }
        drop(events);
        server
            .send_response(&HookResponse {
                allowed,
                reason: Some(reason.into()),
            })
            .await?;
        if terminate {
            bail!("user requested target termination");
        }
    }
}

fn policy_denial(config: &SandboxConfig, operation: &HookOperation) -> Option<&'static str> {
    match operation {
        HookOperation::RegistrySet { .. }
        | HookOperation::RegistryDelete { .. }
        | HookOperation::RegistryRead { .. }
        | HookOperation::RegistryOpen { .. }
            if !config.allow_registry =>
        {
            Some("registry access is disabled")
        }
        HookOperation::NetworkConnect { port, .. }
        | HookOperation::NetworkSend { port, .. }
        | HookOperation::NetworkReceive { port, .. } => {
            /* The current wire contract has no resolver hook. Port 53 requests
            can enforce the DNS setting here; this is not coverage of DoH,
            arbitrary resolver APIs, or traffic that bypasses these hooks. */
            if *port == 53 {
                (!config.allow_dns).then_some("DNS traffic is disabled")
            } else {
                (!config.allow_internet).then_some("network access is disabled")
            }
        }
        _ => None,
    }
}

fn event_type(operation: &HookOperation) -> EventType {
    match operation {
        HookOperation::FileCreate { .. } => EventType::HookFileCreate,
        HookOperation::FileWrite { .. } => EventType::HookFileWrite,
        HookOperation::FileDelete { .. } => EventType::HookFileDelete,
        HookOperation::FileRead { .. } => EventType::HookFileRead,
        HookOperation::FileMove { .. } => EventType::HookFileMove,
        HookOperation::FileCopy { .. } => EventType::HookFileCopy,
        HookOperation::FileAttributeChange { .. } => EventType::HookFileAttributeChange,
        HookOperation::FolderCreate { .. } => EventType::HookFolderCreate,
        HookOperation::FolderDelete { .. } => EventType::HookFolderDelete,
        HookOperation::RegistrySet { .. } => EventType::HookRegistrySet,
        HookOperation::RegistryDelete { .. } => EventType::HookRegistryDelete,
        HookOperation::RegistryRead { .. } => EventType::HookRegistryRead,
        HookOperation::RegistryOpen { .. } => EventType::HookRegistryOpen,
        HookOperation::NetworkConnect { .. } => EventType::HookNetworkConnect,
        HookOperation::NetworkSend { .. } => EventType::HookNetworkSend,
        HookOperation::NetworkReceive { .. } => EventType::HookNetworkReceive,
        HookOperation::ProcessCreate { .. } => EventType::HookProcessCreate,
        HookOperation::ThreadCreate { .. } => EventType::HookThreadCreate,
        HookOperation::ThreadCreateRemote { .. } => EventType::HookThreadCreateRemote,
        HookOperation::DllLoad { .. } => EventType::HookDllLoad,
        HookOperation::MemoryAllocate { .. } => EventType::HookMemoryAllocate,
        HookOperation::MemoryProtect { .. } => EventType::HookMemoryProtect,
        HookOperation::MemoryWrite { .. } => EventType::HookMemoryWrite,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_hooks.rs"]
mod tests;
