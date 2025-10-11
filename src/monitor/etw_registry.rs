// Real registry monitoring using RegNotifyChangeKeyValue
// This provides ACTUAL real-time registry change notifications

use crate::report::{Event, EventType};
use anyhow::Result;
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Registry::{
    RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_NOTIFY, REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_ATTRIBUTES,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::core::PCWSTR;

pub struct RealRegistryMonitor {
    events: Arc<Mutex<Vec<Event>>>,
    monitored_keys: Vec<String>,
    shutdown: Arc<AtomicBool>,
}

impl RealRegistryMonitor {
    pub fn new(events: Arc<Mutex<Vec<Event>>>, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            events,
            monitored_keys: vec![
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), // HKCU
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "SYSTEM\\CurrentControlSet\\Services".to_string(),
            ],
            shutdown,
        }
    }

    pub async fn monitor(self) -> Result<()> {
        debug!("Starting REAL registry monitor with RegNotifyChangeKeyValue");

        // Monitor both HKLM and HKCU Run keys
        let tasks: Vec<_> = self.monitored_keys.iter().map(|key_path| {
            let key_path = key_path.clone();
            let events = self.events.clone();
            let shutdown = self.shutdown.clone();

            tokio::task::spawn_blocking(move || {
                Self::monitor_key_blocking(&key_path, events, shutdown)
            })
        }).collect();

        // Wait for all monitoring tasks or shutdown
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("🛑 Registry monitor shutting down...");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Abort all blocking tasks on shutdown
        for task in tasks {
            task.abort();
        }

        Ok(())
    }

    fn monitor_key_blocking(key_path: &str, events: Arc<Mutex<Vec<Event>>>, shutdown: Arc<AtomicBool>) {
        unsafe {
            // Try HKLM first
            let key_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();

            let mut hkey = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_wide.as_ptr()),
                0,
                KEY_NOTIFY,
                &mut hkey,
            );

            if result.is_err() {
                // Try HKCU if HKLM fails
                let result = RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(key_wide.as_ptr()),
                    0,
                    KEY_NOTIFY,
                    &mut hkey,
                );

                if result.is_err() {
                    debug!("Could not open registry key for monitoring: {}", key_path);
                    return;
                }
            }

            debug!("Monitoring registry key: {}", key_path);

            // Create event object for interruptible waiting
            let event_handle = match CreateEventW(None, true, false, None) {
                Ok(h) => h,
                Err(e) => {
                    warn!("Failed to create event for registry monitoring: {:?}", e);
                    return;
                }
            };

            loop {
                // Check shutdown signal
                if shutdown.load(Ordering::SeqCst) {
                    debug!("Registry monitor for {} received shutdown signal", key_path);
                    break;
                }

                // Wait for changes with event object (non-blocking)
                let wait_result = RegNotifyChangeKeyValue(
                    hkey,
                    true, // Watch subtree
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_ATTRIBUTES,
                    event_handle,
                    true, // Async notification
                );

                if wait_result.is_err() {
                    debug!("RegNotifyChangeKeyValue failed for {}", key_path);
                    break;
                }

                // Wait with timeout so we can check shutdown signal
                let wait_timeout_result = WaitForSingleObject(event_handle, 500); // 500ms timeout

                if wait_timeout_result == WAIT_OBJECT_0 { // Registry change detected
                    let details = format!("Registry change detected: {}", key_path);
                    warn!("🔧 {}", details);

                    let event = Event {
                        timestamp: chrono::Utc::now(),
                        event_type: EventType::RegistryAccess,
                        details,
                    };

                    // Log event
                    let events_clone = events.clone();
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.block_on(async move {
                            events_clone.lock().await.push(event);
                        });
                    }
                } else if wait_timeout_result == WAIT_TIMEOUT {
                    // No changes detected, loop to check shutdown signal
                    continue;
                } else {
                    // Error occurred
                    debug!("WaitForSingleObject failed for {}", key_path);
                    break;
                }
            }
        }
    }
}
