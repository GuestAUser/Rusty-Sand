/** Registry change notifications, not Event Tracing for Windows.

The module and type names remain for source compatibility. Notifications
identify a watched subtree, not an operation, value, or responsible process.
*/
use crate::report::{Event, EventType};
use anyhow::{bail, Context, Result};
use log::warn;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Registry::{
    RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

pub struct RealRegistryMonitor {
    events: Arc<Mutex<Vec<Event>>>,
    shutdown: Arc<AtomicBool>,
}

impl RealRegistryMonitor {
    pub fn new(events: Arc<Mutex<Vec<Event>>>, shutdown: Arc<AtomicBool>) -> Self {
        Self { events, shutdown }
    }

    pub async fn monitor(self) -> Result<()> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelOnDrop(cancelled.clone());
        let (sender, mut receiver) = mpsc::channel(256);
        let shutdown = self.shutdown;
        let worker = tokio::task::spawn_blocking(move || watch_keys(shutdown, cancelled, sender));

        while let Some(event) = receiver.recv().await {
            self.events.lock().await.push(event);
        }

        /* Join, rather than abort, the blocking worker. Dropping this future
        also requests cancellation; the worker's OS wait is bounded. */
        worker
            .await
            .context("registry notification worker failed")?
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        /* SAFETY: This is an owned RegOpenKeyExW result, never a predefined
        hive. Closing the key cancels its pending notification registration. */
        let status = unsafe { RegCloseKey(self.0) };

        if let Err(error) = status {
            warn!("Closing registry notification key failed: {error}");
        }
    }
}

struct OwnedEvent(HANDLE);

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        /* SAFETY: The event is exclusively owned and its registry key has
        already been closed before this field is dropped. */
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            warn!("Closing registry notification event failed: {error}");
        }
    }
}

struct KeyWatch {
    /* Field drop order cancels the notification before closing its event. */
    key: OwnedKey,
    event: OwnedEvent,
    name: String,
}

impl KeyWatch {
    fn open(hive: HKEY, hive_name: &str, path: &str) -> Result<Self> {
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut key = HKEY::default();

        /* SAFETY: The UTF-16 path is NUL-terminated and live for the call.
        `key` is writable output; success transfers one handle to OwnedKey. */
        unsafe { RegOpenKeyExW(hive, PCWSTR(wide.as_ptr()), 0, KEY_NOTIFY, &mut key) }
            .ok()
            .with_context(|| format!("open {hive_name}\\{path}"))?;
        let key = OwnedKey(key);

        /* SAFETY: No borrowed security descriptor or name is supplied.
        CreateEventW transfers one auto-reset event handle to this owner. */
        let event = OwnedEvent(unsafe { CreateEventW(None, false, false, None) }?);
        let watch = Self {
            key,
            event,
            name: format!("{hive_name}\\{path}"),
        };
        watch.arm()?;
        Ok(watch)
    }

    fn arm(&self) -> Result<()> {
        /* SAFETY: Both handles stay owned on this blocking thread until the
        key closes. Only one registration is outstanding per key; the
        auto-reset event is consumed before registering the next one. */
        unsafe {
            RegNotifyChangeKeyValue(
                self.key.0,
                true,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_ATTRIBUTES,
                self.event.0,
                true,
            )
        }
        .ok()
        .with_context(|| format!("register notification for {}", self.name))
    }
}

fn watch_keys(
    shutdown: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    sender: mpsc::Sender<Event>,
) -> Result<()> {
    let stopping = || shutdown.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire);

    if stopping() {
        return Ok(());
    }

    let mut watches = Vec::new();
    let run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let run_once = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    let services = "SYSTEM\\CurrentControlSet\\Services";

    for (hive, name, path) in [
        (HKEY_LOCAL_MACHINE, "HKLM", run),
        (HKEY_LOCAL_MACHINE, "HKLM", run_once),
        (HKEY_CURRENT_USER, "HKCU", run),
        (HKEY_CURRENT_USER, "HKCU", run_once),
        (HKEY_LOCAL_MACHINE, "HKLM", services),
    ] {
        match KeyWatch::open(hive, name, path) {
            Ok(watch) => watches.push(watch),
            Err(error) => warn!("Registry observation unavailable: {error:#}"),
        }
    }

    if watches.is_empty() {
        bail!("no configured registry keys could be watched");
    }

    let handles: Vec<_> = watches.iter().map(|watch| watch.event.0).collect();

    while !stopping() {
        /* SAFETY: All event handles are live and unique; the slice has at
        most five entries. This bounded wait runs only on a blocking worker. */
        let result = unsafe { WaitForMultipleObjects(&handles, false, 100) };

        if result == WAIT_TIMEOUT {
            /* A timeout leaves the existing registration pending. Rearming
            here would accumulate registrations without a matching change. */
            continue;
        }

        if result == WAIT_FAILED {
            return Err(std::io::Error::last_os_error()).context("wait for registry change");
        }

        let index = result.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        let Some(watch) = watches.get(index) else {
            bail!("unexpected registry notification wait status: {}", result.0);
        };

        if stopping() {
            break;
        }

        let event = Event {
            timestamp: chrono::Utc::now(),
            event_type: EventType::RegistryAccess,
            details: format!(
                "Observed registry subtree change (process unattributed; operation unspecified): {}",
                watch.name
            ),
        };

        match sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                bail!("registry notification queue overflowed; observations are incomplete");
            }
        }

        watch.arm()?;
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_etw_registry.rs"]
mod tests;
