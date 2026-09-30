use crate::approval;
use crate::hooks;
use crate::installation::{InitializationError, Installation};
use crate::ipc_client::HookIpcClient;
use crate::logging;
use crate::reentrancy::HelperGuard;
use crate::types::{HookReady, PROTOCOL_VERSION};
use crate::utils::LastError;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use windows::Win32::System::Threading::GetCurrentProcessId;

const NEW: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const FAILED: u8 = 3;
const STOPPED: u8 = 4;
static STATE: AtomicU8 = AtomicU8::new(NEW);
static INSTALLATION: Mutex<Option<Installation>> = Mutex::new(None);

pub fn is_ready() -> bool {
    STATE.load(Ordering::Acquire) == READY
}

pub fn fail_closed() {
    STATE.store(FAILED, Ordering::Release);
}

pub fn initialize() -> bool {
    let _last_error = LastError::save();
    let Ok(_helper) = HelperGuard::enter() else {
        return false;
    };
    /* Claim lifecycle state only while holding the same lock used by shutdown.
    Otherwise shutdown can finish between the state claim and installation. */
    let Some(mut saved) = INSTALLATION.try_lock() else {
        return false;
    };
    if let Err(state) =
        STATE.compare_exchange(NEW, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
    {
        return state == READY;
    }
    let mut installation = match Installation::new() {
        Ok(installation) => installation,
        Err(error) => {
            logging::error("initialize hooks", &error);
            STATE.store(FAILED, Ordering::Release);
            return false;
        }
    };
    let result = initialize_connected(&mut installation);
    if let Err(error) = &result {
        STATE.store(FAILED, Ordering::Release);
        logging::error("initialize hooks", error);
        if !installation.disable() {
            logging::error(
                "rollback hooks",
                &"some hooks could not be disabled; terminate the target",
            );
        }
        *approval::CLIENT.lock() = None;
    }
    *saved = Some(installation);
    result.is_ok()
}

fn initialize_connected(installation: &mut Installation) -> Result<(), InitializationError> {
    /* SAFETY: GetCurrentProcessId has no pointer or handle preconditions. */
    let pid = unsafe { GetCurrentProcessId() };
    let mut client = HookIpcClient::connect(pid)?;
    hooks::prepare(installation)?;
    /* This lock spans enable and ready. A different thread cannot issue an
    operation message before the complete HookReady frame has been sent. */
    let mut slot = approval::CLIENT.lock();
    installation.activate()?;
    client.send_ready(&HookReady {
        version: PROTOCOL_VERSION,
        pid,
        installed_hooks: installation.count(),
    })?;
    *slot = Some(client);
    STATE.store(READY, Ordering::Release);
    Ok(())
}

pub fn shutdown() -> bool {
    let _last_error = LastError::save();
    let Ok(_helper) = HelperGuard::enter() else {
        return false;
    };
    let Some(mut installation) = INSTALLATION.try_lock() else {
        return false;
    };
    let Some(mut client) = approval::CLIENT.try_lock() else {
        return false;
    };
    if STATE.load(Ordering::Acquire) == STOPPED {
        return true;
    }
    STATE.store(FAILED, Ordering::Release);
    let success = installation.as_mut().is_none_or(Installation::disable);
    *client = None;
    if success {
        STATE.store(STOPPED, Ordering::Release);
    }
    success
}

#[cfg(test)]
#[path = "../tests/unit/runtime.rs"]
mod tests;
