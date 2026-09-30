use crate::ipc_client::HookIpcClient;
use crate::logging;
use crate::reentrancy::{EntryError, HelperGuard};
use crate::types::{HookOperation, HookRequest};
use crate::utils::{InspectionError, LastError};
use parking_lot::Mutex;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

pub static CLIENT: Mutex<Option<HookIpcClient>> = Mutex::new(None);

pub fn approve(describe: impl FnOnce() -> Result<HookOperation, InspectionError>) -> bool {
    let _last_error = LastError::save();
    let _helper = match HelperGuard::enter() {
        Ok(guard) => guard,
        Err(EntryError::Reentrant) => return true,
        Err(EntryError::ThreadExiting) => return false,
    };
    let operation = match describe() {
        Ok(operation) => operation,
        Err(error) => {
            logging::error("inspect callback arguments; operation denied", &error);
            return false;
        }
    };
    /* SAFETY: These APIs return calling-thread/process identifiers and borrow
    no memory. Description, serialization, and IPC all run inside the guard. */
    let request = HookRequest {
        operation,
        pid: unsafe { GetCurrentProcessId() },
        tid: unsafe { GetCurrentThreadId() },
    };
    let mut client = CLIENT.lock();
    if !crate::runtime::is_ready() {
        return false;
    }
    let Some(connection) = client.as_mut() else {
        return false;
    };
    match connection.request_approval(&request) {
        Ok(response) => response.allowed,
        Err(error) => {
            /* An incomplete exchange must not leave a stale reply that could
            approve a different thread's request on the next callback. */
            *client = None;
            crate::runtime::fail_closed();
            drop(client);
            logging::error("approval transport failed; operation denied", &error);
            false
        }
    }
    /* All helper state and the last-error guard are gone when this function
    returns. The caller invokes the original API outside the bypass scope. */
}
