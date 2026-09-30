/*! Windows API approval hooks and their shared wire contract. */

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod approval;
#[cfg(any(windows, test))]
mod buffers;
#[cfg(any(windows, test))]
mod framing;
#[cfg(windows)]
mod hooks;
#[cfg(windows)]
mod installation;
#[cfg(windows)]
mod ipc_client;
#[cfg(windows)]
mod logging;
#[cfg(any(windows, test))]
mod permissions;
#[cfg(any(windows, test))]
mod reentrancy;
#[cfg(any(windows, test))]
pub mod registry_utils;
#[cfg(windows)]
mod runtime;
mod types;
#[cfg(windows)]
mod utils;

#[cfg(any(windows, test))]
pub use framing::FrameError;
#[cfg(windows)]
pub use ipc_client::TransportError;
pub use types::*;
#[cfg(windows)]
pub use utils::InspectionError;

/**
Connect and install all required hooks after the loader has returned.
Returns one only after sending HookReady. Concurrent lifecycle calls return
zero without waiting; a failed installation cannot be retried in the same
process. The parameter is ignored and may be null.

# Safety
Call outside the loader lock while the target's primary thread remains
suspended. The host must observe both this result and HookReady before resume.
The initialized DLL is pinned for process lifetime to protect live callbacks.
*/
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn RustySandInitialize(_parameter: *mut core::ffi::c_void) -> u32 {
    u32::from(runtime::initialize())
}

/**
Disable hooks outside the loader lock. Returns zero if an approval or lifecycle
operation is in progress, or if a hook cannot be disabled. It never waits for
an outstanding user decision. Trampolines and the DLL remain alive until exit.

# Safety
Call outside DllMain, without holding locks needed by target threads. Do not
resume an untrusted target after disabling its approval hooks.
*/
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn RustySandShutdown(_parameter: *mut core::ffi::c_void) -> u32 {
    u32::from(runtime::shutdown())
}

/**
# Safety
Windows calls this entry point with the system ABI while holding the loader
lock. All arguments are opaque; neither attach nor detach accesses resources.
*/
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _module: windows::Win32::Foundation::HMODULE,
    _reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> windows::Win32::Foundation::BOOL {
    windows::Win32::Foundation::BOOL(1)
}
