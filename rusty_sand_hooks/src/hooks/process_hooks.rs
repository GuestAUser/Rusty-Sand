use crate::approval::approve;
use crate::buffers::start_address;
use crate::installation::{InitializationError, Installation};
use crate::types::HookOperation;
use crate::utils::{deny, wide_string};
use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{
    GetProcessId, LPTHREAD_START_ROUTINE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};

type CreateProcess = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    PROCESS_CREATION_FLAGS,
    *const c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;
type CreateThread = unsafe extern "system" fn(
    *const SECURITY_ATTRIBUTES,
    usize,
    LPTHREAD_START_ROUTINE,
    *const c_void,
    u32,
    *mut u32,
) -> HANDLE;
type CreateRemoteThread = unsafe extern "system" fn(
    HANDLE,
    *const SECURITY_ATTRIBUTES,
    usize,
    LPTHREAD_START_ROUTINE,
    *const c_void,
    u32,
    *mut u32,
) -> HANDLE;
static CREATE_PROCESS: OnceLock<CreateProcess> = OnceLock::new();
static CREATE_THREAD: OnceLock<CreateThread> = OnceLock::new();
static CREATE_REMOTE_THREAD: OnceLock<CreateRemoteThread> = OnceLock::new();

unsafe extern "system" fn create_process(
    application: PCWSTR,
    command_line: PWSTR,
    process_security: *const SECURITY_ATTRIBUTES,
    thread_security: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: PROCESS_CREATION_FLAGS,
    environment: *const c_void,
    directory: PCWSTR,
    startup: *const STARTUPINFOW,
    information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let Some(original) = CREATE_PROCESS.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        let executable = wide_string(application)?;
        let args = wide_string(PCWSTR(command_line.0))?;
        Ok(HookOperation::ProcessCreate {
            executable: if executable.is_empty() {
                args.clone()
            } else {
                executable
            },
            args,
            creation_flags: flags.0,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: The process-lifetime trampoline matches CreateProcessW's ABI.
    The original mutable command line and output structures are forwarded
    unchanged; no helper lock or bypass survives into process creation. */
    unsafe {
        original(
            application,
            command_line,
            process_security,
            thread_security,
            inherit,
            flags,
            environment,
            directory,
            startup,
            information,
        )
    }
}

unsafe extern "system" fn create_thread(
    security: *const SECURITY_ATTRIBUTES,
    stack: usize,
    start: LPTHREAD_START_ROUTINE,
    parameter: *const c_void,
    flags: u32,
    id: *mut u32,
) -> HANDLE {
    let Some(original) = CREATE_THREAD.get() else {
        return deny(HANDLE(0));
    };
    if !approve(|| {
        Ok(HookOperation::ThreadCreate {
            start_address: start_address(start),
            parameter: parameter as u64,
        })
    }) {
        return deny(HANDLE(0));
    }
    /* SAFETY: The CreateThread trampoline receives the nullable system-ABI
    routine unchanged. The hook does not invoke it or borrow its parameter. */
    unsafe { original(security, stack, start, parameter, flags, id) }
}

unsafe extern "system" fn create_remote_thread(
    process: HANDLE,
    security: *const SECURITY_ATTRIBUTES,
    stack: usize,
    start: LPTHREAD_START_ROUTINE,
    parameter: *const c_void,
    flags: u32,
    id: *mut u32,
) -> HANDLE {
    let Some(original) = CREATE_REMOTE_THREAD.get() else {
        return deny(HANDLE(0));
    };
    if !approve(|| {
        /* SAFETY: GetProcessId validates the borrowed process handle. */
        let target_process_id = unsafe { GetProcessId(process) };
        Ok(HookOperation::ThreadCreateRemote {
            target_process_id,
            start_address: start_address(start),
        })
    }) {
        return deny(HANDLE(0));
    }
    /* SAFETY: The CreateRemoteThread trampoline has the matching system ABI.
    Null start routines are forwarded to Windows, never unwrapped by Rust. */
    unsafe { original(process, security, stack, start, parameter, flags, id) }
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"kernel32.dll")?;
    install_hook!(
        installation,
        module,
        c"CreateProcessW",
        create_process,
        CREATE_PROCESS,
        CreateProcess
    );
    install_hook!(
        installation,
        module,
        c"CreateThread",
        create_thread,
        CREATE_THREAD,
        CreateThread
    );
    install_hook!(
        installation,
        module,
        c"CreateRemoteThread",
        create_remote_thread,
        CREATE_REMOTE_THREAD,
        CreateRemoteThread
    );
    Ok(())
}
