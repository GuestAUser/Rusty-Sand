//! Process and thread operation hooks (CreateProcessW, CreateThread, etc.)

use crate::hooks::file_hooks::IPC_CLIENT;
use crate::types::{HookOperation, HookRequest};
use crate::utils;
use minhook::MinHook;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, LPTHREAD_START_ROUTINE, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOW,
};

// Original function pointers
static mut ORIG_CREATE_PROCESS_W: Option<FnCreateProcessW> = None;
static mut ORIG_CREATE_THREAD: Option<FnCreateThread> = None;
static mut ORIG_CREATE_REMOTE_THREAD: Option<FnCreateRemoteThread> = None;

// Function type definitions
type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,                          // lpApplicationName
    windows::core::PWSTR,            // lpCommandLine
    *const SECURITY_ATTRIBUTES,      // lpProcessAttributes
    *const SECURITY_ATTRIBUTES,      // lpThreadAttributes
    BOOL,                            // bInheritHandles
    PROCESS_CREATION_FLAGS,          // dwCreationFlags
    *const std::ffi::c_void,         // lpEnvironment
    PCWSTR,                          // lpCurrentDirectory
    *const STARTUPINFOW,             // lpStartupInfo
    *mut PROCESS_INFORMATION,        // lpProcessInformation
) -> BOOL;

type FnCreateThread = unsafe extern "system" fn(
    *const SECURITY_ATTRIBUTES,      // lpThreadAttributes
    usize,                           // dwStackSize
    LPTHREAD_START_ROUTINE,          // lpStartAddress
    *const std::ffi::c_void,         // lpParameter
    u32,                             // dwCreationFlags
    *mut u32,                        // lpThreadId
) -> HANDLE;

type FnCreateRemoteThread = unsafe extern "system" fn(
    HANDLE,                          // hProcess
    *const SECURITY_ATTRIBUTES,      // lpThreadAttributes
    usize,                           // dwStackSize
    LPTHREAD_START_ROUTINE,          // lpStartAddress
    *const std::ffi::c_void,         // lpParameter
    u32,                             // dwCreationFlags
    *mut u32,                        // lpThreadId
) -> HANDLE;

/// Request approval from main process via IPC
fn request_approval(operation: HookOperation) -> bool {
    use crate::hook_log;

    let client_guard = IPC_CLIENT.lock();

    if let Some(client) = client_guard.as_ref() {
        let request = HookRequest {
            operation: operation.clone(),
            pid: unsafe { GetCurrentProcessId() },
            tid: unsafe { GetCurrentThreadId() },
        };

        hook_log!(Trace, "Requesting approval for: {:?}", operation);

        match client.request_approval(&request) {
            Ok(response) => {
                if response.allowed {
                    hook_log!(Debug, "Operation ALLOWED: {:?}", operation);
                } else {
                    hook_log!(Warn, "Operation DENIED: {:?}", operation);
                }
                response.allowed
            }
            Err(e) => {
                hook_log!(Error, "IPC request failed: {} - Operation DENIED", e);
                false
            }
        }
    } else {
        hook_log!(Error, "No IPC client available - Operation DENIED");
        false
    }
}

/// Hooked CreateProcessW - intercepts child process creation
unsafe extern "system" fn hooked_create_process_w(
    lpapplicationname: PCWSTR,
    lpcommandline: windows::core::PWSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const std::ffi::c_void,
    lpcurrentdirectory: PCWSTR,
    lpstartupinfo: *const STARTUPINFOW,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL {
    // Extract executable path
    let executable = utils::extract_path_from_pcwstr(lpapplicationname);

    // Extract command line arguments
    let args = if !lpcommandline.is_null() && !lpcommandline.0.is_null() {
        let mut len = 0;
        while len < 32767 && *lpcommandline.0.offset(len) != 0 {
            len += 1;
        }
        if len > 0 {
            let slice = std::slice::from_raw_parts(lpcommandline.0, len as usize);
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let operation = HookOperation::ProcessCreate {
        executable: if executable.is_empty() { args.clone() } else { executable },
        args,
        creation_flags: dwcreationflags.0,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return FALSE
        return BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CREATE_PROCESS_W {
        orig(
            lpapplicationname,
            lpcommandline,
            lpprocessattributes,
            lpthreadattributes,
            binherithandles,
            dwcreationflags,
            lpenvironment,
            lpcurrentdirectory,
            lpstartupinfo,
            lpprocessinformation,
        )
    } else {
        BOOL(0)
    }
}

/// Hooked CreateThread - intercepts thread creation
unsafe extern "system" fn hooked_create_thread(
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: *const std::ffi::c_void,
    dwcreationflags: u32,
    lpthreadid: *mut u32,
) -> HANDLE {
    let operation = HookOperation::ThreadCreate {
        start_address: lpstartaddress.unwrap() as u64,
        parameter: lpparameter as u64,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return invalid handle
        return HANDLE(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CREATE_THREAD {
        orig(
            lpthreadattributes,
            dwstacksize,
            lpstartaddress,
            lpparameter,
            dwcreationflags,
            lpthreadid,
        )
    } else {
        HANDLE(0)
    }
}

/// Hooked CreateRemoteThread - intercepts remote thread injection (major malware technique!)
unsafe extern "system" fn hooked_create_remote_thread(
    hprocess: HANDLE,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: *const std::ffi::c_void,
    dwcreationflags: u32,
    lpthreadid: *mut u32,
) -> HANDLE {
    // Get target process ID
    let target_pid = unsafe {
        use windows::Win32::System::Threading::GetProcessId;
        GetProcessId(hprocess)
    };

    let operation = HookOperation::ThreadCreateRemote {
        target_process_id: target_pid,
        start_address: lpstartaddress.unwrap() as u64,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return invalid handle
        return HANDLE(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CREATE_REMOTE_THREAD {
        orig(
            hprocess,
            lpthreadattributes,
            dwstacksize,
            lpstartaddress,
            lpparameter,
            dwcreationflags,
            lpthreadid,
        )
    } else {
        HANDLE(0)
    }
}

/// Install process/thread operation hooks
pub unsafe fn install_process_hooks() -> Result<(), String> {
    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::PCSTR(c"kernel32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to get kernel32: {}", e))?;

    // Hook CreateProcessW
    let createprocessw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateProcessW".as_ptr() as *const u8),
    )
    .ok_or("CreateProcessW not found")?;

    let orig_createprocessw = MinHook::create_hook(
        createprocessw_addr as *mut _,
        hooked_create_process_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateProcessW: {:?}", e))?;

    ORIG_CREATE_PROCESS_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateProcessW>(orig_createprocessw));

    MinHook::enable_hook(createprocessw_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateProcessW hook: {:?}", e))?;

    // Hook CreateThread
    let createthread_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateThread".as_ptr() as *const u8),
    )
    .ok_or("CreateThread not found")?;

    let orig_createthread = MinHook::create_hook(
        createthread_addr as *mut _,
        hooked_create_thread as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateThread: {:?}", e))?;

    ORIG_CREATE_THREAD = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateThread>(orig_createthread));

    MinHook::enable_hook(createthread_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateThread hook: {:?}", e))?;

    // Hook CreateRemoteThread
    let createremotethread_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateRemoteThread".as_ptr() as *const u8),
    )
    .ok_or("CreateRemoteThread not found")?;

    let orig_createremotethread = MinHook::create_hook(
        createremotethread_addr as *mut _,
        hooked_create_remote_thread as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateRemoteThread: {:?}", e))?;

    ORIG_CREATE_REMOTE_THREAD = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateRemoteThread>(orig_createremotethread));

    MinHook::enable_hook(createremotethread_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateRemoteThread hook: {:?}", e))?;

    Ok(())
}
