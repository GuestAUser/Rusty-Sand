//! File operation hooks (CreateFileW, DeleteFileW, etc.)

use crate::ipc_client::HookIpcClient;
use crate::types::{HookOperation, HookRequest};
use crate::utils;
use minhook::MinHook;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::FILE_SHARE_MODE;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// Global IPC client (shared with all hooks)
pub static IPC_CLIENT: Lazy<Arc<Mutex<Option<HookIpcClient>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

// Original function pointers (trampolines)
static mut ORIG_CREATE_FILE_W: Option<FnCreateFileW> = None;
static mut ORIG_DELETE_FILE_W: Option<FnDeleteFileW> = None;

// Function type definitions
type FnCreateFileW = unsafe extern "system" fn(
    PCWSTR,
    u32,
    FILE_SHARE_MODE,
    *const std::ffi::c_void,
    u32,
    u32,
    HANDLE,
) -> HANDLE;

type FnDeleteFileW = unsafe extern "system" fn(PCWSTR) -> windows::Win32::Foundation::BOOL;

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
                false // Fail closed on IPC error
            }
        }
    } else {
        hook_log!(Error, "No IPC client available - Operation DENIED");
        false // No IPC client = deny
    }
}

/// Hooked CreateFileW - intercepts ALL file operations BEFORE execution
unsafe extern "system" fn hooked_create_file_w(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: *const std::ffi::c_void,
    dwcreationdisposition: u32,
    dwflagsandattributes: u32,
    htemplatefile: HANDLE,
) -> HANDLE {
    // Extract file path
    let file_path = utils::extract_path_from_pcwstr(lpfilename);

    if file_path.is_empty() {
        // Call original if path is empty/invalid
        if let Some(orig) = ORIG_CREATE_FILE_W {
            return orig(
                lpfilename,
                dwdesiredaccess,
                dwsharemode,
                lpsecurityattributes,
                dwcreationdisposition,
                dwflagsandattributes,
                htemplatefile,
            );
        }
        return INVALID_HANDLE_VALUE;
    }

    // Check if this is a directory operation
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;

    let is_directory = (dwflagsandattributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        || (dwflagsandattributes & FILE_FLAG_BACKUP_SEMANTICS) != 0;

    // Determine operation type
    let operation = if utils::file_disposition::creates_new_file(dwcreationdisposition) {
        if is_directory {
            HookOperation::FolderCreate {
                path: file_path.clone(),
            }
        } else {
            HookOperation::FileCreate {
                path: file_path.clone(),
                access_rights: dwdesiredaccess,
                share_mode: dwsharemode.0,
                creation_disposition: dwcreationdisposition,
                flags_and_attributes: dwflagsandattributes,
            }
        }
    } else if utils::file_access::has_write_access(dwdesiredaccess) {
        HookOperation::FileWrite {
            path: file_path.clone(),
            handle: 0, // Not yet created
        }
    } else {
        // Read-only - allow without prompting (if configured)
        if let Some(orig) = ORIG_CREATE_FILE_W {
            return orig(
                lpfilename,
                dwdesiredaccess,
                dwsharemode,
                lpsecurityattributes,
                dwcreationdisposition,
                dwflagsandattributes,
                htemplatefile,
            );
        }
        return INVALID_HANDLE_VALUE;
    };

    // REQUEST APPROVAL - THIS IS WHERE WE BLOCK!
    if !request_approval(operation) {
        // DENIED - return error WITHOUT calling original
        return INVALID_HANDLE_VALUE;
    }

    // ALLOWED - call original function
    if let Some(orig) = ORIG_CREATE_FILE_W {
        orig(
            lpfilename,
            dwdesiredaccess,
            dwsharemode,
            lpsecurityattributes,
            dwcreationdisposition,
            dwflagsandattributes,
            htemplatefile,
        )
    } else {
        INVALID_HANDLE_VALUE
    }
}

/// Hooked DeleteFileW - intercepts file deletion BEFORE execution
unsafe extern "system" fn hooked_delete_file_w(lpfilename: PCWSTR) -> windows::Win32::Foundation::BOOL {
    // Extract file path
    let file_path = utils::extract_path_from_pcwstr(lpfilename);

    if file_path.is_empty() {
        // Call original if path is empty
        if let Some(orig) = ORIG_DELETE_FILE_W {
            return orig(lpfilename);
        }
        return windows::Win32::Foundation::BOOL(0);
    }

    let operation = HookOperation::FileDelete {
        path: file_path,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return FALSE (failure)
        return windows::Win32::Foundation::BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_DELETE_FILE_W {
        orig(lpfilename)
    } else {
        windows::Win32::Foundation::BOOL(0)
    }
}

/// Install file operation hooks
pub unsafe fn install_file_hooks() -> Result<(), String> {
    // Get kernel32.dll
    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::PCSTR(c"kernel32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to get kernel32: {}", e))?;

    // Hook CreateFileW
    let createfilew_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateFileW".as_ptr() as *const u8),
    )
    .ok_or("CreateFileW not found")?;

    let orig_createfilew = MinHook::create_hook(
        createfilew_addr as *mut _,
        hooked_create_file_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateFileW: {:?}", e))?;

    ORIG_CREATE_FILE_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateFileW>(orig_createfilew));

    MinHook::enable_hook(createfilew_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateFileW hook: {:?}", e))?;

    // Hook DeleteFileW
    let deletefilew_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"DeleteFileW".as_ptr() as *const u8),
    )
    .ok_or("DeleteFileW not found")?;

    let orig_deletefilew = MinHook::create_hook(
        deletefilew_addr as *mut _,
        hooked_delete_file_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook DeleteFileW: {:?}", e))?;

    ORIG_DELETE_FILE_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnDeleteFileW>(orig_deletefilew));

    MinHook::enable_hook(deletefilew_addr as *mut _)
        .map_err(|e| format!("Failed to enable DeleteFileW hook: {:?}", e))?;

    Ok(())
}
