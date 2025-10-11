//! Folder/directory operation hooks (CreateDirectoryW, RemoveDirectoryW)

use crate::hooks::file_hooks::{IPC_CLIENT};
use crate::types::{HookOperation, HookRequest};
use crate::utils;
use minhook::MinHook;
use windows::core::PCWSTR;
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// Original function pointers
static mut ORIG_CREATE_DIRECTORY_W: Option<FnCreateDirectoryW> = None;
static mut ORIG_REMOVE_DIRECTORY_W: Option<FnRemoveDirectoryW> = None;

// Function type definitions
type FnCreateDirectoryW = unsafe extern "system" fn(PCWSTR, *const std::ffi::c_void) -> BOOL;
type FnRemoveDirectoryW = unsafe extern "system" fn(PCWSTR) -> BOOL;

/// Request approval from main process via IPC
fn request_approval(operation: HookOperation) -> bool {
    let client_guard = IPC_CLIENT.lock();

    if let Some(client) = client_guard.as_ref() {
        let request = HookRequest {
            operation,
            pid: unsafe { GetCurrentProcessId() },
            tid: unsafe { GetCurrentThreadId() },
        };

        match client.request_approval(&request) {
            Ok(response) => response.allowed,
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Hooked CreateDirectoryW - intercepts folder creation BEFORE execution
unsafe extern "system" fn hooked_create_directory_w(
    lppathname: PCWSTR,
    lpsecurityattributes: *const std::ffi::c_void,
) -> BOOL {
    let folder_path = utils::extract_path_from_pcwstr(lppathname);

    if folder_path.is_empty() {
        if let Some(orig) = ORIG_CREATE_DIRECTORY_W {
            return orig(lppathname, lpsecurityattributes);
        }
        return BOOL(0);
    }

    let operation = HookOperation::FolderCreate {
        path: folder_path,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        return BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CREATE_DIRECTORY_W {
        orig(lppathname, lpsecurityattributes)
    } else {
        BOOL(0)
    }
}

/// Hooked RemoveDirectoryW - intercepts folder deletion BEFORE execution
unsafe extern "system" fn hooked_remove_directory_w(lppathname: PCWSTR) -> BOOL {
    let folder_path = utils::extract_path_from_pcwstr(lppathname);

    if folder_path.is_empty() {
        if let Some(orig) = ORIG_REMOVE_DIRECTORY_W {
            return orig(lppathname);
        }
        return BOOL(0);
    }

    let operation = HookOperation::FolderDelete {
        path: folder_path,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        return BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_REMOVE_DIRECTORY_W {
        orig(lppathname)
    } else {
        BOOL(0)
    }
}

/// Install folder operation hooks
pub unsafe fn install_folder_hooks() -> Result<(), String> {
    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::PCSTR(c"kernel32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to get kernel32: {}", e))?;

    // Hook CreateDirectoryW
    let createdirectoryw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateDirectoryW".as_ptr() as *const u8),
    )
    .ok_or("CreateDirectoryW not found")?;

    let orig_createdirectoryw = MinHook::create_hook(
        createdirectoryw_addr as *mut _,
        hooked_create_directory_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateDirectoryW: {:?}", e))?;

    ORIG_CREATE_DIRECTORY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateDirectoryW>(orig_createdirectoryw));

    MinHook::enable_hook(createdirectoryw_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateDirectoryW hook: {:?}", e))?;

    // Hook RemoveDirectoryW
    let removedirectoryw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"RemoveDirectoryW".as_ptr() as *const u8),
    )
    .ok_or("RemoveDirectoryW not found")?;

    let orig_removedirectoryw = MinHook::create_hook(
        removedirectoryw_addr as *mut _,
        hooked_remove_directory_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RemoveDirectoryW: {:?}", e))?;

    ORIG_REMOVE_DIRECTORY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRemoveDirectoryW>(orig_removedirectoryw));

    MinHook::enable_hook(removedirectoryw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RemoveDirectoryW hook: {:?}", e))?;

    Ok(())
}
