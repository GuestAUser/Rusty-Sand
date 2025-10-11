//! Memory and DLL operation hooks (VirtualAlloc, VirtualProtect, LoadLibraryW, etc.)

use crate::hooks::file_hooks::IPC_CLIENT;
use crate::types::{HookOperation, HookRequest};
use crate::utils;
use minhook::MinHook;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// Original function pointers
static mut ORIG_VIRTUAL_ALLOC: Option<FnVirtualAlloc> = None;
static mut ORIG_VIRTUAL_PROTECT: Option<FnVirtualProtect> = None;
static mut ORIG_WRITE_PROCESS_MEMORY: Option<FnWriteProcessMemory> = None;
static mut ORIG_LOAD_LIBRARY_W: Option<FnLoadLibraryW> = None;
static mut ORIG_LOAD_LIBRARY_EX_W: Option<FnLoadLibraryExW> = None;

// Function type definitions
type FnVirtualAlloc = unsafe extern "system" fn(
    *const std::ffi::c_void,      // lpAddress
    usize,                         // dwSize
    VIRTUAL_ALLOCATION_TYPE,       // flAllocationType
    u32,                           // flProtect
) -> *mut std::ffi::c_void;

type FnVirtualProtect = unsafe extern "system" fn(
    *const std::ffi::c_void,      // lpAddress
    usize,                         // dwSize
    u32,                           // flNewProtect
    *mut u32,                      // lpflOldProtect
) -> windows::Win32::Foundation::BOOL;

type FnWriteProcessMemory = unsafe extern "system" fn(
    HANDLE,                        // hProcess
    *const std::ffi::c_void,       // lpBaseAddress
    *const std::ffi::c_void,       // lpBuffer
    usize,                         // nSize
    *mut usize,                    // lpNumberOfBytesWritten
) -> windows::Win32::Foundation::BOOL;

type FnLoadLibraryW = unsafe extern "system" fn(PCWSTR) -> windows::Win32::Foundation::HINSTANCE;

type FnLoadLibraryExW = unsafe extern "system" fn(
    PCWSTR,                        // lpLibFileName
    HANDLE,                        // hFile
    u32,                           // dwFlags
) -> windows::Win32::Foundation::HINSTANCE;

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

/// Hooked VirtualAlloc - intercepts memory allocation
unsafe extern "system" fn hooked_virtual_alloc(
    lpaddress: *const std::ffi::c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: u32,
) -> *mut std::ffi::c_void {
    let operation = HookOperation::MemoryAllocate {
        base_address: lpaddress as u64,
        size: dwsize,
        protection: flprotect,
        allocation_type: flallocationtype.0,
    };

    // REQUEST APPROVAL (especially for RWX memory - highly suspicious!)
    if !request_approval(operation) {
        // DENIED - return null pointer
        return std::ptr::null_mut();
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_VIRTUAL_ALLOC {
        orig(lpaddress, dwsize, flallocationtype, flprotect)
    } else {
        std::ptr::null_mut()
    }
}

/// Hooked VirtualProtect - intercepts memory protection changes
unsafe extern "system" fn hooked_virtual_protect(
    lpaddress: *const std::ffi::c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> windows::Win32::Foundation::BOOL {
    // Read old protection before calling
    let old_protect = if !lpfloldprotect.is_null() {
        *lpfloldprotect
    } else {
        0
    };

    let operation = HookOperation::MemoryProtect {
        base_address: lpaddress as u64,
        size: dwsize,
        old_protection: old_protect,
        new_protection: flnewprotect,
    };

    // REQUEST APPROVAL (especially for RWX changes - code injection indicator!)
    if !request_approval(operation) {
        // DENIED - return FALSE
        return windows::Win32::Foundation::BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_VIRTUAL_PROTECT {
        orig(lpaddress, dwsize, flnewprotect, lpfloldprotect)
    } else {
        windows::Win32::Foundation::BOOL(0)
    }
}

/// Hooked WriteProcessMemory - intercepts process injection
unsafe extern "system" fn hooked_write_process_memory(
    hprocess: HANDLE,
    lpbaseaddress: *const std::ffi::c_void,
    lpbuffer: *const std::ffi::c_void,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize,
) -> windows::Win32::Foundation::BOOL {
    // Get target process ID
    let target_pid = unsafe {
        use windows::Win32::System::Threading::GetProcessId;
        GetProcessId(hprocess)
    };

    let operation = HookOperation::MemoryWrite {
        target_process_id: target_pid,
        base_address: lpbaseaddress as u64,
        bytes_to_write: nsize as u32,
    };

    // REQUEST APPROVAL (cross-process memory writes = injection!)
    if !request_approval(operation) {
        // DENIED - return FALSE
        return windows::Win32::Foundation::BOOL(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_WRITE_PROCESS_MEMORY {
        orig(hprocess, lpbaseaddress, lpbuffer, nsize, lpnumberofbyteswritten)
    } else {
        windows::Win32::Foundation::BOOL(0)
    }
}

/// Hooked LoadLibraryW - intercepts DLL loading
unsafe extern "system" fn hooked_load_library_w(
    lplibfilename: PCWSTR,
) -> windows::Win32::Foundation::HINSTANCE {
    let dll_path = utils::extract_path_from_pcwstr(lplibfilename);

    if dll_path.is_empty() {
        // Call original if path is empty
        if let Some(orig) = ORIG_LOAD_LIBRARY_W {
            return orig(lplibfilename);
        }
        return windows::Win32::Foundation::HINSTANCE(0);
    }

    let operation = HookOperation::DllLoad {
        dll_path,
        load_flags: 0,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return null handle
        return windows::Win32::Foundation::HINSTANCE(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_LOAD_LIBRARY_W {
        orig(lplibfilename)
    } else {
        windows::Win32::Foundation::HINSTANCE(0)
    }
}

/// Hooked LoadLibraryExW - intercepts DLL loading with flags
unsafe extern "system" fn hooked_load_library_ex_w(
    lplibfilename: PCWSTR,
    hfile: HANDLE,
    dwflags: u32,
) -> windows::Win32::Foundation::HINSTANCE {
    let dll_path = utils::extract_path_from_pcwstr(lplibfilename);

    if dll_path.is_empty() {
        // Call original if path is empty
        if let Some(orig) = ORIG_LOAD_LIBRARY_EX_W {
            return orig(lplibfilename, hfile, dwflags);
        }
        return windows::Win32::Foundation::HINSTANCE(0);
    }

    let operation = HookOperation::DllLoad {
        dll_path,
        load_flags: dwflags,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return null handle
        return windows::Win32::Foundation::HINSTANCE(0);
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_LOAD_LIBRARY_EX_W {
        orig(lplibfilename, hfile, dwflags)
    } else {
        windows::Win32::Foundation::HINSTANCE(0)
    }
}

/// Install memory/DLL operation hooks
pub unsafe fn install_memory_hooks() -> Result<(), String> {
    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::PCSTR(c"kernel32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to get kernel32: {}", e))?;

    // Hook VirtualAlloc
    let virtualalloc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"VirtualAlloc".as_ptr() as *const u8),
    )
    .ok_or("VirtualAlloc not found")?;

    let orig_virtualalloc = MinHook::create_hook(
        virtualalloc_addr as *mut _,
        hooked_virtual_alloc as *mut _,
    )
    .map_err(|e| format!("Failed to hook VirtualAlloc: {:?}", e))?;

    ORIG_VIRTUAL_ALLOC = Some(std::mem::transmute::<*mut std::ffi::c_void, FnVirtualAlloc>(orig_virtualalloc));

    MinHook::enable_hook(virtualalloc_addr as *mut _)
        .map_err(|e| format!("Failed to enable VirtualAlloc hook: {:?}", e))?;

    // Hook VirtualProtect
    let virtualprotect_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"VirtualProtect".as_ptr() as *const u8),
    )
    .ok_or("VirtualProtect not found")?;

    let orig_virtualprotect = MinHook::create_hook(
        virtualprotect_addr as *mut _,
        hooked_virtual_protect as *mut _,
    )
    .map_err(|e| format!("Failed to hook VirtualProtect: {:?}", e))?;

    ORIG_VIRTUAL_PROTECT = Some(std::mem::transmute::<*mut std::ffi::c_void, FnVirtualProtect>(orig_virtualprotect));

    MinHook::enable_hook(virtualprotect_addr as *mut _)
        .map_err(|e| format!("Failed to enable VirtualProtect hook: {:?}", e))?;

    // Hook WriteProcessMemory
    let writeprocessmemory_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"WriteProcessMemory".as_ptr() as *const u8),
    )
    .ok_or("WriteProcessMemory not found")?;

    let orig_writeprocessmemory = MinHook::create_hook(
        writeprocessmemory_addr as *mut _,
        hooked_write_process_memory as *mut _,
    )
    .map_err(|e| format!("Failed to hook WriteProcessMemory: {:?}", e))?;

    ORIG_WRITE_PROCESS_MEMORY = Some(std::mem::transmute::<*mut std::ffi::c_void, FnWriteProcessMemory>(orig_writeprocessmemory));

    MinHook::enable_hook(writeprocessmemory_addr as *mut _)
        .map_err(|e| format!("Failed to enable WriteProcessMemory hook: {:?}", e))?;

    // Hook LoadLibraryW
    let loadlibraryw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"LoadLibraryW".as_ptr() as *const u8),
    )
    .ok_or("LoadLibraryW not found")?;

    let orig_loadlibraryw = MinHook::create_hook(
        loadlibraryw_addr as *mut _,
        hooked_load_library_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook LoadLibraryW: {:?}", e))?;

    ORIG_LOAD_LIBRARY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnLoadLibraryW>(orig_loadlibraryw));

    MinHook::enable_hook(loadlibraryw_addr as *mut _)
        .map_err(|e| format!("Failed to enable LoadLibraryW hook: {:?}", e))?;

    // Hook LoadLibraryExW
    let loadlibraryexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"LoadLibraryExW".as_ptr() as *const u8),
    )
    .ok_or("LoadLibraryExW not found")?;

    let orig_loadlibraryexw = MinHook::create_hook(
        loadlibraryexw_addr as *mut _,
        hooked_load_library_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook LoadLibraryExW: {:?}", e))?;

    ORIG_LOAD_LIBRARY_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnLoadLibraryExW>(orig_loadlibraryexw));

    MinHook::enable_hook(loadlibraryexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable LoadLibraryExW hook: {:?}", e))?;

    Ok(())
}
