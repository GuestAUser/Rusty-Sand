//! API Hooking DLL for Rusty Sand - V2 (REAL Inline Hooks - FIXED)
//!
//! This DLL implements TRUE real-time prevention using MinHook for inline hooking.
//! Operations are intercepted BEFORE execution and blocked if user denies.

use minhook::MinHook;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR};
use windows::Win32::Networking::WinSock::{SOCKADDR, SOCKET};
use windows::Win32::Storage::FileSystem::FILE_SHARE_MODE;
use windows::Win32::System::Registry::{HKEY, REG_VALUE_TYPE};
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// ==============================================
// IPC PROTOCOL
// ==============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRequest {
    pub operation: HookOperation,
    pub pid: u32,
    pub tid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    pub allowed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookOperation {
    FileCreate { path: String },
    FileWrite { path: String },
    FileDelete { path: String },
    FolderCreate { path: String },
    FolderDelete { path: String },
    RegistrySet { key: String, value: String },
    RegistryDelete { key: String },
    RegistryRead { key: String, value: String },
    RegistryOpen { key: String },
    NetworkConnect { remote_addr: String, port: u16 },
    ProcessCreate { executable: String, args: String },
}

// ==============================================
// IPC CLIENT
// ==============================================

pub struct HookIpcClient {
    pipe_handle: HANDLE,
}

impl HookIpcClient {
    pub fn connect() -> Result<Self, String> {
        let pipe_name = r"\\.\pipe\rusty_sand_hooks";
        let mut pipe_name_wide: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();

        let pipe_handle = unsafe {
            windows::Win32::Storage::FileSystem::CreateFileW(
                PCWSTR(pipe_name_wide.as_mut_ptr()),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_MODE(0),
                None,
                windows::Win32::Storage::FileSystem::OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE(0),
            )
        };

        if pipe_handle.is_err() || pipe_handle.as_ref().unwrap().is_invalid() {
            return Err("Failed to connect to IPC pipe".to_string());
        }

        Ok(Self {
            pipe_handle: pipe_handle.unwrap(),
        })
    }

    pub fn request_approval(&self, request: &HookRequest) -> Result<HookResponse, String> {
        // Serialize request
        let json = serde_json::to_string(request).map_err(|e| e.to_string())?;
        let json_bytes = json.as_bytes();

        // Write request
        let mut bytes_written = 0u32;
        unsafe {
            windows::Win32::Storage::FileSystem::WriteFile(
                self.pipe_handle,
                Some(json_bytes),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|e| format!("IPC write failed: {}", e))?;
        }

        // Read response
        let mut buffer = [0u8; 4096];
        let mut bytes_read = 0u32;
        unsafe {
            windows::Win32::Storage::FileSystem::ReadFile(
                self.pipe_handle,
                Some(&mut buffer[..]),
                Some(&mut bytes_read),
                None,
            )
            .map_err(|e| format!("IPC read failed: {}", e))?;
        }

        // Deserialize response
        let json_str = std::str::from_utf8(&buffer[..bytes_read as usize])
            .map_err(|e| format!("UTF-8 decode failed: {}", e))?;
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse failed: {}", e))
    }
}

// ==============================================
// GLOBAL STATE
// ==============================================

static IPC_CLIENT: Lazy<Arc<Mutex<Option<HookIpcClient>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

// Original function pointers (trampolines) - FIXED FFI SIGNATURES
static mut ORIG_CREATE_FILE_W: Option<FnCreateFileW> = None;
static mut ORIG_REMOVE_DIRECTORY_W: Option<FnRemoveDirectoryW> = None;
static mut ORIG_CONNECT: Option<FnConnect> = None;
static mut ORIG_REG_SET_VALUE_EX_W: Option<FnRegSetValueExW> = None;
static mut ORIG_REG_DELETE_KEY_W: Option<FnRegDeleteKeyW> = None;
static mut ORIG_REG_QUERY_VALUE_EX_W: Option<FnRegQueryValueExW> = None;
static mut ORIG_REG_OPEN_KEY_EX_W: Option<FnRegOpenKeyExW> = None;

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

// ==============================================
// FUNCTION TYPE DEFINITIONS - FFI SAFE!
// ==============================================

type FnCreateFileW = unsafe extern "system" fn(
    PCWSTR,
    u32,
    FILE_SHARE_MODE,
    *const std::ffi::c_void,
    u32,
    u32,
    HANDLE,
) -> HANDLE; // FIXED: Returns raw HANDLE, not Result!

type FnRemoveDirectoryW = unsafe extern "system" fn(PCWSTR) -> windows::Win32::Foundation::BOOL;

type FnConnect = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;

type FnRegSetValueExW = unsafe extern "system" fn(
    HKEY,
    PCWSTR,
    u32,
    REG_VALUE_TYPE,
    *const u8,
    u32,
) -> WIN32_ERROR;

type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, PCWSTR) -> WIN32_ERROR;

type FnRegQueryValueExW = unsafe extern "system" fn(
    HKEY,
    PCWSTR,
    *const u32,
    *mut REG_VALUE_TYPE,
    *mut u8,
    *mut u32,
) -> WIN32_ERROR;

type FnRegOpenKeyExW = unsafe extern "system" fn(
    HKEY,
    PCWSTR,
    u32,
    u32,
    *mut HKEY,
) -> WIN32_ERROR;

// ==============================================
// HOOKED FUNCTIONS - FFI SAFE!
// ==============================================

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
    let file_path = if !lpfilename.is_null() {
        let mut len = 0;
        while *lpfilename.0.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(lpfilename.0, len as usize);
        String::from_utf16_lossy(slice)
    } else {
        // Call original if null
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

    // Determine operation type
    const CREATE_NEW: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const OPEN_ALWAYS: u32 = 4;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;

    // Check if this is a directory operation
    let is_directory = (dwflagsandattributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        || (dwflagsandattributes & FILE_FLAG_BACKUP_SEMANTICS) != 0;

    let operation = match dwcreationdisposition {
        CREATE_NEW | CREATE_ALWAYS => {
            if is_directory {
                HookOperation::FolderCreate {
                    path: file_path.clone(),
                }
            } else {
                HookOperation::FileCreate {
                    path: file_path.clone(),
                }
            }
        }
        OPEN_EXISTING | OPEN_ALWAYS if dwdesiredaccess & GENERIC_WRITE != 0 => {
            HookOperation::FileWrite {
                path: file_path.clone(),
            }
        }
        _ => {
            // Read-only - allow without prompting
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

/// Hooked RemoveDirectoryW - intercepts folder deletion BEFORE execution
unsafe extern "system" fn hooked_remove_directory_w(lppathname: PCWSTR) -> windows::Win32::Foundation::BOOL {
    // Extract folder path
    let folder_path = if !lppathname.is_null() {
        let mut len = 0;
        while *lppathname.0.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(lppathname.0, len as usize);
        String::from_utf16_lossy(slice)
    } else {
        // Call original if null
        if let Some(orig) = ORIG_REMOVE_DIRECTORY_W {
            return orig(lppathname);
        }
        return windows::Win32::Foundation::BOOL(0);
    };

    let operation = HookOperation::FolderDelete {
        path: folder_path,
    };

    // REQUEST APPROVAL - THIS IS WHERE WE BLOCK!
    if !request_approval(operation) {
        // DENIED - return FALSE (failure)
        return windows::Win32::Foundation::BOOL(0);
    }

    // ALLOWED - call original function
    if let Some(orig) = ORIG_REMOVE_DIRECTORY_W {
        orig(lppathname)
    } else {
        windows::Win32::Foundation::BOOL(0)
    }
}

/// Hooked connect - intercepts network connections BEFORE execution
unsafe extern "system" fn hooked_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    // Extract IP and port
    let (addr, port) = if !name.is_null() && namelen >= 16 {
        let sockaddr = &*name;
        let port_bytes =
            std::slice::from_raw_parts((sockaddr as *const _ as *const u8).offset(2), 2);
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

        let ip_bytes =
            std::slice::from_raw_parts((sockaddr as *const _ as *const u8).offset(4), 4);
        let addr = format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        );

        (addr, port)
    } else {
        ("unknown".to_string(), 0)
    };

    let operation = HookOperation::NetworkConnect {
        remote_addr: addr,
        port,
    };

    // REQUEST APPROVAL - THIS IS WHERE WE BLOCK!
    if !request_approval(operation) {
        // DENIED - return error WITHOUT calling original
        return -1; // SOCKET_ERROR
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_CONNECT {
        orig(s, name, namelen)
    } else {
        -1
    }
}

/// Hooked RegSetValueExW - intercepts registry value writes
unsafe extern "system" fn hooked_reg_set_value_ex_w(
    hkey: HKEY,
    lpvaluename: PCWSTR,
    reserved: u32,
    dwtype: REG_VALUE_TYPE,
    lpdata: *const u8,
    cbdata: u32,
) -> WIN32_ERROR {
    // Extract value name
    let value_name = if !lpvaluename.is_null() {
        match lpvaluename.to_string() {
            Ok(s) => s,
            Err(_) => "<invalid>".to_string(),
        }
    } else {
        "(Default)".to_string()
    };

    // For registry, we need to get the key path
    // For simplicity, we'll use a generic description
    let key_path = format!("HKEY_{:?}", hkey.0);

    let operation = HookOperation::RegistrySet {
        key: key_path.clone(),
        value: value_name,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return access denied error
        return WIN32_ERROR(5); // ERROR_ACCESS_DENIED
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_REG_SET_VALUE_EX_W {
        orig(hkey, lpvaluename, reserved, dwtype, lpdata, cbdata)
    } else {
        WIN32_ERROR(1) // ERROR_INVALID_FUNCTION
    }
}

/// Hooked RegDeleteKeyW - intercepts registry key deletions
unsafe extern "system" fn hooked_reg_delete_key_w(hkey: HKEY, lpsubkey: PCWSTR) -> WIN32_ERROR {
    // Extract subkey name
    let subkey_name = if !lpsubkey.is_null() {
        match lpsubkey.to_string() {
            Ok(s) => s,
            Err(_) => "<invalid>".to_string(),
        }
    } else {
        "".to_string()
    };

    let key_path = format!("HKEY_{:?}\\{}", hkey.0, subkey_name);

    let operation = HookOperation::RegistryDelete { key: key_path };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return access denied error
        return WIN32_ERROR(5); // ERROR_ACCESS_DENIED
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_REG_DELETE_KEY_W {
        orig(hkey, lpsubkey)
    } else {
        WIN32_ERROR(1) // ERROR_INVALID_FUNCTION
    }
}

/// Hooked RegQueryValueExW - intercepts registry value READS
unsafe extern "system" fn hooked_reg_query_value_ex_w(
    hkey: HKEY,
    lpvaluename: PCWSTR,
    lpreserved: *const u32,
    lptype: *mut REG_VALUE_TYPE,
    lpdata: *mut u8,
    lpcbdata: *mut u32,
) -> WIN32_ERROR {
    // Extract value name
    let value_name = if !lpvaluename.is_null() {
        match lpvaluename.to_string() {
            Ok(s) => s,
            Err(_) => "<invalid>".to_string(),
        }
    } else {
        "(Default)".to_string()
    };

    let key_path = format!("HKEY_{:?}", hkey.0);

    let operation = HookOperation::RegistryRead {
        key: key_path.clone(),
        value: value_name,
    };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return access denied error
        return WIN32_ERROR(5); // ERROR_ACCESS_DENIED
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_REG_QUERY_VALUE_EX_W {
        orig(hkey, lpvaluename, lpreserved, lptype, lpdata, lpcbdata)
    } else {
        WIN32_ERROR(1) // ERROR_INVALID_FUNCTION
    }
}

/// Hooked RegOpenKeyExW - intercepts registry key OPENS
unsafe extern "system" fn hooked_reg_open_key_ex_w(
    hkey: HKEY,
    lpsubkey: PCWSTR,
    uloptions: u32,
    samdesired: u32,
    phkresult: *mut HKEY,
) -> WIN32_ERROR {
    // Extract subkey name
    let subkey_name = if !lpsubkey.is_null() {
        match lpsubkey.to_string() {
            Ok(s) => s,
            Err(_) => "<invalid>".to_string(),
        }
    } else {
        "".to_string()
    };

    let key_path = format!("HKEY_{:?}\\{}", hkey.0, subkey_name);

    let operation = HookOperation::RegistryOpen { key: key_path };

    // REQUEST APPROVAL
    if !request_approval(operation) {
        // DENIED - return access denied error
        return WIN32_ERROR(5); // ERROR_ACCESS_DENIED
    }

    // ALLOWED - call original
    if let Some(orig) = ORIG_REG_OPEN_KEY_EX_W {
        orig(hkey, lpsubkey, uloptions, samdesired, phkresult)
    } else {
        WIN32_ERROR(1) // ERROR_INVALID_FUNCTION
    }
}

// ==============================================
// HOOK INSTALLATION
// ==============================================

unsafe fn install_hooks() -> Result<(), String> {
    // Get kernel32.dll
    let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::PCSTR(c"kernel32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to get kernel32: {}", e))?;

    // Get ws2_32.dll
    let ws2_32 = windows::Win32::System::LibraryLoader::LoadLibraryA(
        windows::core::PCSTR(c"ws2_32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to load ws2_32: {}", e))?;

    // Get advapi32.dll (for registry functions)
    let advapi32 = windows::Win32::System::LibraryLoader::LoadLibraryA(
        windows::core::PCSTR(c"advapi32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to load advapi32: {}", e))?;

    // Get CreateFileW address
    let createfilew_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"CreateFileW".as_ptr() as *const u8),
    )
    .ok_or("CreateFileW not found")?;

    // Get RemoveDirectoryW address
    let removedirectoryw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        kernel32,
        windows::core::PCSTR(c"RemoveDirectoryW".as_ptr() as *const u8),
    )
    .ok_or("RemoveDirectoryW not found")?;

    // Get connect address
    let connect_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        ws2_32,
        windows::core::PCSTR(c"connect".as_ptr() as *const u8),
    )
    .ok_or("connect not found")?;

    // Get RegSetValueExW address
    let regsetvalueexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegSetValueExW".as_ptr() as *const u8),
    )
    .ok_or("RegSetValueExW not found")?;

    // Get RegDeleteKeyW address
    let regdeletekeyw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegDeleteKeyW".as_ptr() as *const u8),
    )
    .ok_or("RegDeleteKeyW not found")?;

    // Get RegQueryValueExW address
    let regqueryvalueexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegQueryValueExW".as_ptr() as *const u8),
    )
    .ok_or("RegQueryValueExW not found")?;

    // Get RegOpenKeyExW address
    let regopenkeyexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegOpenKeyExW".as_ptr() as *const u8),
    )
    .ok_or("RegOpenKeyExW not found")?;

    // Hook CreateFileW
    let orig_createfilew = MinHook::create_hook(
        createfilew_addr as *mut _,
        hooked_create_file_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook CreateFileW: {:?}", e))?;

    ORIG_CREATE_FILE_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnCreateFileW>(orig_createfilew));

    MinHook::enable_hook(createfilew_addr as *mut _)
        .map_err(|e| format!("Failed to enable CreateFileW hook: {:?}", e))?;

    // Hook RemoveDirectoryW
    let orig_removedirectoryw = MinHook::create_hook(
        removedirectoryw_addr as *mut _,
        hooked_remove_directory_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RemoveDirectoryW: {:?}", e))?;

    ORIG_REMOVE_DIRECTORY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRemoveDirectoryW>(orig_removedirectoryw));

    MinHook::enable_hook(removedirectoryw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RemoveDirectoryW hook: {:?}", e))?;

    // Hook connect
    let orig_connect = MinHook::create_hook(connect_addr as *mut _, hooked_connect as *mut _)
        .map_err(|e| format!("Failed to hook connect: {:?}", e))?;

    ORIG_CONNECT = Some(std::mem::transmute::<*mut std::ffi::c_void, FnConnect>(orig_connect));

    MinHook::enable_hook(connect_addr as *mut _)
        .map_err(|e| format!("Failed to enable connect hook: {:?}", e))?;

    // Hook RegSetValueExW
    let orig_regsetvalueexw = MinHook::create_hook(
        regsetvalueexw_addr as *mut _,
        hooked_reg_set_value_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegSetValueExW: {:?}", e))?;

    ORIG_REG_SET_VALUE_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegSetValueExW>(orig_regsetvalueexw));

    MinHook::enable_hook(regsetvalueexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegSetValueExW hook: {:?}", e))?;

    // Hook RegDeleteKeyW
    let orig_regdeletekeyw = MinHook::create_hook(
        regdeletekeyw_addr as *mut _,
        hooked_reg_delete_key_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegDeleteKeyW: {:?}", e))?;

    ORIG_REG_DELETE_KEY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegDeleteKeyW>(orig_regdeletekeyw));

    MinHook::enable_hook(regdeletekeyw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegDeleteKeyW hook: {:?}", e))?;

    // Hook RegQueryValueExW (READ)
    let orig_regqueryvalueexw = MinHook::create_hook(
        regqueryvalueexw_addr as *mut _,
        hooked_reg_query_value_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegQueryValueExW: {:?}", e))?;

    ORIG_REG_QUERY_VALUE_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegQueryValueExW>(orig_regqueryvalueexw));

    MinHook::enable_hook(regqueryvalueexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegQueryValueExW hook: {:?}", e))?;

    // Hook RegOpenKeyExW (OPEN)
    let orig_regopenkeyexw = MinHook::create_hook(
        regopenkeyexw_addr as *mut _,
        hooked_reg_open_key_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegOpenKeyExW: {:?}", e))?;

    ORIG_REG_OPEN_KEY_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegOpenKeyExW>(orig_regopenkeyexw));

    MinHook::enable_hook(regopenkeyexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegOpenKeyExW hook: {:?}", e))?;

    Ok(())
}

// ==============================================
// DLL ENTRY POINT
// ==============================================

/// DLL entry point for hook initialization
///
/// # Safety
///
/// This function is called by Windows when the DLL is loaded/unloaded.
/// It must maintain proper FFI calling conventions and handle all Windows-specific
/// synchronization requirements. The function:
/// - Connects to the IPC server on DLL_PROCESS_ATTACH
/// - Installs API hooks using MinHook
/// - Disables all hooks on DLL_PROCESS_DETACH
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HANDLE,
    fdw_reason: u32,
    _lpv_reserved: *const std::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Connect to IPC server FIRST
            match HookIpcClient::connect() {
                Ok(client) => {
                    *IPC_CLIENT.lock() = Some(client);

                    // Install REAL hooks
                    match install_hooks() {
                        Ok(_) => {
                            // SUCCESS - hooks are active!
                            BOOL(1)
                        }
                        Err(_e) => {
                            // Failed to install hooks - still load but no interception
                            BOOL(1)
                        }
                    }
                }
                Err(_e) => {
                    // Failed to connect to IPC - load anyway
                    BOOL(1)
                }
            }
        }
        DLL_PROCESS_DETACH => {
            // Disable all hooks
            let _ = MinHook::disable_all_hooks();
            BOOL(1)
        }
        _ => BOOL(1),
    }
}
