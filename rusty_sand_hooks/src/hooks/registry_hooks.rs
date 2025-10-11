//! Registry operation hooks (RegSetValueExW, RegDeleteKeyW, etc.)

use crate::hooks::file_hooks::IPC_CLIENT;
use crate::registry_utils;
use crate::types::{HookOperation, HookRequest};
use minhook::MinHook;
use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Registry::{HKEY, REG_VALUE_TYPE};
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

// Original function pointers
static mut ORIG_REG_SET_VALUE_EX_W: Option<FnRegSetValueExW> = None;
static mut ORIG_REG_DELETE_KEY_W: Option<FnRegDeleteKeyW> = None;
static mut ORIG_REG_QUERY_VALUE_EX_W: Option<FnRegQueryValueExW> = None;
static mut ORIG_REG_OPEN_KEY_EX_W: Option<FnRegOpenKeyExW> = None;

// Function type definitions
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
    let value_name = registry_utils::pcwstr_to_string(lpvaluename);

    // Build full registry path (now human-readable!)
    let key_path = registry_utils::build_registry_path_with_value(hkey, "", &value_name);

    let operation = HookOperation::RegistrySet {
        key: key_path,
        value: value_name,
        data_type: dwtype.0,
        data_size: cbdata,
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
    let subkey_name = registry_utils::pcwstr_to_string(lpsubkey);

    // Build full registry path
    let key_path = registry_utils::build_registry_path(hkey, &subkey_name);

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
    let value_name = registry_utils::pcwstr_to_string(lpvaluename);

    // Build full registry path with value
    let key_path = registry_utils::build_registry_path_with_value(hkey, "", &value_name);

    let operation = HookOperation::RegistryRead {
        key: key_path,
        value: value_name,
    };

    // REQUEST APPROVAL (will be auto-allowed for read operations if configured)
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
    let subkey_name = registry_utils::pcwstr_to_string(lpsubkey);

    // Build full registry path
    let key_path = registry_utils::build_registry_path(hkey, &subkey_name);

    let operation = HookOperation::RegistryOpen {
        key: key_path,
        access_rights: samdesired,
    };

    // REQUEST APPROVAL (will be auto-allowed for read-only access if configured)
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

/// Install registry operation hooks
pub unsafe fn install_registry_hooks() -> Result<(), String> {
    // Load advapi32.dll (for registry functions)
    let advapi32 = windows::Win32::System::LibraryLoader::LoadLibraryA(
        windows::core::PCSTR(c"advapi32.dll".as_ptr() as *const u8),
    )
    .map_err(|e| format!("Failed to load advapi32: {}", e))?;

    // Hook RegSetValueExW
    let regsetvalueexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegSetValueExW".as_ptr() as *const u8),
    )
    .ok_or("RegSetValueExW not found")?;

    let orig_regsetvalueexw = MinHook::create_hook(
        regsetvalueexw_addr as *mut _,
        hooked_reg_set_value_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegSetValueExW: {:?}", e))?;

    ORIG_REG_SET_VALUE_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegSetValueExW>(orig_regsetvalueexw));

    MinHook::enable_hook(regsetvalueexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegSetValueExW hook: {:?}", e))?;

    // Hook RegDeleteKeyW
    let regdeletekeyw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegDeleteKeyW".as_ptr() as *const u8),
    )
    .ok_or("RegDeleteKeyW not found")?;

    let orig_regdeletekeyw = MinHook::create_hook(
        regdeletekeyw_addr as *mut _,
        hooked_reg_delete_key_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegDeleteKeyW: {:?}", e))?;

    ORIG_REG_DELETE_KEY_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegDeleteKeyW>(orig_regdeletekeyw));

    MinHook::enable_hook(regdeletekeyw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegDeleteKeyW hook: {:?}", e))?;

    // Hook RegQueryValueExW (READ)
    let regqueryvalueexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegQueryValueExW".as_ptr() as *const u8),
    )
    .ok_or("RegQueryValueExW not found")?;

    let orig_regqueryvalueexw = MinHook::create_hook(
        regqueryvalueexw_addr as *mut _,
        hooked_reg_query_value_ex_w as *mut _,
    )
    .map_err(|e| format!("Failed to hook RegQueryValueExW: {:?}", e))?;

    ORIG_REG_QUERY_VALUE_EX_W = Some(std::mem::transmute::<*mut std::ffi::c_void, FnRegQueryValueExW>(orig_regqueryvalueexw));

    MinHook::enable_hook(regqueryvalueexw_addr as *mut _)
        .map_err(|e| format!("Failed to enable RegQueryValueExW hook: {:?}", e))?;

    // Hook RegOpenKeyExW (OPEN)
    let regopenkeyexw_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        advapi32,
        windows::core::PCSTR(c"RegOpenKeyExW".as_ptr() as *const u8),
    )
    .ok_or("RegOpenKeyExW not found")?;

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
