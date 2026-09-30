use crate::approval::approve;
use crate::installation::{InitializationError, Installation};
use crate::registry_utils::{build_registry_path, build_registry_path_with_value};
use crate::types::HookOperation;
use crate::utils::wide_string;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, WIN32_ERROR};
use windows::Win32::System::Registry::{HKEY, REG_VALUE_TYPE};

type SetValue =
    unsafe extern "system" fn(HKEY, PCWSTR, u32, REG_VALUE_TYPE, *const u8, u32) -> WIN32_ERROR;
type DeleteKey = unsafe extern "system" fn(HKEY, PCWSTR) -> WIN32_ERROR;
type QueryValue = unsafe extern "system" fn(
    HKEY,
    PCWSTR,
    *mut u32,
    *mut REG_VALUE_TYPE,
    *mut u8,
    *mut u32,
) -> WIN32_ERROR;
type OpenKey = unsafe extern "system" fn(HKEY, PCWSTR, u32, u32, *mut HKEY) -> WIN32_ERROR;
static SET_VALUE: OnceLock<SetValue> = OnceLock::new();
static DELETE_KEY: OnceLock<DeleteKey> = OnceLock::new();
static QUERY_VALUE: OnceLock<QueryValue> = OnceLock::new();
static OPEN_KEY: OnceLock<OpenKey> = OnceLock::new();

unsafe extern "system" fn set_value(
    key: HKEY,
    name: PCWSTR,
    reserved: u32,
    kind: REG_VALUE_TYPE,
    data: *const u8,
    length: u32,
) -> WIN32_ERROR {
    let Some(original) = SET_VALUE.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if !approve(|| {
        let value = wide_string(name)?;
        Ok(HookOperation::RegistrySet {
            key: build_registry_path_with_value(key, "", &value)?,
            value,
            data_type: kind.0,
            data_size: length,
        })
    }) {
        return ERROR_ACCESS_DENIED;
    }
    /* SAFETY: The immutable trampoline has RegSetValueExW's system ABI.
    Data is never dereferenced by Rust; the borrowed arguments are unchanged. */
    unsafe { original(key, name, reserved, kind, data, length) }
}

unsafe extern "system" fn delete_key(key: HKEY, subkey: PCWSTR) -> WIN32_ERROR {
    let Some(original) = DELETE_KEY.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if !approve(|| {
        Ok(HookOperation::RegistryDelete {
            key: build_registry_path(key, &wide_string(subkey)?)?,
        })
    }) {
        return ERROR_ACCESS_DENIED;
    }
    /* SAFETY: This process-lifetime RegDeleteKeyW trampoline receives the
    same borrowed handle and UTF-16 pointer supplied by its caller. */
    unsafe { original(key, subkey) }
}

unsafe extern "system" fn query_value(
    key: HKEY,
    name: PCWSTR,
    reserved: *mut u32,
    kind: *mut REG_VALUE_TYPE,
    data: *mut u8,
    length: *mut u32,
) -> WIN32_ERROR {
    let Some(original) = QUERY_VALUE.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if !approve(|| {
        let value = wide_string(name)?;
        Ok(HookOperation::RegistryRead {
            key: build_registry_path_with_value(key, "", &value)?,
            value,
        })
    }) {
        return ERROR_ACCESS_DENIED;
    }
    /* SAFETY: The RegQueryValueExW trampoline has the exact system ABI. Only
    Windows accesses output pointers, including nullable sizing buffers. */
    unsafe { original(key, name, reserved, kind, data, length) }
}

unsafe extern "system" fn open_key(
    key: HKEY,
    subkey: PCWSTR,
    options: u32,
    access: u32,
    result: *mut HKEY,
) -> WIN32_ERROR {
    let Some(original) = OPEN_KEY.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if !approve(|| {
        Ok(HookOperation::RegistryOpen {
            key: build_registry_path(key, &wide_string(subkey)?)?,
            access_rights: access,
        })
    }) {
        return ERROR_ACCESS_DENIED;
    }
    /* SAFETY: The RegOpenKeyExW trampoline and caller agree on ABI and output
    ownership. The hook neither reads nor writes the result handle. */
    unsafe { original(key, subkey, options, access, result) }
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"advapi32.dll")?;
    install_hook!(
        installation,
        module,
        c"RegSetValueExW",
        set_value,
        SET_VALUE,
        SetValue
    );
    install_hook!(
        installation,
        module,
        c"RegDeleteKeyW",
        delete_key,
        DELETE_KEY,
        DeleteKey
    );
    install_hook!(
        installation,
        module,
        c"RegQueryValueExW",
        query_value,
        QUERY_VALUE,
        QueryValue
    );
    install_hook!(
        installation,
        module,
        c"RegOpenKeyExW",
        open_key,
        OPEN_KEY,
        OpenKey
    );
    Ok(())
}
