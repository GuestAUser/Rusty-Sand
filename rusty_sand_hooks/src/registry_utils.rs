fn predefined_root(handle: isize) -> Option<&'static str> {
    let raw = handle as u32;
    /* Windows predefined HKEY values sign-extend LONG, not unsigned DWORD. */
    if handle != raw as i32 as isize {
        return None;
    }
    match raw {
        0x8000_0000 => Some("HKCR"),
        0x8000_0001 => Some("HKCU"),
        0x8000_0002 => Some("HKLM"),
        0x8000_0003 => Some("HKU"),
        0x8000_0004 => Some("HKPD"),
        0x8000_0005 => Some("HKPT"),
        0x8000_0006 => Some("HKPN"),
        0x8000_0007 => Some("HKCC"),
        _ => None,
    }
}

fn display_native_path(path: &str) -> String {
    for (prefix, root) in [(r"\REGISTRY\MACHINE", "HKLM"), (r"\REGISTRY\USER", "HKU")] {
        if let Some(head) = path.get(..prefix.len()) {
            if head.eq_ignore_ascii_case(prefix) {
                let suffix = &path[prefix.len()..];
                if suffix.is_empty() || suffix.starts_with('\\') {
                    return format!("{root}{suffix}");
                }
            }
        }
    }
    path.to_owned()
}

fn join_path(root: &str, subkey: &str) -> String {
    if subkey.is_empty() {
        root.to_owned()
    } else {
        format!("{root}\\{subkey}")
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::buffers::{self, BufferError};
    use crate::utils::InspectionError;
    use std::ffi::c_void;
    use windows::Win32::System::Registry::HKEY;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryKey(
            key: HKEY,
            information_class: u32,
            information: *mut c_void,
            length: u32,
            result_length: *mut u32,
        ) -> i32;
    }

    pub fn hkey_to_root_name(key: HKEY) -> Result<String, InspectionError> {
        if let Some(root) = predefined_root(key.0) {
            return Ok(root.into());
        }
        let mut length = 0;
        /* SAFETY: KeyNameInformation (3) accepts a zero-length sizing query.
        The kernel validates the borrowed HKEY; only local length is written. */
        let status = unsafe { NtQueryKey(key, 3, std::ptr::null_mut(), 0, &mut length) };
        if status != 0xC000_0023_u32 as i32 && status != 0x8000_0005_u32 as i32 {
            return Err(InspectionError::RegistryStatus(status));
        }
        if !(4..=65_540).contains(&length) {
            return Err(BufferError::InvalidLength.into());
        }
        let mut storage = vec![0_u32; (length as usize).div_ceil(4)];
        let capacity = length;
        /* SAFETY: u32 storage has the alignment required by KEY_NAME_INFORMATION
        and owns at least capacity initialized bytes until the call returns. */
        let status =
            unsafe { NtQueryKey(key, 3, storage.as_mut_ptr().cast(), capacity, &mut length) };
        if status != 0 {
            return Err(InspectionError::RegistryStatus(status));
        }
        if length > capacity {
            return Err(BufferError::InvalidLength.into());
        }
        /* SAFETY: u32 has no padding; all storage bytes are initialized and the
        returned byte count was checked against the allocation's capacity. */
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
        Ok(display_native_path(&buffers::registry_name(bytes)?))
    }

    pub fn build_registry_path(key: HKEY, subkey: &str) -> Result<String, InspectionError> {
        Ok(join_path(&hkey_to_root_name(key)?, subkey))
    }

    pub fn build_registry_path_with_value(
        key: HKEY,
        subkey: &str,
        value: &str,
    ) -> Result<String, InspectionError> {
        let path = build_registry_path(key, subkey)?;
        let value = if value.is_empty() { "(Default)" } else { value };
        Ok(format!("{path}::{value}"))
    }
}

#[cfg(windows)]
pub use native::{build_registry_path, build_registry_path_with_value, hkey_to_root_name};

pub fn reg_type_to_string(reg_type: u32) -> &'static str {
    match reg_type {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

pub fn is_sensitive_registry_key(key_path: &str) -> bool {
    let lower = key_path.to_ascii_lowercase();
    lower
        .split('\\')
        .any(|part| matches!(part, "run" | "runonce" | "runonceex" | "sam"))
        || [
            "windows defender",
            "firewall",
            "antivirus",
            "security center",
            r"\environment\windir",
            "ms-settings",
            r"\policies\system",
            r"\control\lsa",
        ]
        .iter()
        .any(|pattern| lower.contains(pattern))
}

#[cfg(test)]
#[path = "../tests/unit/registry_utils.rs"]
mod tests;
