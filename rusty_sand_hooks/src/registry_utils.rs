//! Registry utilities for HKEY resolution and path construction
//!
//! This module provides utilities to convert raw HKEY handles into human-readable
//! registry paths like "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

use windows::core::PCWSTR;
use windows::Win32::System::Registry::HKEY;

/// Predefined registry key handles
/// These are constant values defined by Windows API
const HKEY_CLASSES_ROOT: isize = 0x80000000_u32 as isize;
const HKEY_CURRENT_USER: isize = 0x80000001_u32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002_u32 as isize;
const HKEY_USERS: isize = 0x80000003_u32 as isize;
const HKEY_PERFORMANCE_DATA: isize = 0x80000004_u32 as isize;
const HKEY_CURRENT_CONFIG: isize = 0x80000007_u32 as isize;
const HKEY_DYN_DATA: isize = 0x80000006_u32 as isize;

/// Convert HKEY handle to human-readable root key name
///
/// # Arguments
/// * `hkey` - Raw HKEY handle from Windows API
///
/// # Returns
/// String representation like "HKLM", "HKCU", etc.
pub fn hkey_to_root_name(hkey: HKEY) -> String {
    let handle_value = hkey.0 as isize;

    match handle_value {
        HKEY_CLASSES_ROOT => "HKCR".to_string(),
        HKEY_CURRENT_USER => "HKCU".to_string(),
        HKEY_LOCAL_MACHINE => "HKLM".to_string(),
        HKEY_USERS => "HKU".to_string(),
        HKEY_PERFORMANCE_DATA => "HKPD".to_string(),
        HKEY_CURRENT_CONFIG => "HKCC".to_string(),
        HKEY_DYN_DATA => "HKDD".to_string(),
        _ => {
            // This is a subkey handle opened by RegOpenKeyEx, not a predefined root
            // We can't resolve it without maintaining a global handle->path map
            // For now, return a placeholder
            format!("HKEY_HANDLE(0x{:X})", handle_value)
        }
    }
}

/// Convert HKEY handle to full name (expanded form)
///
/// # Arguments
/// * `hkey` - Raw HKEY handle from Windows API
///
/// # Returns
/// String representation like "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", etc.
///
/// Note: Kept for future detailed reporting features
#[allow(dead_code)]
pub fn hkey_to_full_name(hkey: HKEY) -> String {
    let handle_value = hkey.0 as isize;

    match handle_value {
        HKEY_CLASSES_ROOT => "HKEY_CLASSES_ROOT".to_string(),
        HKEY_CURRENT_USER => "HKEY_CURRENT_USER".to_string(),
        HKEY_LOCAL_MACHINE => "HKEY_LOCAL_MACHINE".to_string(),
        HKEY_USERS => "HKEY_USERS".to_string(),
        HKEY_PERFORMANCE_DATA => "HKEY_PERFORMANCE_DATA".to_string(),
        HKEY_CURRENT_CONFIG => "HKEY_CURRENT_CONFIG".to_string(),
        HKEY_DYN_DATA => "HKEY_DYN_DATA".to_string(),
        _ => format!("HKEY_HANDLE(0x{:X})", handle_value),
    }
}

/// Build full registry path from HKEY and subkey
///
/// # Arguments
/// * `hkey` - Root registry key handle
/// * `subkey` - Subkey path (can be empty)
///
/// # Returns
/// Full registry path like "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
///
/// # Safety
/// This function is safe to call with any HKEY and string
pub fn build_registry_path(hkey: HKEY, subkey: &str) -> String {
    let root = hkey_to_root_name(hkey);

    if subkey.is_empty() {
        root
    } else {
        format!("{}\\{}", root, subkey)
    }
}

/// Build full registry path with value name
///
/// # Arguments
/// * `hkey` - Root registry key handle
/// * `subkey` - Subkey path (can be empty)
/// * `value_name` - Value name (use "(Default)" for default value)
///
/// # Returns
/// Full registry path with value like "HKLM\Software\...\Run::StartupApp"
pub fn build_registry_path_with_value(hkey: HKEY, subkey: &str, value_name: &str) -> String {
    let key_path = build_registry_path(hkey, subkey);

    if value_name.is_empty() || value_name == "(Default)" {
        format!("{}::(Default)", key_path)
    } else {
        format!("{}::{}", key_path, value_name)
    }
}

/// Extract string from PCWSTR (wide string pointer)
///
/// # Arguments
/// * `pcwstr` - Pointer to wide string (UTF-16)
///
/// # Returns
/// Rust String, or "<null>" / "<invalid>" on error
///
/// # Safety
/// Caller must ensure the pointer is valid and null-terminated
pub unsafe fn pcwstr_to_string(pcwstr: PCWSTR) -> String {
    if pcwstr.is_null() {
        return "<null>".to_string();
    }

    match pcwstr.to_string() {
        Ok(s) => s,
        Err(_) => {
            // Fallback: manual UTF-16 parsing
            let mut len = 0;
            while *pcwstr.0.offset(len) != 0 {
                len += 1;
                if len > 32767 {
                    // Prevent infinite loop on invalid pointer
                    return "<invalid>".to_string();
                }
            }
            let slice = std::slice::from_raw_parts(pcwstr.0, len as usize);
            String::from_utf16_lossy(slice)
        }
    }
}

/// Convert registry data type to human-readable string
///
/// # Arguments
/// * `reg_type` - REG_VALUE_TYPE from Windows API
///
/// # Returns
/// String like "REG_SZ", "REG_DWORD", etc.
///
/// Note: Kept for future content analysis features (Phase 3)
#[allow(dead_code)]
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

/// Check if registry key path is sensitive (requires elevated privileges or security critical)
///
/// # Arguments
/// * `key_path` - Full registry key path
///
/// # Returns
/// true if the key is considered sensitive
///
/// Note: Kept for future risk scoring system (Phase 3)
#[allow(dead_code)]
pub fn is_sensitive_registry_key(key_path: &str) -> bool {
    let key_lower = key_path.to_lowercase();

    // Persistence mechanisms
    if key_lower.contains("\\run") || key_lower.contains("\\runonce") {
        return true;
    }

    // Security products
    if key_lower.contains("windows defender")
        || key_lower.contains("firewall")
        || key_lower.contains("antivirus")
        || key_lower.contains("security center") {
        return true;
    }

    // UAC bypass vectors
    if key_lower.contains("\\environment\\windir")
        || key_lower.contains("ms-settings") {
        return true;
    }

    // System integrity
    if key_lower.contains("\\policies\\system")
        || key_lower.contains("\\control\\lsa")
        || key_lower.contains("\\sam\\") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkey_to_root_name() {
        // Test predefined handles
        let hklm = HKEY(0x80000002_u32 as isize);
        assert_eq!(hkey_to_root_name(hklm), "HKLM");

        let hkcu = HKEY(0x80000001_u32 as isize);
        assert_eq!(hkey_to_root_name(hkcu), "HKCU");
    }

    #[test]
    fn test_build_registry_path() {
        let hklm = HKEY(0x80000002_u32 as isize);
        let path = build_registry_path(hklm, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        assert_eq!(path, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    }

    #[test]
    fn test_is_sensitive_registry_key() {
        assert!(is_sensitive_registry_key("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(is_sensitive_registry_key("HKCU\\Software\\Microsoft\\Windows Defender"));
        assert!(!is_sensitive_registry_key("HKCU\\Software\\MyApp\\Settings"));
    }

    #[test]
    fn test_reg_type_to_string() {
        assert_eq!(reg_type_to_string(1), "REG_SZ");
        assert_eq!(reg_type_to_string(4), "REG_DWORD");
        assert_eq!(reg_type_to_string(11), "REG_QWORD");
    }
}
