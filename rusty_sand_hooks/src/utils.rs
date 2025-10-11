//! Common utilities for hook implementations

use windows::core::PCWSTR;

/// Extract file path from PCWSTR (wide string pointer)
///
/// # Safety
/// Caller must ensure the pointer is valid and null-terminated
pub unsafe fn extract_path_from_pcwstr(pcwstr: PCWSTR) -> String {
    if pcwstr.is_null() {
        return String::new();
    }

    match pcwstr.to_string() {
        Ok(s) => s,
        Err(_) => {
            // Fallback: manual UTF-16 parsing
            let mut len = 0;
            while len < 32767 && *pcwstr.0.offset(len) != 0 {
                len += 1;
            }
            if len == 0 {
                return String::new();
            }
            let slice = std::slice::from_raw_parts(pcwstr.0, len as usize);
            String::from_utf16_lossy(slice)
        }
    }
}

/// Check if a file path appears suspicious
///
/// Note: Kept for future risk scoring system (Phase 3)
#[allow(dead_code)]
pub fn is_suspicious_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();

    // System directories
    if path_lower.contains("\\windows\\system32")
        || path_lower.contains("\\windows\\syswow64") {
        return true;
    }

    // Startup locations
    if path_lower.contains("\\startup")
        || path_lower.contains("\\programdata\\microsoft\\windows\\start menu\\programs\\startup") {
        return true;
    }

    // Suspicious extensions in temp locations
    if (path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp"))
        && (path_lower.ends_with(".exe")
            || path_lower.ends_with(".dll")
            || path_lower.ends_with(".bat")
            || path_lower.ends_with(".vbs")
            || path_lower.ends_with(".ps1")) {
        return true;
    }

    false
}

/// Check if an IP address is private (RFC1918)
///
/// Note: Kept for future network analysis features (Phase 3)
#[allow(dead_code)]
pub fn is_private_ip(ip: &str) -> bool {
    // Parse IP address
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Vec<u8> = parts
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if octets.len() != 4 {
        return false;
    }

    // Check private ranges
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // Loopback 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }

    false
}

/// Check if a port number is considered suspicious (commonly used by malware)
///
/// Note: Kept for future threat detection features (Phase 3)
#[allow(dead_code)]
pub fn is_suspicious_port(port: u16) -> bool {
    matches!(port,
        // Common C2 ports (including Metasploit default 4444)
        4444 | 5555 | 6666 | 7777 | 8888 | 9999 |
        // Common backdoor ports
        31337 | 12345 | 54321 | 6667 | 6697 |
        // RAT ports
        1337 | 10000 | 20000 | 65535
    )
}

/// Memory protection constants and helpers
///
/// Note: These are kept for future memory analysis features (Phase 3)
#[allow(dead_code)]
pub mod memory_protection {
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    /// Check if memory protection includes execute permission
    pub fn is_executable(protection: u32) -> bool {
        protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// Check if memory protection allows write access
    pub fn is_writable(protection: u32) -> bool {
        protection & (0x04 | 0x08 | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// Check if memory protection is RWX (highly suspicious)
    pub fn is_rwx(protection: u32) -> bool {
        protection == PAGE_EXECUTE_READWRITE
    }
}

/// File access rights constants
///
/// Note: Some helpers kept for future file analysis features (Phase 3)
#[allow(dead_code)]
pub mod file_access {
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;

    pub fn has_write_access(access: u32) -> bool {
        access & (GENERIC_WRITE | GENERIC_ALL) != 0
    }

    pub fn has_read_access(access: u32) -> bool {
        access & (GENERIC_READ | GENERIC_ALL) != 0
    }
}

/// File creation disposition constants
///
/// Note: Some constants kept for future file analysis features (Phase 3)
#[allow(dead_code)]
pub mod file_disposition {
    pub const CREATE_NEW: u32 = 1;
    pub const CREATE_ALWAYS: u32 = 2;
    pub const OPEN_EXISTING: u32 = 3;
    pub const OPEN_ALWAYS: u32 = 4;
    pub const TRUNCATE_EXISTING: u32 = 5;

    pub fn creates_new_file(disposition: u32) -> bool {
        matches!(disposition, CREATE_NEW | CREATE_ALWAYS)
    }
}
