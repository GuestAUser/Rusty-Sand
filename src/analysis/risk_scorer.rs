//! Risk scoring system for security operations
//!
//! Analyzes hooked operations and assigns risk scores (0-100) based on
//! multiple factors including operation type, target, and context.

use crate::ipc::HookOperation;

/// Risk score from 0 (safe) to 100 (critical threat)
#[derive(Debug, Clone, Copy)]
pub struct RiskScore {
    pub score: u8,
    pub category: ThreatCategory,
}

/// Threat category classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    /// 0-30: Low risk, normal operations
    Low,
    /// 31-60: Medium risk, potentially suspicious
    Medium,
    /// 61-85: High risk, likely malicious
    High,
    /// 86-100: Critical risk, almost certainly malicious
    Critical,
}

impl ThreatCategory {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=30 => ThreatCategory::Low,
            31..=60 => ThreatCategory::Medium,
            61..=85 => ThreatCategory::High,
            _ => ThreatCategory::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Low => "LOW",
            ThreatCategory::Medium => "MEDIUM",
            ThreatCategory::High => "HIGH",
            ThreatCategory::Critical => "CRITICAL",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            ThreatCategory::Low => "🟢",
            ThreatCategory::Medium => "🟡",
            ThreatCategory::High => "🟠",
            ThreatCategory::Critical => "🔴",
        }
    }
}

/// Analyze a hooked operation and calculate risk score
pub fn analyze_operation(operation: &HookOperation) -> RiskScore {
    let score = match operation {
        HookOperation::FileCreate { path, flags_and_attributes, .. } => {
            analyze_file_create(path, *flags_and_attributes)
        }
        HookOperation::FileWrite { path, .. } => analyze_file_write(path),
        HookOperation::FileDelete { path } => analyze_file_delete(path),
        HookOperation::FileRead { .. } => 5, // Read operations are low risk
        HookOperation::FileMove { source, destination } => analyze_file_move(source, destination),
        HookOperation::FileCopy { source, destination } => analyze_file_copy(source, destination),
        HookOperation::FileAttributeChange { path, .. } => analyze_file_attribute_change(path),

        HookOperation::FolderCreate { path } => analyze_folder_create(path),
        HookOperation::FolderDelete { path } => analyze_folder_delete(path),

        HookOperation::RegistrySet { key, data_type, .. } => analyze_registry_set(key, *data_type),
        HookOperation::RegistryDelete { key } => analyze_registry_delete(key),
        HookOperation::RegistryRead { .. } => 5, // Read operations are low risk
        HookOperation::RegistryOpen { key, access_rights } => analyze_registry_open(key, *access_rights),

        HookOperation::NetworkConnect { remote_addr, port, .. } => {
            analyze_network_connect(remote_addr, *port)
        }
        HookOperation::NetworkSend { port, bytes_to_send, .. } => {
            analyze_network_send(*port, *bytes_to_send)
        }
        HookOperation::NetworkReceive { .. } => 10, // Receiving data is low risk

        HookOperation::ProcessCreate { executable, args, .. } => {
            analyze_process_create(executable, args)
        }
        HookOperation::ThreadCreate { .. } => 40, // Thread creation is medium risk
        HookOperation::ThreadCreateRemote { .. } => 95, // Remote thread = CRITICAL (injection!)

        HookOperation::DllLoad { dll_path, .. } => analyze_dll_load(dll_path),
        HookOperation::MemoryAllocate { protection, size, .. } => {
            analyze_memory_allocate(*protection, *size)
        }
        HookOperation::MemoryProtect { new_protection, old_protection, .. } => {
            analyze_memory_protect(*old_protection, *new_protection)
        }
        HookOperation::MemoryWrite { target_process_id, .. } => {
            analyze_memory_write(*target_process_id)
        }
    };

    let clamped_score = score.min(100);
    RiskScore {
        score: clamped_score,
        category: ThreatCategory::from_score(clamped_score),
    }
}

/// Analyze file creation risk
fn analyze_file_create(path: &str, _flags: u32) -> u8 {
    let mut score = 20; // Base score for file creation

    let path_lower = path.to_lowercase();

    // System directories - HIGH RISK
    if path_lower.contains("\\windows\\system32") || path_lower.contains("\\windows\\syswow64") {
        score += 50;
    }

    // Startup locations - HIGH RISK (persistence)
    if path_lower.contains("\\startup")
        || path_lower.contains("\\start menu\\programs\\startup") {
        score += 60;
    }

    // Program Files - MEDIUM RISK
    if path_lower.contains("\\program files") {
        score += 30;
    }

    // Temp directory executables - MEDIUM RISK
    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp") {
        if path_lower.ends_with(".exe") || path_lower.ends_with(".dll") {
            score += 40;
        } else if path_lower.ends_with(".bat") || path_lower.ends_with(".vbs") || path_lower.ends_with(".ps1") {
            score += 35;
        }
    }

    // Suspicious extensions
    if path_lower.ends_with(".exe") || path_lower.ends_with(".dll") || path_lower.ends_with(".sys") {
        score += 15;
    }

    // Ransomware-like extensions
    if path_lower.ends_with(".encrypted") || path_lower.ends_with(".locked")
        || path_lower.contains(".crypt") || path_lower.ends_with("readme.txt") {
        score += 70;
    }

    score
}

/// Analyze file write risk
fn analyze_file_write(path: &str) -> u8 {
    let mut score = 15; // Base score

    let path_lower = path.to_lowercase();

    // System files
    if path_lower.contains("\\windows\\") {
        score += 40;
    }

    // User data
    if path_lower.contains("\\documents") || path_lower.contains("\\desktop") {
        score += 10;
    }

    score
}

/// Analyze file deletion risk
fn analyze_file_delete(path: &str) -> u8 {
    let mut score = 30; // Base score for deletion

    let path_lower = path.to_lowercase();

    // System files - CRITICAL
    if path_lower.contains("\\windows\\system32") {
        score += 65;
    }

    // User data - HIGH
    if path_lower.contains("\\documents") || path_lower.contains("\\desktop")
        || path_lower.contains("\\pictures") {
        score += 50;
    }

    // Important file types
    if path_lower.ends_with(".doc") || path_lower.ends_with(".pdf")
        || path_lower.ends_with(".jpg") || path_lower.ends_with(".png") {
        score += 20;
    }

    score
}

/// Analyze file move operations
fn analyze_file_move(_source: &str, destination: &str) -> u8 {
    let mut score = 25;

    // Moving to suspicious locations
    if destination.to_lowercase().contains("\\startup") {
        score += 55;
    }

    if destination.to_lowercase().contains("\\temp\\") && destination.to_lowercase().ends_with(".exe") {
        score += 40;
    }

    score
}

/// Analyze file copy operations
fn analyze_file_copy(_source: &str, destination: &str) -> u8 {
    // Similar to move but slightly less risky
    analyze_file_move(_source, destination).saturating_sub(5u8)
}

/// Analyze file attribute changes
fn analyze_file_attribute_change(path: &str) -> u8 {
    let mut score = 20;

    // Hiding files is suspicious
    if path.to_lowercase().contains("\\system") {
        score += 30;
    }

    score
}

/// Analyze folder creation risk
fn analyze_folder_create(path: &str) -> u8 {
    let mut score = 15;

    let path_lower = path.to_lowercase();

    // ProgramData (common persistence location)
    if path_lower.contains("\\programdata\\") && !path_lower.contains("microsoft") {
        score += 30;
    }

    // Hidden folders (Unix-style naming)
    if path.split('\\').last().map_or(false, |name| name.starts_with('.')) {
        score += 25;
    }

    score
}

/// Analyze folder deletion risk
fn analyze_folder_delete(path: &str) -> u8 {
    let mut score = 35;

    let path_lower = path.to_lowercase();

    // System folders - CRITICAL
    if path_lower.contains("\\windows\\system32") || path_lower.contains("\\program files") {
        score += 60;
    }

    // User data folders - HIGH
    if path_lower.contains("\\documents") || path_lower.contains("\\desktop")
        || path_lower.contains("\\downloads") {
        score += 50;
    }

    score
}

/// Analyze registry set operations
fn analyze_registry_set(key: &str, _data_type: u32) -> u8 {
    let mut score = 25;

    let key_lower = key.to_lowercase();

    // Persistence mechanisms - CRITICAL
    if key_lower.contains("\\run") || key_lower.contains("\\runonce") {
        score += 65;
    }

    // UAC bypass - CRITICAL
    if key_lower.contains("\\environment\\windir") || key_lower.contains("ms-settings") {
        score += 70;
    }

    // Security product tampering - CRITICAL
    if key_lower.contains("windows defender") || key_lower.contains("firewall")
        || key_lower.contains("security center") {
        score += 70;
    }

    // System policies - HIGH
    if key_lower.contains("\\policies\\system") || key_lower.contains("\\control\\lsa") {
        score += 55;
    }

    score
}

/// Analyze registry deletion
fn analyze_registry_delete(key: &str) -> u8 {
    // Deletion is generally more suspicious than setting
    analyze_registry_set(key, 0).saturating_add(10u8)
}

/// Analyze registry open operations
fn analyze_registry_open(key: &str, access_rights: u32) -> u8 {
    // Read-only opens are low risk
    const KEY_READ: u32 = 0x20019;

    if access_rights == KEY_READ {
        return 5;
    }

    // Write access to sensitive keys
    let mut score = 15;

    if key.to_lowercase().contains("\\run") {
        score += 20;
    }

    score
}

/// Analyze network connections
fn analyze_network_connect(remote_addr: &str, port: u16) -> u8 {
    let mut score = 20u8; // Base score for network activity

    // Check if private IP (less risky)
    if is_private_ip(remote_addr) {
        score = score.saturating_sub(10u8);
    } else {
        // Public internet connection
        score += 25;
    }

    // Known C2 ports - CRITICAL
    if is_suspicious_port(port) {
        score += 60;
    }

    // Common malware ports
    match port {
        4444 => score += 55, // Metasploit
        31337 => score += 55, // Elite/backdoor
        6667 | 6697 => score += 45, // IRC (C2)
        _ => {}
    }

    score
}

/// Analyze network send operations
fn analyze_network_send(port: u16, bytes: u32) -> u8 {
    let mut score = 15;

    // Large data transfers (possible exfiltration)
    if bytes > 1_000_000 { // > 1MB
        score += 40;
    } else if bytes > 100_000 { // > 100KB
        score += 20;
    }

    // Suspicious ports
    if is_suspicious_port(port) {
        score += 35;
    }

    score
}

/// Analyze process creation
fn analyze_process_create(executable: &str, args: &str) -> u8 {
    let mut score = 30; // Base score for process creation

    let exe_lower = executable.to_lowercase();
    let args_lower = args.to_lowercase();

    // PowerShell with suspicious arguments - CRITICAL
    if exe_lower.contains("powershell") {
        score += 40;

        if args_lower.contains("-enc") || args_lower.contains("-e ") {
            score += 50; // Encoded commands
        }
        if args_lower.contains("downloadstring") || args_lower.contains("invoke-expression") {
            score += 45;
        }
        if args_lower.contains("-nop") || args_lower.contains("-w hidden") {
            score += 35;
        }
    }

    // CMD with suspicious arguments
    if exe_lower.contains("cmd.exe") && args_lower.contains("/c") {
        score += 20;
    }

    // Living off the land binaries
    if exe_lower.contains("wscript") || exe_lower.contains("cscript")
        || exe_lower.contains("mshta") || exe_lower.contains("regsvr32") {
        score += 40;
    }

    // From temp directory
    if exe_lower.contains("\\temp\\") || exe_lower.contains("\\appdata\\local\\temp") {
        score += 35;
    }

    score
}

/// Analyze DLL loading
fn analyze_dll_load(dll_path: &str) -> u8 {
    let mut score = 25;

    let path_lower = dll_path.to_lowercase();

    // Loading from temp - suspicious
    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp") {
        score += 45;
    }

    // System DLLs from non-system locations - CRITICAL
    if path_lower.ends_with("kernel32.dll") || path_lower.ends_with("ntdll.dll")
        || path_lower.ends_with("user32.dll") {
        if !path_lower.contains("\\windows\\system32") {
            score += 65; // DLL hijacking
        }
    }

    score
}

/// Analyze memory allocation
fn analyze_memory_allocate(protection: u32, size: usize) -> u8 {
    let mut score = 30;

    // RWX memory - CRITICAL (shellcode execution)
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    if protection == PAGE_EXECUTE_READWRITE {
        score += 65;
    }

    // Executable memory
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ)) != 0 {
        score += 40;
    }

    // Large allocations
    if size > 10_000_000 { // > 10MB
        score += 20;
    }

    score
}

/// Analyze memory protection changes
fn analyze_memory_protect(_old_protection: u32, new_protection: u32) -> u8 {
    let mut score = 35;

    // Changing to RWX - CRITICAL (code injection preparation)
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    if new_protection == PAGE_EXECUTE_READWRITE {
        score += 60;
    }

    // Adding execute permission
    const PAGE_EXECUTE: u32 = 0x10;
    if (new_protection & PAGE_EXECUTE) != 0 {
        score += 45;
    }

    score
}

/// Analyze cross-process memory writes
fn analyze_memory_write(target_pid: u32) -> u8 {
    // Cross-process memory writes are almost always malicious
    let mut score = 85;

    // Writing to own process (less suspicious)
    let current_pid = std::process::id();
    if target_pid == current_pid {
        score = 35;
    }

    score
}

/// Check if IP is private (RFC1918)
fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Vec<u8> = parts.iter().filter_map(|s| s.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }

    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
}

/// Check if port is suspicious
fn is_suspicious_port(port: u16) -> bool {
    matches!(port,
        4444 | 5555 | 6666 | 7777 | 8888 | 9999 | // Common C2 ports
        31337 | 12345 | 54321 | 6667 | 6697 | // Backdoors/IRC
        1337 | 10000 | 20000 | 65535 // RAT ports
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_categories() {
        assert_eq!(ThreatCategory::from_score(15), ThreatCategory::Low);
        assert_eq!(ThreatCategory::from_score(45), ThreatCategory::Medium);
        assert_eq!(ThreatCategory::from_score(75), ThreatCategory::High);
        assert_eq!(ThreatCategory::from_score(95), ThreatCategory::Critical);
    }

    #[test]
    fn test_suspicious_operations() {
        // Remote thread injection should be critical
        let op = HookOperation::ThreadCreateRemote {
            target_process_id: 1234,
            start_address: 0x12345678,
        };
        let risk = analyze_operation(&op);
        assert!(risk.score >= 90);
        assert_eq!(risk.category, ThreatCategory::Critical);
    }

    #[test]
    fn test_read_operations_low_risk() {
        let op = HookOperation::FileRead {
            path: "C:\\Users\\test\\document.txt".to_string(),
        };
        let risk = analyze_operation(&op);
        assert!(risk.score <= 30);
    }
}
