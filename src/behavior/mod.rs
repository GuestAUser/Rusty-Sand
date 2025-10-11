pub mod patterns;
pub mod rules;

use crate::report::{Event, EventType};
use log::warn;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ThreatDetection {
    pub threat_type: String,
    pub level: ThreatLevel,
    pub description: String,
    pub evidence: Vec<String>,
    pub should_pause: bool,
}

pub struct BehaviorAnalyzer {
    // Track suspicious patterns
    file_operations: HashMap<String, usize>,
    registry_operations: HashMap<String, usize>,
    network_connections: Vec<String>,
    process_creations: Vec<String>,

    // Counters for pattern detection
    rapid_file_creation_count: usize,
    encryption_like_patterns: usize,
    persistence_attempts: usize,
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        Self {
            file_operations: HashMap::new(),
            registry_operations: HashMap::new(),
            network_connections: Vec::new(),
            process_creations: Vec::new(),
            rapid_file_creation_count: 0,
            encryption_like_patterns: 0,
            persistence_attempts: 0,
        }
    }

    pub fn analyze_event(&mut self, event: &Event) -> Option<ThreatDetection> {
        match &event.event_type {
            EventType::FileCreated => self.analyze_file_creation(event),
            EventType::FileModified => self.analyze_file_modification(event),
            EventType::FileDeleted => self.analyze_file_deletion(event),
            EventType::FolderCreated => self.analyze_folder_creation(event),
            EventType::FolderDeleted => self.analyze_folder_deletion(event),
            EventType::RegistryAccess => self.analyze_registry_access(event),
            EventType::NetworkConnection => self.analyze_network_connection(event),
            EventType::ProcessCreated => self.analyze_process_creation(event),
            _ => None,
        }
    }

    fn analyze_file_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        self.rapid_file_creation_count += 1;

        // Check for suspicious file extensions
        let path = &event.details;

        // Ransomware pattern: Many files created quickly
        if self.rapid_file_creation_count > 50 {
            return Some(ThreatDetection {
                threat_type: "Potential Ransomware".to_string(),
                level: ThreatLevel::Critical,
                description: format!(
                    "Rapid file creation detected ({} files). This may indicate ransomware encryption activity.",
                    self.rapid_file_creation_count
                ),
                evidence: vec![path.clone()],
                should_pause: true,
            });
        }

        // Check for suspicious extensions
        if path.ends_with(".encrypted")
            || path.ends_with(".locked")
            || path.ends_with(".crypto")
            || path.contains(".crypt")
            || path.ends_with("README") {

            self.encryption_like_patterns += 1;

            return Some(ThreatDetection {
                threat_type: "Ransomware Indicator".to_string(),
                level: ThreatLevel::High,
                description: "File created with encryption-related extension".to_string(),
                evidence: vec![path.clone()],
                should_pause: true,
            });
        }

        // Check for temp/appdata suspicious activity
        if (path.contains("\\AppData\\") || path.contains("\\Temp\\"))
            && (path.ends_with(".exe") || path.ends_with(".dll") || path.ends_with(".bat") || path.ends_with(".vbs")) {

            return Some(ThreatDetection {
                threat_type: "Suspicious File Drop".to_string(),
                level: ThreatLevel::Medium,
                description: "Executable dropped in temporary location".to_string(),
                evidence: vec![path.clone()],
                should_pause: false,
            });
        }

        None
    }

    fn analyze_file_modification(&mut self, _event: &Event) -> Option<ThreatDetection> {
        // Track file modifications for encryption detection
        None
    }

    fn analyze_file_deletion(&mut self, event: &Event) -> Option<ThreatDetection> {
        // Mass deletion can indicate ransomware
        let path = &event.details;

        if path.ends_with(".doc")
            || path.ends_with(".pdf")
            || path.ends_with(".jpg")
            || path.ends_with(".png") {

            warn!("Document/image deletion detected: {}", path);
        }

        None
    }

    fn analyze_folder_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        let path = &event.details;

        // Check for suspicious folder creation patterns
        if path.contains("\\ProgramData\\") && !path.contains("Microsoft") {
            return Some(ThreatDetection {
                threat_type: "Suspicious Folder Creation".to_string(),
                level: ThreatLevel::Medium,
                description: "Folder created in ProgramData (potential persistence location)".to_string(),
                evidence: vec![path.clone()],
                should_pause: false,
            });
        }

        // Check for hidden folder creation attempts (folders starting with .)
        if path.split('\\').next_back().unwrap_or("").starts_with('.') {
            return Some(ThreatDetection {
                threat_type: "Hidden Folder Creation".to_string(),
                level: ThreatLevel::Low,
                description: "Creating hidden folder (Unix-style naming)".to_string(),
                evidence: vec![path.clone()],
                should_pause: false,
            });
        }

        None
    }

    fn analyze_folder_deletion(&mut self, event: &Event) -> Option<ThreatDetection> {
        let path = &event.details;

        // Check for critical system folder deletion attempts
        if path.contains("\\Windows\\System32")
            || path.contains("\\Windows\\SysWOW64")
            || path.contains("\\Program Files") {

            return Some(ThreatDetection {
                threat_type: "Critical Folder Deletion Attempt".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting to delete critical system folder".to_string(),
                evidence: vec![path.clone()],
                should_pause: true,
            });
        }

        // Check for user data folder deletion (potential data destruction)
        if path.contains("\\Documents") || path.contains("\\Desktop") || path.contains("\\Downloads") {
            return Some(ThreatDetection {
                threat_type: "User Data Folder Deletion".to_string(),
                level: ThreatLevel::High,
                description: "Attempting to delete user data folder".to_string(),
                evidence: vec![path.clone()],
                should_pause: true,
            });
        }

        None
    }

    fn analyze_registry_access(&mut self, event: &Event) -> Option<ThreatDetection> {
        let key = &event.details;

        *self.registry_operations.entry(key.clone()).or_insert(0) += 1;

        // Check for persistence mechanisms
        if key.contains("\\Run") || key.contains("\\RunOnce") {
            self.persistence_attempts += 1;

            return Some(ThreatDetection {
                threat_type: "Persistence Mechanism".to_string(),
                level: ThreatLevel::High,
                description: "Attempting to add startup entry".to_string(),
                evidence: vec![key.clone()],
                should_pause: true,
            });
        }

        // Check for UAC bypass attempts
        if key.contains("\\Environment\\windir")
            || key.contains("\\ms-settings\\") {

            return Some(ThreatDetection {
                threat_type: "UAC Bypass Attempt".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting known UAC bypass technique".to_string(),
                evidence: vec![key.clone()],
                should_pause: true,
            });
        }

        // Check for security product tampering
        if key.to_lowercase().contains("windows defender")
            || key.to_lowercase().contains("antivirus")
            || key.to_lowercase().contains("firewall") {

            return Some(ThreatDetection {
                threat_type: "Security Tampering".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting to modify security software settings".to_string(),
                evidence: vec![key.clone()],
                should_pause: true,
            });
        }

        None
    }

    fn analyze_network_connection(&mut self, event: &Event) -> Option<ThreatDetection> {
        let connection = &event.details;
        self.network_connections.push(connection.clone());

        // Check for known C2 indicators
        if connection.contains(":4444")
            || connection.contains(":8080")
            || connection.contains(":31337") {

            return Some(ThreatDetection {
                threat_type: "Suspicious Port".to_string(),
                level: ThreatLevel::High,
                description: "Connection to commonly used malware port".to_string(),
                evidence: vec![connection.clone()],
                should_pause: true,
            });
        }

        None
    }

    fn analyze_process_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        let process_info = &event.details;
        self.process_creations.push(process_info.clone());

        // Check for suspicious process names
        if process_info.to_lowercase().contains("powershell")
            && (process_info.contains("-enc")
                || process_info.contains("-e ")
                || process_info.contains("downloadstring")
                || process_info.contains("invoke-expression")) {

            return Some(ThreatDetection {
                threat_type: "PowerShell Abuse".to_string(),
                level: ThreatLevel::Critical,
                description: "Suspicious PowerShell execution detected".to_string(),
                evidence: vec![process_info.clone()],
                should_pause: true,
            });
        }

        // Check for process hollowing indicators
        if process_info.to_lowercase().contains("cmd.exe")
            && process_info.contains("/c") {

            return Some(ThreatDetection {
                threat_type: "Command Execution".to_string(),
                level: ThreatLevel::Medium,
                description: "cmd.exe spawned with /c parameter".to_string(),
                evidence: vec![process_info.clone()],
                should_pause: false,
            });
        }

        None
    }

    pub fn get_summary(&self) -> String {
        format!(
            "Behavior Summary:\n\
             - File operations: {}\n\
             - Registry operations: {}\n\
             - Network connections: {}\n\
             - Process creations: {}\n\
             - Rapid file creation count: {}\n\
             - Encryption patterns: {}\n\
             - Persistence attempts: {}",
            self.file_operations.len(),
            self.registry_operations.len(),
            self.network_connections.len(),
            self.process_creations.len(),
            self.rapid_file_creation_count,
            self.encryption_like_patterns,
            self.persistence_attempts
        )
    }
}
