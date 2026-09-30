use super::{BehaviorAnalyzer, ThreatDetection, ThreatLevel};
use crate::report::Event;
use log::warn;

impl BehaviorAnalyzer {
    pub(super) fn analyze_file_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        self.file_creation_count += 1;

        let path = event.details.to_lowercase();

        if self.file_creation_count > 50 {
            return Some(ThreatDetection {
                threat_type: "Potential Ransomware".to_string(),
                level: ThreatLevel::Critical,
                description: format!(
                    "High file creation volume ({} files) in this execution; review for encryption activity.",
                    self.file_creation_count
                ),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if path.ends_with(".encrypted")
            || path.ends_with(".locked")
            || path.ends_with(".crypto")
            || path.contains(".crypt")
            || path.ends_with("readme")
        {
            self.encryption_like_patterns += 1;

            return Some(ThreatDetection {
                threat_type: "Ransomware Indicator".to_string(),
                level: ThreatLevel::High,
                description: "File created with encryption-related extension".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if (path.contains("\\appdata\\") || path.contains("\\temp\\"))
            && (path.ends_with(".exe")
                || path.ends_with(".dll")
                || path.ends_with(".bat")
                || path.ends_with(".vbs"))
        {
            return Some(ThreatDetection {
                threat_type: "Suspicious File Drop".to_string(),
                level: ThreatLevel::Medium,
                description: "Executable dropped in temporary location".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: false,
            });
        }

        None
    }

    pub(super) fn analyze_file_deletion(&mut self, event: &Event) -> Option<ThreatDetection> {
        let path = event.details.to_lowercase();

        if path.ends_with(".doc")
            || path.ends_with(".pdf")
            || path.ends_with(".jpg")
            || path.ends_with(".png")
        {
            warn!("Document/image deletion detected: {}", path);
        }

        None
    }

    pub(super) fn analyze_folder_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        let path = event.details.to_lowercase();

        if path.contains("\\programdata\\") && !path.contains("microsoft") {
            return Some(ThreatDetection {
                threat_type: "Suspicious Folder Creation".to_string(),
                level: ThreatLevel::Medium,
                description: "Folder created in ProgramData (potential persistence location)"
                    .to_string(),
                evidence: vec![event.details.clone()],
                should_pause: false,
            });
        }

        if path.split('\\').next_back().unwrap_or("").starts_with('.') {
            return Some(ThreatDetection {
                threat_type: "Hidden Folder Creation".to_string(),
                level: ThreatLevel::Low,
                description: "Creating hidden folder (Unix-style naming)".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: false,
            });
        }

        None
    }

    pub(super) fn analyze_folder_deletion(&mut self, event: &Event) -> Option<ThreatDetection> {
        let path = event.details.to_lowercase();

        if path.contains("\\windows\\system32")
            || path.contains("\\windows\\syswow64")
            || path.contains("\\program files")
        {
            return Some(ThreatDetection {
                threat_type: "Critical Folder Deletion Attempt".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting to delete critical system folder".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if path.contains("\\documents")
            || path.contains("\\desktop")
            || path.contains("\\downloads")
        {
            return Some(ThreatDetection {
                threat_type: "User Data Folder Deletion".to_string(),
                level: ThreatLevel::High,
                description: "Attempting to delete user data folder".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        None
    }
}
