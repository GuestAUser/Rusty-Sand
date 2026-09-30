pub mod patterns;
pub mod rules;

mod files;
mod operations;

#[cfg(test)]
#[path = "../../tests/unit/domain/behavior.rs"]
mod tests;

use crate::report::{Event, EventType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    file_operations: usize,
    registry_operations: usize,
    network_connections: usize,
    process_creations: usize,

    /*
     * Counters cover the complete execution history. They are not rates:
     * no time window is inferred from the interval between observations.
     */
    file_creation_count: usize,
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
            file_operations: 0,
            registry_operations: 0,
            network_connections: 0,
            process_creations: 0,
            file_creation_count: 0,
            encryption_like_patterns: 0,
            persistence_attempts: 0,
        }
    }

    pub fn analyze_event(&mut self, event: &Event) -> Option<ThreatDetection> {
        if matches!(
            event.event_type,
            EventType::FileCreated | EventType::FileModified | EventType::FileDeleted
        ) {
            self.file_operations += 1;
        }

        /*
         * Hook events describe requests, not completed changes. They are scored
         * separately; including them here would double-count observations.
         */
        match &event.event_type {
            EventType::FileCreated => self.analyze_file_creation(event),
            EventType::FileModified => None,
            EventType::FileDeleted => self.analyze_file_deletion(event),
            EventType::FolderCreated => self.analyze_folder_creation(event),
            EventType::FolderDeleted => self.analyze_folder_deletion(event),
            EventType::RegistryAccess => self.analyze_registry_access(event),
            EventType::NetworkConnection => self.analyze_network_connection(event),
            EventType::ProcessCreated => self.analyze_process_creation(event),
            _ => None,
        }
    }

    pub fn get_summary(&self) -> String {
        format!(
            "Behavior Summary:\n\
             - File operations: {}\n\
             - Registry operations: {}\n\
             - Network connections: {}\n\
             - Process creations: {}\n\
             - File creation count: {}\n\
             - Encryption patterns: {}\n\
             - Persistence attempts: {}",
            self.file_operations,
            self.registry_operations,
            self.network_connections,
            self.process_creations,
            self.file_creation_count,
            self.encryption_like_patterns,
            self.persistence_attempts
        )
    }
}
