use super::{BehaviorAnalyzer, ThreatDetection, ThreatLevel};
use crate::report::Event;
use std::net::SocketAddr;

impl BehaviorAnalyzer {
    pub(super) fn analyze_registry_access(&mut self, event: &Event) -> Option<ThreatDetection> {
        let key = event.details.to_lowercase();

        self.registry_operations += 1;

        if key
            .split('\\')
            .any(|component| matches!(component, "run" | "runonce" | "runservices"))
        {
            self.persistence_attempts += 1;

            return Some(ThreatDetection {
                threat_type: "Persistence Mechanism".to_string(),
                level: ThreatLevel::High,
                description: "Attempting to add startup entry".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if key.contains("\\environment\\windir") || key.contains("\\ms-settings\\") {
            return Some(ThreatDetection {
                threat_type: "UAC Bypass Attempt".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting known UAC bypass technique".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if key.contains("windows defender") || key.contains("antivirus") || key.contains("firewall")
        {
            return Some(ThreatDetection {
                threat_type: "Security Tampering".to_string(),
                level: ThreatLevel::Critical,
                description: "Attempting to modify security software settings".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        None
    }

    pub(super) fn analyze_network_connection(&mut self, event: &Event) -> Option<ThreatDetection> {
        let connection = &event.details;
        self.network_connections += 1;

        /*
         * TCP observations include local and remote endpoints. Only the remote
         * port informs this rule; local bindings and IPv6 address segments are
         * not evidence of a connection to a suspicious service.
         */
        let remote = connection
            .rsplit_once(" -> ")
            .map_or(connection.as_str(), |(_, remote)| remote);
        let remote_port = remote
            .split_whitespace()
            .next()?
            .parse::<SocketAddr>()
            .ok()?
            .port();

        if matches!(remote_port, 4444 | 8080 | 31337) {
            return Some(ThreatDetection {
                threat_type: "Suspicious Port".to_string(),
                level: ThreatLevel::High,
                description: "Connection to a commonly abused remote port".to_string(),
                evidence: vec![connection.clone()],
                should_pause: true,
            });
        }

        None
    }

    pub(super) fn analyze_process_creation(&mut self, event: &Event) -> Option<ThreatDetection> {
        let process_info = event.details.to_lowercase();
        self.process_creations += 1;

        if process_info.contains("powershell")
            && (process_info.contains("-enc")
                || process_info.contains("-e ")
                || process_info.contains("downloadstring")
                || process_info.contains("invoke-expression"))
        {
            return Some(ThreatDetection {
                threat_type: "PowerShell Abuse".to_string(),
                level: ThreatLevel::Critical,
                description: "Suspicious PowerShell execution detected".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: true,
            });
        }

        if process_info.contains("cmd.exe") && process_info.contains("/c") {
            return Some(ThreatDetection {
                threat_type: "Command Execution".to_string(),
                level: ThreatLevel::Medium,
                description: "cmd.exe spawned with /c parameter".to_string(),
                evidence: vec![event.details.clone()],
                should_pause: false,
            });
        }

        None
    }
}
