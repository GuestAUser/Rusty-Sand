//! Reference rule metadata for callers extending behavioral analysis.
//!
//! These definitions do not install detectors or establish detection coverage.

use super::ThreatLevel;

pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub level: ThreatLevel,
    pub description: &'static str,
}

pub const RULE_MASS_FILE_ENCRYPTION: DetectionRule = DetectionRule {
    id: "R001",
    name: "Mass File Encryption",
    level: ThreatLevel::Critical,
    description: "Rapid file creation/modification indicating encryption activity",
};

pub const RULE_RANSOM_NOTE: DetectionRule = DetectionRule {
    id: "R002",
    name: "Ransom Note Creation",
    level: ThreatLevel::Critical,
    description: "Creation of files typically associated with ransom demands",
};

pub const RULE_REGISTRY_PERSISTENCE: DetectionRule = DetectionRule {
    id: "P001",
    name: "Registry Persistence",
    level: ThreatLevel::High,
    description: "Modification of registry keys for persistence",
};

pub const RULE_UAC_BYPASS: DetectionRule = DetectionRule {
    id: "E001",
    name: "UAC Bypass Attempt",
    level: ThreatLevel::Critical,
    description: "Attempt to bypass User Account Control",
};

pub const RULE_SECURITY_TAMPERING: DetectionRule = DetectionRule {
    id: "E002",
    name: "Security Software Tampering",
    level: ThreatLevel::Critical,
    description: "Attempt to disable or modify security software",
};

pub const RULE_C2_CONNECTION: DetectionRule = DetectionRule {
    id: "N001",
    name: "C2 Connection",
    level: ThreatLevel::High,
    description: "Connection to potential command and control server",
};

pub const RULE_SUSPICIOUS_PORT: DetectionRule = DetectionRule {
    id: "N002",
    name: "Suspicious Port Usage",
    level: ThreatLevel::Medium,
    description: "Connection to commonly abused ports",
};
