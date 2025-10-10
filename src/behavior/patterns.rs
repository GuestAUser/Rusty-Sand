// Behavioral patterns for threat detection

pub struct ThreatPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub indicators: &'static [&'static str],
}

pub const RANSOMWARE_PATTERNS: &[ThreatPattern] = &[
    ThreatPattern {
        name: "File Encryption",
        description: "Rapid file modification with extension changes",
        indicators: &[".encrypted", ".locked", ".crypto", "_RECOVER_"],
    },
    ThreatPattern {
        name: "Ransom Note",
        description: "Creation of ransom demand files",
        indicators: &["README", "DECRYPT", "RECOVER", "RANSOM"],
    },
];

pub const PERSISTENCE_PATTERNS: &[ThreatPattern] = &[
    ThreatPattern {
        name: "Registry Run Keys",
        description: "Startup persistence via registry",
        indicators: &["\\Run", "\\RunOnce", "\\RunServices"],
    },
    ThreatPattern {
        name: "Scheduled Tasks",
        description: "Persistence via scheduled tasks",
        indicators: &["schtasks", "at.exe"],
    },
];

pub const EVASION_PATTERNS: &[ThreatPattern] = &[
    ThreatPattern {
        name: "Anti-Sandbox",
        description: "Techniques to detect sandbox environments",
        indicators: &["IsDebuggerPresent", "Sleep", "GetTickCount"],
    },
    ThreatPattern {
        name: "Process Injection",
        description: "Code injection into other processes",
        indicators: &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    },
];
