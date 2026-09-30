use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedFilePatterns,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFilePatterns => formatter.write_str(
                "filesystem allowlist enforcement is unsupported; allowed_file_patterns must be empty",
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Requested execution policy. Individual monitors and hooks determine coverage;
/// these settings do not establish an isolation boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Allow internet access (default: false)
    pub allow_internet: bool,

    /// Allow DNS resolution (default: false)
    pub allow_dns: bool,

    /// Allow registry access (default: true, monitored)
    pub allow_registry: bool,

    /// Maximum execution time
    pub timeout: Duration,

    /// Working directory for the sandboxed process
    pub working_dir: Option<PathBuf>,

    /** Reserved for filesystem enforcement. Nonempty patterns are rejected
    because directory observation cannot enforce a filesystem allowlist. */
    pub allowed_file_patterns: Vec<String>,

    /// Maximum memory usage in MB (0 = unlimited)
    pub max_memory_mb: u64,

    /// Maximum CPU time in seconds (0 = unlimited)
    pub max_cpu_time: u64,

    /// Enable verbose monitoring
    pub verbose: bool,

    /** Log observed network endpoints. The serialized field name is retained
    for compatibility; this option does not capture packet payloads. */
    pub log_network_packets: bool,

    /// Enable API call hooking (advanced)
    pub enable_api_hooks: bool,

    /// Enable interactive mode (pause on suspicious behavior)
    pub interactive_mode: bool,

    /**
    Opt into EOF cancellation for a caller-owned input control pipe.

    Noninteractive library sessions otherwise leave process stdin alone.
    This runtime transport setting is not part of serialized report policy.
    */
    #[serde(skip)]
    pub cancel_on_stdin_eof: bool,

    /// Enable behavioral analysis
    pub enable_behavior_detection: bool,

    /// Auto-terminate on critical threats
    pub auto_terminate_on_critical: bool,

    /// Output directory for logs and artifacts
    pub output_dir: PathBuf,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_internet: false,
            allow_dns: false,
            allow_registry: true,
            timeout: Duration::from_secs(300),
            working_dir: None,
            allowed_file_patterns: vec![],
            max_memory_mb: 1024,
            max_cpu_time: 300,
            verbose: false,
            log_network_packets: false,
            enable_api_hooks: true,
            interactive_mode: true,
            cancel_on_stdin_eof: false,
            enable_behavior_detection: true,
            auto_terminate_on_critical: false,
            output_dir: PathBuf::from("./sandbox_output"),
        }
    }
}

impl SandboxConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.allowed_file_patterns.is_empty() {
            return Err(ConfigError::UnsupportedFilePatterns);
        }

        Ok(())
    }

    pub fn with_internet(mut self, enabled: bool) -> Self {
        self.allow_internet = enabled;

        /*
         * Enabling internet also enables name resolution. Disabling it preserves
         * an independently configured DNS policy for compatibility.
         */
        if enabled {
            self.allow_dns = true;
        }

        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_output_dir(mut self, dir: PathBuf) -> Self {
        self.output_dir = dir;
        self
    }

    pub fn with_memory_limit(mut self, mb: u64) -> Self {
        self.max_memory_mb = mb;
        self
    }
}

#[cfg(test)]
#[path = "../tests/unit/domain/config.rs"]
mod tests;
