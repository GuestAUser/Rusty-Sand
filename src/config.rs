use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

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

    /// File system access patterns to allow
    pub allowed_file_patterns: Vec<String>,

    /// Maximum memory usage in MB (0 = unlimited)
    pub max_memory_mb: u64,

    /// Maximum CPU time in seconds (0 = unlimited)
    pub max_cpu_time: u64,

    /// Enable verbose monitoring
    pub verbose: bool,

    /// Enable network packet logging
    pub log_network_packets: bool,

    /// Enable API call hooking (advanced)
    pub enable_api_hooks: bool,

    /// Enable interactive mode (pause on suspicious behavior)
    pub interactive_mode: bool,

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
            allow_internet: false,  // SECURITY: Default deny
            allow_dns: false,
            allow_registry: true,   // Allow but monitor
            timeout: Duration::from_secs(300), // 5 minutes
            working_dir: None,
            allowed_file_patterns: vec![],
            max_memory_mb: 1024,    // 1GB default limit
            max_cpu_time: 300,      // 5 minutes
            verbose: false,
            log_network_packets: false,
            enable_api_hooks: true,  // Enable API hooking for TRUE prevention by default
            interactive_mode: true,  // Enable interactive mode by default
            enable_behavior_detection: true,  // Enable threat detection by default
            auto_terminate_on_critical: false,  // Don't auto-terminate, ask user
            output_dir: PathBuf::from("./sandbox_output"),
        }
    }
}

impl SandboxConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_internet(mut self, enabled: bool) -> Self {
        self.allow_internet = enabled;
        if enabled {
            self.allow_dns = true; // DNS needed for internet
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
