use anyhow::Result;
use log::info;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_ALL_ACCESS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Create a restricted token with reduced privileges
pub fn create_restricted_token() -> Result<HANDLE> {
    let mut token_handle = HANDLE::default();

    unsafe {
        // Open the current process token
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ALL_ACCESS,
            &mut token_handle,
        )?;

        // Create a restricted token with disabled privileges
        let mut restricted_token = HANDLE::default();
        CreateRestrictedToken(
            token_handle,
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut restricted_token,
        )?;

        info!("Created restricted security token");
        Ok(restricted_token)
    }
}

/// Security measures for process isolation
pub struct IsolationPolicy {
    pub network_isolation: bool,
    pub file_system_isolation: bool,
    pub registry_isolation: bool,
    pub process_isolation: bool,
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self {
            network_isolation: true,  // Block network by default
            file_system_isolation: true,
            registry_isolation: false, // Allow but monitor
            process_isolation: true,
        }
    }
}

impl IsolationPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_network(mut self, isolated: bool) -> Self {
        self.network_isolation = isolated;
        self
    }

    pub fn with_filesystem(mut self, isolated: bool) -> Self {
        self.file_system_isolation = isolated;
        self
    }

    pub fn summary(&self) -> String {
        format!(
            "Network: {}, FileSystem: {}, Registry: {}, Process: {}",
            if self.network_isolation { "ISOLATED" } else { "ALLOWED" },
            if self.file_system_isolation { "ISOLATED" } else { "ALLOWED" },
            if self.registry_isolation { "ISOLATED" } else { "MONITORED" },
            if self.process_isolation { "ISOLATED" } else { "ALLOWED" }
        )
    }
}
