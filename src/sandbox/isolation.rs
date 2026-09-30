use super::resource::{with_cleanup, OwnedHandle};
use anyhow::{Context, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_ALL_ACCESS};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/** Create a restricted token. The caller owns the returned handle.

This helper does not apply the token to a process; creating it alone is not
evidence that any execution is isolated.
*/
pub fn create_restricted_token() -> Result<HANDLE> {
    let mut token_handle = HANDLE::default();

    /* SAFETY: Output handles have live stack storage and are immediately owned;
    GetCurrentProcess is a borrowed pseudo-handle, never closed here. */
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token_handle) }
        .context("open source token")?;
    let mut token = OwnedHandle::new(token_handle);
    let mut restricted = HANDLE::default();
    let created = unsafe {
        CreateRestrictedToken(
            token.raw(),
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut restricted,
        )
    }
    .context("create restricted token");
    if let Err(error) = created {
        return with_cleanup(Err(error), token.close());
    }
    let mut restricted = OwnedHandle::new(restricted);
    if let Err(error) = token.close() {
        return with_cleanup(Err(error), restricted.close());
    }
    Ok(restricted.into_raw())
}

/**
Describes a requested isolation policy for library consumers.

This value does not install enforcement. Resource limits and selected API hooks
must not be presented as complete network, filesystem, or registry isolation.
*/
pub struct IsolationPolicy {
    pub network_isolation: bool,
    pub file_system_isolation: bool,
    pub registry_isolation: bool,
    pub process_isolation: bool,
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self {
            network_isolation: true,
            file_system_isolation: true,
            registry_isolation: false,
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
            "Requested isolation (not enforced by this value): network={}, filesystem={}, registry={}, process={}",
            self.network_isolation,
            self.file_system_isolation,
            self.registry_isolation,
            self.process_isolation
        )
    }
}
