use super::resource::{with_cleanup, OwnedHandle};
use anyhow::{bail, Context, Result};
use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::{
    CreateRestrictedToken, GetTokenInformation, IsWellKnownSid, TokenGroups,
    WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid, WinWorldSid,
    DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/*
 * These winnt.h group attributes are exposed by windows 0.52 under the
 * otherwise unused SystemServices feature. Keep their documented values here
 * rather than adding a dependency feature solely for constants.
 */
const GROUP_INTEGRITY: u32 = 0x0000_0020;
const GROUP_LOGON_ID: u32 = 0xc000_0000;

/** Create a restricted primary token. The caller must close the returned handle.

This helper does not apply the token to a process; creating it alone is not
evidence that execution uses it. SandboxConfig::restricted_token applies it
through CreateProcessAsUserW.

All privileges except SeChangeNotifyPrivilege are removed. Everyone,
Authenticated Users, Builtin Users, Interactive, the logon SID, and integrity
SIDs are retained. Other groups become deny-only, including administrator,
operator, domain, and custom groups. This conservative policy can deny access
to resources granted only through a custom group.

The user SID, integrity level, desktop, and environment are not isolated.
This is least privilege, not filesystem, network, or VM isolation. No low
integrity or AppContainer policy is installed.
*/
pub fn create_restricted_token() -> Result<HANDLE> {
    create_owned_restricted_token().map(OwnedHandle::into_raw)
}

pub(crate) fn create_owned_restricted_token() -> Result<OwnedHandle> {
    let mut token_handle = HANDLE::default();

    /* SAFETY: Output handles have live stack storage and are immediately owned;
    GetCurrentProcess is a borrowed pseudo-handle, never closed here.
    Opening the process token, rather than a thread token, supplies a primary
    token. CreateRestrictedToken preserves its type and granted handle access.
    CreateProcessAsUserW requires QUERY, DUPLICATE, and ASSIGN_PRIMARY. */
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut token_handle,
        )
    }
    .context("open source primary token")?;

    let mut token = OwnedHandle::new(token_handle);
    let created = (|| -> Result<OwnedHandle> {
        let groups = TokenGroupsBuffer(query_token_information(token.raw(), TokenGroups)?);
        let disabled: Vec<SID_AND_ATTRIBUTES> = groups
            .entries()
            .iter()
            .filter(|group| !retain_group(group))
            .copied()
            .collect();
        let mut restricted = HANDLE::default();

        /* SAFETY: Each SID points into groups, whose allocation remains alive
        and unmoved through this synchronous call. Windows copies the SIDs.
        Disabling all non-basic groups avoids an incomplete list of privileged
        built-in, domain, or custom group identities. No restricting-SID list
        or SANDBOX_INERT flag is introduced. */
        unsafe {
            CreateRestrictedToken(
                token.raw(),
                DISABLE_MAX_PRIVILEGE,
                Some(&disabled),
                None,
                None,
                &mut restricted,
            )
        }
        .context("create restricted primary token")?;

        Ok(OwnedHandle::new(restricted))
    })();

    let mut restricted = match created {
        Ok(restricted) => restricted,
        Err(error) => return with_cleanup(Err(error), token.close()),
    };

    if let Err(error) = token.close() {
        return with_cleanup(Err(error), restricted.close());
    }

    Ok(restricted)
}

fn retain_group(group: &SID_AND_ATTRIBUTES) -> bool {
    if group.Attributes & GROUP_INTEGRITY != 0
        || group.Attributes & GROUP_LOGON_ID == GROUP_LOGON_ID
    {
        return true;
    }

    /* SAFETY: Callers supply group entries from GetTokenInformation, retaining
    the allocation containing their valid SIDs throughout this query. */
    unsafe {
        [
            WinWorldSid,
            WinAuthenticatedUserSid,
            WinBuiltinUsersSid,
            WinInteractiveSid,
        ]
        .iter()
        .any(|kind| IsWellKnownSid(group.Sid, *kind).as_bool())
    }
}

/** Pointer-aligned storage for native token information.

The kernel determines the required length. Allocation is bounded, and a size
change between queries fails rather than entering an unbounded retry loop.
*/
fn query_token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    const MAX_TOKEN_INFORMATION_BYTES: u32 = 1024 * 1024;
    let mut required = 0;

    /* SAFETY: The first query supplies no buffer and only writes required. */
    match unsafe { GetTokenInformation(token, class, None, 0, &mut required) } {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {}
        Err(error) => return Err(error).context("size token information"),
        Ok(()) => bail!("token information query unexpectedly required no buffer"),
    }

    if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
        bail!("token information exceeds the supported size bound");
    }

    let mut storage = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];

    /* SAFETY: usize storage provides the alignment required by the queried
    TOKEN_* structures and at least required writable bytes. The allocation
    remains stable, including any SID pointers written into it. */
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(storage.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .context("query token information")?;

    Ok(storage)
}

struct TokenGroupsBuffer(Vec<usize>);

impl TokenGroupsBuffer {
    fn entries(&self) -> &[SID_AND_ATTRIBUTES] {
        let groups = self.0.as_ptr().cast::<TOKEN_GROUPS>();

        /* SAFETY: This type is constructed only from a successful TokenGroups
        query. Windows supplies the count and initialized flexible-array
        entries. Use the raw field address without forming a reference to the
        binding's one-element array, including when GroupCount is zero. */
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
                (*groups).GroupCount as usize,
            )
        }
    }
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

#[cfg(test)]
#[path = "../../tests/unit/windows/isolation/restricted_token.rs"]
mod tests;
