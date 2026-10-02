use super::*;
use crate::config::SandboxConfig;
use crate::sandbox::process::create_sandboxed_process;
use crate::sandbox::wait::HandleWait;
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetHandleInformation, BOOL, ERROR_FILE_NOT_FOUND, LUID, PSID};
use windows::Win32::Security::{
    GetLengthSid, LookupPrivilegeValueW, TokenIntegrityLevel, TokenIsAppContainer, TokenPrimary,
    TokenPrivileges, TokenType, TokenUser, LUID_AND_ATTRIBUTES, SE_CHANGE_NOTIFY_NAME,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_TYPE, TOKEN_USER,
};
use windows::Win32::System::JobObjects::IsProcessInJob;

#[derive(Debug, PartialEq, Eq)]
struct TokenSnapshot {
    user: Vec<u8>,
    integrity: Vec<u8>,
    token_type: i32,
    app_container: u32,
    groups: Vec<(Vec<u8>, u32)>,
    privileges: Vec<(u32, i32, u32)>,
}

unsafe fn copy_sid(sid: PSID) -> Vec<u8> {
    /* SAFETY: Callers supply a SID returned by a successful native token
    query, keeping the containing allocation alive until this copy completes. */
    unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), GetLengthSid(sid) as usize).to_vec() }
}

fn snapshot(process: HANDLE) -> Result<TokenSnapshot> {
    let mut raw = HANDLE::default();

    /* SAFETY: process is borrowed for this synchronous call. raw is live output
    storage and the successful result is immediately placed in an owner. */
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) }
        .context("open actual process token")?;
    let mut token = OwnedHandle::new(raw);

    let result = (|| -> Result<TokenSnapshot> {
        let user = query_token_information(token.raw(), TokenUser)?;
        let integrity = query_token_information(token.raw(), TokenIntegrityLevel)?;
        let token_type = query_token_information(token.raw(), TokenType)?;
        let app_container = query_token_information(token.raw(), TokenIsAppContainer)?;
        let groups = TokenGroupsBuffer(query_token_information(token.raw(), TokenGroups)?);
        let privileges = query_token_information(token.raw(), TokenPrivileges)?;

        /* SAFETY: Every allocation is pointer-aligned and contains the exact
        native structure requested above. Embedded SID pointers remain valid
        while their containing allocations are retained. The flexible-array
        pointer does not create a reference to the binding's single element. */
        let result = unsafe {
            let native_privileges = privileges.as_ptr().cast::<TOKEN_PRIVILEGES>();
            let privilege_entries = std::slice::from_raw_parts(
                std::ptr::addr_of!((*native_privileges).Privileges).cast::<LUID_AND_ATTRIBUTES>(),
                (*native_privileges).PrivilegeCount as usize,
            );

            let mut groups: Vec<(Vec<u8>, u32)> = groups
                .entries()
                .iter()
                .map(|group| (copy_sid(group.Sid), group.Attributes))
                .collect();
            groups.sort_unstable();

            let mut privileges: Vec<(u32, i32, u32)> = privilege_entries
                .iter()
                .map(|privilege| {
                    (
                        privilege.Luid.LowPart,
                        privilege.Luid.HighPart,
                        privilege.Attributes.0,
                    )
                })
                .collect();
            privileges.sort_unstable();

            TokenSnapshot {
                user: copy_sid((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid),
                integrity: copy_sid(
                    (*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
                        .Label
                        .Sid,
                ),
                token_type: (*token_type.as_ptr().cast::<TOKEN_TYPE>()).0,
                app_container: *app_container.as_ptr().cast::<u32>(),
                groups,
                privileges,
            }
        };

        Ok(result)
    })();

    with_cleanup(result, token.close())
}

fn sid_bytes(authority: u8, subauthorities: &[u32]) -> Vec<u8> {
    let mut sid = vec![1, subauthorities.len() as u8, 0, 0, 0, 0, 0, authority];

    for subauthority in subauthorities {
        sid.extend_from_slice(&subauthority.to_le_bytes());
    }

    sid
}

fn assert_restrictions(source: &TokenSnapshot, target: &TokenSnapshot) -> Result<usize> {
    assert_eq!(target.token_type, TokenPrimary.0);
    assert_eq!(target.user, source.user);
    assert_eq!(target.integrity, source.integrity);
    assert_eq!(target.app_container, source.app_container);

    let mut change_notify = LUID::default();
    /* SAFETY: The SDK supplies the terminated privilege name, and output
    storage remains valid for the synchronous lookup. */
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_CHANGE_NOTIFY_NAME, &mut change_notify) }
        .context("resolve traversal privilege")?;

    /*
     * Check privileges actually present, not only their enabled flags.
     * Removed privileges cannot subsequently be enabled by the target.
     */
    assert!(target.privileges.iter().all(|(low, high, _)| {
        *low == change_notify.LowPart && *high == change_notify.HighPart
    }));

    /*
     * Independent SID encodings and documented attribute values deliberately
     * avoid reusing the production policy predicate for expected results.
     */
    let retained = [
        sid_bytes(1, &[0]),
        sid_bytes(5, &[11]),
        sid_bytes(5, &[32, 545]),
        sid_bytes(5, &[4]),
    ];
    let mut denied = 0;

    for (sid, attributes) in &source.groups {
        let actual = target
            .groups
            .iter()
            .find(|(actual_sid, _)| actual_sid == sid)
            .context("restricted target lost a source group")?
            .1;

        if *attributes & 0x20 != 0
            || *attributes & 0xc000_0000 == 0xc000_0000
            || retained.contains(sid)
        {
            assert_eq!(actual, *attributes);
        } else {
            assert_eq!(actual & 0x16, 0x10);
            denied += 1;
        }
    }

    /*
     * Explicitly cover Administrators whenever present, including elevated
     * callers and UAC callers whose membership was already deny-only.
     */
    let administrators = sid_bytes(5, &[32, 544]);
    if let Some((_, attributes)) = target.groups.iter().find(|(sid, _)| sid == &administrators) {
        assert_eq!(*attributes & 0x16, 0x10);
    }

    Ok(denied)
}

#[tokio::test]
async fn actual_suspended_target_tokens_preserve_normal_and_apply_restricted_policy() -> Result<()>
{
    let executable = format!("{}\\System32\\cmd.exe", std::env::var("SystemRoot")?);
    let args = vec!["/D".into(), "/C".into(), "exit 17".into()];

    /* SAFETY: GetCurrentProcess returns a borrowed pseudo-handle. snapshot
    opens and closes a separate token handle and never owns the pseudo-handle. */
    let source = snapshot(unsafe { GetCurrentProcess() })?;

    for restricted_token in [false, true] {
        let config = SandboxConfig {
            restricted_token,
            interactive_mode: false,
            enable_api_hooks: false,
            ..SandboxConfig::default()
        };
        let mut process = create_sandboxed_process(&executable, &args, &config)?;
        assert!(process.is_suspended);
        assert_eq!(process.exit_code()?, None);
        assert!(process.executable().eq_ignore_ascii_case(&executable));

        let job = process.job_handle.context("target has no owned job")?;
        let mut in_job = BOOL::default();
        /* SAFETY: Both handles remain owned by process during the query. */
        unsafe { IsProcessInJob(process.process_handle, job, &mut in_job) }
            .context("query target job membership")?;
        assert!(in_job.as_bool());

        for handle in [process.process_handle, process.thread_handle, job] {
            let mut flags = 0;
            /* SAFETY: The queried handle remains owned throughout the call. */
            unsafe { GetHandleInformation(handle, &mut flags) }
                .context("query owned handle inheritance")?;
            assert_eq!(flags & 1, 0);
        }

        let actual = snapshot(process.process_handle)?;
        if restricted_token {
            let denied = assert_restrictions(&source, &actual)?;
            eprintln!(
                "restricted target pid={}: privileges {} -> {}, deny-only policy groups={}",
                process.process_id,
                source.privileges.len(),
                actual.privileges.len(),
                denied
            );
        } else {
            assert_eq!(actual, source);
        }

        /*
         * Subscribe before resume. The production resume method also verifies
         * that the initial thread had exactly one suspension outstanding.
         */
        let mut completion = HandleWait::new(process.process_handle)?;
        process.resume_initial_thread()?;
        tokio::time::timeout(Duration::from_secs(10), completion.wait())
            .await
            .context("benign token-test target did not exit")??;
        assert_eq!(process.exit_code()?, Some(17));

        let cleanup = with_cleanup(completion.close(), process.close());
        cleanup?;
        assert!(process.process_handle.is_invalid());
        assert!(process.thread_handle.is_invalid());
        assert!(process.job_handle.is_none());
    }

    /* Creating restricted targets must not mutate the caller's token. */
    let after = snapshot(unsafe { GetCurrentProcess() })?;
    assert_eq!(after, source);
    Ok(())
}

#[test]
fn restricted_process_creation_returns_native_failure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing-benign-target.exe");
    let executable = missing.to_str().context("fixture path is not Unicode")?;
    let config = SandboxConfig {
        restricted_token: true,
        interactive_mode: false,
        enable_api_hooks: false,
        ..SandboxConfig::default()
    };

    let error = match create_sandboxed_process(executable, &[], &config) {
        Err(error) => error,
        Ok(_) => bail!("a nonexistent executable unexpectedly started"),
    };
    assert_eq!(
        error
            .downcast_ref::<windows::core::Error>()
            .context("creation error lost its native cause")?
            .code(),
        HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
    );

    Ok(())
}
