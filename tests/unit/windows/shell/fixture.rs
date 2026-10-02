use crate::config::SandboxConfig;
use crate::live::{LiveSession, RunState};
use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use crate::sandbox::wait::{wait_for_handle, HandleWait};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, SetEvent, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

pub(crate) use crate::monitor::tests::SESSION_TERMINAL as UI_LOCK;

const FIXTURE_PREFIX: &str = "rusty-shell-fixture-";
const FIXTURE_TEST: &str = "live::shell_tests::fixture::owned_target_fixture";

pub(crate) struct Fixture {
    directory: tempfile::TempDir,
    executable: PathBuf,
    ready: OwnedHandle,
    release: OwnedHandle,
}

impl Fixture {
    pub(crate) fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let suffix = directory
            .path()
            .file_name()
            .context("fixture directory has no filename")?
            .to_string_lossy();
        let stem = format!("{FIXTURE_PREFIX}{suffix}");
        let executable = directory.path().join(format!("{stem}.exe"));

        /*
         * Select the source-known child role by its copied executable name.
         * No process-global environment mutation or production env override
         * is needed. The parent creates both event gates before launch.
         */
        std::fs::copy(std::env::current_exe()?, &executable)?;
        let ready = event(&format!("{stem}-ready"))?;
        let release = event(&format!("{stem}-release"))?;

        Ok(Self {
            directory,
            executable,
            ready,
            release,
        })
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn session(&self) -> Result<LiveSession> {
        LiveSession::new(
            self.executable
                .to_str()
                .context("fixture path is not Unicode")?,
            &self.args(),
            self.config(),
        )
    }

    pub(crate) fn config(&self) -> SandboxConfig {
        SandboxConfig {
            interactive_mode: true,
            cancel_on_stdin_eof: true,
            enable_api_hooks: false,
            allow_registry: false,
            enable_behavior_detection: false,
            max_cpu_time: 0,
            timeout: Duration::from_secs(30),
            working_dir: Some(self.directory.path().to_owned()),
            output_dir: self.output(),
            ..SandboxConfig::default()
        }
    }

    pub(crate) fn args(&self) -> Vec<String> {
        vec![
            "--exact".into(),
            FIXTURE_TEST.into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ]
    }

    pub(crate) async fn running(&self, session: &LiveSession) -> Result<()> {
        let mut state = session
            .subscribe()
            .context("fixture has no active execution")?;

        tokio::time::timeout(Duration::from_secs(10), async {
            state
                .wait_for(|state| *state == RunState::Running || state.is_finished())
                .await
                .context("execution state publisher disappeared")?;

            assert_eq!(session.state(), RunState::Running);
            wait_for_handle(self.ready.raw()).await
        })
        .await
        .context("fixture never became ready")??;

        Ok(())
    }

    pub(crate) fn release(&self) -> Result<()> {
        /* SAFETY: The fixture retains this named manual-reset event. */
        unsafe { SetEvent(self.release.raw()) }.context("release benign fixture")
    }

    pub(crate) fn output(&self) -> PathBuf {
        self.directory.path().join("reports")
    }
}

fn event(name: &str) -> Result<OwnedHandle> {
    let name: Vec<u16> = format!("Local\\{name}")
        .encode_utf16()
        .chain(Some(0))
        .collect();

    /* SAFETY: The terminated name outlives this synchronous call. The new
    native handle receives one checked owner immediately. */
    Ok(OwnedHandle::new(unsafe {
        CreateEventW(None, true, false, PCWSTR(name.as_ptr()))?
    }))
}

#[test]
fn owned_target_fixture() -> Result<()> {
    let executable = std::env::current_exe()?;
    let stem = executable
        .file_stem()
        .context("test executable has no stem")?
        .to_string_lossy();

    if !stem.starts_with(FIXTURE_PREFIX) {
        return Ok(());
    }

    let ready = event(&format!("{stem}-ready"))?;
    let release = event(&format!("{stem}-release"))?;

    /* SAFETY: Both event handles remain owned through this bounded gate.
    There is no readiness sleep or timing-dependent polling assertion. */
    unsafe {
        SetEvent(ready.raw())?;
        assert_eq!(WaitForSingleObject(release.raw(), 30_000), WAIT_OBJECT_0);
    }

    Ok(())
}

pub(crate) fn process_completion(session: &LiveSession) -> Result<HandleWait> {
    let pid = session
        .process_id()
        .context("fixture has no owned process")?;

    /* SAFETY: This wait-only handle observes the exact benign process the
    test created. It is never used to terminate or control another process. */
    let mut process = OwnedHandle::new(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid)? });
    let wait = HandleWait::new(process.raw());

    with_cleanup(wait, process.close())
}
