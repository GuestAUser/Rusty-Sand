use super::*;
use crate::sandbox::wait::HandleWait;
use std::time::Duration;

/* Keep test error modes on a dedicated OS thread. Always join it, including
when the operation returns an error or panics; no timeout detaches the owner. */
fn on_error_mode_thread(
    mode: THREAD_ERROR_MODE,
    operation: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    let worker = std::thread::spawn(move || {
        let mut previous = THREAD_ERROR_MODE::default();

        /* SAFETY: This test owns the dedicated calling thread. */
        unsafe { SetThreadErrorMode(mode, Some(&mut previous)) }
            .context("set test thread error mode")?;

        let result = operation();
        /* SAFETY: Restore the mode on the same thread that saved it. A panic
        instead ends this dedicated thread without changing any other thread. */
        let restored =
            unsafe { SetThreadErrorMode(previous, None) }.context("restore test thread error mode");

        with_cleanup(result, restored)
    });

    match worker.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn creation_error_mode_is_scoped_and_restores_on_drop() -> Result<()> {
    for prior in [THREAD_ERROR_MODE::default(), SEM_NOOPENFILEERRORBOX] {
        on_error_mode_thread(prior, move || {
            {
                let _mode = CreationErrorMode::suppress_dialogs()?;

                /* SAFETY: Query only this dedicated thread's current mode. */
                let active = THREAD_ERROR_MODE(unsafe { GetThreadErrorMode() });
                assert_eq!(
                    active,
                    prior | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
                );
            }

            /* SAFETY: The guard has left scope on this same thread. */
            assert_eq!(unsafe { GetThreadErrorMode() }, prior.0);
            Ok(())
        })?;
    }

    Ok(())
}

#[test]
fn successful_creation_restores_prior_thread_error_mode() -> Result<()> {
    for prior in [THREAD_ERROR_MODE::default(), SEM_NOOPENFILEERRORBOX] {
        on_error_mode_thread(prior, move || {
            let executable = format!("{}\\System32\\cmd.exe", std::env::var("SystemRoot")?);
            let args = vec!["/D".into(), "/C".into(), "exit 0".into()];

            for restricted_token in [false, true] {
                let config = SandboxConfig {
                    restricted_token,
                    interactive_mode: false,
                    enable_api_hooks: false,
                    ..SandboxConfig::default()
                };
                let mut process = create_sandboxed_process(&executable, &args, &config)?;

                /* SAFETY: Creation returned on the thread with the saved mode. */
                assert_eq!(unsafe { GetThreadErrorMode() }, prior.0);
                assert!(process.is_suspended);
                assert!(process.job_handle.is_some());
                assert_eq!(process.exit_code()?, None);

                process.resume_initial_thread()?;
                assert_eq!(wait_for_process(&process, 10_000)?, WAIT_OBJECT_0.0);
                assert_eq!(process.exit_code()?, Some(0));
                process.close()?;
            }

            Ok(())
        })?;
    }

    Ok(())
}

#[test]
fn failed_creation_returns_native_errors_and_restores_prior_thread_error_mode() -> Result<()> {
    use windows::core::HRESULT;
    use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;

    /* A missing file returns without entering the image loader. Malformed
    images belong in the separately bounded CLI subprocess regression. */
    for prior in [THREAD_ERROR_MODE::default(), SEM_NOOPENFILEERRORBOX] {
        on_error_mode_thread(prior, move || {
            let directory = tempfile::tempdir()?;
            let missing = directory.path().join("missing.exe");
            let executable = missing.to_str().context("fixture path is not Unicode")?;

            for restricted_token in [false, true] {
                let config = SandboxConfig {
                    restricted_token,
                    interactive_mode: false,
                    enable_api_hooks: false,
                    ..SandboxConfig::default()
                };
                let result = create_sandboxed_process(executable, &[], &config);

                /* SAFETY: Failure returned on the thread with the saved mode. */
                assert_eq!(unsafe { GetThreadErrorMode() }, prior.0);

                let error = match result {
                    Err(error) => error,
                    Ok(_) => bail!("missing target unexpectedly launched"),
                };
                let code = error
                    .downcast_ref::<windows::core::Error>()
                    .context("creation error lost its native cause")?
                    .code();

                assert_eq!(code, HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0));
            }

            Ok(())
        })?;
    }

    Ok(())
}

#[tokio::test]
async fn reserved_exit_status_is_distinguished_from_a_live_process() -> Result<()> {
    let executable = format!("{}\\System32\\cmd.exe", std::env::var("SystemRoot")?);
    let config = SandboxConfig {
        interactive_mode: false,
        enable_api_hooks: false,
        ..SandboxConfig::default()
    };
    let mut process = create_sandboxed_process(
        &executable,
        &["/D".into(), "/C".into(), "exit 259".into()],
        &config,
    )?;
    assert_eq!(process.exit_code()?, None);
    let mut completion = HandleWait::new(process.process_handle)?;

    process.resume_initial_thread()?;
    tokio::time::timeout(Duration::from_secs(5), completion.wait())
        .await
        .context("reserved-status process did not exit")??;

    assert_eq!(process.exit_code()?, Some(259));
    completion.close()?;
    process.close()?;
    Ok(())
}

#[test]
fn resource_limits_are_checked_before_process_creation() {
    let mut config = SandboxConfig {
        max_memory_mb: u64::MAX,
        ..SandboxConfig::default()
    };
    assert!(job_limits(&config).is_err());
    config.max_memory_mb = 0;
    config.max_cpu_time = u64::MAX;
    assert!(job_limits(&config).is_err());
    config.max_cpu_time = 2;
    assert_eq!(
        job_limits(&config)
            .unwrap()
            .BasicLimitInformation
            .PerProcessUserTimeLimit,
        20_000_000
    );
}

#[tokio::test]
async fn failed_job_assignment_terminates_owned_normal_and_restricted_targets() -> Result<()> {
    use windows::core::HRESULT;
    use windows::Win32::Foundation::ERROR_INVALID_HANDLE;

    let executable = format!("{}\\System32\\cmd.exe", std::env::var("SystemRoot")?);
    let args = vec!["/D".into(), "/C".into(), "exit 23".into()];

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

        let mut observer = OwnedHandle::duplicate(process.process_handle)?;
        let mut completion = HandleWait::new(process.process_handle)?;

        /*
         * Keep the original job alive independently so kill-on-job-close cannot
         * make this test pass. The failure path must terminate the still-owned
         * process itself. An invalid destination deterministically exercises
         * the real AssignProcessToJobObject error and production cleanup path.
         */
        let mut original_job = OwnedHandle::new(
            process
                .job_handle
                .take()
                .context("created target has no job")?,
        );
        let result = finish_suspended_process(process, OwnedHandle::new(HANDLE::default()));
        let error = match result {
            Err(error) => error,
            Ok(_) => bail!("assignment to an invalid job unexpectedly succeeded"),
        };
        assert_eq!(
            error
                .downcast_ref::<windows::core::Error>()
                .context("assignment error lost its native cause")?
                .code(),
            HRESULT::from_win32(ERROR_INVALID_HANDLE.0)
        );

        tokio::time::timeout(Duration::from_secs(10), completion.wait())
            .await
            .context("assignment failure left the owned target alive")??;

        let mut exit_code = 0;
        /* SAFETY: observer owns a duplicate process handle and completion
        confirmed that the process has exited. The original job is still open. */
        unsafe { GetExitCodeProcess(observer.raw(), &mut exit_code) }
            .context("query failed-assignment target exit code")?;
        assert_eq!(exit_code, 1);

        let cleanup = with_cleanup(completion.close(), observer.close());
        with_cleanup(cleanup, original_job.close())?;
    }

    Ok(())
}

#[tokio::test]
async fn noninteractive_creation_stays_suspended_and_cleanup_kills_it() -> Result<()> {
    let executable = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").context("Windows directory is unavailable")?,
    )
    .join("System32")
    .join("cmd.exe");
    let executable = executable
        .to_str()
        .context("Windows directory is not Unicode")?;
    let config = SandboxConfig {
        interactive_mode: false,
        enable_api_hooks: false,
        ..SandboxConfig::default()
    };
    let args = vec!["/D".into(), "/C".into(), "exit 7".into()];
    let process = create_sandboxed_process(executable, &args, &config)?;
    assert!(process.is_suspended);
    assert_eq!(process.exit_code()?, None);
    let mut wait = HandleWait::new(process.process_handle)?;
    drop(process);
    tokio::time::timeout(Duration::from_secs(5), wait.wait())
        .await
        .context("dropped suspended process remained alive")??;
    wait.close()?;

    let mut process = create_sandboxed_process(executable, &args, &config)?;
    let mut wait = HandleWait::new(process.process_handle)?;
    process.resume_initial_thread()?;
    tokio::time::timeout(Duration::from_secs(5), wait.wait())
        .await
        .context("approved process did not exit")??;
    assert_eq!(process.exit_code()?, Some(7));
    assert!(!process.executable().is_empty());
    wait.close()?;
    process.terminate(0)?;
    process.close()?;
    assert!(process.process_handle.is_invalid());
    assert!(process.thread_handle.is_invalid());
    assert!(process.job_handle.is_none());
    Ok(())
}
