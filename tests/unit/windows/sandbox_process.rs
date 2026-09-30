use super::*;
use crate::sandbox::wait::HandleWait;
use std::time::Duration;

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
