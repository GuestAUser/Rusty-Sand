use super::*;
use crate::sandbox::{process::create_sandboxed_process, wait::HandleWait, Sandbox};
use anyhow::Context;
use std::time::Duration;

/* Full sessions share the process-wide human terminal, just as the CLI does.
 * Serialize only these terminal-owning integration cases; other platform tests
 * retain parallel execution and do not contend for prompt/activity ownership. */
static SESSION_TERMINAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn command_interpreter() -> Result<String> {
    let directory = std::env::var_os("SystemRoot").context("Windows directory is unavailable")?;
    std::path::PathBuf::from(directory)
        .join("System32")
        .join("cmd.exe")
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("Windows directory is not Unicode"))
}

#[tokio::test]
async fn noninteractive_library_execution_ignores_closed_process_stdin() -> Result<()> {
    use crate::sandbox::wait::wait_for_handle;
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    use windows::Win32::Foundation::HANDLE;

    /*
     * Isolate process-global stdin in a child harness, leaving parallel tests
     * untouched. Re-run the original behavioral test with an already closed
     * pipe, matching CI rather than changing its assertions or input policy.
     */
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "monitor::tests::library_execution_sets_executable_and_joins_observers",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdin.take());

    let completed = tokio::time::timeout(
        Duration::from_secs(20),
        wait_for_handle(HANDLE(child.as_raw_handle() as isize)),
    )
    .await;
    if !matches!(&completed, Ok(Ok(()))) {
        child.kill()?;
    }
    let output = child.wait_with_output()?;
    completed.context("closed-stdin library regression did not finish")??;
    assert!(
        output.status.success(),
        "child status: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[test]
fn event_retention_keeps_the_newest_entries_in_order() {
    let timestamp = Utc::now();
    let mut events: Vec<_> = (0..MAX_RETAINED_EVENTS + 3)
        .map(|index| Event {
            timestamp,
            event_type: EventType::ApiCall,
            details: index.to_string(),
        })
        .collect();
    trim_event_history(&mut events);
    assert_eq!(events.len(), MAX_RETAINED_EVENTS);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.details.parse::<usize>().unwrap(), index + 3);
    }
    trim_event_history(&mut events);
    assert_eq!(events.len(), MAX_RETAINED_EVENTS);
}

#[tokio::test]
async fn library_execution_sets_executable_and_joins_observers() -> Result<()> {
    let _terminal = SESSION_TERMINAL.lock().await;
    let output = tempfile::tempdir()?;
    let config = SandboxConfig {
        enable_api_hooks: false,
        interactive_mode: false,
        allow_registry: false,
        timeout: Duration::from_secs(10),
        output_dir: output.path().to_owned(),
        ..SandboxConfig::default()
    };
    let executable = command_interpreter()?;
    let report = Sandbox::new(config)?
        .execute(&executable, &["/D".into(), "/C".into(), "exit 7".into()])
        .await?;
    assert!(report.executable.eq_ignore_ascii_case(&executable));
    assert_eq!(report.exit_code, 7);
    assert!(report
        .events
        .iter()
        .any(|event| event.event_type == EventType::SandboxStopped));
    assert!(!report
        .events
        .iter()
        .any(|event| event.event_type == EventType::HookBlocked));
    Ok(())
}

#[tokio::test]
async fn requested_hook_startup_failure_never_runs_the_primary_thread() -> Result<()> {
    let _terminal = SESSION_TERMINAL.lock().await;
    use crate::ipc::HookIpcServer;
    use crate::sandbox::resource::OwnedHandle;
    use windows::Win32::System::Threading::GetExitCodeProcess;

    let config = SandboxConfig {
        interactive_mode: false,
        timeout: Duration::from_secs(10),
        ..SandboxConfig::default()
    };
    let process = create_sandboxed_process(
        &command_interpreter()?,
        &["/D".into(), "/C".into(), "exit 7".into()],
        &config,
    )?;
    let mut process_copy = OwnedHandle::duplicate(process.process_handle)?;
    let mut wait = HandleWait::new(process.process_handle)?;
    let mut occupied_pipe = HookIpcServer::for_process(process.process_id)?;
    assert!(MonitoringEngine::new(config)?
        .monitor_process(process)
        .await
        .is_err());
    tokio::time::timeout(Duration::from_secs(5), wait.wait())
        .await
        .context("failed hook startup left a process alive")??;
    let mut code = 0;
    /* SAFETY: The duplicate remains owned here after monitoring closes its
    own handle; the completion notification proves that exit has finished. */
    unsafe { GetExitCodeProcess(process_copy.raw(), &mut code)? };
    assert_ne!(code, 7);
    occupied_pipe.disconnect()?;
    wait.close()?;
    process_copy.close()?;
    Ok(())
}

#[tokio::test]
async fn startup_deadline_terminates_without_resuming() -> Result<()> {
    let _terminal = SESSION_TERMINAL.lock().await;
    let config = SandboxConfig {
        timeout: Duration::ZERO,
        interactive_mode: false,
        ..SandboxConfig::default()
    };
    let process = create_sandboxed_process(
        &command_interpreter()?,
        &["/D".into(), "/C".into(), "exit 7".into()],
        &config,
    )?;
    let mut wait = HandleWait::new(process.process_handle)?;
    let error = MonitoringEngine::new(config)?
        .monitor_process(process)
        .await
        .unwrap_err();
    assert!(error.is::<DeadlineExceeded>(), "{error:#}");
    tokio::time::timeout(Duration::from_secs(5), wait.wait())
        .await
        .context("startup deadline left a suspended process alive")??;
    wait.close()?;
    Ok(())
}
