use super::recording::Recording;
use super::session::Session;
use super::DebugReport;
use crate::config::SandboxConfig;
use crate::sandbox::process::create_sandboxed_process;
use anyhow::{anyhow, bail, Context, Result};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const MAX_INPUT_BYTES: usize = 131_068;

pub(super) fn execute(
    executable: &str,
    args: &[String],
    config: &SandboxConfig,
    cancel: &AtomicBool,
) -> Result<DebugReport> {
    /*
     * Bound allocations made by the reused command-line encoder before calling
     * it. That encoder remains authoritative for Windows quoting and its UTF-16
     * command-line limit.
     */
    let mut input_bytes = executable.len();

    for argument in args {
        input_bytes = input_bytes
            .checked_add(argument.len())
            .and_then(|length| length.checked_add(1))
            .context("debugger command line length overflow")?;

        if input_bytes > MAX_INPUT_BYTES {
            bail!("debugger command line exceeds its input bound");
        }
    }

    if input_bytes > MAX_INPUT_BYTES
        || config
            .working_dir
            .as_ref()
            .is_some_and(|path| path.as_os_str().len() > MAX_INPUT_BYTES)
    {
        bail!("debugger creation input exceeds its input bound");
    }

    let started = Instant::now();
    let deadline = started
        .checked_add(config.timeout)
        .context("debugger timeout exceeds the monotonic clock range")?;

    /*
     * Debugger attachment and its event queue are thread-affine. A fresh thread
     * also prevents kill-on-debugger-exit policy from affecting another session
     * on a reused async blocking-pool thread.
     */
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("owned-windows-debugger".into())
            .spawn_scoped(scope, move || {
                run_owned(executable, args, config, cancel, started, deadline)
            })
            .context("create dedicated debugger OS thread")?;

        worker
            .join()
            .map_err(|_| anyhow!("dedicated debugger OS thread panicked"))?
    })
}

fn run_owned(
    executable: &str,
    args: &[String],
    config: &SandboxConfig,
    cancel: &AtomicBool,
    started: Instant,
    deadline: Instant,
) -> Result<DebugReport> {
    let process = create_sandboxed_process(executable, args, config)?;
    let executable = process.executable().to_owned();
    let target_pid = process.process_id;
    let mut session = Session::new(process);
    let mut recording = Recording::new(started);

    /*
     * Keep ownership outside the unwind boundary so even an unexpected loop
     * panic goes through termination, event draining, reaping, and checked close.
     */
    let result = catch_unwind(AssertUnwindSafe(|| {
        session.run(deadline, cancel, &mut recording)
    }))
    .map_err(|_| anyhow!("debugger event loop panicked"))
    .and_then(|result| result);

    let code = session.finish(result)?;

    Ok(recording.into_report(executable, target_pid, code))
}
