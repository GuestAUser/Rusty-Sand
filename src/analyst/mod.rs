//! Owned asynchronous frontend for the synchronous native debugger.
//!
//! Explicit cancellation waits for debugger cleanup. Dropping the outer future
//! signals the same cancellation flag; no hook execution API is involved.

use crate::debugger::{debug_executable, DebugReport};
use crate::monitor::input::{ConsoleInput, InputEnd};
use crate::sandbox::resource::with_cleanup;
use crate::ui::{self, Panel, PromptEnd, Tone};
use crate::SandboxConfig;
use anyhow::{anyhow, bail, Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal::windows::CtrlC;
use tokio::sync::watch;

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Debug a new target with fail-closed approval and owned cancellation.
///
/// Noninteractive library calls do not read ambient stdin unless the caller
/// explicitly enables `cancel_on_stdin_eof` for its owned control transport.
pub async fn run_debug(
    executable: &str,
    args: &[String],
    config: SandboxConfig,
) -> Result<DebugReport> {
    config.validate()?;

    let mut signal =
        tokio::signal::windows::ctrl_c().context("register debugger Ctrl-C cancellation")?;
    let mut input = if config.interactive_mode || config.cancel_on_stdin_eof {
        Some(ConsoleInput::new()?)
    } else {
        None
    };
    let mut status = input.as_ref().map(ConsoleInput::status);

    let result = run_owned(
        executable,
        args,
        config,
        &mut input,
        &mut status,
        &mut signal,
    )
    .await;
    let cleanup = input.as_mut().map_or(Ok(()), ConsoleInput::close);

    with_cleanup(result, cleanup)
}

async fn run_owned(
    executable: &str,
    args: &[String],
    config: SandboxConfig,
    input: &mut Option<ConsoleInput>,
    status: &mut Option<watch::Receiver<Option<InputEnd>>>,
    signal: &mut CtrlC,
) -> Result<DebugReport> {
    let approval = tokio::select! {
        biased;
        reason = cancelled(status, signal) => Err(reason),
        result = tokio::time::timeout(
            config.timeout,
            approve(executable, config.interactive_mode, input),
        ) => result.context("debugger startup approval timed out").and_then(|result| result),
    };
    approval?;

    if let Some(status) = status.as_ref() {
        check_input(status)?;
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let guard = CancelOnDrop(cancel.clone());
    let executable = executable.to_owned();
    let args = args.to_vec();
    let mut worker =
        tokio::task::spawn_blocking(move || debug_executable(&executable, &args, &config, &cancel));

    // Never abort or abandon this task on an explicit CLI cancellation.
    // Its return is the acknowledgement that native debugger cleanup finished.
    let (joined, interruption) = tokio::select! {
        biased;
        reason = cancelled(status, signal) => {
            guard.0.store(true, Ordering::Release);
            (worker.await, Some(reason))
        }
        result = &mut worker => (result, None),
    };
    guard.0.store(true, Ordering::Release);

    let result = joined
        .context("debugger blocking task failed")
        .and_then(|result| result);

    if let Some(reason) = interruption {
        let mut report = result.with_context(|| format!("Debugger cancellation: {reason:#}"))?;
        report.cancelled = true;
        report
            .limitations
            .push(format!("Frontend cancellation: {reason:#}"));

        Ok(report)
    } else {
        result
    }
}

async fn approve(
    executable: &str,
    interactive: bool,
    input: &mut Option<ConsoleInput>,
) -> Result<()> {
    if !interactive {
        return Ok(());
    }

    let input = input
        .as_mut()
        .context("debugger approval reader is missing")?;
    let status = input.status();
    let answer = input.read_line();
    let prompt = ui::terminal().begin_prompt(&Panel {
        title: "Debugger startup approval".into(),
        tone: Tone::Warning,
        fields: vec![("Target".into(), executable.to_owned())],
        notes: vec![
            "Approval launches the target under the native debugger, without API hooks.".into(),
            "Hook-based internet, DNS, registry, and filesystem policy is not enforced.".into(),
            "[Y] Allow startup / [N] Deny (default). Ctrl-C or input EOF cancels.".into(),
        ],
    })?;
    let answer = answer.await?;

    // Match the existing reader's approval release checkpoint.
    tokio::task::yield_now().await;
    check_input(&status)?;
    prompt.finish(PromptEnd::Answered)?;

    if !answer.trim().eq_ignore_ascii_case("Y") {
        bail!("user denied debugger startup");
    }

    Ok(())
}

fn check_input(status: &watch::Receiver<Option<InputEnd>>) -> Result<()> {
    match status.borrow().clone() {
        None => Ok(()),
        Some(InputEnd::Eof) => bail!("input closed; debugger session cancelled"),
        Some(InputEnd::Cancelled) => bail!("user cancelled debugger session"),
        Some(InputEnd::Failed(error)) => bail!("debugger input failed: {error}"),
    }
}

async fn input_ended(status: &mut Option<watch::Receiver<Option<InputEnd>>>) -> anyhow::Error {
    let Some(status) = status else {
        return std::future::pending().await;
    };

    loop {
        if let Err(error) = check_input(status) {
            return error;
        }
        if let Err(error) = status.changed().await {
            return anyhow!("debugger input status channel closed: {error}");
        }
    }
}

async fn cancelled(
    status: &mut Option<watch::Receiver<Option<InputEnd>>>,
    signal: &mut CtrlC,
) -> anyhow::Error {
    tokio::select! {
        biased;
        event = signal.recv() => {
            if event.is_some() {
                anyhow!("Ctrl-C; debugger session cancelled")
            } else {
                anyhow!("debugger Ctrl-C stream closed")
            }
        }
        reason = input_ended(status) => reason,
    }
}
