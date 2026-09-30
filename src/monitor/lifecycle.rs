use super::{
    hooks,
    input::{ConsoleInput, InputEnd},
    review,
    tasks::MonitorTasks,
};
use crate::behavior::BehaviorAnalyzer;
use crate::config::SandboxConfig;
use crate::control::UserDecision;
use crate::ipc::HookIpcServer;
use crate::report::{Event, EventType};
use crate::sandbox::deadline::Deadline;
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::with_cleanup;
use crate::sandbox::wait::wait_for_handle;
use crate::ui::{self, Panel, PromptEnd, Tone};
use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};

pub(super) struct Session {
    observers: Option<MonitorTasks>,
    input: Option<ConsoleInput>,
    server: Option<HookIpcServer>,
    pub(super) process: ProcessHandle,
}

impl Session {
    pub(super) fn new(process: ProcessHandle) -> Self {
        Self {
            observers: None,
            input: None,
            server: None,
            process,
        }
    }

    pub(super) async fn run(
        &mut self,
        config: &SandboxConfig,
        events: Arc<Mutex<Vec<Event>>>,
        deadline: Deadline,
    ) -> Result<u32> {
        if !self.process.is_suspended {
            bail!("monitoring requires an initially suspended process");
        }
        let mut signal =
            tokio::signal::windows::ctrl_c().context("register Ctrl-C cancellation")?;
        if config.interactive_mode || (config.cancel_on_stdin_eof && redirected_pipe()?) {
            self.input = Some(ConsoleInput::new()?);
        }
        let mut status = self.input.as_ref().map(ConsoleInput::status);

        /* Cancellation owns the outer race across every startup and running
         * await. Explicit checks at release boundaries cover work completed
         * within a single poll before this select can be polled again. */
        tokio::select! {
            biased;
            result = cancelled(&mut status, &mut signal) => result,
            result = self.run_active(config, events, deadline) => result,
        }
    }

    async fn run_active(
        &mut self,
        config: &SandboxConfig,
        events: Arc<Mutex<Vec<Event>>>,
        deadline: Deadline,
    ) -> Result<u32> {
        let initialization = ui::terminal().activity("Initializing suspended target")?;
        if config.interactive_mode {
            let input = self
                .input
                .as_mut()
                .context("console reader was not initialized")?;
            let status = input.status();
            let answer = input.read_line();
            let prompt = ui::terminal().begin_prompt(&Panel {
                title: "Startup approval".into(),
                tone: Tone::Warning,
                fields: vec![("Suspended PID".into(), self.process.process_id.to_string())],
                notes: vec![
                    "Approval permits loader and hook initialization, then the target's primary thread.".into(),
                    "[Y] Allow startup / [N] Deny (default). Ctrl-C cancels.".into(),
                ],
            })?;
            let answer = answer.await?;
            tokio::task::yield_now().await;
            check_input(&status)?;
            prompt.finish(PromptEnd::Answered)?;
            if !answer.trim().eq_ignore_ascii_case("Y") {
                bail!("user denied process startup");
            }
        }
        deadline.check()?;
        if config.enable_api_hooks {
            let library = crate::injection::ensure_hook_dll_exists()?;
            self.server = Some(HookIpcServer::for_process(self.process.process_id)?);
            let server = self
                .server
                .as_mut()
                .context("hook pipe was not initialized")?;
            tokio::try_join!(
                crate::injection::inject_dll_async(self.process.process_handle, &library),
                server.handshake(),
            )
            .context("required hook startup failed")?;
        }
        self.observers = Some(MonitorTasks::start(
            config.clone(),
            events.clone(),
            self.process.process_id,
        )?);
        /* Registration precedes resume so even an immediately exiting process
        has a completion notification. No readiness sleeps are necessary. */
        let mut process_wait = crate::sandbox::wait::HandleWait::new(self.process.process_handle)?;
        /* Give the outer biased cancellation race a release checkpoint even
         * when initialization completed without a pending await. */
        tokio::task::yield_now().await;
        let resume = self
            .input
            .as_ref()
            .map_or(Ok(()), |input| check_input(&input.status()))
            .and_then(|()| deadline.check())
            .and_then(|()| self.process.resume_initial_thread());
        if let Err(error) = resume {
            return with_cleanup(Err(error), process_wait.close());
        }
        initialization.finish(
            "Initialization complete; primary thread resumed",
            Tone::Success,
        )?;
        let running = ui::terminal().activity("Running target and observing activity")?;
        let observers = self
            .observers
            .as_mut()
            .context("observers were not initialized")?;
        let (reviews, review_broker) = review::channel();
        let input_status = self.input.as_ref().map(ConsoleInput::status);
        let result = tokio::select! {
            biased;
            result = process_wait.wait() => {
                result.and_then(|()| self.process.exit_code())
                    .and_then(|code| code.context("signaled process has no exit code"))
            }
            result = observers.ended() => {
                result.and_then(|()| Err(anyhow!("observation worker stopped while the target was running")))
            }
            result = hooks::serve(self.server.as_mut(), &reviews, config, events.clone(), input_status.as_ref()) => {
                /* Pipe disconnect and process exit can arrive together. Only a
                   confirmed OS exit makes a disconnect normal. */
                match result {
                    Err(error) if disconnected(&error) => match self.process.exit_code() {
                        Ok(Some(code)) => Ok(code),
                        Ok(None) => Err(error),
                        Err(query) => with_cleanup(Err(error), Err(query)),
                    },
                    Err(error) => Err(error),
                    Ok(()) => Err(anyhow!("hook approval service stopped")),
                }
            }
            result = analyze(config, events, &reviews) => result.and_then(|()| Err(anyhow!("behavior analysis stopped"))),
            result = review_broker.run(self.input.as_mut()) => result.and_then(|()| Err(anyhow!("interactive review service stopped"))),
        };
        let (outcome, tone) = match &result {
            Ok(0) => ("Target exited successfully", Tone::Success),
            Ok(_) => ("Target exited with a nonzero status", Tone::Warning),
            Err(_) => ("Target monitoring stopped with an error", Tone::Danger),
        };
        let presentation = running.finish(outcome, tone).map_err(Into::into);
        let result = with_cleanup(result, presentation);
        with_cleanup(result, process_wait.close())
    }

    pub(super) async fn close(&mut self, code: u32) -> Result<()> {
        let activity = ui::terminal().activity("Cleaning up target, readers and observers");
        let mut result = self.process.terminate(code);
        if let Some(server) = self.server.as_mut() {
            result = with_cleanup(result, server.disconnect());
        }
        self.server = None;
        if let Some(input) = self.input.as_mut() {
            result = with_cleanup(result, input.close());
        }
        self.input = None;
        if let Some(observers) = self.observers.as_mut() {
            result = with_cleanup(result, observers.close().await);
        }
        self.observers = None;
        let waited = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_handle(self.process.process_handle),
        )
        .await
        .context("terminated process did not exit within cleanup deadline")
        .and_then(|result| result);
        result = with_cleanup(result, waited);
        result = with_cleanup(result, self.process.close());
        let presentation = match activity {
            Ok(activity) => activity.finish(
                if result.is_ok() {
                    "Cleanup complete"
                } else {
                    "Cleanup failed"
                },
                if result.is_ok() {
                    Tone::Success
                } else {
                    Tone::Danger
                },
            ),
            Err(error) => Err(error),
        };
        with_cleanup(result, presentation.map_err(Into::into))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        /* An externally cancelled execute future still kills the target before
        field destructors join workers and close communication resources. */
        if !self.process.process_handle.is_invalid() {
            if let Err(error) = self.process.terminate(1) {
                log::error!("Cancelled session termination failed: {error:#}");
            }
        }
    }
}

fn redirected_pipe() -> Result<bool> {
    use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
    use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

    /* SAFETY: The standard handle is only queried, never closed or retained.
     * Noninteractive native sessions need only the independent Ctrl-C stream. */
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }?;
    Ok(unsafe { GetFileType(input) } == FILE_TYPE_PIPE)
}

pub(super) fn check_input(status: &watch::Receiver<Option<InputEnd>>) -> Result<()> {
    match status.borrow().clone() {
        None => Ok(()),
        Some(InputEnd::Eof) => bail!("input closed; session cancelled"),
        Some(InputEnd::Cancelled) => bail!("user cancelled session"),
        Some(InputEnd::Failed(error)) => bail!("input failed: {error}"),
    }
}

async fn input_ended(status: &mut Option<watch::Receiver<Option<InputEnd>>>) -> Result<()> {
    let Some(status) = status else {
        return std::future::pending().await;
    };

    loop {
        check_input(status)?;
        status
            .changed()
            .await
            .context("input status channel closed")?;
    }
}

async fn cancelled(
    status: &mut Option<watch::Receiver<Option<InputEnd>>>,
    signal: &mut tokio::signal::windows::CtrlC,
) -> Result<u32> {
    tokio::select! {
        biased;
        _ = signal.recv() => bail!("Ctrl-C; session cancelled"),
        result = input_ended(status) => { result?; bail!("input reader stopped") },
    }
}

fn disconnected(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        use std::io::ErrorKind;
        matches!(
            error.kind(),
            ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::NotConnected
        )
    })
}

async fn analyze(
    config: &SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
    reviews: &review::ReviewClient,
) -> Result<()> {
    let mut analyzer = BehaviorAnalyzer::new();
    let mut processed = 0;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let recent = {
            let mut events = events.lock().await;
            let recent = events[processed.min(events.len())..].to_vec();
            super::trim_event_history(&mut events);
            processed = events.len();
            recent
        };
        if !config.enable_behavior_detection {
            continue;
        }
        for event in recent {
            if let Some(threat) = analyzer.analyze_event(&event) {
                log::warn!(
                    "Behavior observation: {} ({:?})",
                    threat.threat_type,
                    threat.level
                );
                events.lock().await.push(Event {
                    timestamp: chrono::Utc::now(),
                    event_type: EventType::Suspicious,
                    details: format!("{}: {}", threat.threat_type, threat.description),
                });
                let decision = await_review(
                    reviews.observation(config, &threat),
                    &events,
                    &mut processed,
                    &mut interval,
                )
                .await?;
                let mut events = events.lock().await;
                review::apply_observation_decision(&threat, decision, &mut events)?;
            }
        }
    }
}

async fn await_review(
    review: impl std::future::Future<Output = Result<Option<UserDecision>>>,
    events: &Mutex<Vec<Event>>,
    processed: &mut usize,
    interval: &mut tokio::time::Interval,
) -> Result<Option<UserDecision>> {
    tokio::pin!(review);
    loop {
        tokio::select! {
            biased;
            decision = &mut review => return decision,
            _ = interval.tick() => {
                /* Keep history bounded during a human decision without losing
                the cursor into the still-retained, unanalyzed observations. */
                let mut events = events.lock().await;
                let previous_len = events.len();
                super::trim_event_history(&mut events);
                *processed = processed.saturating_sub(previous_len - events.len());
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_lifecycle.rs"]
mod tests;
