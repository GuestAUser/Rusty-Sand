use super::{hooks, input::ConsoleInput, review, tasks::MonitorTasks};
use crate::behavior::BehaviorAnalyzer;
use crate::config::SandboxConfig;
use crate::control::UserDecision;
use crate::ipc::HookIpcServer;
use crate::report::{Event, EventType};
use crate::sandbox::deadline::Deadline;
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::with_cleanup;
use crate::sandbox::wait::wait_for_handle;
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
        if config.interactive_mode {
            self.input = Some(ConsoleInput::new()?);
            println!("\nProcess {} is suspended.", self.process.process_id);
            println!("Startup approval permits loader and hook initialization,");
            println!("then execution of the target's primary thread.");
            println!("Allow startup? [Y/N]");
            std::io::stdout().flush()?;
            let input = self
                .input
                .as_mut()
                .context("console reader was not initialized")?;
            if !input.read_line().await?.trim().eq_ignore_ascii_case("Y") {
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
        let resume = deadline
            .check()
            .and_then(|()| self.process.resume_initial_thread());
        if let Err(error) = resume {
            return with_cleanup(Err(error), process_wait.close());
        }
        let observers = self
            .observers
            .as_mut()
            .context("observers were not initialized")?;
        let (reviews, review_broker) = review::channel();
        let result = tokio::select! {
            biased;
            result = process_wait.wait() => {
                result.and_then(|()| self.process.exit_code())
                    .and_then(|code| code.context("signaled process has no exit code"))
            }
            result = observers.ended() => {
                result.and_then(|()| Err(anyhow!("observation worker stopped while the target was running")))
            }
            result = hooks::serve(self.server.as_mut(), &reviews, config, events.clone()) => {
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
        with_cleanup(result, process_wait.close())
    }

    pub(super) async fn close(&mut self, code: u32) -> Result<()> {
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
        with_cleanup(result, self.process.close())
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
