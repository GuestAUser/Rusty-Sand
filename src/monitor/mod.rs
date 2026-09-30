pub mod etw_registry;
pub mod filesystem;
pub mod network;
pub mod process;
pub mod registry;

mod hooks;
mod input;
mod lifecycle;
mod review;
mod tasks;

use crate::config::SandboxConfig;
use crate::report::{Event, EventType, SandboxReport};
use crate::sandbox::deadline::{Deadline, DeadlineExceeded};
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::with_cleanup;
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_RETAINED_EVENTS: usize = 10_000;

fn trim_event_history(events: &mut Vec<Event>) {
    if events.len() > MAX_RETAINED_EVENTS {
        let discarded = events.len() - MAX_RETAINED_EVENTS;
        events.drain(..discarded);
        log::warn!("Discarded {discarded} oldest report events at the retention limit");
    }
}

pub struct MonitoringEngine {
    config: SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
    start_time: chrono::DateTime<Utc>,
}

impl MonitoringEngine {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Ok(Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            start_time: Utc::now(),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.start_time = Utc::now();
        self.log_event(EventType::SandboxStarted, "Sandbox initialized".into())
            .await;
        Ok(())
    }

    pub async fn monitor_process(&mut self, process: ProcessHandle) -> Result<SandboxReport> {
        self.monitor_process_until(process, Deadline::after(self.config.timeout)?)
            .await
    }

    pub(crate) async fn monitor_process_until(
        &mut self,
        process: ProcessHandle,
        deadline: Deadline,
    ) -> Result<SandboxReport> {
        let mut session = lifecycle::Session::new(process);
        let executable = session.process.executable().to_owned();
        let mut result = deadline
            .run(async {
                session
                    .run(&self.config, self.events.clone(), deadline)
                    .await
            })
            .await;
        if result
            .as_ref()
            .is_err_and(|error| error.is::<DeadlineExceeded>())
        {
            self.log_event(
                EventType::ResourceLimitReached,
                "Wall-clock timeout reached; this is separate from the configured CPU-time limit"
                    .into(),
            )
            .await;
            if !session.process.is_suspended {
                result = Ok(windows::Win32::Foundation::WAIT_TIMEOUT.0);
            }
        }
        let termination_code = match &result {
            Ok(code) => *code,
            Err(_) => 1,
        };
        let cleanup = session.close(termination_code).await;
        let code = with_cleanup(result, cleanup)?;
        if code == 0xc000_0044 {
            self.log_event(
                EventType::ResourceLimitReached,
                "Process exited with STATUS_QUOTA_EXCEEDED; an OS resource quota was reached"
                    .into(),
            )
            .await;
        }
        self.log_event(
            EventType::SandboxStopped,
            format!("Process execution completed with exit code {code}"),
        )
        .await;
        let end_time = Utc::now();
        let events = {
            let mut events = self.events.lock().await;
            /* All producers have joined. This final bound also covers events
            emitted during teardown after periodic analysis stopped. */
            trim_event_history(&mut events);
            events.clone()
        };
        Ok(SandboxReport {
            executable,
            start_time: self.start_time,
            end_time,
            duration_seconds: (end_time - self.start_time).num_seconds().max(0) as u64,
            events,
            exit_code: code,
            config: self.config.clone(),
        })
    }

    pub async fn log_event(&self, event_type: EventType, details: String) {
        if self.config.verbose {
            log::debug!("{event_type:?}: {details}");
        }
        self.events.lock().await.push(Event {
            timestamp: Utc::now(),
            event_type,
            details,
        });
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor.rs"]
mod tests;
