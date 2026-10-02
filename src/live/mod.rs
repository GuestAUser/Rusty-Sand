//! Owned monitored execution. There is no arbitrary-PID attachment API.
//!
//! A session retains one active execution and its last successful report.
//! Explicit stop and Drop both join the independently owned monitor worker.

mod control;
mod report;
mod worker;

use crate::analysis::static_analysis::{analyze_file, StaticReport};
use crate::config::SandboxConfig;
use crate::report::{Event, SandboxReport};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;
use tokio::sync::watch;
use worker::{Active, Operation};

pub const MAX_EVENT_PAGE: usize = 100;

/** SnapshotPaused means retained increments on one root-process snapshot.
It does not imply an atomic freeze or suspension of descendants. */
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RunState {
    Idle,
    Starting,
    Running,
    SnapshotPaused,
    Stopping,
    Completed,
    Failed,
}

impl RunState {
    pub(crate) fn is_finished(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

pub struct LiveSession {
    executable: String,
    args: Vec<String>,
    config: SandboxConfig,
    active: Option<Active>,
    completed: Option<SandboxReport>,
    failure: Option<String>,
}

impl LiveSession {
    pub fn new(executable: &str, args: &[String], config: SandboxConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            executable: executable.into(),
            args: args.to_vec(),
            config,
            active: None,
            completed: None,
            failure: None,
        })
    }

    /** Inspect file bytes only. This method never creates a target process. */
    pub fn inspect(&self) -> Result<StaticReport> {
        analyze_file(Path::new(&self.executable))
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn state(&self) -> RunState {
        if let Some(active) = &self.active {
            return active.state();
        }

        if self.failure.is_some() {
            RunState::Failed
        } else if self.completed.is_some() {
            RunState::Completed
        } else {
            RunState::Idle
        }
    }

    pub fn process_id(&self) -> Option<u32> {
        self.active.as_ref().and_then(Active::pid)
    }

    pub fn has_active_run(&self) -> bool {
        self.active.is_some()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub fn completed_report(&self) -> Option<&SandboxReport> {
        self.completed.as_ref()
    }

    /** Observe worker transitions without extending the target's lifetime. */
    pub fn subscribe(&self) -> Option<watch::Receiver<RunState>> {
        self.active.as_ref().map(|active| active.state.clone())
    }

    /** Launch on the owned worker and return after suspended Job assignment.
    Cancelling this await does not detach the newly owned execution. */
    pub async fn run(&mut self) -> Result<u32> {
        if self.active.is_some() {
            bail!("an execution is already owned; stop or join it before another run");
        }

        let mut config = self.config.clone();

        /*
         * The shell owns stdin. Preserve every other caller policy field,
         * including restricted_token and all automatic hook decisions.
         */
        config.interactive_mode = false;
        config.cancel_on_stdin_eof = false;

        let active = match Active::start(self.executable.clone(), self.args.clone(), config) {
            Ok(active) => active,
            Err(error) => {
                self.failure = Some(format!("{error:#}"));
                return Err(error);
            }
        };

        self.failure = None;
        self.active = Some(active);

        let started = self
            .active
            .as_mut()
            .context("new execution ownership disappeared")?
            .started()
            .await;

        match started {
            Ok(pid) => Ok(pid),
            Err(error) => {
                /*
                 * The completion result preserves the actual creation/runtime
                 * error, rather than replacing it with a channel error.
                 */
                self.wait().await?;
                Err(error)
            }
        }
    }

    pub async fn pause(&self) -> Result<()> {
        self.active
            .as_ref()
            .context("no active execution")?
            .request(Operation::Pause)
            .await
    }

    pub async fn resume(&self) -> Result<()> {
        self.active
            .as_ref()
            .context("no active execution")?
            .request(Operation::Resume)
            .await
    }

    /** Return actual retained observations, never synthetic command history. */
    pub async fn events(&self, limit: usize) -> Vec<Event> {
        let limit = limit.min(MAX_EVENT_PAGE);

        if let Some(active) = &self.active {
            let events = active.events.lock().await;
            return events[events.len().saturating_sub(limit)..].to_vec();
        }

        match &self.completed {
            Some(report) => report.events[report.events.len().saturating_sub(limit)..].to_vec(),
            None => Vec::new(),
        }
    }

    /** Join without requesting termination. Cancellation leaves ownership
    and the completion receiver in this session. */
    pub async fn wait(&mut self) -> Result<()> {
        let result = self
            .active
            .as_mut()
            .context("no active execution")?
            .finish()
            .await;

        self.active = None;

        match result {
            Ok(report) => {
                self.completed = Some(report);
                self.failure = None;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(format!("{error:#}"));
                Err(error)
            }
        }
    }

    pub async fn refresh(&mut self) -> Result<()> {
        if self.active.as_ref().is_some_and(Active::finished) {
            self.wait().await?;
        }

        Ok(())
    }

    pub(crate) fn request_stop(&mut self) {
        if let Some(active) = &mut self.active {
            active.signal_stop();
        }
    }

    /** Terminate only the owned execution's Job and join its monitor.
    Repeated stop does not discard a completed report. */
    pub async fn stop(&mut self) -> Result<()> {
        self.request_stop();

        if self.active.is_some() {
            self.wait().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/shell/live.rs"]
pub(crate) mod shell_tests;
