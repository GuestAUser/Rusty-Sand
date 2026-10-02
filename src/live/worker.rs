use super::{control, RunState};
use crate::config::SandboxConfig;
use crate::monitor::MonitoringEngine;
use crate::report::{Event, SandboxReport};
use crate::sandbox::deadline::Deadline;
use crate::sandbox::process::create_sandboxed_process;
use crate::sandbox::resource::with_cleanup;
use anyhow::{anyhow, bail, Context, Result};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

pub(super) enum Operation {
    Pause,
    Resume,
}

pub(super) struct Request {
    pub(super) operation: Operation,
    pub(super) reply: oneshot::Sender<Result<()>>,
}

/** Own the OS worker, not a detachable Tokio task. Process creation happens
only after that worker successfully creates its independent runtime. */
pub(super) struct Active {
    pid: Arc<AtomicU32>,
    pub(super) events: Arc<Mutex<Vec<Event>>>,
    pub(super) state: watch::Receiver<RunState>,
    commands: mpsc::Sender<Request>,
    stop: Option<oneshot::Sender<()>>,
    startup: Option<oneshot::Receiver<u32>>,
    completion: Option<oneshot::Receiver<Result<SandboxReport>>>,
    worker: Option<JoinHandle<()>>,
    stopping: bool,
}

impl Active {
    pub(super) fn start(
        executable: String,
        args: Vec<String>,
        config: SandboxConfig,
    ) -> Result<Self> {
        let deadline = Deadline::after(config.timeout)?;
        let mut monitor = MonitoringEngine::new(config.clone())?;
        let events = monitor.retained_events();
        let pid = Arc::new(AtomicU32::new(0));
        let worker_pid = pid.clone();
        let (commands, requests) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel();
        let (started, startup) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let (state_send, state) = watch::channel(RunState::Starting);

        let worker = std::thread::Builder::new()
            .name("sandbox-live".into())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .max_blocking_threads(4)
                        .build()
                        .context("create live execution runtime")?;

                    let result = runtime.block_on(async {
                        monitor.start().await?;
                        deadline.check()?;

                        let process = create_sandboxed_process(&executable, &args, &config)?;
                        worker_pid.store(process.process_id, Ordering::Release);

                        if started.send(process.process_id).is_err() {
                            log::debug!("Live launch caller cancelled its startup answer");
                        }

                        control::drive(monitor, process, deadline, requests, stopped, &state_send)
                            .await
                    });

                    /* Join finite blocking work before publishing completion. */
                    drop(runtime);
                    result
                })();

                state_send.send_replace(if result.is_ok() {
                    RunState::Completed
                } else {
                    RunState::Failed
                });

                if let Err(Err(error)) = completed.send(result) {
                    log::error!("Uncollected live execution failed: {error:#}");
                }
            })
            .context("start owned live execution worker")?;

        Ok(Self {
            pid,
            events,
            state,
            commands,
            stop: Some(stop),
            startup: Some(startup),
            completion: Some(completion),
            worker: Some(worker),
            stopping: false,
        })
    }

    pub(super) async fn started(&mut self) -> Result<u32> {
        let result = self
            .startup
            .as_mut()
            .context("startup answer was already consumed")?
            .await
            .context("execution ended before process creation completed");

        self.startup = None;
        result
    }

    pub(super) fn pid(&self) -> Option<u32> {
        let pid = self.pid.load(Ordering::Acquire);
        (pid != 0).then_some(pid)
    }

    pub(super) fn state(&self) -> RunState {
        let state = *self.state.borrow();

        if self.stopping && !state.is_finished() {
            RunState::Stopping
        } else {
            state
        }
    }

    pub(super) fn finished(&self) -> bool {
        self.state.borrow().is_finished()
            || self.worker.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub(super) async fn request(&self, operation: Operation) -> Result<()> {
        if self.stopping {
            bail!("execution is stopping");
        }

        let (reply, response) = oneshot::channel();

        self.commands
            .send(Request { operation, reply })
            .await
            .context("execution control worker ended")?;

        response
            .await
            .context("execution ended before its control request completed")?
    }

    pub(super) fn signal_stop(&mut self) {
        self.stopping = true;

        if let Some(stop) = self.stop.take() {
            if stop.send(()).is_err() {
                log::debug!("Live execution had already ended before stop");
            }
        }
    }

    pub(super) async fn finish(&mut self) -> Result<SandboxReport> {
        let result = self
            .completion
            .as_mut()
            .context("live completion was already consumed")?
            .await
            .context("live execution worker ended without a result")
            .and_then(|result| result);

        self.completion = None;
        self.stop = None;

        with_cleanup(result, self.join())
    }

    fn join(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow!("live execution worker panicked"))?;
        }

        Ok(())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.signal_stop();

        if let Err(error) = self.join() {
            log::error!("Live execution join failed: {error:#}");
        }

        if let Some(mut completion) = self.completion.take() {
            match completion.try_recv() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    log::error!("Live execution cleanup failed: {error:#}");
                }
                Err(error) => {
                    log::error!("Live completion unavailable after joining: {error}");
                }
            }
        }
    }
}
