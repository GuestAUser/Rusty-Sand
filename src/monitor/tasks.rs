use super::{etw_registry, filesystem, network, process};
use crate::config::SandboxConfig;
use crate::report::Event;
use crate::sandbox::resource::with_cleanup;
use anyhow::{anyhow, Context, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

/** Own the observation runtime so even nested blocking snapshots are joined.

Aborting a leaf future alone cannot cancel its spawn_blocking call. Dropping
this dedicated runtime after joining the async tasks waits for those finite
snapshots too; none are left on the application's runtime at shutdown.
*/
pub(super) struct MonitorTasks {
    stop: Option<oneshot::Sender<()>>,
    completion: Option<oneshot::Receiver<Result<()>>>,
    worker: Option<JoinHandle<()>>,
}

impl MonitorTasks {
    pub(super) fn start(
        config: SandboxConfig,
        events: Arc<Mutex<Vec<Event>>>,
        pid: u32,
    ) -> Result<Self> {
        let filesystem = filesystem::FileSystemMonitor::new(config.clone(), events.clone())?;
        let network = network::NetworkMonitor::new(config.clone(), events.clone(), pid)?;
        let process = process::ProcessMonitor::new(pid, events.clone())?;
        let (stop, stopped) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let worker = std::thread::Builder::new().name("sandbox-observers".into()).spawn(move || {
            let result = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
                    .max_blocking_threads(4).build().context("create observation runtime")?;
                let result = runtime.block_on(async move {
                    let shutdown = Arc::new(AtomicBool::new(false));
                    let mut tasks = JoinSet::new();
                    tasks.spawn(async move { ("filesystem", filesystem.start().await) });
                    tasks.spawn(async move { ("network", network.monitor().await) });
                    tasks.spawn(async move { ("process", process.monitor().await) });
                    let registry = config.allow_registry.then(|| {
                        let monitor = etw_registry::RealRegistryMonitor::new(events, shutdown.clone());
                        tokio::spawn(monitor.monitor())
                    });
                    let mut stopped = stopped;
                    let mut registry = registry;
                    let result = loop {
                        tokio::select! {
                            _ = &mut stopped => break Ok(()),
                            ended = tasks.join_next(), if !tasks.is_empty() => {
                                match ended {
                                    Some(Ok(("process", Ok(())))) => {}
                                    Some(Ok((name, Ok(())))) => break Err(anyhow!("{name} observer ended unexpectedly")),
                                    Some(Ok((name, Err(error)))) => break Err(error.context(format!("{name} observer"))),
                                    Some(Err(error)) => break Err(error.into()),
                                    None => {}
                                }
                            }
                            ended = async { match registry.as_mut() {
                                Some(task) => task.await,
                                None => std::future::pending().await,
                            } } => {
                                registry = None;
                                break match ended {
                                    Ok(Ok(())) => Err(anyhow!("registry observer ended unexpectedly")),
                                    Ok(Err(error)) => Err(error.context("registry observer")),
                                    Err(error) => Err(error.into()),
                                };
                            }
                        }
                    };
                    shutdown.store(true, Ordering::Release);
                    tasks.abort_all();
                    let mut cleanup = Ok(());
                    while let Some(ended) = tasks.join_next().await {
                        match ended {
                            Ok((_, result)) => cleanup = with_cleanup(cleanup, result),
                            Err(error) if error.is_cancelled() => {}
                            Err(error) => cleanup = with_cleanup(cleanup, Err(error.into())),
                        }
                    }
                    if let Some(task) = registry {
                        let ended = task.await.context("join registry observer").and_then(|result| result);
                        cleanup = with_cleanup(cleanup, ended);
                    }
                    with_cleanup(result, cleanup)
                });
                drop(runtime);
                result
            })();
            if let Err(Err(error)) = completed.send(result) {
                log::error!("Observation worker failed during cancellation: {error:#}");
            }
        }).context("start observation worker")?;
        Ok(Self {
            stop: Some(stop),
            completion: Some(completion),
            worker: Some(worker),
        })
    }

    pub(super) async fn ended(&mut self) -> Result<()> {
        let result = match self.completion.as_mut() {
            Some(completion) => completion
                .await
                .context("observation worker ended without completion"),
            None => return Err(anyhow!("observation completion already consumed")),
        };
        self.completion = None;
        result.and_then(|result| result)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        self.signal_stop();
        let result = if self.completion.is_some() {
            self.ended().await
        } else {
            Ok(())
        };
        with_cleanup(result, self.join())
    }

    fn signal_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            if stop.send(()).is_err() {
                log::debug!("Observation worker already stopped");
            }
        }
    }

    fn join(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow!("observation worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for MonitorTasks {
    fn drop(&mut self) {
        self.signal_stop();
        if let Err(error) = self.join() {
            log::error!("Observation worker cleanup failed: {error:#}");
        }
        if let Some(mut completion) = self.completion.take() {
            match completion.try_recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::error!("Observation cleanup failed: {error:#}"),
                Err(error) => {
                    log::error!("Observation completion unavailable after joining: {error}")
                }
            }
        }
    }
}
