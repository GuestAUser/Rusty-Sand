use super::worker::{Operation, Request};
use super::RunState;
use crate::control::ProcessController;
use crate::monitor::MonitoringEngine;
use crate::report::SandboxReport;
use crate::sandbox::deadline::Deadline;
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{bail, Result};
use tokio::sync::{mpsc, oneshot, watch};

pub(super) async fn drive(
    mut monitor: MonitoringEngine,
    process: ProcessHandle,
    deadline: Deadline,
    mut commands: mpsc::Receiver<Request>,
    stopped: oneshot::Receiver<()>,
    state: &watch::Sender<RunState>,
) -> Result<SandboxReport> {
    /*
     * Keep the process identity allocated until control has stopped, even
     * while the monitor closes handles and assembles its final report.
     * A recycled numeric PID must never become a suspension target.
     */
    let mut identity = match OwnedHandle::duplicate(process.process_handle) {
        Ok(identity) => identity,
        Err(error) => {
            let (stop, stopped) = oneshot::channel();
            drop(stop);

            let cleanup = monitor
                .monitor_process_controlled(process, deadline, Some(stopped), None)
                .await
                .map(|_| ());

            return with_cleanup(Err(error), cleanup);
        }
    };
    let mut controller = ProcessController::new(process.process_id);
    let (ready, mut started) = oneshot::channel();

    let result = {
        let execution =
            monitor.monitor_process_controlled(process, deadline, Some(stopped), Some(ready));
        tokio::pin!(execution);

        let mut awaiting_start = true;
        let mut commands_open = true;

        loop {
            tokio::select! {
                biased;
                result = &mut execution => break result,
                result = &mut started, if awaiting_start => {
                    awaiting_start = false;

                    if result.is_ok() {
                        state.send_replace(RunState::Running);
                    }
                }
                request = commands.recv(), if commands_open => {
                    let Some(request) = request else {
                        commands_open = false;
                        continue;
                    };

                    let current = *state.borrow();
                    let result = apply(&mut controller, current, request.operation);

                    /*
                     * Failed snapshot rollback may still own increments.
                     * Publish ownership, not an invented all-thread state.
                     */
                    if current != RunState::Starting {
                        state.send_replace(if controller.is_suspended() {
                            RunState::SnapshotPaused
                        } else {
                            RunState::Running
                        });
                    }

                    if request.reply.send(result).is_err() {
                        log::debug!("Live control caller cancelled its answer");
                    }
                }
            }
        }
    };

    /*
     * The existing monitor has terminated its Job and joined observation.
     * The existing controller releases its retained handles here and reports
     * native resume failures through its established Drop diagnostics.
     */
    drop(controller);

    with_cleanup(result, identity.close())
}

fn apply(controller: &mut ProcessController, state: RunState, operation: Operation) -> Result<()> {
    if !matches!(state, RunState::Running | RunState::SnapshotPaused) {
        bail!("thread control is available only after monitored startup");
    }

    match operation {
        Operation::Pause => controller.suspend_process(),
        Operation::Resume => controller.resume_process(),
    }
}
