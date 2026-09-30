use std::io::{self, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::sink::{lock, record_error, State};
use super::Tone;

pub(super) struct Active {
    started: Instant,
    frame: usize,
}

pub(super) enum Command {
    Stop,
    #[cfg(test)]
    Tick(Duration, mpsc::SyncSender<()>),
}

struct Worker {
    sender: mpsc::SyncSender<Command>,
    thread: JoinHandle<io::Result<()>>,
}

/// Owns the only live activity worker. Finishing or dropping always joins it.
#[must_use = "retain the activity guard while real work is running"]
pub struct ActivityGuard {
    shared: Arc<Mutex<State>>,
    worker: Option<Worker>,
    finished: bool,
}

impl ActivityGuard {
    pub(super) fn start(shared: Arc<Mutex<State>>, text: &str) -> io::Result<Self> {
        let animate = {
            let mut state = lock(&shared)?;
            state.check_error()?;

            if state.active.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "activity already active",
                ));
            }

            state.stage(text, Tone::Heading)?;
            state.active = Some(Active {
                started: Instant::now(),
                frame: 0,
            });
            state.policy.animated()
        };
        let mut guard = Self {
            shared,
            worker: None,
            finished: false,
        };

        if animate {
            let (sender, receiver) = mpsc::sync_channel(1);
            let shared = Arc::clone(&guard.shared);
            let thread = thread::Builder::new()
                .name("terminal-activity".into())
                .spawn(move || run(shared, receiver))?;

            guard.worker = Some(Worker { sender, thread });
        }

        Ok(guard)
    }

    /// Stop and join the effect, then emit the caller's actual work result.
    /// No elapsed-time threshold can complete an activity.
    ///
    /// # Errors
    /// Returns worker or destination I/O errors, after releasing activity state.
    pub fn finish(mut self, text: &str, tone: Tone) -> io::Result<()> {
        let worker_result = self.stop_worker();
        self.finished = true;
        let output_result = self.end(text, tone);
        worker_result.and(output_result)
    }

    fn stop_worker(&mut self) -> io::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };

        /*
         * Disconnection means the worker already exited; its join result carries
         * the actual error. Neither send nor join holds the output mutex.
         */
        match worker.sender.send(Command::Stop) {
            Ok(()) | Err(mpsc::SendError(Command::Stop)) => {}
            #[cfg(test)]
            Err(mpsc::SendError(Command::Tick(_, _))) => {
                return Err(io::Error::other("unexpected activity stop message"));
            }
        }

        worker
            .thread
            .join()
            .map_err(|_| io::Error::other("activity worker panicked"))?
    }

    fn end(&self, text: &str, tone: Tone) -> io::Result<()> {
        let mut state = lock(&self.shared)?;
        state.active = None;
        state.clear_transient()?;
        state.stage(text, tone)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ui/activity_support.rs"]
mod test_support;

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        if !self.finished {
            let worker_result = self.stop_worker();
            let output_result =
                self.end("Activity ended without a completion result", Tone::Warning);

            if let Err(error) = worker_result.and(output_result) {
                record_error(&self.shared, error);
            }
        }
    }
}

/* Tests drive the same worker and tick renderer using acknowledged commands.
 * Production uses a low-rate timeout solely to refresh elapsed time; it never
 * advances workflow state. Prompt ownership is checked under the write mutex. */
fn run(shared: Arc<Mutex<State>>, receiver: mpsc::Receiver<Command>) -> io::Result<()> {
    loop {
        #[cfg(not(test))]
        let command = receiver.recv_timeout(Duration::from_millis(750));
        #[cfg(test)]
        let command = receiver
            .recv()
            .map_err(|_| mpsc::RecvTimeoutError::Disconnected);

        match command {
            Ok(Command::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => tick(&shared, None)?,
            #[cfg(test)]
            Ok(Command::Tick(elapsed, acknowledge)) => {
                tick(&shared, Some(elapsed))?;
                acknowledge
                    .send(())
                    .map_err(|_| io::Error::other("activity observer disconnected"))?;
            }
        }
    }
}

fn tick(shared: &Mutex<State>, elapsed: Option<Duration>) -> io::Result<()> {
    let mut state = lock(shared)?;

    if state.prompt.is_some() || !state.policy.animated() {
        return Ok(());
    }

    let Some(active) = state.active.as_mut() else {
        return Ok(());
    };
    let elapsed = elapsed.unwrap_or_else(|| active.started.elapsed());
    let spinner = ['|', '/', '-', '\\'][active.frame % 4];
    active.frame = active.frame.wrapping_add(1);
    let frame = format!("[ACTIVE] {spinner} {}s", elapsed.as_secs());
    let columns = state.policy.width();
    let frame = super::text::wrap(&frame, columns).remove(0);

    state.clear_transient()?;
    /* Mark first so the guard also cleans up a partially written frame. */
    state.transient = true;
    write!(state.writer, "{}{frame}\x1b[0m", Tone::Heading.ansi())?;
    state.writer.flush()
}
