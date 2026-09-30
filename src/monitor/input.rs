mod backend;
mod line;

use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{anyhow, Context, Result};
use backend::{Backend, Sample};
use line::{Edit, Line};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use tokio::sync::{oneshot, watch};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};

struct Request {
    boundary: u64,
    ready: Arc<AtomicBool>,
    reply: oneshot::Sender<Result<String>>,
    #[cfg(test)]
    armed: Option<mpsc::Sender<()>>,
}

/** Closing the receiver before waking the reader makes abandonment observable
even if this future was never polled and native input is gated on rendering. */
struct PendingLine {
    receive: oneshot::Receiver<Result<String>>,
    request: Arc<OwnedHandle>,
}

impl Drop for PendingLine {
    fn drop(&mut self) {
        self.receive.close();
        /* SAFETY: This guard retains the event while notifying the worker. */
        if let Err(error) = unsafe { SetEvent(self.request.raw()) } {
            log::error!("Wake abandoned approval input failed: {error}");
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum InputEnd {
    Eof,
    Cancelled,
    Failed(String),
}

/** One exclusive reader for native consoles and redirected UTF-8 pipes.

The worker continuously drains unsolicited input, so queued answers cannot approve
future prompts. No pipe read can block: PIPE_NOWAIT is established before spawn,
and only cancellation/event waits may wait (at most 20 ms between pipe reads).
The owner cancels and joins before restoring the shared pipe mode.
*/
pub(super) struct ConsoleInput {
    backend: Backend,
    cancel: Arc<OwnedHandle>,
    request: Arc<OwnedHandle>,
    requests: mpsc::SyncSender<Request>,
    cursor: Arc<Mutex<u64>>,
    status: watch::Receiver<Option<InputEnd>>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl ConsoleInput {
    pub(super) fn new() -> Result<Self> {
        /* SAFETY: GetStdHandle is borrowed; Backend immediately duplicates it. */
        Self::from_handle(unsafe { GetStdHandle(STD_INPUT_HANDLE)? })
    }

    fn from_handle(handle: HANDLE) -> Result<Self> {
        let backend = Backend::new(handle)?;
        /* SAFETY: Unnamed events have no borrowed name/security pointers. */
        let cancel = Arc::new(OwnedHandle::new(unsafe {
            CreateEventW(None, true, false, None)?
        }));
        let request = Arc::new(OwnedHandle::new(unsafe {
            CreateEventW(None, false, false, None)?
        }));
        let (requests, receiver) = mpsc::sync_channel::<Request>(1);
        let (status_send, status) = watch::channel(None);
        let cursor = Arc::new(Mutex::new(0));
        let worker_cursor = cursor.clone();
        let worker_cancel = cancel.clone();
        let worker_request = request.clone();
        let input = backend.raw();
        let pipe = backend.is_pipe();
        let worker = std::thread::Builder::new()
            .name("sandbox-input".into())
            .spawn(move || {
                let result = read_requests(
                    input,
                    pipe,
                    worker_cancel.raw(),
                    worker_request.raw(),
                    receiver,
                    worker_cursor,
                );
                let end = match &result {
                    Ok(end) => end.clone(),
                    Err(error) => InputEnd::Failed(format!("{error:#}")),
                };
                status_send.send_replace(Some(end));
                result.map(|_| ())
            })
            .context("start cancellable input reader")?;

        Ok(Self {
            backend,
            cancel,
            request,
            requests,
            cursor,
            status,
            worker: Some(worker),
        })
    }

    pub(super) fn status(&self) -> watch::Receiver<Option<InputEnd>> {
        self.status.clone()
    }

    /** Arm synchronously before returning the awaitable answer. Callers must
    create this future before displaying the prompt, then await it afterwards;
    otherwise a fast response is indistinguishable from unsolicited input. */
    pub(super) fn read_line(&mut self) -> impl std::future::Future<Output = Result<String>> + '_ {
        let (reply, receive) = oneshot::channel();
        let ready = Arc::new(AtomicBool::new(false));
        let mut pending = PendingLine {
            receive,
            request: self.request.clone(),
        };
        let end = self.status.borrow().clone();
        let queued = match end {
            Some(InputEnd::Failed(error)) => Err(anyhow!("interactive input failed: {error}")),
            Some(end) => Err(anyhow!("interactive input ended: {end:?}")),
            None => self.queue_request(Request {
                boundary: 0,
                ready: ready.clone(),
                reply,
                #[cfg(test)]
                armed: None,
            }),
        };

        async move {
            queued?;
            /* The caller has now rendered its prompt. Keep native echo from
            racing begin_prompt while retaining bytes after the armed boundary
            in the kernel buffer until this first poll. */
            ready.store(true, Ordering::Release);
            /* SAFETY: The pending answer retains this event through the wait. */
            unsafe { SetEvent(pending.request.raw()) }.context("activate approval input")?;
            (&mut pending.receive)
                .await
                .context("approval input worker stopped")?
        }
    }

    fn queue_request(&self, mut request: Request) -> Result<()> {
        /* Serialize only the immediate availability query and queue insertion
        with immediate reads. Never hold this lock during an event wait, UI
        rendering, or an async suspension. Input after this boundary belongs to
        this request even if the worker has not yet been scheduled. */
        let cursor = self
            .cursor
            .lock()
            .map_err(|_| anyhow!("input cursor poisoned"))?;
        request.boundary = *cursor + u64::from(self.backend.available()?);
        self.requests
            .try_send(request)
            .context("queue approval input request")?;
        drop(cursor);

        /* SAFETY: Both owners retain the event through worker shutdown. */
        unsafe { SetEvent(self.request.raw()) }.context("signal approval input request")
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let mut result = Ok(());
        if let Some(worker) = self.worker.take() {
            /* Cancellation wins even if input or a request is also ready. */
            result = unsafe { SetEvent(self.cancel.raw()) }.context("cancel approval input");
            result = with_cleanup(
                result,
                worker
                    .join()
                    .map_err(|_| anyhow!("input reader panicked"))
                    .and_then(|result| result),
            );
            result = with_cleanup(result, self.backend.close());
        }
        if let Some(cancel) = Arc::get_mut(&mut self.cancel) {
            result = with_cleanup(result, cancel.close());
        }
        if let Some(request) = Arc::get_mut(&mut self.request) {
            result = with_cleanup(result, request.close());
        }
        result
    }
}

impl Drop for ConsoleInput {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("Approval input cleanup failed: {error:#}");
        }
    }
}

fn cancelled(cancel: HANDLE) -> Result<bool> {
    /* SAFETY: The owner retains this event until the reader has joined. */
    match unsafe { WaitForSingleObject(cancel, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(windows::core::Error::from_win32()).context("query input cancellation"),
    }
}

fn read_requests(
    input: HANDLE,
    pipe: bool,
    cancel: HANDLE,
    request: HANDLE,
    requests: mpsc::Receiver<Request>,
    cursor: Arc<Mutex<u64>>,
) -> Result<InputEnd> {
    let mut line = Line::default();
    let mut active: Option<Request> = None;
    let mut pending: Option<Request> = None;
    let mut discard = false;

    loop {
        if cancelled(cancel)? {
            return Ok(InputEnd::Cancelled);
        }
        if active
            .as_ref()
            .is_some_and(|request| request.reply.is_closed())
        {
            active = None;
            discard = true;
        }

        let sample = {
            let mut cursor = cursor
                .lock()
                .map_err(|_| anyhow!("input cursor poisoned"))?;
            if active.is_none() && pending.is_none() {
                match requests.try_recv() {
                    Ok(request) if !request.reply.is_closed() => pending = Some(request),
                    Ok(_) | Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(InputEnd::Cancelled),
                }
            }
            if pending
                .as_ref()
                .is_some_and(|request| request.boundary <= *cursor)
            {
                let request = pending
                    .take()
                    .context("pending input request disappeared")?;
                if !request.reply.is_closed() {
                    /* Pre-request input has been consumed. A partial stale line
                    stays poisoned through its terminator rather than lending
                    its suffix to the new prompt. */
                    discard = line.partial();
                    #[cfg(test)]
                    if let Some(armed) = &request.armed {
                        armed.send(()).context("signal test input readiness")?;
                    }
                    active = Some(request);
                }
            }
            let sample = if active
                .as_ref()
                .is_some_and(|request| !request.ready.load(Ordering::Acquire))
            {
                Sample::Empty
            } else {
                backend::sample(input, pipe)?
            };
            if matches!(
                sample,
                Sample::Byte(_) | Sample::Key(_, _) | Sample::Ignored
            ) {
                *cursor += 1;
            }
            sample
        };
        let edits = match sample {
            Sample::Empty => {
                let awaiting_prompt = active
                    .as_ref()
                    .is_some_and(|request| !request.ready.load(Ordering::Acquire));
                let handles = if pipe || awaiting_prompt {
                    vec![cancel, request]
                } else {
                    vec![cancel, request, input]
                };
                /* Pipes are not waited on as data-ready objects. Only an
                immediate read observes data; the event wait caps idle latency. */
                let timeout = if pipe { 20 } else { INFINITE };
                let status = unsafe { WaitForMultipleObjects(&handles, false, timeout) };
                if status == WAIT_OBJECT_0 {
                    return Ok(InputEnd::Cancelled);
                }
                if status == WAIT_TIMEOUT
                    || (status.0 > WAIT_OBJECT_0.0
                        && status.0 < WAIT_OBJECT_0.0 + handles.len() as u32)
                {
                    continue;
                }
                return Err(windows::core::Error::from_win32()).context("wait for approval input");
            }
            Sample::Eof => {
                line.end()?;
                return Ok(InputEnd::Eof);
            }
            Sample::Ignored => continue,
            Sample::Byte(byte) => vec![line.byte(byte)?],
            Sample::Key(unit, repeat) => {
                let mut edits = Vec::new();
                for _ in 0..repeat {
                    if cancelled(cancel)? {
                        return Ok(InputEnd::Cancelled);
                    }
                    edits.push(line.unit(unit)?);
                }
                edits
            }
        };

        for edit in edits.into_iter().flatten() {
            let echo = !pipe && active.is_some() && !discard;
            match edit {
                Edit::Cancel => return Ok(InputEnd::Cancelled),
                Edit::Line(text) => {
                    if !discard {
                        if let Some(request) = active.take() {
                            if echo {
                                crate::ui::terminal().input(crate::ui::InputEdit::Newline)?;
                            }
                            let _ = request.reply.send(Ok(text));
                        }
                    }
                    discard = false;
                }
                Edit::Append(character) if echo => {
                    crate::ui::terminal()
                        .input(crate::ui::InputEdit::Append(character.to_string()))?;
                }
                Edit::Backspace if echo => {
                    crate::ui::terminal().input(crate::ui::InputEdit::Backspace)?;
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_input.rs"]
mod tests;
