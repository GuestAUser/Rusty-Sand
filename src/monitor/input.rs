use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use tokio::sync::oneshot;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, ReadConsoleInputW, CONSOLE_MODE, INPUT_RECORD, KEY_EVENT,
    STD_INPUT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE};

type Reply = oneshot::Sender<Result<String>>;

/** One exclusive console reader, with an OS cancellation event and a joined worker.

Redirected stdin is rejected rather than using Tokio stdin: its blocking reader
cannot be cancelled when a deadline expires. The application must not run another
reader against the same console while this object exists.
*/
pub(super) struct ConsoleInput {
    cancel: Arc<OwnedHandle>,
    request: Arc<OwnedHandle>,
    requests: mpsc::SyncSender<Reply>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl ConsoleInput {
    pub(super) fn new() -> Result<Self> {
        /* SAFETY: GetStdHandle returns a borrowed handle, which is immediately
        duplicated. Mode validation does not change the caller's console. */
        let input = OwnedHandle::duplicate(unsafe { GetStdHandle(STD_INPUT_HANDLE)? })?;
        let mut mode = CONSOLE_MODE::default();
        unsafe { GetConsoleMode(input.raw(), &mut mode) }
            .context("interactive approval requires a console; redirected stdin is unsupported")?;
        /* SAFETY: Unnamed events have no borrowed security or name pointers. */
        let cancel = Arc::new(OwnedHandle::new(unsafe {
            CreateEventW(None, true, false, None)?
        }));
        let request = Arc::new(OwnedHandle::new(unsafe {
            CreateEventW(None, false, false, None)?
        }));
        let (requests, receiver) = mpsc::sync_channel::<Reply>(1);
        let worker_cancel = cancel.clone();
        let worker_request = request.clone();
        let worker = std::thread::Builder::new()
            .name("sandbox-console".into())
            .spawn(move || {
                let result = read_requests(
                    input.raw(),
                    worker_cancel.raw(),
                    worker_request.raw(),
                    receiver,
                );
                let mut input = input;
                with_cleanup(result, input.close())
            })
            .context("start cancellable console reader")?;
        Ok(Self {
            cancel,
            request,
            requests,
            worker: Some(worker),
        })
    }

    pub(super) async fn read_line(&mut self) -> Result<String> {
        let (reply, receive) = oneshot::channel();
        self.requests
            .try_send(reply)
            .context("queue console approval request")?;
        /* SAFETY: The worker and this object retain the event until shutdown. */
        unsafe { SetEvent(self.request.raw()) }.context("signal console approval request")?;
        receive.await.context("console input worker stopped")?
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let mut result = Ok(());
        if let Some(worker) = self.worker.take() {
            /* SAFETY: Both owners retain the manual-reset event while waiting;
            cancellation wins if console input is simultaneously signaled. */
            result = unsafe { SetEvent(self.cancel.raw()) }.context("cancel console input");
            result = with_cleanup(
                result,
                worker
                    .join()
                    .map_err(|_| anyhow!("console reader panicked"))
                    .and_then(|result| result),
            );
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
            log::error!("Console input cleanup failed: {error:#}");
        }
    }
}

fn read_requests(
    input: HANDLE,
    cancel: HANDLE,
    request: HANDLE,
    requests: mpsc::Receiver<Reply>,
) -> Result<()> {
    loop {
        if wait(cancel, request)? {
            return Ok(());
        }
        let reply = requests
            .try_recv()
            .context("receive signaled console request")?;
        let result = read_line(input, cancel);
        match result {
            Ok(Some(line)) => {
                if reply.send(Ok(line)).is_err() {
                    log::debug!("Console approval was cancelled");
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                if let Err(Err(error)) = reply.send(Err(error)) {
                    return Err(error);
                }
                return Ok(());
            }
        }
    }
}

fn wait(cancel: HANDLE, event: HANDLE) -> Result<bool> {
    /* SAFETY: The worker's owners retain both handles for this wait. These are
    waitable console/event objects; cancellation is first in the array. */
    let status = unsafe { WaitForMultipleObjects(&[cancel, event], false, INFINITE) };
    if status == WAIT_OBJECT_0 {
        return Ok(true);
    }
    if status.0 == WAIT_OBJECT_0.0 + 1 {
        return Ok(false);
    }
    Err(windows::core::Error::from_win32()).context("wait for console input or cancellation")
}

fn read_line(input: HANDLE, cancel: HANDLE) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        if wait(cancel, input)? {
            return Ok(None);
        }
        let mut records = [INPUT_RECORD::default()];
        let mut count = 0;
        /* SAFETY: This worker is the application's exclusive console reader.
        The signaled console contains an input record. The output slice and
        count remain valid for the synchronous, single-record read. */
        unsafe { ReadConsoleInputW(input, &mut records, &mut count) }
            .context("read console input record")?;
        if count == 0 || records[0].EventType != KEY_EVENT as u16 {
            continue;
        }
        /* SAFETY: The event discriminator selects KeyEvent, and ReadConsoleInputW
        populated UnicodeChar rather than its ANSI union member. */
        let key = unsafe { records[0].Event.KeyEvent };
        if !key.bKeyDown.as_bool() {
            continue;
        }
        let character = unsafe { key.uChar.UnicodeChar };
        match character {
            0 => {}
            13 => {
                std::io::stdout().write_all(b"\n")?;
                return String::from_utf16(&line)
                    .map(Some)
                    .context("invalid console Unicode input");
            }
            8 => {
                if line.pop().is_some() {
                    std::io::stdout().write_all(b"\x08 \x08")?;
                }
            }
            3 | 4 | 26 => bail!("console approval input ended"),
            character => {
                if line.len() >= 64 {
                    bail!("console approval exceeds 64 UTF-16 units");
                }
                line.push(character);
                std::io::stdout().write_all(String::from_utf16_lossy(&[character]).as_bytes())?;
            }
        }
        std::io::stdout().flush()?;
    }
}
