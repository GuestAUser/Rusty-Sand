use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{bail, Context, Result};
use windows::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_PIPE};
use windows::Win32::System::Console::{
    GetConsoleMode, GetNumberOfConsoleInputEvents, ReadConsoleInputW, CONSOLE_MODE, INPUT_RECORD,
    KEY_EVENT,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeHandleStateW, PeekNamedPipe, SetNamedPipeHandleState, NAMED_PIPE_MODE, PIPE_NOWAIT,
    PIPE_READMODE_MESSAGE,
};
use windows::Win32::System::Threading::WaitForSingleObject;

pub(super) enum Sample {
    Byte(u8),
    Key(u16, u16),
    Ignored,
    Empty,
    Eof,
}

/** The owner outlives the reader thread. Pipe mode belongs to the shared kernel
object, not the duplicated handle, so restoration must happen after joining. */
pub(super) struct Backend {
    input: OwnedHandle,
    mode: Option<NAMED_PIPE_MODE>,
}

impl Backend {
    pub(super) fn new(handle: HANDLE) -> Result<Self> {
        let input = OwnedHandle::duplicate(handle)?;
        let mut console_mode = CONSOLE_MODE::default();

        /* SAFETY: The duplicated handle and mode output remain owned locally. */
        if unsafe { GetConsoleMode(input.raw(), &mut console_mode) }.is_ok() {
            return Ok(Self { input, mode: None });
        }
        if unsafe { GetFileType(input.raw()) } != FILE_TYPE_PIPE {
            bail!("interactive input requires a Windows console or pipe");
        }

        let mut mode = NAMED_PIPE_MODE::default();
        /* SAFETY: The mode output is valid for the synchronous query. No remote
        collection settings are requested on this local stdin pipe. */
        unsafe { GetNamedPipeHandleStateW(input.raw(), Some(&mut mode), None, None, None, None) }
            .ok()
            .context("query stdin pipe mode")?;
        let nonblocking = (mode & PIPE_READMODE_MESSAGE) | PIPE_NOWAIT;
        unsafe { SetNamedPipeHandleState(input.raw(), Some(&nonblocking), None, None) }
            .context("set stdin pipe nonblocking mode")?;

        Ok(Self {
            input,
            mode: Some(mode),
        })
    }

    pub(super) fn raw(&self) -> HANDLE {
        self.input.raw()
    }

    pub(super) fn is_pipe(&self) -> bool {
        self.mode.is_some()
    }

    /** Called under the cursor lock, which excludes the worker's immediate
    read. This snapshot separates stale input from answers typed after a request
    is queued, independent of when Windows schedules the reader thread. */
    pub(super) fn available(&self) -> Result<u32> {
        let mut count = 0;
        if self.is_pipe() {
            /* SAFETY: This is a local nonblocking pipe with no competing read.
            Only the byte-count output is requested; no data is consumed. */
            match unsafe { PeekNamedPipe(self.raw(), None, 0, None, Some(&mut count), None) } {
                Ok(()) => {}
                Err(error) if error.code() == ERROR_BROKEN_PIPE.to_hresult() => {}
                Err(error) => return Err(error).context("snapshot queued pipe input"),
            }
        } else {
            /* SAFETY: The owned console input handle and output remain valid. */
            unsafe { GetNumberOfConsoleInputEvents(self.raw(), &mut count) }
                .context("snapshot queued console input")?;
        }
        Ok(count)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let mut result = Ok(());
        if let Some(mode) = self.mode {
            /* Only read/wait flags can be set; server/type flags returned by
            GetNamedPipeHandleStateW are not valid SetNamedPipeHandleState input. */
            let mode = mode & (PIPE_NOWAIT | PIPE_READMODE_MESSAGE);
            result = unsafe { SetNamedPipeHandleState(self.raw(), Some(&mode), None, None) }
                .context("restore stdin pipe mode");
            if result.is_ok() {
                self.mode = None;
            }
        }
        with_cleanup(result, self.input.close())
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        if !self.input.raw().is_invalid() {
            if let Err(error) = self.close() {
                log::error!("Input backend cleanup failed: {error:#}");
            }
        }
    }
}

pub(super) fn sample(input: HANDLE, pipe: bool) -> Result<Sample> {
    if pipe {
        let mut byte = [0];
        let mut count = 0;
        /* SAFETY: PIPE_NOWAIT was set before starting this exclusive reader.
        The one-byte buffer and count live through this immediate ReadFile. */
        return match unsafe { ReadFile(input, Some(&mut byte), Some(&mut count), None) } {
            Ok(()) if count == 0 => Ok(Sample::Eof),
            Ok(()) => Ok(Sample::Byte(byte[0])),
            Err(error) if error.code() == ERROR_NO_DATA.to_hresult() => Ok(Sample::Empty),
            Err(error) if error.code() == ERROR_BROKEN_PIPE.to_hresult() => Ok(Sample::Eof),
            Err(error) => Err(error).context("read stdin pipe"),
        };
    }

    /* SAFETY: This worker is the only console reader. A zero-time wait proves
    a record is available without ever leaving an uncancellable blocking read. */
    match unsafe { WaitForSingleObject(input, 0) } {
        WAIT_TIMEOUT => return Ok(Sample::Empty),
        WAIT_OBJECT_0 => {}
        _ => return Err(windows::core::Error::from_win32()).context("query console input"),
    }
    let mut records = [INPUT_RECORD::default()];
    let mut count = 0;
    unsafe { ReadConsoleInputW(input, &mut records, &mut count) }
        .context("read console input record")?;
    if count == 0 || records[0].EventType != KEY_EVENT as u16 {
        return Ok(Sample::Ignored);
    }

    /* SAFETY: The discriminator selects the Unicode keyboard event union. */
    let key = unsafe { records[0].Event.KeyEvent };
    if !key.bKeyDown.as_bool() {
        return Ok(Sample::Ignored);
    }
    Ok(Sample::Key(
        unsafe { key.uChar.UnicodeChar },
        key.wRepeatCount,
    ))
}
