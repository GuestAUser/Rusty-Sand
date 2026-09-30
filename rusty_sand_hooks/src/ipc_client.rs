use crate::framing::{self, FrameError};
use crate::types::{pipe_name, HookReady, HookRequest, HookResponse, MAX_MESSAGE_SIZE};
use serde::Serialize;
use std::fmt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_MORE_DATA, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{SetNamedPipeHandleState, PIPE_READMODE_MESSAGE};

#[derive(Debug)]
pub enum TransportError {
    Windows {
        operation: &'static str,
        source: windows::core::Error,
    },
    Encode(serde_json::Error),
    Decode(serde_json::Error),
    Frame(FrameError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows { operation, source } => write!(f, "{operation}: {source}"),
            Self::Encode(error) => write!(f, "encode hook message: {error}"),
            Self::Decode(error) => write!(f, "decode hook response: {error}"),
            Self::Frame(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { source, .. } => Some(source),
            Self::Encode(source) | Self::Decode(source) => Some(source),
            Self::Frame(source) => Some(source),
        }
    }
}

impl From<FrameError> for TransportError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

pub struct HookIpcClient {
    pipe: OwnedHandle,
}

impl HookIpcClient {
    pub fn connect(pid: u32) -> Result<Self, TransportError> {
        let name: Vec<u16> = pipe_name(pid).encode_utf16().chain(Some(0)).collect();
        /* SAFETY: The local pipe name is owned and terminated. CreateFileW
        returns a newly owned synchronous handle, never a borrowed handle. */
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                0xC000_0000,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE(0),
            )
        }
        .map_err(|source| TransportError::Windows {
            operation: "open hook pipe",
            source,
        })?;
        /* SAFETY: A successful CreateFileW returns a valid uniquely owned
        handle; OwnedHandle closes it on every subsequent error path. */
        let pipe = unsafe { OwnedHandle::from_raw_handle(handle.0 as *mut _) };
        /* SAFETY: The live handle belongs to this client. Message read mode
        prevents a partial frame from being accepted as a complete reply. */
        unsafe { SetNamedPipeHandleState(handle, Some(&PIPE_READMODE_MESSAGE), None, None) }
            .map_err(|source| TransportError::Windows {
                operation: "set pipe message mode",
                source,
            })?;
        Ok(Self { pipe })
    }

    pub fn send_ready(&mut self, ready: &HookReady) -> Result<(), TransportError> {
        self.send(ready)
    }

    pub fn request_approval(
        &mut self,
        request: &HookRequest,
    ) -> Result<HookResponse, TransportError> {
        self.send(request)?;
        let mut buffer = [0; MAX_MESSAGE_SIZE];
        let mut read = 0;
        /* SAFETY: The synchronous read borrows only this initialized local
        buffer. &mut self and the approval mutex serialize whole exchanges. */
        let result = unsafe { ReadFile(self.handle(), Some(&mut buffer), Some(&mut read), None) };
        if let Err(source) = result {
            return Err(
                if source.code() == windows::core::HRESULT::from_win32(ERROR_MORE_DATA.0) {
                    FrameError::TooLarge.into()
                } else {
                    TransportError::Windows {
                        operation: "read hook response",
                        source,
                    }
                },
            );
        }
        /* Validate even unknown JSON fields as UTF-8 rather than accepting
        or replacing malformed bytes during policy parsing. */
        let text = framing::message_text(&buffer[..read as usize])?;
        serde_json::from_str(text).map_err(TransportError::Decode)
    }

    fn send(&mut self, message: &impl Serialize) -> Result<(), TransportError> {
        let bytes = serde_json::to_vec(message).map_err(TransportError::Encode)?;
        framing::check_size(bytes.len())?;
        let mut written = 0;
        /* SAFETY: The synchronous write borrows an owned buffer for its exact
        length and a local count. The pipe handle remains owned by self. */
        unsafe { WriteFile(self.handle(), Some(&bytes), Some(&mut written), None) }.map_err(
            |source| TransportError::Windows {
                operation: "write hook message",
                source,
            },
        )?;
        framing::check_write(bytes.len(), written).map_err(TransportError::Frame)
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.pipe.as_raw_handle() as isize)
    }
}
