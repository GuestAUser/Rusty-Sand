/*! Cancellable local named-pipe transport. The first message proves hook readiness. */

#[path = "windows_messages.rs"]
mod messages;

use super::{
    pipe_name, HookReady, HookRequest, HookResponse, EXPECTED_HOOK_COUNT, MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
};
use anyhow::{bail, Context, Result};
use std::os::windows::io::AsRawHandle;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Listening,
    Accepted,
    Connected,
    Ready,
    Closed,
}

pub struct HookIpcServer {
    pipe: NamedPipeServer,
    expected_pid: u32,
    state: State,
}

impl HookIpcServer {
    pub fn new() -> Result<Self> {
        Self::for_process(std::process::id())
    }

    /** Bind before injection; another server with this PID's name is an error. */
    pub fn for_process(pid: u32) -> Result<Self> {
        Self::bind(pid, &pipe_name(pid))
    }

    fn bind(pid: u32, name: &str) -> Result<Self> {
        let pipe = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(1)
            .pipe_mode(PipeMode::Message)
            .in_buffer_size(MAX_MESSAGE_SIZE as u32)
            .out_buffer_size(MAX_MESSAGE_SIZE as u32)
            .create(name)
            .context("create local hook pipe")?;
        Ok(Self {
            pipe,
            expected_pid: pid,
            state: State::Listening,
        })
    }

    pub async fn wait_for_connection(&mut self) -> Result<()> {
        if self.state != State::Listening {
            bail!("hook pipe is not listening");
        }
        match self.pipe.connect().await {
            Ok(()) => {}
            /* Tokio also handles this race internally; retain the Win32
            contract if an implementation returns the status directly. */
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED.0 as i32) => {}
            Err(error) => return Err(error).context("accept hook pipe client"),
        }
        self.state = State::Accepted;
        let mut client_pid = 0;
        /* SAFETY: Tokio owns a connected named-pipe handle for this call. The
        output PID has stack storage and is not retained by Windows. */
        unsafe {
            GetNamedPipeClientProcessId(HANDLE(self.pipe.as_raw_handle() as isize), &mut client_pid)
        }
        .context("authenticate hook pipe client")?;
        validate_pid(self.expected_pid, client_pid, "pipe client")?;
        self.state = State::Connected;
        Ok(())
    }

    pub async fn read_ready(&mut self) -> Result<HookReady> {
        if self.state != State::Connected {
            bail!("hook readiness requires an authenticated connection");
        }
        let ready: HookReady = messages::read(&mut self.pipe).await?;
        validate_ready(self.expected_pid, &ready)?;
        self.state = State::Ready;
        Ok(ready)
    }

    pub async fn handshake(&mut self) -> Result<()> {
        self.wait_for_connection().await?;
        self.read_ready().await?;
        Ok(())
    }

    pub async fn read_request(&mut self) -> Result<HookRequest> {
        if self.state != State::Ready {
            bail!("operation request arrived before verified hook readiness");
        }
        let request: HookRequest = messages::read(&mut self.pipe).await?;
        validate_pid(self.expected_pid, request.pid, "hook request")?;
        Ok(request)
    }

    pub async fn send_response(&mut self, response: &HookResponse) -> Result<()> {
        if self.state != State::Ready {
            bail!("hook pipe is not ready for responses");
        }
        messages::write(&mut self.pipe, response).await
    }

    pub fn disconnect(&mut self) -> Result<()> {
        if matches!(
            self.state,
            State::Accepted | State::Connected | State::Ready
        ) {
            match self.pipe.disconnect() {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED.0 as i32) => {}
                Err(error) => return Err(error).context("disconnect hook pipe"),
            }
        }
        self.state = State::Closed;
        Ok(())
    }
}

impl Drop for HookIpcServer {
    fn drop(&mut self) {
        if let Err(error) = self.disconnect() {
            log::error!("Hook pipe cleanup failed: {error:#}");
        }
        /* Tokio cancels outstanding overlapped I/O and owns handle closure. */
    }
}

pub struct HookIpcClient {
    pipe: NamedPipeClient,
}

impl HookIpcClient {
    /** The server must already exist; startup does not use connection retries. */
    pub fn connect() -> Result<Self> {
        Self::connect_to(std::process::id())
    }

    pub fn connect_to(pid: u32) -> Result<Self> {
        let pipe = ClientOptions::new()
            .pipe_mode(PipeMode::Message)
            .open(pipe_name(pid))
            .context("connect hook pipe")?;
        Ok(Self { pipe })
    }

    pub async fn send_ready(&mut self, ready: &HookReady) -> Result<()> {
        messages::write(&mut self.pipe, ready).await
    }

    pub async fn request_approval(&mut self, request: &HookRequest) -> Result<HookResponse> {
        messages::write(&mut self.pipe, request).await?;
        messages::read(&mut self.pipe).await
    }
}

fn validate_pid(expected: u32, actual: u32, source: &str) -> Result<()> {
    if actual != expected {
        bail!("{source} PID mismatch: expected {expected}, received {actual}");
    }
    Ok(())
}

fn validate_ready(pid: u32, ready: &HookReady) -> Result<()> {
    validate_pid(pid, ready.pid, "hook readiness")?;
    if ready.version != PROTOCOL_VERSION {
        bail!(
            "unsupported hook protocol version {} (expected {PROTOCOL_VERSION})",
            ready.version
        );
    }
    if ready.installed_hooks != EXPECTED_HOOK_COUNT {
        bail!(
            "incomplete hook installation: {} of {EXPECTED_HOOK_COUNT}",
            ready.installed_hooks
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/ipc_transport.rs"]
mod tests;
