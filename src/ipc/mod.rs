//! IPC module for communication between main process and injected hook DLL
//!
//! Architecture:
//! - Main process creates named pipe server
//! - Hook DLL connects as client
//! - Protocol: Request (from hooks) → Response (allow/deny)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, ConnectNamedPipe, DisconnectNamedPipe, WaitNamedPipeW, NAMED_PIPE_MODE,
};
use windows::core::PCWSTR;

// Windows pipe constants (raw values from Windows API)
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
const PIPE_WAIT: u32 = 0x00000000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

/// Request from hook DLL to main process asking for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRequest {
    pub operation: HookOperation,
    pub pid: u32,
    pub tid: u32,
}

/// Types of operations that can be hooked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookOperation {
    FileCreate { path: String },
    FileWrite { path: String },
    FileDelete { path: String },
    FolderCreate { path: String },
    FolderDelete { path: String },
    RegistrySet { key: String, value: String },
    RegistryDelete { key: String },
    RegistryRead { key: String, value: String },
    RegistryOpen { key: String },
    NetworkConnect { remote_addr: String, port: u16 },
    ProcessCreate { executable: String, args: String },
}

/// Response from main process to hook DLL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    pub allowed: bool,
    pub reason: Option<String>,
}

const PIPE_NAME: &str = "\\\\.\\pipe\\rusty_sand_hooks";
const BUFFER_SIZE: u32 = 8192;

/// Server side (main process)
pub struct HookIpcServer {
    pipe_handle: HANDLE,
}

impl HookIpcServer {
    /// Create named pipe server
    pub fn new() -> Result<Self> {
        let pipe_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();

        let pipe_handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX),
                NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT),
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            )
        };

        if pipe_handle.is_invalid() {
            return Err(anyhow!("Failed to create named pipe"));
        }

        Ok(Self { pipe_handle })
    }

    /// Wait for client connection
    pub fn wait_for_connection(&self) -> Result<()> {
        unsafe {
            ConnectNamedPipe(self.pipe_handle, None)?;
        }
        Ok(())
    }

    /// Read request from hook DLL
    pub fn read_request(&self) -> Result<HookRequest> {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read = 0u32;

        unsafe {
            ReadFile(
                self.pipe_handle,
                Some(&mut buffer[..]),
                Some(&mut bytes_read),
                None,
            )?;
        }

        let json_str = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let request: HookRequest = serde_json::from_str(&json_str)?;
        Ok(request)
    }

    /// Send response to hook DLL
    pub fn send_response(&self, response: &HookResponse) -> Result<()> {
        let json = serde_json::to_string(response)?;
        let bytes = json.as_bytes();
        let mut bytes_written = 0u32;

        unsafe {
            WriteFile(
                self.pipe_handle,
                Some(bytes),
                Some(&mut bytes_written),
                None,
            )?;
        }

        Ok(())
    }

    /// Disconnect client
    pub fn disconnect(&self) -> Result<()> {
        unsafe {
            DisconnectNamedPipe(self.pipe_handle)?;
        }
        Ok(())
    }
}

impl Drop for HookIpcServer {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.pipe_handle);
        }
    }
}

/// Client side (hook DLL)
pub struct HookIpcClient {
    pipe_handle: HANDLE,
}

impl HookIpcClient {
    /// Connect to server (with timeout and retry)
    pub fn connect() -> Result<Self> {
        let pipe_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();

        // Wait for pipe to be available (30 second timeout)
        unsafe {
            if !WaitNamedPipeW(PCWSTR(pipe_name.as_ptr()), 30000).as_bool() {
                return Err(anyhow!("Pipe not available"));
            }
        }

        // Connect to pipe
        let pipe_handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )?  // Returns Result
        };

        Ok(Self { pipe_handle })
    }

    /// Send request and wait for response (blocking)
    pub fn request_approval(&self, request: &HookRequest) -> Result<HookResponse> {
        // Send request
        let json = serde_json::to_string(request)?;
        let bytes = json.as_bytes();
        let mut bytes_written = 0u32;

        unsafe {
            WriteFile(
                self.pipe_handle,
                Some(bytes),
                Some(&mut bytes_written),
                None,
            )?;
        }

        // Read response
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read = 0u32;

        unsafe {
            ReadFile(
                self.pipe_handle,
                Some(&mut buffer[..]),
                Some(&mut bytes_read),
                None,
            )?;
        }

        let json_str = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let response: HookResponse = serde_json::from_str(&json_str)?;
        Ok(response)
    }
}

impl Drop for HookIpcClient {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.pipe_handle);
        }
    }
}
