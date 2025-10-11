//! IPC client for communication with main process

use crate::types::{HookRequest, HookResponse};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    OPEN_EXISTING,
};

const PIPE_NAME: &str = r"\\.\pipe\rusty_sand_hooks";
const BUFFER_SIZE: usize = 8192;

/// IPC client for communicating with the main Rusty Sand process
pub struct HookIpcClient {
    pipe_handle: HANDLE,
}

impl HookIpcClient {
    /// Connect to the IPC server (main process)
    ///
    /// # Returns
    /// Result with HookIpcClient on success, or error message on failure
    pub fn connect() -> Result<Self, String> {
        let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();

        let pipe_handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE(0),
            )
        };

        if pipe_handle.is_err() || pipe_handle.as_ref().unwrap().is_invalid() {
            return Err("Failed to connect to IPC pipe".to_string());
        }

        Ok(Self {
            pipe_handle: pipe_handle.unwrap(),
        })
    }

    /// Request approval for an operation
    ///
    /// # Arguments
    /// * `request` - The hook request containing operation details
    ///
    /// # Returns
    /// Result with HookResponse indicating approval/denial, or error message
    pub fn request_approval(&self, request: &HookRequest) -> Result<HookResponse, String> {
        // Serialize request to JSON
        let json = serde_json::to_string(request).map_err(|e| format!("JSON serialize error: {}", e))?;
        let json_bytes = json.as_bytes();

        // Validate size
        if json_bytes.len() > BUFFER_SIZE {
            return Err(format!("Request too large: {} bytes (max {})", json_bytes.len(), BUFFER_SIZE));
        }

        // Write request to pipe
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                self.pipe_handle,
                Some(json_bytes),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|e| format!("IPC write failed: {}", e))?;
        }

        // Read response from pipe
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut bytes_read = 0u32;
        unsafe {
            ReadFile(
                self.pipe_handle,
                Some(&mut buffer[..]),
                Some(&mut bytes_read),
                None,
            )
            .map_err(|e| format!("IPC read failed: {}", e))?;
        }

        // Deserialize response from JSON
        let json_str = std::str::from_utf8(&buffer[..bytes_read as usize])
            .map_err(|e| format!("UTF-8 decode failed: {}", e))?;

        serde_json::from_str(json_str).map_err(|e| format!("JSON parse failed: {}", e))
    }
}

impl Drop for HookIpcClient {
    fn drop(&mut self) {
        // Close pipe handle when client is dropped
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.pipe_handle);
        }
    }
}

// Thread-safe for passing between threads (if needed)
unsafe impl Send for HookIpcClient {}
unsafe impl Sync for HookIpcClient {}
