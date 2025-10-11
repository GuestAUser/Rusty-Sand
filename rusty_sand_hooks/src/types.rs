//! Shared types for IPC communication between hook DLL and main process

use serde::{Deserialize, Serialize};

/// Request from hook DLL to main process asking for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRequest {
    pub operation: HookOperation,
    pub pid: u32,
    pub tid: u32,
}

/// Response from main process to hook DLL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Types of operations that can be hooked
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum HookOperation {
    // File operations
    FileCreate {
        path: String,
        access_rights: u32,
        share_mode: u32,
        creation_disposition: u32,
        flags_and_attributes: u32,
    },
    FileWrite {
        path: String,
        handle: u64,
    },
    FileDelete {
        path: String,
    },
    FileRead {
        path: String,
    },
    FileMove {
        source: String,
        destination: String,
    },
    FileCopy {
        source: String,
        destination: String,
    },
    FileAttributeChange {
        path: String,
        new_attributes: u32,
    },

    // Folder operations
    FolderCreate {
        path: String,
    },
    FolderDelete {
        path: String,
    },

    // Registry operations
    RegistrySet {
        key: String,
        value: String,
        data_type: u32,
        data_size: u32,
    },
    RegistryDelete {
        key: String,
    },
    RegistryRead {
        key: String,
        value: String,
    },
    RegistryOpen {
        key: String,
        access_rights: u32,
    },

    // Network operations
    NetworkConnect {
        remote_addr: String,
        port: u16,
        protocol: NetworkProtocol,
    },
    NetworkSend {
        remote_addr: String,
        port: u16,
        bytes_to_send: u32,
    },
    NetworkReceive {
        remote_addr: String,
        port: u16,
        bytes_to_receive: u32,
    },

    // Process operations
    ProcessCreate {
        executable: String,
        args: String,
        creation_flags: u32,
    },

    // Thread operations
    ThreadCreate {
        start_address: u64,
        parameter: u64,
    },
    ThreadCreateRemote {
        target_process_id: u32,
        start_address: u64,
    },

    // DLL/Memory operations
    DllLoad {
        dll_path: String,
        load_flags: u32,
    },
    MemoryAllocate {
        base_address: u64,
        size: usize,
        protection: u32,
        allocation_type: u32,
    },
    MemoryProtect {
        base_address: u64,
        size: usize,
        old_protection: u32,
        new_protection: u32,
    },
    MemoryWrite {
        target_process_id: u32,
        base_address: u64,
        bytes_to_write: u32,
    },
}

/// Network protocol type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
}

/// Operation criticality level (for smart filtering)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperationCriticality {
    /// Read-only operations (low risk)
    Low = 0,
    /// Normal operations (medium risk)
    Medium = 1,
    /// Potentially dangerous operations (high risk)
    High = 2,
    /// Very dangerous operations (critical risk)
    Critical = 3,
}

impl HookOperation {
    /// Determine the criticality level of an operation
    pub fn criticality(&self) -> OperationCriticality {
        match self {
            // Read operations are low criticality
            HookOperation::FileRead { .. } => OperationCriticality::Low,
            HookOperation::RegistryRead { .. } => OperationCriticality::Low,
            HookOperation::RegistryOpen { .. } => OperationCriticality::Low,
            HookOperation::NetworkReceive { .. } => OperationCriticality::Low,

            // Normal write operations are medium criticality
            HookOperation::FileWrite { .. } => OperationCriticality::Medium,
            HookOperation::FileCreate { .. } => OperationCriticality::Medium,
            HookOperation::FolderCreate { .. } => OperationCriticality::Medium,
            HookOperation::FileCopy { .. } => OperationCriticality::Medium,
            HookOperation::RegistrySet { .. } => OperationCriticality::Medium,
            HookOperation::NetworkConnect { .. } => OperationCriticality::Medium,
            HookOperation::NetworkSend { .. } => OperationCriticality::Medium,

            // Deletion and modification are high criticality
            HookOperation::FileDelete { .. } => OperationCriticality::High,
            HookOperation::FolderDelete { .. } => OperationCriticality::High,
            HookOperation::FileMove { .. } => OperationCriticality::High,
            HookOperation::FileAttributeChange { .. } => OperationCriticality::High,
            HookOperation::RegistryDelete { .. } => OperationCriticality::High,
            HookOperation::MemoryProtect { .. } => OperationCriticality::High,

            // Process/thread creation and memory manipulation are critical
            HookOperation::ProcessCreate { .. } => OperationCriticality::Critical,
            HookOperation::ThreadCreate { .. } => OperationCriticality::Critical,
            HookOperation::ThreadCreateRemote { .. } => OperationCriticality::Critical,
            HookOperation::DllLoad { .. } => OperationCriticality::Critical,
            HookOperation::MemoryAllocate { .. } => OperationCriticality::Critical,
            HookOperation::MemoryWrite { .. } => OperationCriticality::Critical,
        }
    }

    /// Check if this is a read-only operation
    pub fn is_read_only(&self) -> bool {
        matches!(self.criticality(), OperationCriticality::Low)
    }
}
