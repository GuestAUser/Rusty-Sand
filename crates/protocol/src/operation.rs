use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum HookOperation {
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

    FolderCreate {
        path: String,
    },
    FolderDelete {
        path: String,
    },

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

    ProcessCreate {
        executable: String,
        args: String,
        creation_flags: u32,
    },

    ThreadCreate {
        start_address: u64,
        parameter: u64,
    },
    ThreadCreateRemote {
        target_process_id: u32,
        start_address: u64,
    },

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
