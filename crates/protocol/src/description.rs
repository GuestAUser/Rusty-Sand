use crate::HookOperation;

impl HookOperation {
    /** A short description for display. */
    pub fn short_description(&self) -> String {
        match self {
            HookOperation::FileCreate { path, .. } => format!("Create file: {}", path),
            HookOperation::FileWrite { path, .. } => format!("Write to file: {}", path),
            HookOperation::FileDelete { path } => format!("Delete file: {}", path),
            HookOperation::FileRead { path } => format!("Read file: {}", path),
            HookOperation::FileMove {
                source,
                destination,
            } => {
                format!("Move file: {} -> {}", source, destination)
            }
            HookOperation::FileCopy {
                source,
                destination,
            } => {
                format!("Copy file: {} -> {}", source, destination)
            }
            HookOperation::FileAttributeChange { path, .. } => {
                format!("Change file attributes: {}", path)
            }
            HookOperation::FolderCreate { path } => format!("Create folder: {}", path),
            HookOperation::FolderDelete { path } => format!("Delete folder: {}", path),
            HookOperation::RegistrySet { key, value, .. } => {
                format!("Set registry: {}::{}", key, value)
            }
            HookOperation::RegistryDelete { key } => format!("Delete registry key: {}", key),
            HookOperation::RegistryRead { key, value } => {
                format!("Read registry: {}::{}", key, value)
            }
            HookOperation::RegistryOpen { key, .. } => format!("Open registry key: {}", key),
            HookOperation::NetworkConnect {
                remote_addr, port, ..
            } => {
                format!("Connect to: {}:{}", remote_addr, port)
            }
            HookOperation::NetworkSend {
                remote_addr,
                port,
                bytes_to_send,
            } => {
                format!("Send {} bytes to {}:{}", bytes_to_send, remote_addr, port)
            }
            HookOperation::NetworkReceive {
                remote_addr,
                port,
                bytes_to_receive,
            } => {
                format!(
                    "Receive {} bytes from {}:{}",
                    bytes_to_receive, remote_addr, port
                )
            }
            HookOperation::ProcessCreate {
                executable, args, ..
            } => {
                format!("Execute: {} {}", executable, args)
            }
            HookOperation::ThreadCreate { start_address, .. } => {
                format!("Create thread at 0x{:X}", start_address)
            }
            HookOperation::ThreadCreateRemote {
                target_process_id,
                start_address,
            } => {
                format!(
                    "Create remote thread in PID {} at 0x{:X}",
                    target_process_id, start_address
                )
            }
            HookOperation::DllLoad { dll_path, .. } => format!("Load DLL: {}", dll_path),
            HookOperation::MemoryAllocate {
                base_address, size, ..
            } => {
                format!("Allocate {} bytes at 0x{:X}", size, base_address)
            }
            HookOperation::MemoryProtect {
                base_address,
                size,
                old_protection,
                new_protection,
            } => {
                format!(
                    "Change memory protection at 0x{:X} (size: {}, 0x{:X} -> 0x{:X})",
                    base_address, size, old_protection, new_protection
                )
            }
            HookOperation::MemoryWrite {
                target_process_id,
                base_address,
                bytes_to_write,
            } => {
                format!(
                    "Write {} bytes to PID {} at 0x{:X}",
                    bytes_to_write, target_process_id, base_address
                )
            }
        }
    }
}
