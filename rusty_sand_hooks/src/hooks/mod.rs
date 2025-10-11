//! API hook implementations organized by category
//!
//! Each module contains hooks for a specific category of Windows APIs:
//! - file_hooks: File operations (CreateFileW, DeleteFileW, etc.)
//! - folder_hooks: Directory operations (CreateDirectoryW, RemoveDirectoryW)
//! - network_hooks: Network operations (connect, send, recv)
//! - registry_hooks: Registry operations (RegSetValueExW, RegDeleteKeyW, etc.)
//! - process_hooks: Process/thread operations (CreateProcessW, CreateThread, etc.)
//! - memory_hooks: Memory operations (VirtualAlloc, VirtualProtect, etc.)

pub mod file_hooks;
pub mod folder_hooks;
pub mod memory_hooks;
pub mod network_hooks;
pub mod process_hooks;
pub mod registry_hooks;
