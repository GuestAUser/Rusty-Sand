//! API Hooking DLL for Rusty Sand - V3 (Modular Architecture)
//!
//! This DLL implements TRUE real-time prevention using MinHook for inline hooking.
//! Operations are intercepted BEFORE execution and blocked if user denies.
//!
//! Architecture:
//! - Modular hook organization by category (file, folder, network, registry)
//! - Shared IPC client for communication with main process
//! - Registry utilities for human-readable key paths
//! - Type-safe operation definitions with criticality levels

mod hooks;
mod ipc_client;
mod logging;
mod registry_utils;
mod types;
mod utils;

use hooks::{file_hooks, folder_hooks, memory_hooks, network_hooks, process_hooks, registry_hooks};
use ipc_client::HookIpcClient;
use minhook::MinHook;
use windows::Win32::Foundation::{BOOL, HANDLE};

/// Initialize the hooking system
///
/// This function is called during DLL_PROCESS_ATTACH.
/// It connects to the IPC server and installs all API hooks.
///
/// # Returns
/// true on success, false on failure
unsafe fn initialize_hooks() -> bool {
    // Step 0: Initialize logging system
    logging::init();
    hook_log!(Info, "Rusty Sand Hook DLL initializing...");

    // Step 1: Connect to IPC server FIRST (must be running before hooks are installed)
    hook_log!(Debug, "Connecting to IPC server...");
    match HookIpcClient::connect() {
        Ok(client) => {
            // Store IPC client in global state (accessible to all hooks)
            *file_hooks::IPC_CLIENT.lock() = Some(client);
            hook_log!(Info, "IPC connection established successfully");
        }
        Err(e) => {
            // Failed to connect - hooks won't work without IPC
            hook_log!(Error, "Failed to connect to IPC server: {}", e);
            return false;
        }
    }

    // Step 2: Install all hooks (organized by category)
    let mut success = true;
    let mut hooks_installed = 0;

    // Install file operation hooks (CreateFileW, DeleteFileW)
    hook_log!(Debug, "Installing file operation hooks...");
    match file_hooks::install_file_hooks() {
        Ok(_) => {
            hook_log!(Info, "File hooks installed successfully");
            hooks_installed += 2;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install file hooks: {}", e);
            success = false;
        }
    }

    // Install folder operation hooks (CreateDirectoryW, RemoveDirectoryW)
    hook_log!(Debug, "Installing folder operation hooks...");
    match folder_hooks::install_folder_hooks() {
        Ok(_) => {
            hook_log!(Info, "Folder hooks installed successfully");
            hooks_installed += 2;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install folder hooks: {}", e);
            success = false;
        }
    }

    // Install network operation hooks (connect)
    hook_log!(Debug, "Installing network operation hooks...");
    match network_hooks::install_network_hooks() {
        Ok(_) => {
            hook_log!(Info, "Network hooks installed successfully");
            hooks_installed += 1;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install network hooks: {}", e);
            success = false;
        }
    }

    // Install registry operation hooks (RegSetValueExW, RegDeleteKeyW, etc.)
    hook_log!(Debug, "Installing registry operation hooks...");
    match registry_hooks::install_registry_hooks() {
        Ok(_) => {
            hook_log!(Info, "Registry hooks installed successfully");
            hooks_installed += 4;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install registry hooks: {}", e);
            success = false;
        }
    }

    // Install process/thread operation hooks (CreateProcessW, CreateThread, CreateRemoteThread)
    hook_log!(Debug, "Installing process/thread operation hooks...");
    match process_hooks::install_process_hooks() {
        Ok(_) => {
            hook_log!(Info, "Process/thread hooks installed successfully");
            hooks_installed += 3;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install process/thread hooks: {}", e);
            success = false;
        }
    }

    // Install memory/DLL operation hooks (VirtualAlloc, VirtualProtect, WriteProcessMemory, LoadLibraryW, LoadLibraryExW)
    hook_log!(Debug, "Installing memory/DLL operation hooks...");
    match memory_hooks::install_memory_hooks() {
        Ok(_) => {
            hook_log!(Info, "Memory/DLL hooks installed successfully");
            hooks_installed += 5;
        }
        Err(e) => {
            hook_log!(Error, "Failed to install memory/DLL hooks: {}", e);
            success = false;
        }
    }

    hook_log!(Info, "Hook installation complete: {}/17 hooks active (target: 29)", hooks_installed);
    success
}

/// Cleanup the hooking system
///
/// This function is called during DLL_PROCESS_DETACH.
/// It disables all API hooks and cleans up resources.
unsafe fn cleanup_hooks() {
    hook_log!(Info, "Rusty Sand Hook DLL unloading...");

    // Disable all hooks
    hook_log!(Debug, "Disabling all hooks...");
    match MinHook::disable_all_hooks() {
        Ok(_) => hook_log!(Info, "All hooks disabled successfully"),
        Err(e) => hook_log!(Error, "Failed to disable hooks: {:?}", e),
    }

    // Clear IPC client
    *file_hooks::IPC_CLIENT.lock() = None;
    hook_log!(Info, "Hook DLL cleanup complete");
}

/// DLL entry point for hook initialization
///
/// # Safety
///
/// This function is called by Windows when the DLL is loaded/unloaded.
/// It must maintain proper FFI calling conventions and handle all Windows-specific
/// synchronization requirements. The function:
/// - Connects to the IPC server on DLL_PROCESS_ATTACH
/// - Installs API hooks using MinHook
/// - Disables all hooks on DLL_PROCESS_DETACH
///
/// # Arguments
/// * `_hinst_dll` - Handle to the DLL module
/// * `fdw_reason` - Reason code for the entry point being called
/// * `_lpv_reserved` - Reserved parameter
///
/// # Returns
/// TRUE if initialization/cleanup succeeded, FALSE otherwise
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HANDLE,
    fdw_reason: u32,
    _lpv_reserved: *const std::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Initialize hooks on DLL load
            if initialize_hooks() {
                BOOL(1) // Success
            } else {
                // Failed to initialize - still load DLL but hooks won't work
                BOOL(1)
            }
        }
        DLL_PROCESS_DETACH => {
            // Cleanup hooks on DLL unload
            cleanup_hooks();
            BOOL(1)
        }
        _ => BOOL(1), // Other DLL notifications - just return success
    }
}

// Re-export types for potential external use
pub use types::{HookOperation, HookRequest, HookResponse, NetworkProtocol, OperationCriticality};
