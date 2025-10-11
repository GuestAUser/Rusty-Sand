//! DLL Injection module
//!
//! Injects our hook DLL into the target process to intercept API calls BEFORE they execute.
//! Uses classic CreateRemoteThread + LoadLibrary injection technique.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, WaitForSingleObject, INFINITE,
};

/// Inject a DLL into a target process
///
/// This function:
/// 1. Allocates memory in target process for DLL path
/// 2. Writes DLL path to target process memory
/// 3. Gets address of LoadLibraryW in kernel32.dll
/// 4. Creates remote thread in target to call LoadLibraryW(dll_path)
/// 5. Waits for injection to complete
///
/// # Safety
/// Uses unsafe Windows APIs. Target process must have appropriate access rights.
pub fn inject_dll(process_handle: HANDLE, dll_path: &Path) -> Result<()> {
    info!("🔧 Injecting hook DLL: {}", dll_path.display());

    // Get full path to DLL
    let dll_path_str = dll_path
        .to_str()
        .ok_or_else(|| anyhow!("Invalid DLL path"))?;

    let dll_path_wide: Vec<u16> = OsStr::new(dll_path_str)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let dll_path_size = dll_path_wide.len() * 2; // bytes

    // Step 1: Allocate memory in target process
    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        return Err(anyhow!("VirtualAllocEx failed"));
    }

    debug!("Allocated remote buffer at {:?}", remote_buffer);

    // Step 2: Write DLL path to remote process
    let mut bytes_written = 0usize;
    let write_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_path_wide.as_ptr() as *const _,
            dll_path_size,
            Some(&mut bytes_written),
        )
    };

    if write_result.is_err() {
        unsafe {
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE)?;
        }
        return Err(anyhow!("WriteProcessMemory failed"));
    }

    debug!("Wrote {} bytes to remote process", bytes_written);

    // Step 3: Get address of LoadLibraryW
    let kernel32_name: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    let loadlibrary_name = std::ffi::CString::new("LoadLibraryW")?;

    let kernel32_handle = unsafe { GetModuleHandleW(PCWSTR(kernel32_name.as_ptr()))? };

    let loadlibrary_addr = unsafe {
        GetProcAddress(kernel32_handle, windows::core::PCSTR(loadlibrary_name.as_ptr() as *const u8))
            .ok_or_else(|| anyhow!("GetProcAddress failed for LoadLibraryW"))?
    };

    debug!("LoadLibraryW address: {:?}", loadlibrary_addr as *const ());

    // Step 4: Create remote thread to call LoadLibraryW
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute::<unsafe extern "system" fn() -> isize, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(loadlibrary_addr)),
            Some(remote_buffer),
            0,
            None,
        )?
    };

    info!("✓ Remote thread created, waiting for injection to complete...");

    // Step 5: Wait for thread to finish
    unsafe {
        WaitForSingleObject(thread_handle, INFINITE);
        windows::Win32::Foundation::CloseHandle(thread_handle)?;
    }

    // Cleanup
    unsafe {
        VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE)?;
    }

    info!("✅ DLL injection completed successfully");
    Ok(())
}

/// Build hook DLL if it doesn't exist
///
/// Compiles the hook DLL from source if needed
pub fn ensure_hook_dll_exists() -> Result<std::path::PathBuf> {
    let dll_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("Cannot get exe directory"))?
        .join("rusty_sand_hooks.dll");

    if !dll_path.exists() {
        warn!("Hook DLL not found at {}", dll_path.display());
        warn!("You need to build the hook DLL separately:");
        warn!("  cargo build --release --package rusty_sand_hooks");
        return Err(anyhow!("Hook DLL not found. Build it first."));
    }

    info!("Found hook DLL at: {}", dll_path.display());
    Ok(dll_path)
}
