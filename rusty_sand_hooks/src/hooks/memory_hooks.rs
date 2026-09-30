use crate::approval::approve;
use crate::buffers::BufferError;
use crate::installation::{InitializationError, Installation};
use crate::types::HookOperation;
use crate::utils::{deny, previous_protection, wide_string};
use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE};
use windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE;
use windows::Win32::System::Threading::GetProcessId;

type VirtualAlloc =
    unsafe extern "system" fn(*const c_void, usize, VIRTUAL_ALLOCATION_TYPE, u32) -> *mut c_void;
type VirtualProtect = unsafe extern "system" fn(*const c_void, usize, u32, *mut u32) -> BOOL;
type WriteProcessMemory =
    unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL;
type LoadLibrary = unsafe extern "system" fn(PCWSTR) -> HMODULE;
type LoadLibraryEx = unsafe extern "system" fn(PCWSTR, HANDLE, u32) -> HMODULE;
static VIRTUAL_ALLOC: OnceLock<VirtualAlloc> = OnceLock::new();
static VIRTUAL_PROTECT: OnceLock<VirtualProtect> = OnceLock::new();
static WRITE_PROCESS_MEMORY: OnceLock<WriteProcessMemory> = OnceLock::new();
static LOAD_LIBRARY: OnceLock<LoadLibrary> = OnceLock::new();
static LOAD_LIBRARY_EX: OnceLock<LoadLibraryEx> = OnceLock::new();

unsafe extern "system" fn virtual_alloc(
    address: *const c_void,
    size: usize,
    allocation: VIRTUAL_ALLOCATION_TYPE,
    protection: u32,
) -> *mut c_void {
    let Some(original) = VIRTUAL_ALLOC.get() else {
        return deny(std::ptr::null_mut());
    };
    if !approve(|| {
        Ok(HookOperation::MemoryAllocate {
            base_address: address as u64,
            size,
            protection,
            allocation_type: allocation.0,
        })
    }) {
        return deny(std::ptr::null_mut());
    }
    /* SAFETY: The published trampoline has VirtualAlloc's system ABI; the
    address and size are forwarded to Windows for allocation validation. */
    unsafe { original(address, size, allocation, protection) }
}

unsafe extern "system" fn virtual_protect(
    address: *const c_void,
    size: usize,
    protection: u32,
    old_protection: *mut u32,
) -> BOOL {
    let Some(original) = VIRTUAL_PROTECT.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        Ok(HookOperation::MemoryProtect {
            base_address: address as u64,
            size,
            old_protection: previous_protection(address),
            new_protection: protection,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: The trampoline has VirtualProtect's ABI. Only Windows writes
    the caller's output pointer; inspection never reads its prior contents. */
    unsafe { original(address, size, protection, old_protection) }
}

unsafe extern "system" fn write_process_memory(
    process: HANDLE,
    address: *const c_void,
    buffer: *const c_void,
    size: usize,
    written: *mut usize,
) -> BOOL {
    let Some(original) = WRITE_PROCESS_MEMORY.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        let bytes_to_write = u32::try_from(size).map_err(|_| BufferError::InvalidLength)?;
        /* SAFETY: GetProcessId validates the borrowed process handle. */
        let target_process_id = unsafe { GetProcessId(process) };
        Ok(HookOperation::MemoryWrite {
            target_process_id,
            base_address: address as u64,
            bytes_to_write,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: The process-lifetime trampoline has WriteProcessMemory's ABI.
    No Rust reference is formed to the caller's source or output buffers. */
    unsafe { original(process, address, buffer, size, written) }
}

unsafe extern "system" fn load_library(name: PCWSTR) -> HMODULE {
    let Some(original) = LOAD_LIBRARY.get() else {
        return deny(HMODULE(0));
    };
    if !approve(|| {
        Ok(HookOperation::DllLoad {
            dll_path: wide_string(name)?,
            load_flags: 0,
        })
    }) {
        return deny(HMODULE(0));
    }
    /* SAFETY: The LoadLibraryW trampoline remains allocated and receives the
    borrowed name unchanged. DllMain runs after the helper guard is dropped. */
    unsafe { original(name) }
}

unsafe extern "system" fn load_library_ex(name: PCWSTR, file: HANDLE, flags: u32) -> HMODULE {
    let Some(original) = LOAD_LIBRARY_EX.get() else {
        return deny(HMODULE(0));
    };
    if !approve(|| {
        Ok(HookOperation::DllLoad {
            dll_path: wide_string(name)?,
            load_flags: flags,
        })
    }) {
        return deny(HMODULE(0));
    }
    /* SAFETY: The LoadLibraryExW trampoline's ABI matches and all caller-owned
    arguments are unchanged. Target initialization inherits no helper bypass. */
    unsafe { original(name, file, flags) }
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"kernel32.dll")?;
    install_hook!(
        installation,
        module,
        c"VirtualAlloc",
        virtual_alloc,
        VIRTUAL_ALLOC,
        VirtualAlloc
    );
    install_hook!(
        installation,
        module,
        c"VirtualProtect",
        virtual_protect,
        VIRTUAL_PROTECT,
        VirtualProtect
    );
    install_hook!(
        installation,
        module,
        c"WriteProcessMemory",
        write_process_memory,
        WRITE_PROCESS_MEMORY,
        WriteProcessMemory
    );
    install_hook!(
        installation,
        module,
        c"LoadLibraryW",
        load_library,
        LOAD_LIBRARY,
        LoadLibrary
    );
    install_hook!(
        installation,
        module,
        c"LoadLibraryExW",
        load_library_ex,
        LOAD_LIBRARY_EX,
        LoadLibraryEx
    );
    Ok(())
}
