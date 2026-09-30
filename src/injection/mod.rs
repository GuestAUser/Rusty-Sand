/*! Explicit hook loading and initialization while the target's primary thread is suspended. */

mod image;
mod remote;

use crate::sandbox::resource::with_cleanup;
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::{s, w};
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE,
};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::GetCurrentProcess;

/** Synchronous compatibility entry point. Async callers must use `inject_dll_async`.

The caller must bind the target's pipe server before initialization. Loading the
library executes loader code; it is not a zero-code-execution operation.
*/
pub fn inject_dll(process_handle: HANDLE, dll_path: &Path) -> Result<()> {
    if tokio::runtime::Handle::try_current().is_ok() {
        bail!("use inject_dll_async from an async runtime");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            inject_dll_async(process_handle, dll_path),
        )
        .await
        .context("hook initialization deadline exceeded")?
    })
}

pub async fn inject_dll_async(process_handle: HANDLE, dll_path: &Path) -> Result<()> {
    let mut execution = remote::RemoteExecution::new(process_handle)?;
    let result = initialize(&mut execution, dll_path).await;
    with_cleanup(result, execution.close())
}

async fn initialize(execution: &mut remote::RemoteExecution, dll_path: &Path) -> Result<()> {
    validate_architecture(execution.process())?;
    let path = dll_path
        .canonicalize()
        .context("resolve hook library path")?;
    if path.metadata()?.len() > 64 * 1024 * 1024 {
        bail!("hook library exceeds the supported 64 MiB image size");
    }
    let rva = image::initializer_rva(&std::fs::read(&path).context("read hook library image")?)?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("hook library path contains NUL");
    }
    let byte_length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .context("library path size overflow")?,
    )
    .context("hook library path exceeds UNICODE_STRING length")?;
    let maximum_length = byte_length
        .checked_add(2)
        .context("library path terminator exceeds UNICODE_STRING length")?;
    wide.push(0);

    /* A newly created suspended process need not have kernel32 loaded. Ntdll is
    already mapped. Calling its loader through a small ABI adapter avoids
    assuming a remote LoadLibraryW address, and returns the complete HMODULE
    through memory rather than truncating it to a thread's DWORD exit code. */
    let loader = remote_loader(execution.process())?;
    let context = execution.allocate(24 + usize::from(maximum_length))?;
    let mut data = vec![0u8; 24];
    data[8..10].copy_from_slice(&byte_length.to_le_bytes());
    data[10..12].copy_from_slice(&maximum_length.to_le_bytes());
    data[16..24].copy_from_slice(&((context + 24) as u64).to_le_bytes());
    for unit in wide {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    execution.write(context, &data)?;
    let thunk = loader_thunk(loader as u64);
    let code = execution.allocate(thunk.len())?;
    execution.write(code, &thunk)?;
    execution.make_executable(code, thunk.len())?;
    let status = execution.call(code, context).await?;
    if status != 0 {
        bail!("remote LdrLoadDll failed with NTSTATUS {status:#010x}");
    }
    let module = execution.read_pointer(context)?;
    if module == 0 {
        bail!("remote loader returned a null module");
    }
    let initializer = module
        .checked_add(rva as usize)
        .context("initializer address overflow")?;
    validate_executable_address(execution.process(), initializer, module)?;
    let status = execution.call(initializer, 0).await?;
    if status != 1 {
        bail!("RustySandInitialize rejected startup (status {status})");
    }
    Ok(())
}

fn validate_architecture(target: HANDLE) -> Result<()> {
    if !cfg!(target_arch = "x86_64") {
        bail!("hook injection supports a native AMD64 host and target only");
    }
    /* SAFETY: Both names are static NUL-terminated strings. The resolved API's
    ABI uses HANDLE and two writable USHORT pointers as documented by Windows.
    Dynamic resolution permits an explicit unsupported-platform error. */
    unsafe {
        let kernel = GetModuleHandleW(w!("kernel32.dll"))?;
        let address = GetProcAddress(kernel, s!("IsWow64Process2"))
            .context("IsWow64Process2 is required for architecture validation")?;
        let query = std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(HANDLE, *mut u16, *mut u16) -> BOOL,
        >(address);
        for process in [GetCurrentProcess(), target] {
            let mut process_machine = 0;
            let mut native_machine = 0;
            query(process, &mut process_machine, &mut native_machine)
                .ok()
                .context("query process architecture")?;
            if process_machine != 0 || native_machine != 0x8664 {
                bail!("unsupported target architecture: process {process_machine:#x}, native {native_machine:#x}; native AMD64 required");
            }
        }
    }
    Ok(())
}

fn remote_loader(process: HANDLE) -> Result<usize> {
    /* SAFETY: Ntdll is loaded for the lifetime of this Windows process. The
    exported pointer is inspected, not called with an incompatible ABI. */
    let (module, address, current) = unsafe {
        let module = GetModuleHandleW(w!("ntdll.dll"))?;
        let address =
            GetProcAddress(module, s!("LdrLoadDll")).context("resolve LdrLoadDll")? as usize;
        (module.0 as usize, address, GetCurrentProcess())
    };
    validate_executable_address(process, address, module)
        .context("target does not share the expected native ntdll mapping")?;
    if mapped_path(current, address)? != mapped_path(process, address)? {
        bail!("target ntdll mapping does not match the injector; unsupported loader layout");
    }
    Ok(address)
}

fn mapped_path(process: HANDLE, address: usize) -> Result<Vec<u16>> {
    let mut path = vec![0u16; 32_768];
    /* SAFETY: The writable slice has the advertised length; the address is
    interpreted by Windows in the supplied process, never dereferenced here. */
    let length =
        unsafe { GetMappedFileNameW(process, address as *const c_void, &mut path) } as usize;
    if length == 0 || length >= path.len() {
        return Err(windows::core::Error::from_win32()).context("identify remote loader mapping");
    }
    path.truncate(length);
    Ok(path)
}

fn validate_executable_address(process: HANDLE, address: usize, module: usize) -> Result<()> {
    let mut information = MEMORY_BASIC_INFORMATION::default();
    /* SAFETY: Windows fills the aligned, correctly sized local structure. The
    remote address is never converted to a local reference. */
    let size = unsafe {
        VirtualQueryEx(
            process,
            Some(address as *const c_void),
            &mut information,
            std::mem::size_of_val(&information),
        )
    };
    if size != std::mem::size_of_val(&information) {
        return Err(windows::core::Error::from_win32()).context("query remote code mapping");
    }
    if information.AllocationBase as usize != module
        || information.Type != MEM_IMAGE
        || information.State != MEM_COMMIT
        || information.Protect.0 & 0xf0 == 0
    {
        bail!("remote entry point is not executable code in the expected image");
    }
    Ok(())
}

fn loader_thunk(loader: u64) -> Vec<u8> {
    /* Windows AMD64: reserve 32-byte shadow space plus alignment; RCX points to
    { HMODULE, UNICODE_STRING }. LdrLoadDll(NULL, NULL, &name, &module) returns
    NTSTATUS in EAX. Only volatile registers are used; the stack is restored. */
    let mut code = vec![
        0x48, 0x83, 0xec, 0x28, 0x4c, 0x8b, 0xc9, 0x4c, 0x8d, 0x41, 0x08, 0x31, 0xd2, 0x31, 0xc9,
        0x48, 0xb8,
    ];
    code.extend_from_slice(&loader.to_le_bytes());
    code.extend_from_slice(&[0xff, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    code
}

pub fn ensure_hook_dll_exists() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("locate sandbox executable")?;
    let path = executable
        .parent()
        .context("sandbox executable has no parent directory")?
        .join("rusty_sand_hooks.dll");
    if !path.is_file() {
        bail!(
            "hook DLL not found at {}; build and deploy rusty_sand_hooks.dll beside the executable",
            path.display()
        );
    }
    Ok(path)
}
