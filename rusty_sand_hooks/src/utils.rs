use crate::buffers::{self, BufferError};
use crate::permissions;
use std::ffi::c_void;
use std::fmt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{SetLastError, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::Threading::GetCurrentProcess;

/* The projected GetLastError converts to HRESULT and loses application-defined
high bits. The raw ABI is needed to preserve the target's entire DWORD. */
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> WIN32_ERROR;
}

#[derive(Debug)]
pub enum InspectionError {
    Buffer(BufferError),
    Windows(windows::core::Error),
    InaccessibleMemory,
    PartialRead { expected: usize, actual: usize },
    RegistryStatus(i32),
    UnsupportedSocketType(i32),
}

impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Buffer(error) => error.fmt(f),
            Self::Windows(error) => error.fmt(f),
            Self::InaccessibleMemory => f.write_str("caller memory is not readable"),
            Self::PartialRead { expected, actual } => {
                write!(f, "caller memory read {actual} of {expected} bytes")
            }
            Self::RegistryStatus(status) => {
                write!(f, "NtQueryKey failed with NTSTATUS {status:#010x}")
            }
            Self::UnsupportedSocketType(kind) => write!(f, "unsupported socket type {kind}"),
        }
    }
}

impl std::error::Error for InspectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Buffer(error) => Some(error),
            Self::Windows(error) => Some(error),
            _ => None,
        }
    }
}

impl From<BufferError> for InspectionError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

impl From<windows::core::Error> for InspectionError {
    fn from(error: windows::core::Error) -> Self {
        Self::Windows(error)
    }
}

pub struct LastError(WIN32_ERROR);

impl LastError {
    pub fn save() -> Self {
        /* SAFETY: GetLastError reads the calling thread's error slot. */
        Self(unsafe { GetLastError() })
    }
}

impl Drop for LastError {
    fn drop(&mut self) {
        /* SAFETY: Restoring the saved scalar affects only this thread. */
        unsafe { SetLastError(self.0) };
    }
}

pub fn deny<T>(result: T) -> T {
    /* SAFETY: No pointers are involved; this is the Win32 denial contract. */
    unsafe { SetLastError(windows::Win32::Foundation::ERROR_ACCESS_DENIED) };
    result
}

pub fn copy_caller_bytes(
    address: *const c_void,
    destination: &mut [u8],
) -> Result<(), InspectionError> {
    buffers::validate_pointer_length(address as usize, destination.len())?;
    if destination.is_empty() {
        return Ok(());
    }
    let mut copied = 0;
    /* SAFETY: ReadProcessMemory validates the source in the current process.
    The destination is owned, initialized, and writable for exactly its
    supplied length. No Rust reference is formed to caller-owned memory. */
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address,
            destination.as_mut_ptr().cast(),
            destination.len(),
            Some(&mut copied),
        )?;
    }
    if copied != destination.len() {
        return Err(InspectionError::PartialRead {
            expected: destination.len(),
            actual: copied,
        });
    }
    Ok(())
}

pub fn wide_string(pointer: PCWSTR) -> Result<String, InspectionError> {
    const MAX_WCHARS: usize = 32_767;
    if pointer.is_null() {
        return Ok(String::new());
    }
    buffers::validate_wide_address(pointer.0 as usize)?;
    let mut address = pointer.0 as usize;
    let mut bytes = Vec::new();
    while bytes.len() / 2 <= MAX_WCHARS {
        let mut region = MEMORY_BASIC_INFORMATION::default();
        /* SAFETY: VirtualQuery probes an address without dereferencing it in
        Rust, and writes only to the fully-sized local structure. */
        let returned = unsafe {
            VirtualQuery(
                Some(address as *const c_void),
                &mut region,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if returned != size_of::<MEMORY_BASIC_INFORMATION>()
            || !permissions::readable_region(region.State.0, region.Protect.0)
        {
            return Err(InspectionError::InaccessibleMemory);
        }
        let end = (region.BaseAddress as usize)
            .checked_add(region.RegionSize)
            .ok_or(BufferError::InvalidLength)?;
        let available = end.checked_sub(address).ok_or(BufferError::InvalidLength)?;
        let length = available.min(256).min((MAX_WCHARS + 1) * 2 - bytes.len()) & !1;
        if length == 0 {
            return Err(BufferError::UnterminatedString.into());
        }
        let mut chunk = [0; 256];
        copy_caller_bytes(address as *const c_void, &mut chunk[..length])?;
        if buffers::append_wide_chunk(&mut bytes, &chunk[..length], MAX_WCHARS)? {
            return Ok(buffers::utf16_from_bytes(&bytes)?);
        }
        address = address
            .checked_add(length)
            .ok_or(BufferError::InvalidLength)?;
    }
    Err(BufferError::UnterminatedString.into())
}

pub fn previous_protection(address: *const c_void) -> u32 {
    let mut region = MEMORY_BASIC_INFORMATION::default();
    /* SAFETY: The address is queried, not read, and the output is a local
    structure. VirtualProtect's caller-owned output is never inspected. */
    let returned = unsafe {
        VirtualQuery(
            Some(address),
            &mut region,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if returned == size_of::<MEMORY_BASIC_INFORMATION>() {
        permissions::prior_protection(region.State.0, region.Protect.0)
    } else {
        0
    }
}

#[cfg(test)]
#[path = "../tests/unit/utils.rs"]
mod tests;
