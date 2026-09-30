use super::*;
use windows::core::w;
use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

#[test]
fn caller_strings_are_copied_without_dereferencing_invalid_pointers() -> Result<(), InspectionError>
{
    assert_eq!(wide_string(w!("owned input"))?, "owned input");
    assert_eq!(wide_string(PCWSTR::null())?, "");
    let misaligned = std::ptr::dangling::<u8>().cast::<u16>();
    assert!(matches!(
        wide_string(PCWSTR(misaligned)),
        Err(InspectionError::Buffer(BufferError::MisalignedWideString))
    ));
    assert!(wide_string(PCWSTR(std::ptr::dangling::<u16>())).is_err());
    assert!(copy_caller_bytes(std::ptr::null(), &mut []).is_ok());
    assert!(matches!(
        copy_caller_bytes(std::ptr::null(), &mut [0]),
        Err(InspectionError::Buffer(BufferError::NullPointer))
    ));
    Ok(())
}

#[test]
fn prior_protection_distinguishes_committed_from_reserved_memory() -> windows::core::Result<()> {
    for (allocation, expected) in [
        (MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE.0),
        (MEM_RESERVE, 0),
    ] {
        /* SAFETY: Windows chooses a page-aligned allocation. This test
        owns the returned region and releases it before assertions. */
        let memory = unsafe { VirtualAlloc(None, 4096, allocation, PAGE_READWRITE) };
        if memory.is_null() {
            return Err(windows::core::Error::from_win32());
        }
        let protection = previous_protection(memory);
        /* SAFETY: memory is the base of the live region owned above. */
        unsafe { VirtualFree(memory, 0, MEM_RELEASE) }?;
        assert_eq!(protection, expected);
    }
    Ok(())
}

#[test]
fn helper_guard_preserves_all_last_error_bits_and_denial_sets_access_denied() {
    let _saved = LastError::save();
    /* SAFETY: Test changes only its own thread's error slot. */
    unsafe {
        SetLastError(WIN32_ERROR(0xe123_4567));
    }
    {
        let _guard = LastError::save();
        /* SAFETY: This error is restored by the local guard. */
        unsafe {
            SetLastError(WIN32_ERROR(7));
        }
    }
    /* SAFETY: Raw GetLastError reads only this thread's DWORD slot. */
    assert_eq!(unsafe { GetLastError() }.0, 0xe123_4567);
    assert_eq!(deny(0), 0);
    /* SAFETY: The denial just set this thread's Win32 error. */
    assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
}
