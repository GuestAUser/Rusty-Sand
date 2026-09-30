use crate::approval::approve;
use crate::installation::{InitializationError, Installation};
use crate::types::HookOperation;
use crate::utils::{deny, wide_string};
use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::BOOL;

type CreateDirectory = unsafe extern "system" fn(PCWSTR, *const c_void) -> BOOL;
type RemoveDirectory = unsafe extern "system" fn(PCWSTR) -> BOOL;
static CREATE_DIRECTORY: OnceLock<CreateDirectory> = OnceLock::new();
static REMOVE_DIRECTORY: OnceLock<RemoveDirectory> = OnceLock::new();

unsafe extern "system" fn create_directory(path: PCWSTR, security: *const c_void) -> BOOL {
    let Some(original) = CREATE_DIRECTORY.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        Ok(HookOperation::FolderCreate {
            path: wide_string(path)?,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: The immutable trampoline has CreateDirectoryW's ABI and forwards
    borrowed caller pointers unchanged, outside all helper scopes. */
    unsafe { original(path, security) }
}

unsafe extern "system" fn remove_directory(path: PCWSTR) -> BOOL {
    let Some(original) = REMOVE_DIRECTORY.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        Ok(HookOperation::FolderDelete {
            path: wide_string(path)?,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: The process-lifetime trampoline matches RemoveDirectoryW's ABI.
    The caller retains ownership of the unchanged path pointer. */
    unsafe { original(path) }
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"kernel32.dll")?;
    install_hook!(
        installation,
        module,
        c"CreateDirectoryW",
        create_directory,
        CREATE_DIRECTORY,
        CreateDirectory
    );
    install_hook!(
        installation,
        module,
        c"RemoveDirectoryW",
        remove_directory,
        REMOVE_DIRECTORY,
        RemoveDirectory
    );
    Ok(())
}
