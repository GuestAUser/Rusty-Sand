use crate::approval::approve;
use crate::installation::{InitializationError, Installation};
use crate::permissions::{file_intent, FileIntent};
use crate::types::HookOperation;
use crate::utils::{deny, wide_string};
use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::FILE_SHARE_MODE;

type CreateFile = unsafe extern "system" fn(
    PCWSTR,
    u32,
    FILE_SHARE_MODE,
    *const c_void,
    u32,
    u32,
    HANDLE,
) -> HANDLE;
type DeleteFile = unsafe extern "system" fn(PCWSTR) -> BOOL;
static CREATE_FILE: OnceLock<CreateFile> = OnceLock::new();
static DELETE_FILE: OnceLock<DeleteFile> = OnceLock::new();

unsafe extern "system" fn create_file(
    name: PCWSTR,
    access: u32,
    share: FILE_SHARE_MODE,
    security: *const c_void,
    disposition: u32,
    flags: u32,
    template: HANDLE,
) -> HANDLE {
    let Some(original) = CREATE_FILE.get() else {
        return deny(INVALID_HANDLE_VALUE);
    };
    if !approve(|| {
        let path = wide_string(name)?;
        Ok(match file_intent(access, disposition, flags) {
            FileIntent::Create => HookOperation::FileCreate {
                path,
                access_rights: access,
                share_mode: share.0,
                creation_disposition: disposition,
                flags_and_attributes: flags,
            },
            FileIntent::Write => HookOperation::FileWrite { path, handle: 0 },
            FileIntent::Read => HookOperation::FileRead { path },
        })
    }) {
        return deny(INVALID_HANDLE_VALUE);
    }
    /* SAFETY: The immutable trampoline has CreateFileW's ABI and remains
    allocated. All caller-owned inputs are forwarded unchanged; helper
    scopes have ended before Windows can invoke arbitrary target code. */
    unsafe { original(name, access, share, security, disposition, flags, template) }
}

unsafe extern "system" fn delete_file(name: PCWSTR) -> BOOL {
    let Some(original) = DELETE_FILE.get() else {
        return deny(BOOL(0));
    };
    if !approve(|| {
        Ok(HookOperation::FileDelete {
            path: wide_string(name)?,
        })
    }) {
        return deny(BOOL(0));
    }
    /* SAFETY: This process-lifetime trampoline has DeleteFileW's ABI and
    receives the original caller's pointer without extending its lifetime. */
    unsafe { original(name) }
}

pub fn install(installation: &mut Installation) -> Result<(), InitializationError> {
    let module = installation.module(c"kernel32.dll")?;
    install_hook!(
        installation,
        module,
        c"CreateFileW",
        create_file,
        CREATE_FILE,
        CreateFile
    );
    install_hook!(
        installation,
        module,
        c"DeleteFileW",
        delete_file,
        DELETE_FILE,
        DeleteFile
    );
    Ok(())
}
