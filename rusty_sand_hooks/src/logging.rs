use crate::utils::LastError;
use std::fmt::Display;
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;

pub fn error(context: &str, error: &dyn Display) {
    let _last_error = LastError::save();
    let message: Vec<u16> = format!("Rusty Sand hooks: {context}: {error}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    /* SAFETY: The owned UTF-16 buffer is terminated and lives through the
    call. Debug output uses neither hooked file APIs nor the approval lock. */
    unsafe { OutputDebugStringW(PCWSTR(message.as_ptr())) };
}
