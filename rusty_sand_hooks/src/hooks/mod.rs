use crate::installation::{InitializationError, Installation};

macro_rules! install_hook {
    ($installation:expr, $module:expr, $name:literal, $callback:ident, $slot:ident, $signature:ty) => {{
        let callback: $signature = $callback;
        /* SAFETY: Each invocation names the Windows export corresponding to
        the explicit system-ABI signature. Creation leaves the hook disabled;
        the immutable trampoline is published before any hook is enabled. */
        let original = unsafe {
            let address = $installation.create(
                $module,
                $name,
                callback as *const () as *mut std::ffi::c_void,
            )?;
            std::mem::transmute::<*mut std::ffi::c_void, $signature>(address)
        };
        $slot
            .set(original)
            .map_err(|_| InitializationError::DuplicateTrampoline($name))?;
    }};
}

mod file_hooks;
mod folder_hooks;
mod memory_hooks;
mod network_hooks;
mod process_hooks;
mod registry_hooks;

pub fn prepare(installation: &mut Installation) -> Result<(), InitializationError> {
    file_hooks::install(installation)?;
    folder_hooks::install(installation)?;
    network_hooks::install(installation)?;
    registry_hooks::install(installation)?;
    process_hooks::install(installation)?;
    memory_hooks::install(installation)
}
