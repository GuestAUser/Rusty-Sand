use crate::ipc_client::TransportError;
use crate::logging;
use minhook::MH_STATUS;
use std::ffi::{c_void, CStr};
use std::fmt;
use windows::core::PCSTR;
use windows::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleExA, GetProcAddress, LoadLibraryExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_PIN, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/* The crate's convenience initializer panics on MH_Initialize failure. These
bindings use its linked MinHook implementation and status ABI directly so
initialization failures remain ordinary errors at the DLL boundary. */
unsafe extern "system" {
    fn MH_Initialize() -> MH_STATUS;
    fn MH_Uninitialize() -> MH_STATUS;
    fn MH_CreateHook(
        target: *mut c_void,
        detour: *mut c_void,
        original: *mut *mut c_void,
    ) -> MH_STATUS;
    fn MH_QueueEnableHook(target: *mut c_void) -> MH_STATUS;
    fn MH_ApplyQueued() -> MH_STATUS;
    fn MH_DisableHook(target: *mut c_void) -> MH_STATUS;
    fn MH_RemoveHook(target: *mut c_void) -> MH_STATUS;
}

#[derive(Debug)]
pub enum InitializationError {
    Windows(windows::core::Error),
    Transport(TransportError),
    MissingExport(&'static CStr),
    MinHook {
        operation: &'static str,
        status: MH_STATUS,
    },
    DuplicateTrampoline(&'static CStr),
    HookCount {
        expected: u32,
        actual: usize,
    },
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(error) => error.fmt(f),
            Self::Transport(error) => error.fmt(f),
            Self::MissingExport(name) => write!(f, "missing export {name:?}"),
            Self::MinHook { operation, status } => write!(f, "{operation}: {status:?}"),
            Self::DuplicateTrampoline(name) => {
                write!(f, "trampoline already initialized: {name:?}")
            }
            Self::HookCount { expected, actual } => {
                write!(f, "expected {expected} hooks, prepared {actual}")
            }
        }
    }
}

impl std::error::Error for InitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<windows::core::Error> for InitializationError {
    fn from(error: windows::core::Error) -> Self {
        Self::Windows(error)
    }
}

impl From<TransportError> for InitializationError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

struct Target {
    address: usize,
    name: &'static CStr,
}

pub struct Installation {
    targets: Vec<Target>,
    modules: Vec<(&'static CStr, HMODULE)>,
    engine_initialized: bool,
    activation_attempted: bool,
}

impl Installation {
    pub fn new() -> Result<Self, InitializationError> {
        /* SAFETY: The lifecycle CAS permits exactly one MinHook initializer;
        no hook can run until all of its trampolines have been published. */
        check("initialize MinHook", unsafe { MH_Initialize() })?;
        Ok(Self {
            targets: Vec::new(),
            modules: Vec::new(),
            engine_initialized: true,
            activation_attempted: false,
        })
    }

    pub fn module(&mut self, name: &'static CStr) -> Result<HMODULE, InitializationError> {
        if let Some((_, handle)) = self.modules.iter().find(|(loaded, _)| *loaded == name) {
            return Ok(*handle);
        }
        /* SAFETY: The fixed system module name is terminated and retained for
        process lifetime along with its trampolines. System32-only search
        avoids resolving a same-named DLL from the target's working folder. */
        let handle = unsafe {
            LoadLibraryExA(
                PCSTR(name.as_ptr().cast()),
                HANDLE(0),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }?;
        self.modules.push((name, handle));
        Ok(handle)
    }

    /**
    # Safety
    The detour and eventual trampoline type must exactly match the named
    export's system ABI. The module must stay loaded for process lifetime.
    */
    pub unsafe fn create(
        &mut self,
        module: HMODULE,
        name: &'static CStr,
        detour: *mut c_void,
    ) -> Result<*mut c_void, InitializationError> {
        /* SAFETY: module is a retained library handle, and name is a static
        terminated export name. The caller supplies its matching ABI. */
        let address = unsafe { GetProcAddress(module, PCSTR(name.as_ptr().cast())) }
            .ok_or(InitializationError::MissingExport(name))? as *mut c_void;
        let mut original = std::ptr::null_mut();
        /* SAFETY: MinHook writes a callable trampoline to local storage but
        leaves the detour disabled. The caller publishes it before enable. */
        check("create hook", unsafe {
            MH_CreateHook(address, detour, &mut original)
        })?;
        self.targets.push(Target {
            address: address as usize,
            name,
        });
        Ok(original)
    }

    pub fn activate(&mut self) -> Result<(), InitializationError> {
        let expected = crate::types::EXPECTED_HOOK_COUNT;
        if self.targets.len() != expected as usize {
            return Err(InitializationError::HookCount {
                expected,
                actual: self.targets.len(),
            });
        }
        let mut module = HMODULE::default();
        /* SAFETY: FROM_ADDRESS treats this function address as an address,
        not a string. Pinning keeps callbacks and MinHook storage loaded
        even if the host later calls FreeLibrary while callbacks run. */
        unsafe {
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                PCSTR(crate::RustySandInitialize as *const () as *const u8),
                &mut module,
            )
        }?;
        for target in &self.targets {
            /* SAFETY: Every target is a disabled MinHook entry whose immutable
            trampoline has been stored by its corresponding installer. */
            check("queue hook", unsafe {
                MH_QueueEnableHook(target.address as *mut c_void)
            })?;
        }
        self.activation_attempted = true;
        /* SAFETY: All 17 trampolines are published before MinHook suspends
        other threads and patches the queued targets. */
        check("enable hooks", unsafe { MH_ApplyQueued() })
    }

    pub fn count(&self) -> u32 {
        self.targets.len() as u32
    }

    pub fn disable(&mut self) -> bool {
        if !self.activation_attempted {
            return self.remove_unactivated();
        }
        let mut success = true;
        for target in &self.targets {
            /* SAFETY: The recorded target belongs to this MinHook instance.
            Disabled trampolines remain allocated for in-flight callbacks. */
            let status = unsafe { MH_DisableHook(target.address as *mut c_void) };
            if !matches!(status, MH_STATUS::MH_OK | MH_STATUS::MH_ERROR_DISABLED) {
                logging::error(
                    "disable hook",
                    &format_args!("{:?}: {status:?}", target.name),
                );
                success = false;
            }
        }
        success
    }

    fn remove_unactivated(&mut self) -> bool {
        self.targets.retain(|target| {
            /* SAFETY: No hook has ever been enabled, so no callback can hold
            a trampoline being removed. Failed removals remain recorded. */
            let status = unsafe { MH_RemoveHook(target.address as *mut c_void) };
            if status == MH_STATUS::MH_OK {
                return false;
            }
            logging::error(
                "remove unactivated hook",
                &format_args!("{:?}: {status:?}", target.name),
            );
            true
        });
        if !self.targets.is_empty() {
            return false;
        }
        if self.engine_initialized {
            /* SAFETY: This instance owns MinHook, all its disabled hooks were
            removed, and initialization cannot be retried in this process. */
            let status = unsafe { MH_Uninitialize() };
            if status != MH_STATUS::MH_OK {
                logging::error("release unactivated MinHook", &format_args!("{status:?}"));
                return false;
            }
            self.engine_initialized = false;
        }
        self.modules.retain(|(name, handle)| {
            /* SAFETY: This releases exactly the LoadLibraryExA reference held
            by the installation. No live trampoline refers to this module. */
            match unsafe { FreeLibrary(*handle) } {
                Ok(()) => false,
                Err(error) => {
                    logging::error(
                        "release unactivated module",
                        &format_args!("{name:?}: {error}"),
                    );
                    true
                }
            }
        });
        self.modules.is_empty()
    }
}

fn check(operation: &'static str, status: MH_STATUS) -> Result<(), InitializationError> {
    if status == MH_STATUS::MH_OK {
        Ok(())
    } else {
        Err(InitializationError::MinHook { operation, status })
    }
}
