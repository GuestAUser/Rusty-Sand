//! Native debugger events for one newly created, owned Windows process.
//!
//! Creation and Job assignment remain suspended until debugger setup succeeds.
//! Debugging runs on a fresh, dedicated OS thread, not on the caller's thread.
//! The synchronous entry point can therefore be called from `spawn_blocking`.
//!
//! This mode does not inject hooks or start the monitoring engine. Configuration
//! supplies creation settings, Job memory/CPU limits, and the execution timeout;
//! network, registry, filesystem, and behavioral policies are not enforced here.
//! Debugging changes observable process behavior and is not an isolation boundary.
//!
//! Reports describe debugger events, not every executed instruction. Only bounded
//! diagnostic reads are made, and application exceptions are delivered normally
//! except for the single initialization breakpoint supplied by Windows attach.

#[cfg(target_arch = "x86_64")]
mod diagnostic;
#[cfg(target_arch = "x86_64")]
mod native;
#[cfg(target_arch = "x86_64")]
mod recording;
#[cfg(target_arch = "x86_64")]
mod session;

use crate::config::SandboxConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

pub const MAX_EVENTS: usize = 2_048;
pub const MAX_DEBUG_STRING_BYTES: usize = 2_048;
pub const MAX_INSTRUCTION_BYTES: usize = 32;
/// Maximum image-path query buffer size in UTF-16 units, including its terminator.
pub const MAX_IMAGE_PATH_UNITS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugReport {
    pub executable: String,
    pub target_pid: u32,
    pub exit: ExitOutcome,
    pub timed_out: bool,
    pub cancelled: bool,
    pub events: Vec<DebugEvent>,
    pub counters: DebugCounters,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitOutcome {
    Exited { code: u32 },
    UnhandledException { code: u32, exception_code: u32 },
    Terminated { code: u32 },
}

/**
Payload counters concern retained events. Once the event limit is reached,
events are counted as dropped without performing additional diagnostic reads.
Shutdown and exception delivery continue regardless of report capacity.
*/
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugCounters {
    pub dropped_events: u64,
    pub truncated_debug_strings: u64,
    pub truncated_exception_parameters: u64,
    pub unavailable_contexts: u64,
    pub incomplete_memory_reads: u64,
    pub unavailable_image_paths: u64,
    pub truncated_image_paths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEvent {
    pub sequence: u64,
    pub elapsed_micros: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub event: DebugEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugEventKind {
    ProcessCreated {
        image_base: u64,
        start_address: Option<u64>,
        image_path: ImagePath,
    },
    ProcessExited {
        code: u32,
    },
    ThreadCreated {
        start_address: Option<u64>,
    },
    ThreadExited {
        code: u32,
    },
    ModuleLoaded {
        base_address: u64,
        image_path: ImagePath,
    },
    ModuleUnloaded {
        base_address: u64,
    },
    DebugString {
        data: DebugString,
    },
    Exception {
        details: Box<ExceptionDetails>,
    },
    Rip {
        error: u32,
        #[serde(rename = "rip_type")]
        kind: u32,
    },
    Unknown {
        code: u32,
    },
}

/**
Best-effort path evidence from a debug event's image file handle.

The opened DOS-volume path is queried before closing that handle. It is not a
verified file identity or a reconstructed image. No remote image-name pointers
are followed. Oversized results retain the required buffer size, not an
unspecified partial buffer returned by Windows.
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImagePath {
    Available { path: String, lossy: bool },
    MissingHandle,
    Unavailable { win32_error: Option<u32> },
    Truncated { required_buffer_units: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugString {
    pub unicode: bool,
    /// Raw nDebugStringLength: the low 16 bits of a byte count, not UTF-16 units.
    pub declared_units: u16,
    /// Decoded text before the first terminator; raw bytes remain in memory.
    pub text: String,
    /// The declared payload was clipped, incompletely read, or lacked a terminator.
    pub truncated: bool,
    pub memory: MemoryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionDetails {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub first_chance: bool,
    pub initialization_breakpoint: bool,
    pub declared_parameter_count: u32,
    pub parameters: Vec<u64>,
    pub context: Option<Amd64Registers>,
    pub context_error: Option<String>,
    pub instruction_bytes: MemoryEvidence,
}

/**
Only control and integer registers are requested. Floating-point, vector,
debug-register, stack, and extended processor state are not collected.
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amd64Registers {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub eflags: u32,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEvidence {
    pub address: u64,
    pub requested_bytes: u32,
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

/**
Launch and debug a new owned target. There is deliberately no attach-by-PID API.

Successful return means the owned root process was reaped and owned handles
were closed. Operational and cleanup failures are returned together as errors.
The existing Job also owns descendant termination, but descendants are not
debugged or represented in this report.
*/
pub fn debug_executable(
    executable: &str,
    args: &[String],
    config: &SandboxConfig,
    cancel: &AtomicBool,
) -> Result<DebugReport> {
    config.validate()?;

    #[cfg(target_arch = "x86_64")]
    {
        native::execute(executable, args, config, cancel)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (executable, args, cancel);
        anyhow::bail!("native debugger analysis currently requires an x86_64 debugger build")
    }
}
