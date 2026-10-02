use super::diagnostic::{debug_string, exception_details, image_path};
use super::{DebugCounters, DebugEvent, DebugEventKind, DebugReport, ExitOutcome, MAX_EVENTS};
use crate::sandbox::process::ProcessHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use windows::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
};

pub(super) struct Recording {
    started: Instant,
    sequence: u64,
    events: Vec<DebugEvent>,
    counters: DebugCounters,
    timed_out: bool,
    cancelled: bool,
    second_chance: Option<u32>,
}

impl Recording {
    pub(super) fn new(started: Instant) -> Self {
        Self {
            started,
            sequence: 0,
            events: Vec::new(),
            counters: DebugCounters::default(),
            timed_out: false,
            cancelled: false,
            second_chance: None,
        }
    }

    pub(super) fn observe_stop(&mut self, deadline: Instant, cancel: &AtomicBool) -> bool {
        self.cancelled |= cancel.load(Ordering::Acquire);
        self.timed_out |= Instant::now() >= deadline;

        self.cancelled || self.timed_out
    }

    pub(super) fn record(
        &mut self,
        process: &ProcessHandle,
        event: &DEBUG_EVENT,
        initialization_breakpoint: bool,
    ) {
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);

        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            /* SAFETY: The event discriminator selects this union member. */
            let exception = unsafe { event.u.Exception };

            if exception.dwFirstChance == 0 {
                self.second_chance = Some(exception.ExceptionRecord.ExceptionCode.0 as u32);
            }
        }

        if self.events.len() == MAX_EVENTS {
            self.counters.dropped_events = self.counters.dropped_events.saturating_add(1);
            return;
        }

        /*
         * SAFETY: Only the member selected by dwDebugEventCode is read. Remote
         * pointers become numeric evidence; they are never dereferenced locally.
         * Session retains image file handles until this recording is complete.
         */
        let kind = unsafe {
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let created = event.u.CreateProcessInfo;

                    DebugEventKind::ProcessCreated {
                        image_base: created.lpBaseOfImage as usize as u64,
                        start_address: created
                            .lpStartAddress
                            .map(|address| address as usize as u64),
                        image_path: image_path(created.hFile, &mut self.counters),
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => DebugEventKind::ProcessExited {
                    code: event.u.ExitProcess.dwExitCode,
                },
                CREATE_THREAD_DEBUG_EVENT => DebugEventKind::ThreadCreated {
                    start_address: event
                        .u
                        .CreateThread
                        .lpStartAddress
                        .map(|address| address as usize as u64),
                },
                EXIT_THREAD_DEBUG_EVENT => DebugEventKind::ThreadExited {
                    code: event.u.ExitThread.dwExitCode,
                },
                LOAD_DLL_DEBUG_EVENT => {
                    let loaded = event.u.LoadDll;

                    DebugEventKind::ModuleLoaded {
                        base_address: loaded.lpBaseOfDll as usize as u64,
                        image_path: image_path(loaded.hFile, &mut self.counters),
                    }
                }
                UNLOAD_DLL_DEBUG_EVENT => DebugEventKind::ModuleUnloaded {
                    base_address: event.u.UnloadDll.lpBaseOfDll as usize as u64,
                },
                OUTPUT_DEBUG_STRING_EVENT => DebugEventKind::DebugString {
                    data: debug_string(process, event.u.DebugString, &mut self.counters),
                },
                EXCEPTION_DEBUG_EVENT => DebugEventKind::Exception {
                    details: Box::new(exception_details(
                        process,
                        event.dwThreadId,
                        event.u.Exception,
                        initialization_breakpoint,
                        &mut self.counters,
                    )),
                },
                RIP_EVENT => DebugEventKind::Rip {
                    error: event.u.RipInfo.dwError,
                    kind: event.u.RipInfo.dwType.0,
                },
                other => DebugEventKind::Unknown { code: other.0 },
            }
        };

        self.events.push(DebugEvent {
            sequence,
            elapsed_micros: self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
            event: kind,
        });
    }

    pub(super) fn into_report(self, executable: String, target_pid: u32, code: u32) -> DebugReport {
        let exit = if self.timed_out || self.cancelled {
            ExitOutcome::Terminated { code }
        } else if let Some(exception_code) = self.second_chance {
            ExitOutcome::UnhandledException {
                code,
                exception_code,
            }
        } else {
            ExitOutcome::Exited { code }
        };

        DebugReport {
            executable,
            target_pid,
            exit,
            timed_out: self.timed_out,
            cancelled: self.cancelled,
            events: self.events,
            counters: self.counters,
            limitations: vec![
                "Debugger events are not a complete instruction or behavior trace.".into(),
                "This backend requires x86_64; WOW64 targets are rejected before release.".into(),
                "No hooks are injected. Network, registry, filesystem and behavioral policies are not enforced by debug mode.".into(),
                "Only the owned root is debugged. Its existing Job owns descendant cleanup and configured resource limits.".into(),
                "Image paths are bounded, best-effort opened DOS-volume paths from debug file handles, not verified identities. Missing handles, query failures and oversized paths are explicit; no symbols or image reconstruction are provided.".into(),
                "Evidence is bounded; inaccessible context and memory are reported explicitly. ANSI text is rendered lossily as UTF-8; raw bytes are retained.".into(),
                "Cancellation is checked between debugger events and at most 50 ms event waits; blocking OS calls and cleanup can extend wall time.".into(),
                "An exit code alone does not identify whether a Job memory or CPU limit caused termination.".into(),
            ],
        }
    }
}
