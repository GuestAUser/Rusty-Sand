use super::recording::Recording;
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{anyhow, bail, Context, Result};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use windows::core::HRESULT;
use windows::Win32::Foundation::{
    BOOL, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT, ERROR_TIMEOUT, HANDLE,
    NTSTATUS, STATUS_BREAKPOINT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    WaitForDebugEventEx, CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Threading::{IsWow64Process, ResumeThread, WaitForSingleObject};

const EVENT_WAIT_MS: u32 = 50;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_EXIT_CODE: u32 = 0xE042_0001;

struct PendingEvent {
    event: DEBUG_EVENT,
    continuation: NTSTATUS,
    initialization_breakpoint: bool,
}

pub(super) struct Session {
    process: ProcessHandle,
    attached: bool,
    initialization_pending: bool,
    pending: Option<PendingEvent>,
}

impl Session {
    pub(super) fn new(process: ProcessHandle) -> Self {
        Self {
            process,
            attached: false,
            initialization_pending: true,
            pending: None,
        }
    }

    pub(super) fn run(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
        recording: &mut Recording,
    ) -> Result<()> {
        if recording.observe_stop(deadline, cancel) {
            return Ok(());
        }

        let mut wow64 = BOOL::default();
        /* SAFETY: Creation returned an owned, still-suspended process handle. */
        unsafe { IsWow64Process(self.process.process_handle, &mut wow64) }
            .context("query debugger target architecture")?;

        if wow64.as_bool() {
            bail!("WOW64 debugger targets are unsupported and were not released");
        }

        /*
         * SAFETY: The PID belongs to the suspended process owned by this session.
         * No arbitrary PID enters this path. Attachment is made by the same OS
         * thread that receives and continues all of its debugger events.
         */
        unsafe { DebugActiveProcess(self.process.process_id) }
            .context("attach debugger to owned suspended process")?;
        self.attached = true;

        /* SAFETY: This dedicated thread owns only this debugger attachment. */
        unsafe { DebugSetProcessKillOnExit(true) }
            .context("enable fail-closed debugger thread exit")?;

        if !recording.observe_stop(deadline, cancel) {
            /*
             * Attachment can add suspension beyond CREATE_SUSPENDED. Release
             * exactly the one increment owned by creation, not every remaining
             * suspend count. Windows manages attachment/debug-event suspension;
             * any other explicit suspension must remain untouched.
             *
             * SAFETY: This session owns the original primary-thread handle.
             * Creation supplied one suspend increment, and this startup path
             * has not released it. Debugger setup and Job assignment succeeded.
             */
            let previous = unsafe { ResumeThread(self.process.thread_handle) };

            if previous == u32::MAX {
                return Err(windows::core::Error::from_win32())
                    .context("release debugger target's creation-owned suspension");
            }

            if previous == 0 {
                bail!("debugger target's creation-owned suspension was already absent");
            }

            /*
             * Mark only our creation hold as released. A previous count above
             * one is valid and does not mean the thread is now runnable.
             */
            self.process.is_suspended = false;
        }

        let mut stopping_deadline = None;

        while self.attached {
            if stopping_deadline.is_none() && recording.observe_stop(deadline, cancel) {
                self.process.terminate(STOP_EXIT_CODE)?;
                stopping_deadline = Some(Instant::now() + CLEANUP_TIMEOUT);
            }

            let wait_ms = if let Some(stop_deadline) = stopping_deadline {
                if Instant::now() >= stop_deadline {
                    bail!("owned debugger target did not exit after termination");
                }
                event_wait_ms(stop_deadline)
            } else {
                event_wait_ms(deadline)
            };

            if !self.wait_next(wait_ms)? {
                continue;
            }

            let pending = self
                .pending
                .as_ref()
                .context("debugger event queue has no received event")?;
            recording.record(
                &self.process,
                &pending.event,
                pending.initialization_breakpoint,
            );
            self.continue_pending()?;
        }

        Ok(())
    }

    fn wait_next(&mut self, wait_ms: u32) -> Result<bool> {
        let mut event = DEBUG_EVENT::default();

        /* SAFETY: Windows writes one initialized event into this local buffer. */
        match unsafe { WaitForDebugEventEx(&mut event, wait_ms) } {
            Ok(()) => {}
            Err(error)
                if error.code() == HRESULT::from_win32(ERROR_SEM_TIMEOUT.0)
                    || error.code() == HRESULT::from_win32(ERROR_TIMEOUT.0) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error).context("receive native debugger event"),
        }

        let mut initialization_breakpoint = false;
        let mut continuation = DBG_CONTINUE;

        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            /* SAFETY: The discriminator selects the exception union member. */
            let exception = unsafe { event.u.Exception };
            initialization_breakpoint = self.initialization_pending
                && exception.dwFirstChance != 0
                && exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT;

            if initialization_breakpoint {
                /*
                 * Windows supplies one initial attach breakpoint. The target was
                 * created suspended, so there was no preceding application run.
                 * All later breakpoints, and every other exception at either
                 * chance, are passed to Windows/application exception delivery.
                 */
                self.initialization_pending = false;
            } else {
                continuation = DBG_EXCEPTION_NOT_HANDLED;
            }
        }

        let pending = self.pending.insert(PendingEvent {
            event,
            continuation,
            initialization_breakpoint,
        });

        if pending.event.dwProcessId != self.process.process_id {
            bail!("debugger received an event outside its owned root process");
        }

        Ok(true)
    }

    fn continue_pending(&mut self) -> Result<()> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(());
        };

        /*
         * Recording has already queried any image path while hFile was live.
         * Cleanup also comes through here, closing files even for events that
         * are drained without recording. Automatic debug handles stay untouched.
         */
        close_debug_file(&mut pending.event)?;

        let exited = pending.event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
            && pending.event.dwProcessId == self.process.process_id;

        /*
         * SAFETY: The event was received by this same OS thread and has not yet
         * been continued. Windows owns the CREATE_PROCESS/CREATE_THREAD debug
         * handles and closes them when the corresponding exit is continued.
         * They are not the CreateProcessW handles owned by ProcessHandle.
         */
        unsafe {
            ContinueDebugEvent(
                pending.event.dwProcessId,
                pending.event.dwThreadId,
                pending.continuation,
            )
        }
        .context("continue native debugger event")?;

        self.pending = None;
        if exited {
            self.attached = false;
        }

        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        self.continue_pending()?;
        let deadline = Instant::now() + CLEANUP_TIMEOUT;

        while self.attached {
            if Instant::now() >= deadline {
                bail!("debugger cleanup did not receive the owned process exit");
            }

            if self.wait_next(event_wait_ms(deadline))? {
                self.continue_pending()?;
            }
        }

        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        /*
         * Always terminate the owned Job, including after a natural root exit,
         * so a root cannot leave descendants behind. Do not let an error skip
         * subsequent event release, detach, process wait, or handle close.
         */
        let mut result = self.process.terminate(STOP_EXIT_CODE);

        if self.attached {
            result = with_cleanup(result, self.drain());
        }

        if self.attached {
            /*
             * SAFETY: Only this owned attachment is detached, after termination
             * has been requested. This is the fallback for a broken event pump;
             * the Job and debugger-thread kill-on-exit remain fail-closed guards.
             */
            let detached = unsafe { DebugActiveProcessStop(self.process.process_id) }
                .context("detach owned debugger during failed cleanup");

            if detached.is_ok() {
                self.attached = false;
                self.pending = None;
            }
            result = with_cleanup(result, detached);
        }

        /* SAFETY: The original owned process handle remains live until finish. */
        let waited = match unsafe {
            WaitForSingleObject(
                self.process.process_handle,
                CLEANUP_TIMEOUT.as_millis() as u32,
            )
        } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(anyhow!("owned debugger process did not signal completion")),
            _ => Err(windows::core::Error::from_win32()).context("reap owned debugger process"),
        };

        with_cleanup(result, waited)
    }

    pub(super) fn finish(&mut self, result: Result<()>) -> Result<u32> {
        let result = with_cleanup(result, self.shutdown());
        let result = result.and_then(|()| {
            self.process
                .exit_code()?
                .context("reaped debugger process has no exit status")
        });

        with_cleanup(result, self.process.close())
    }
}

fn event_wait_ms(deadline: Instant) -> u32 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .clamp(1, u128::from(EVENT_WAIT_MS)) as u32
}

fn close_debug_file(event: &mut DEBUG_EVENT) -> Result<()> {
    /*
     * SAFETY: Each union member is selected by the Windows discriminator.
     * Debug file handles, unlike automatic process/thread debug handles, must
     * be closed by the debugger. Taking the field prevents a retry from closing
     * a reused handle if a later operation fails.
     */
    let file = unsafe {
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => std::mem::take(&mut event.u.CreateProcessInfo.hFile),
            LOAD_DLL_DEBUG_EVENT => std::mem::take(&mut event.u.LoadDll.hFile),
            _ => HANDLE::default(),
        }
    };

    OwnedHandle::new(file)
        .close()
        .context("close debugger image file handle")
}

#[cfg(test)]
#[path = "../../tests/unit/windows/debugger/native.rs"]
mod tests;
