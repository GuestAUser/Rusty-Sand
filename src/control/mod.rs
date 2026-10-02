pub mod interactive;
pub mod suspension;

pub use interactive::{InteractiveController, UserDecision};

use anyhow::{bail, Context, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use suspension::ThreadSuspender;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

pub struct ProcessController {
    target_pid: u32,
    threads: ThreadSuspender,
    snapshot_suspended: bool,
}

impl ProcessController {
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            threads: ThreadSuspender::new(),
            snapshot_suspended: false,
        }
    }

    /**
    Suspends threads captured in one snapshot, retaining their handles.

    This is not an atomic process freeze: threads can exit or be created during
    enumeration. It cannot prevent or undo the event that triggered a prompt.
    */
    pub fn suspend_process(&mut self) -> Result<()> {
        if self.snapshot_suspended {
            return Ok(());
        }

        if self.threads.thread_count() != 0 {
            bail!("Unresolved suspension remains; retry resume_process first");
        }

        /* SAFETY: This query takes no pointers and transfers no ownership. */
        if self.target_pid == unsafe { GetCurrentProcessId() } {
            bail!("Cannot suspend the monitoring process itself");
        }

        if let Err(error) = self.suspend_snapshot() {
            return match self.threads.resume_all() {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!(
                    "Suspension rollback failed; retained handles for retry: {rollback:#}"
                ))),
            };
        }

        self.snapshot_suspended = true;
        Ok(())
    }

    fn suspend_snapshot(&mut self) -> Result<()> {
        /* SAFETY: A successful snapshot is a newly owned CloseHandle-compatible
        handle. Ownership transfers immediately to OwnedHandle on all paths. */
        let snapshot = unsafe {
            let handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
            OwnedHandle::from_raw_handle(handle.0 as _)
        };
        let handle = HANDLE(snapshot.as_raw_handle() as isize);
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        /* SAFETY: The snapshot remains owned throughout enumeration. entry is
        initialized writable storage that these synchronous calls do not retain. */
        unsafe {
            Thread32First(handle, &mut entry).context("Cannot enumerate target threads")?;

            loop {
                if entry.th32OwnerProcessID == self.target_pid {
                    self.threads
                        .suspend_thread_in_process(entry.th32ThreadID, self.target_pid)?;
                }

                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

                match Thread32Next(handle, &mut entry) {
                    Ok(()) => {}
                    Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
                    Err(error) => return Err(error).context("Thread enumeration failed"),
                }
            }
        }

        if self.threads.thread_count() == 0 {
            bail!("No threads found for process {}", self.target_pid);
        }

        Ok(())
    }

    /** Releases only this controller's suspend increments on the retained threads. */
    pub fn resume_process(&mut self) -> Result<()> {
        self.snapshot_suspended = false;
        self.threads.resume_all()
    }

    /** Reports retained suspension ownership, not an atomic process-wide state. */
    pub fn is_suspended(&self) -> bool {
        self.threads.thread_count() != 0
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/control.rs"]
mod tests;
