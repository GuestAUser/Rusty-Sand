use anyhow::{bail, Context, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

struct SuspendedThread {
    id: u32,
    handle: OwnedHandle,
}

/** Owns one suspend-count increment and one handle per successfully suspended thread. */
#[derive(Default)]
pub struct ThreadSuspender {
    threads: Vec<SuspendedThread>,
}

impl ThreadSuspender {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn suspend_thread(&mut self, thread_id: u32) -> Result<()> {
        /* SAFETY: This query has no pointer parameters or ownership transfer. */
        if thread_id == unsafe { GetCurrentThreadId() } {
            bail!("Cannot suspend the calling thread");
        }

        /* SAFETY: OpenThread returns a newly owned kernel handle. OwnedHandle
        closes it on every path. SuspendThread borrows it only for the call. */
        let handle = unsafe {
            let raw = OpenThread(THREAD_SUSPEND_RESUME, false, thread_id)
                .with_context(|| format!("Cannot open thread {thread_id}"))?;
            let owned = OwnedHandle::from_raw_handle(raw.0 as _);

            if SuspendThread(raw) == u32::MAX {
                return Err(windows::core::Error::from_win32())
                    .with_context(|| format!("Cannot suspend thread {thread_id}"));
            }

            owned
        };

        self.threads.push(SuspendedThread {
            id: thread_id,
            handle,
        });
        Ok(())
    }

    /** Attempts every release, retaining failed handles so callers can retry. */
    pub fn resume_all(&mut self) -> Result<()> {
        let mut failures = Vec::new();

        self.threads.retain(|thread| {
            let handle = HANDLE(thread.handle.as_raw_handle() as isize);

            /* SAFETY: The owned thread handle stays live through ResumeThread.
            Exactly one increment belongs to this entry; other owners' increments
            must not be released by repeated successful calls. */
            if unsafe { ResumeThread(handle) } == u32::MAX {
                let error = windows::core::Error::from_win32();
                failures.push(format!("thread {}: {error}", thread.id));
                true
            } else {
                false
            }
        });

        if !failures.is_empty() {
            bail!("Cannot resume {}", failures.join("; "));
        }

        Ok(())
    }

    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }
}

impl Drop for ThreadSuspender {
    fn drop(&mut self) {
        if let Err(error) = self.resume_all() {
            log::error!("Failed to release thread suspension during cleanup: {error:#}");
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/control_suspension.rs"]
mod tests;
