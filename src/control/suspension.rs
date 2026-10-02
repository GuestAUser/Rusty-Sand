use anyhow::{bail, Context, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    GetCurrentThreadId, GetProcessIdOfThread, OpenThread, ResumeThread, SuspendThread,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
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
        self.suspend_thread_with_owner(thread_id, None)
    }

    pub(crate) fn suspend_thread_in_process(
        &mut self,
        thread_id: u32,
        process_id: u32,
    ) -> Result<()> {
        self.suspend_thread_with_owner(thread_id, Some(process_id))
    }

    fn suspend_thread_with_owner(
        &mut self,
        thread_id: u32,
        expected_process_id: Option<u32>,
    ) -> Result<()> {
        /* SAFETY: This query has no pointer parameters or ownership transfer. */
        if thread_id == unsafe { GetCurrentThreadId() } {
            bail!("Cannot suspend the calling thread");
        }

        let mut access = THREAD_SUSPEND_RESUME;

        if expected_process_id.is_some() {
            access |= THREAD_QUERY_LIMITED_INFORMATION;
        }

        /* SAFETY: OpenThread returns a newly owned kernel handle. OwnedHandle
        closes it on every path. The owner query and SuspendThread borrow the
        same retained handle, so TID reuse cannot change the checked identity. */
        let handle = unsafe {
            let raw = OpenThread(access, false, thread_id)
                .with_context(|| format!("Cannot open thread {thread_id}"))?;
            let owned = OwnedHandle::from_raw_handle(raw.0 as _);

            if let Some(expected_process_id) = expected_process_id {
                let process_id = GetProcessIdOfThread(raw);

                if process_id == 0 {
                    return Err(windows::core::Error::from_win32())
                        .with_context(|| format!("Cannot query owner of thread {thread_id}"));
                }

                if process_id != expected_process_id {
                    bail!(
                        "Thread {thread_id} belongs to process {process_id}, not {expected_process_id}"
                    );
                }
            }

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
