use super::fixture::{process_completion, Fixture, UI_LOCK};
use crate::live::RunState;
use crate::sandbox::resource::OwnedHandle;
use anyhow::{bail, Context, Result};
use std::time::Duration;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

struct ExternalIncrement {
    thread: OwnedHandle,
    retained: bool,
}

impl ExternalIncrement {
    fn new(pid: u32) -> Result<Self> {
        /* SAFETY: The snapshot is newly owned. Enumeration storage remains
        initialized for each synchronous native call. */
        let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)? });
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe { Thread32First(snapshot.raw(), &mut entry) }?;

        loop {
            if entry.th32OwnerProcessID == pid {
                /* SAFETY: Only a thread of the test-owned fixture is opened.
                Its handle and exactly one suspend increment are retained. */
                let thread = OwnedHandle::new(unsafe {
                    OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)?
                });
                let previous = unsafe { SuspendThread(thread.raw()) };

                if previous == u32::MAX {
                    return Err(windows::core::Error::from_win32())
                        .context("retain external test suspension");
                }

                let increment = Self {
                    thread,
                    retained: true,
                };
                assert_eq!(previous, 0);
                return Ok(increment);
            }

            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            unsafe { Thread32Next(snapshot.raw(), &mut entry) }?;
        }
    }

    fn count(&self) -> Result<u32> {
        /* SAFETY: Add and immediately remove one query increment on the
        retained thread handle, preserving both real suspension owners. */
        let previous = unsafe { SuspendThread(self.thread.raw()) };

        if previous == u32::MAX {
            return Err(windows::core::Error::from_win32()).context("query suspension count");
        }

        let restored = unsafe { ResumeThread(self.thread.raw()) };

        if restored == u32::MAX {
            return Err(windows::core::Error::from_win32()).context("restore query increment");
        }

        assert_eq!(restored, previous + 1);
        Ok(previous)
    }

    fn release(&mut self) -> Result<u32> {
        if !self.retained {
            bail!("test increment was already released");
        }

        /* SAFETY: Exactly one increment belongs to this test guard. */
        let previous = unsafe { ResumeThread(self.thread.raw()) };

        if previous == u32::MAX {
            return Err(windows::core::Error::from_win32())
                .context("release external test suspension");
        }

        self.retained = false;
        Ok(previous)
    }
}

impl Drop for ExternalIncrement {
    fn drop(&mut self) {
        if self.retained {
            if let Err(error) = self.release() {
                log::error!("External test suspension cleanup failed: {error:#}");
            }
        }
    }
}

#[tokio::test]
async fn shell_pause_resume_preserves_other_owners_and_stop_handles_a_pause() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    let pid = session.run().await?;
    fixture.running(&session).await?;

    let mut external = ExternalIncrement::new(pid)?;
    session.pause().await?;
    session.pause().await?;

    assert_eq!(session.state(), RunState::SnapshotPaused);
    assert_eq!(external.count()?, 2);

    session.resume().await?;
    session.resume().await?;

    assert_eq!(session.state(), RunState::Running);
    assert_eq!(external.release()?, 1);

    session.pause().await?;
    let mut completion = process_completion(&session)?;
    tokio::time::timeout(Duration::from_secs(10), session.stop()).await??;
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    completion.close()?;

    assert!(!session.has_active_run());
    assert!(session.completed_report().is_some());
    Ok(())
}
