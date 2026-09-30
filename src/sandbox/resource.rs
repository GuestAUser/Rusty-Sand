pub(crate) use super::cleanup::with_cleanup;
use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::Threading::GetCurrentProcess;

/** An owned kernel handle with a checked close path and a diagnostic fallback. */
pub(crate) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /** The caller transfers a newly created, non-pseudo kernel handle. */
    pub(crate) fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }

    pub(crate) fn duplicate(handle: HANDLE) -> Result<Self> {
        let mut duplicate = HANDLE::default();
        /* SAFETY: DuplicateHandle validates the borrowed source handle. The
        output lives through the call and is immediately given one owner. */
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .context("duplicate kernel handle")?;
        Ok(Self(duplicate))
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        close_handle(&mut self.0)
    }

    pub(crate) fn into_raw(mut self) -> HANDLE {
        std::mem::take(&mut self.0)
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("Kernel handle cleanup failed: {error:#}");
        }
    }
}

pub(crate) fn close_handle(handle: &mut HANDLE) -> Result<()> {
    if !handle.is_invalid() {
        /* SAFETY: The owner invalidates the stored value only after Windows
        confirms closure. No other owner closes this handle. */
        unsafe { CloseHandle(*handle) }.context("close kernel handle")?;
        *handle = HANDLE::default();
    }
    Ok(())
}
