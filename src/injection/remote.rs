use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use crate::sandbox::wait::wait_for_handle;
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, TerminateProcess, WaitForSingleObject,
};

/** Owns remote allocations until no remote thread can access them.

Cancellation kills the target instead of freeing memory underneath a running
loader or initializer. Windows reclaims those allocations at process exit.
*/
pub(super) struct RemoteExecution {
    process: OwnedHandle,
    allocations: Vec<usize>,
    thread: Option<OwnedHandle>,
}

impl RemoteExecution {
    pub(super) fn new(process: HANDLE) -> Result<Self> {
        Ok(Self {
            process: OwnedHandle::duplicate(process)?,
            allocations: Vec::new(),
            thread: None,
        })
    }

    pub(super) fn process(&self) -> HANDLE {
        self.process.raw()
    }

    pub(super) fn allocate(&mut self, size: usize) -> Result<usize> {
        /* SAFETY: Windows reserves storage in the owned target process; no local
        reference is created to that remote address. */
        let address = unsafe {
            VirtualAllocEx(
                self.process(),
                None,
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if address.is_null() {
            return Err(windows::core::Error::from_win32())
                .context("allocate remote initialization memory");
        }
        self.allocations.push(address as usize);
        Ok(address as usize)
    }

    pub(super) fn write(&self, address: usize, bytes: &[u8]) -> Result<()> {
        let mut written = 0;
        /* SAFETY: Windows validates the remote range. The source slice remains
        readable until the synchronous copy returns; no pointer is retained. */
        unsafe {
            WriteProcessMemory(
                self.process(),
                address as *mut c_void,
                bytes.as_ptr().cast(),
                bytes.len(),
                Some(&mut written),
            )
        }
        .context("write remote initialization memory")?;
        if written != bytes.len() {
            bail!("partial remote write: {written} of {} bytes", bytes.len());
        }
        Ok(())
    }

    pub(super) fn read_pointer(&self, address: usize) -> Result<usize> {
        let mut bytes = [0u8; 8];
        let mut read = 0;
        /* SAFETY: Native AMD64 was checked before allocation. The full pointer
        is copied into an eight-byte local buffer, never a DWORD exit code. */
        unsafe {
            ReadProcessMemory(
                self.process(),
                address as *const c_void,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                Some(&mut read),
            )
        }
        .context("read remote module handle")?;
        if read != bytes.len() {
            bail!("partial remote module-handle read");
        }
        usize::try_from(u64::from_le_bytes(bytes))
            .context("remote module handle exceeds host pointer width")
    }

    pub(super) fn make_executable(&self, address: usize, size: usize) -> Result<()> {
        let mut previous = PAGE_PROTECTION_FLAGS::default();
        /* SAFETY: This range is an owned remote allocation. It becomes RX only
        after writing; instruction-cache coherency precedes thread creation. */
        unsafe {
            VirtualProtectEx(
                self.process(),
                address as *const c_void,
                size,
                PAGE_EXECUTE_READ,
                &mut previous,
            )?;
            FlushInstructionCache(self.process(), Some(address as *const c_void), size)?;
        }
        Ok(())
    }

    pub(super) async fn call(&mut self, address: usize, argument: usize) -> Result<u32> {
        /* SAFETY: Callers provide either our AMD64 thread-entry thunk or the
        checked RustySandInitialize export, both with LPTHREAD_START_ROUTINE
        ABI. Remote allocations remain owned through thread completion. */
        let thread = unsafe {
            CreateRemoteThread(
                self.process(),
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(address)),
                Some(argument as *const c_void),
                0,
                None,
            )
        }
        .context("start remote initialization thread")?;
        self.thread = Some(OwnedHandle::new(thread));
        wait_for_handle(thread).await?;
        let mut status = 0;
        /* SAFETY: The registered wait completed and self still owns the thread. */
        unsafe { GetExitCodeThread(thread, &mut status) }
            .context("read remote initializer status")?;
        if let Some(mut thread) = self.thread.take() {
            thread.close()?;
        }
        Ok(status)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let mut result = Ok(());
        let mut may_free = true;
        if let Some(thread) = &self.thread {
            /* SAFETY: A zero-time wait only inspects the still-owned thread. */
            let status = unsafe { WaitForSingleObject(thread.raw(), 0) };
            may_free = status == WAIT_OBJECT_0;
            if !may_free {
                if status != WAIT_TIMEOUT {
                    result = Err(windows::core::Error::from_win32())
                        .context("inspect remote thread during cleanup");
                }
                /* SAFETY: This process belongs to the suspended/monitored
                execution. Killing it cancels all remote initialization work. */
                let terminated = unsafe { TerminateProcess(self.process(), 1) }
                    .context("cancel remote initialization");
                result = with_cleanup(result, terminated);
            }
        }
        if may_free {
            for address in self.allocations.drain(..) {
                /* SAFETY: Each base came from VirtualAllocEx and no remote
                thread can still use it. MEM_RELEASE requires a zero size. */
                let freed = unsafe {
                    VirtualFreeEx(self.process.raw(), address as *mut c_void, 0, MEM_RELEASE)
                }
                .context("release remote initialization allocation");
                result = with_cleanup(result, freed);
            }
        } else {
            self.allocations.clear();
        }
        if let Some(mut thread) = self.thread.take() {
            result = with_cleanup(result, thread.close());
        }
        with_cleanup(result, self.process.close())
    }
}

impl Drop for RemoteExecution {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("Remote initialization cleanup failed: {error:#}");
        }
    }
}
