use super::*;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{
    CreateThread, WaitForSingleObject, CREATE_SUSPENDED, THREAD_CREATION_FLAGS,
};

unsafe extern "system" fn finish_thread(_: *mut std::ffi::c_void) -> u32 {
    0
}

struct TestThread {
    handle: OwnedHandle,
    id: u32,
    initial_suspension: bool,
}

impl TestThread {
    fn new() -> Self {
        let mut id = 0;

        /* SAFETY: The callback has the required Windows ABI, retains no pointers,
        and cannot run until resumed. The returned handle is newly owned. The
        writable id storage is used synchronously by CreateThread. */
        let handle = unsafe {
            let raw = CreateThread(
                None,
                0,
                Some(finish_thread),
                None,
                THREAD_CREATION_FLAGS(CREATE_SUSPENDED.0),
                Some(&mut id),
            )
            .expect("create test thread");
            OwnedHandle::from_raw_handle(raw.0 as _)
        };

        Self {
            handle,
            id,
            initial_suspension: true,
        }
    }

    fn finish(&mut self) {
        let handle = HANDLE(self.handle.as_raw_handle() as isize);

        /* SAFETY: The thread handle remains owned for both synchronous calls.
        This releases the fixture's initial suspend increment and waits on the
        thread's exact completion signal, with a bounded timeout. */
        unsafe {
            let previous = ResumeThread(handle);
            self.initial_suspension = false;
            assert_eq!(previous, 1, "only the fixture's increment should remain");
            assert_eq!(WaitForSingleObject(handle, 5_000), WAIT_OBJECT_0);
        }
    }
}

impl Drop for TestThread {
    fn drop(&mut self) {
        if self.initial_suspension {
            /* SAFETY: The fixture still owns the live handle and its original
            suspend increment. Other suspension owners are dropped first. */
            if unsafe { ResumeThread(HANDLE(self.handle.as_raw_handle() as isize)) } == u32::MAX {
                log::error!(
                    "Cannot release test thread: {}",
                    windows::core::Error::from_win32()
                );
            }
        }
    }
}

#[test]
fn resumes_exactly_owned_increments_and_is_idempotent() {
    let mut thread = TestThread::new();
    let mut suspender = ThreadSuspender::new();
    suspender.suspend_thread(thread.id).unwrap();
    suspender.suspend_thread(thread.id).unwrap();
    assert_eq!(suspender.thread_count(), 2);
    suspender.resume_all().unwrap();
    assert_eq!(suspender.thread_count(), 0);
    suspender.resume_all().unwrap();
    thread.finish();
}

#[test]
fn drop_releases_owned_suspension() {
    let mut thread = TestThread::new();

    {
        let mut suspender = ThreadSuspender::new();
        suspender.suspend_thread(thread.id).unwrap();
    }

    thread.finish();
}

#[test]
fn failed_open_does_not_record_suspension() {
    let mut suspender = ThreadSuspender::new();
    assert!(suspender.suspend_thread(0).is_err());
    assert_eq!(suspender.thread_count(), 0);
    suspender.resume_all().unwrap();
}
