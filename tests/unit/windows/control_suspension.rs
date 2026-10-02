use super::*;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{
    CreateProcessW, CreateThread, GetCurrentProcessId, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW, THREAD_CREATION_FLAGS,
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

struct TestProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
    thread_id: u32,
}

impl TestProcess {
    fn new() -> Self {
        let executable = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").expect("Windows directory is available"),
        )
        .join("System32")
        .join("cmd.exe");
        let application: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut command: Vec<u16> = "cmd.exe /D /C exit 0\0".encode_utf16().collect();
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();

        /* SAFETY: Both strings are NUL-terminated and command is writable.
        All storage remains live for this synchronous call. No handles are
        inherited. Successful process and thread handles transfer immediately
        into OwnedHandle; the primary thread starts suspended. */
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &startup,
                &mut information,
            )
            .expect("create suspended test process");

            Self {
                process: OwnedHandle::from_raw_handle(information.hProcess.0 as _),
                thread: OwnedHandle::from_raw_handle(information.hThread.0 as _),
                process_id: information.dwProcessId,
                thread_id: information.dwThreadId,
            }
        }
    }

    fn assert_suspend_count(&self, expected: u32) {
        let handle = HANDLE(self.thread.as_raw_handle() as isize);

        /* SAFETY: The fixture retains the thread handle. This single probe
        adds one increment and releases exactly that increment before checking
        the count, leaving the fixture's initial suspension intact. */
        unsafe {
            let previous = SuspendThread(handle);
            assert_ne!(previous, u32::MAX, "probe must suspend the owned thread");

            let resumed = ResumeThread(handle);
            assert_eq!(resumed, previous + 1, "probe must release its increment");
            assert_eq!(previous, expected, "unexpected suspend count");
        }
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        let handle = HANDLE(self.process.as_raw_handle() as isize);

        /* SAFETY: This fixture owns the process handle and terminates only its
        child, including on assertion failure. The retained process handle is
        a persistent completion signal; the bounded wait cannot miss exit. */
        unsafe {
            if let Err(error) = TerminateProcess(handle, 0) {
                log::error!("Cannot terminate suspended test process: {error}");
                return;
            }

            let status = WaitForSingleObject(handle, 5_000);

            if status != WAIT_OBJECT_0 {
                log::error!("Cannot confirm test process termination: {status:?}");
            }
        }
    }
}

#[test]
fn mismatched_owner_does_not_add_a_suspend_increment() {
    let process = TestProcess::new();
    let mut suspender = ThreadSuspender::new();

    /* SAFETY: This query has no pointer parameters or ownership transfer. */
    let other_process_id = unsafe { GetCurrentProcessId() };
    assert_ne!(process.process_id, other_process_id);

    assert!(suspender
        .suspend_thread_in_process(process.thread_id, other_process_id)
        .is_err());
    assert_eq!(suspender.thread_count(), 0);
    process.assert_suspend_count(1);

    suspender.resume_all().unwrap();
    process.assert_suspend_count(1);
}

#[test]
fn matching_owner_releases_only_its_suspend_increment() {
    let process = TestProcess::new();
    let mut suspender = ThreadSuspender::new();

    suspender
        .suspend_thread_in_process(process.thread_id, process.process_id)
        .unwrap();
    assert_eq!(suspender.thread_count(), 1);
    process.assert_suspend_count(2);

    suspender.resume_all().unwrap();
    assert_eq!(suspender.thread_count(), 0);
    process.assert_suspend_count(1);

    suspender.resume_all().unwrap();
    process.assert_suspend_count(1);
}

#[test]
fn both_suspend_paths_refuse_the_calling_thread() {
    let mut suspender = ThreadSuspender::new();

    /* SAFETY: These queries have no pointer parameters or ownership transfer. */
    let (thread_id, process_id) = unsafe { (GetCurrentThreadId(), GetCurrentProcessId()) };

    assert!(suspender.suspend_thread(thread_id).is_err());
    assert!(suspender
        .suspend_thread_in_process(thread_id, process_id)
        .is_err());
    assert_eq!(suspender.thread_count(), 0);
}
