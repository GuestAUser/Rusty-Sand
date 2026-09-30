use super::resource::{with_cleanup, OwnedHandle};
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::sync::Mutex;
use tokio::sync::oneshot;
use windows::Win32::Foundation::{BOOLEAN, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{
    RegisterWaitForSingleObject, UnregisterWaitEx, INFINITE, WT_EXECUTEONLYONCE,
};

struct Completion(Mutex<Option<oneshot::Sender<()>>>);

/** One OS notification; cancellation unregisters before freeing its context.

The callback never waits on application work. Synchronous unregistration waits
only for this bounded callback, not for the process or thread being observed.
Console input is not a supported RegisterWaitForSingleObject handle type.
*/
pub(crate) struct HandleWait {
    registration: HANDLE,
    completion: Option<Box<Completion>>,
    receiver: oneshot::Receiver<()>,
    object: OwnedHandle,
}

impl HandleWait {
    pub(crate) fn new(handle: HANDLE) -> Result<Self> {
        let object = OwnedHandle::duplicate(handle)?;
        let (sender, receiver) = oneshot::channel();
        let completion = Box::new(Completion(Mutex::new(Some(sender))));
        let mut registration = HANDLE::default();
        /* SAFETY: The boxed callback context has a stable address until checked
        unregistration completes. The duplicated object outlives registration.
        `notify` uses the system callback ABI and runs at most once. */
        unsafe {
            RegisterWaitForSingleObject(
                &mut registration,
                object.raw(),
                Some(notify),
                Some((&*completion as *const Completion).cast()),
                INFINITE,
                WT_EXECUTEONLYONCE,
            )
        }
        .context("register kernel-object completion")?;
        Ok(Self {
            registration,
            completion: Some(completion),
            receiver,
            object,
        })
    }

    pub(crate) async fn wait(&mut self) -> Result<()> {
        (&mut self.receiver)
            .await
            .context("kernel-object notification callback ended")
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if !self.registration.is_invalid() {
            /* SAFETY: This is not the registered callback thread. Passing the
            invalid-handle sentinel waits for callback completion before the
            Box or the observed handle may be released. */
            unsafe { UnregisterWaitEx(self.registration, INVALID_HANDLE_VALUE) }
                .context("unregister kernel-object completion")?;
            self.registration = HANDLE::default();
            self.completion = None;
        }
        self.object.close()
    }
}

impl Drop for HandleWait {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("Wait cleanup failed: {error:#}");
            /* Unregistration failure must not turn a late callback into a
            use-after-free. This exceptional leak is reported, not hidden. */
            if !self.registration.is_invalid() {
                if let Some(completion) = self.completion.take() {
                    Box::leak(completion);
                }
                let object =
                    std::mem::replace(&mut self.object, OwnedHandle::new(HANDLE::default()));
                /* A still-registered wait also retains its observed handle. */
                let _retained_handle = object.into_raw();
            }
        }
    }
}

unsafe extern "system" fn notify(context: *mut c_void, _timed_out: BOOLEAN) {
    /* SAFETY: RegisterWaitForSingleObject receives exactly this boxed type;
    HandleWait retains it until UnregisterWaitEx has joined the callback. */
    let completion = unsafe { &*context.cast::<Completion>() };
    match completion.0.lock() {
        Ok(mut sender) => {
            if let Some(sender) = sender.take() {
                /* A dropped receiver means cancellation, not a callback error. */
                if sender.send(()).is_err() {
                    log::debug!("Kernel-object notification receiver was cancelled");
                }
            }
        }
        Err(error) => log::error!("Kernel-object notification lock poisoned: {error}"),
    }
}

pub(crate) async fn wait_for_handle(handle: HANDLE) -> Result<()> {
    let mut wait = HandleWait::new(handle)?;
    let result = wait.wait().await;
    with_cleanup(result, wait.close())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox_wait.rs"]
mod tests;
