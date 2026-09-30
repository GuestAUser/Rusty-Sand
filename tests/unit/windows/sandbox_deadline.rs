use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn expired_deadline_does_not_start_work() -> Result<()> {
    let invoked = AtomicBool::new(false);
    let deadline = Deadline::after(Duration::ZERO)?;
    let error = deadline
        .run(async {
            invoked.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(error.is::<DeadlineExceeded>());
    assert!(!invoked.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn deadline_cancels_pending_work_and_drops_its_resources() -> Result<()> {
    struct Guard<'a>(&'a AtomicBool);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = AtomicBool::new(false);
    /* Time is the behavior under test. There is no readiness delay: the
    resource is owned by the bounded future before it is first polled. */
    let guard = Guard(&dropped);
    let error = Deadline::after(Duration::from_millis(1))?
        .run(async move {
            let _guard = guard;
            std::future::pending::<Result<()>>().await
        })
        .await
        .unwrap_err();
    assert!(error.is::<DeadlineExceeded>());
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}
