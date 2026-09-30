use super::*;

#[test]
fn helper_recursion_does_not_leak_into_the_original_call() {
    let helper = HelperGuard::enter().expect("outer helper");
    assert!(matches!(HelperGuard::enter(), Err(EntryError::Reentrant)));
    assert!(matches!(HelperGuard::enter(), Err(EntryError::Reentrant)));
    drop(helper);
    let original_callback = HelperGuard::enter();
    assert!(original_callback.is_ok());
}

#[test]
fn bypass_is_thread_local() {
    let _helper = HelperGuard::enter().expect("outer helper");
    let (completed, completion) = std::sync::mpsc::channel();
    let child = std::thread::spawn(move || {
        let _helper = HelperGuard::enter().expect("independent thread");
        assert!(matches!(HelperGuard::enter(), Err(EntryError::Reentrant)));
        completed.send(()).expect("completion receiver");
    });
    completion
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("thread-local check completed");
    child.join().expect("child completed");
    assert!(matches!(HelperGuard::enter(), Err(EntryError::Reentrant)));
}
