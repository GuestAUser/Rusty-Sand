use super::*;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn busy_lifecycle_calls_neither_wait_nor_claim_state() {
    let lifecycle = INSTALLATION.lock();
    let state_before = STATE.load(Ordering::Acquire);
    let (completed, completion) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        completed
            .send((initialize(), shutdown()))
            .expect("completion receiver");
    });
    let result = completion.recv_timeout(Duration::from_secs(5));
    let state_after = STATE.load(Ordering::Acquire);
    drop(lifecycle);
    caller.join().expect("lifecycle caller completed");
    assert_eq!(
        result.expect("busy calls returned before releasing the lock"),
        (false, false)
    );
    assert_eq!(state_after, state_before);
}
