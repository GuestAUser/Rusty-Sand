use super::*;

#[test]
fn refuses_to_suspend_monitor() {
    /* SAFETY: This query takes no pointers and transfers no ownership. */
    let mut controller = ProcessController::new(unsafe { GetCurrentProcessId() });
    assert!(controller.suspend_process().is_err());
    assert!(!controller.is_suspended());
    assert!(controller.resume_process().is_ok());
}

#[test]
fn missing_process_does_not_claim_suspension() {
    let mut controller = ProcessController::new(u32::MAX);
    assert!(controller.suspend_process().is_err());
    assert!(!controller.is_suspended());
}
