use super::*;
use anyhow::anyhow;

#[test]
fn cleanup_errors_are_not_lost_on_success_or_failure() {
    assert!(with_cleanup(Ok(7), Err(anyhow!("close"))).is_err());
    let error = with_cleanup::<()>(Err(anyhow!("start")), Err(anyhow!("close"))).unwrap_err();
    let details = error.to_string();
    assert!(details.contains("start"));
    assert!(details.contains("close"));
    assert_eq!(with_cleanup(Ok(7), Ok(())).unwrap(), 7);
}

#[test]
fn cleanup_context_preserves_the_typed_operation_error() {
    use crate::sandbox::deadline::DeadlineExceeded;

    let error =
        with_cleanup::<()>(Err(DeadlineExceeded.into()), Err(anyhow!("close failed"))).unwrap_err();

    assert!(error.is::<DeadlineExceeded>());
}
