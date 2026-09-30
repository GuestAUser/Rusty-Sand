use super::*;

#[test]
fn resource_alert_is_immediate_then_rate_limited() {
    let now = Instant::now();
    let mut previous = None;

    assert!(alert_due(&mut previous, now));
    assert!(!alert_due(&mut previous, now + Duration::from_secs(29)));
    assert!(alert_due(&mut previous, now + Duration::from_secs(30)));
}
