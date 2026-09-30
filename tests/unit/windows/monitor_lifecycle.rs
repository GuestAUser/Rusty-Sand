use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn should_pause_detection_reaches_review_and_requests_termination() -> Result<()> {
    let events = Arc::new(Mutex::new(vec![Event {
        timestamp: chrono::Utc::now(),
        event_type: EventType::RegistryAccess,
        details: r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run".into(),
    }]));
    let config = SandboxConfig::default();
    let (reviews, broker) = review::channel();
    let reviewed = AtomicBool::new(false);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = analyze(&config, events.clone(), &reviews) => result,
            result = broker.dispatch(async |request| {
                assert!(matches!(request, review::Review::Observation(threat) if threat.should_pause));
                reviewed.store(true, Ordering::SeqCst);
                Ok(UserDecision::Terminate)
            }) => result.and_then(|()| Err(anyhow!("review service stopped"))),
        }
    }).await.context("behavior review deadline")?;
    assert!(result.is_err());
    assert!(reviewed.load(Ordering::SeqCst));
    assert!(events
        .lock()
        .await
        .iter()
        .any(|event| event.event_type == EventType::Suspicious));
    assert!(!events
        .lock()
        .await
        .iter()
        .any(|event| event.event_type == EventType::HookBlocked));
    Ok(())
}
