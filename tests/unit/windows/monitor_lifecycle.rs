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

#[tokio::test]
async fn input_end_cancels_without_waiting_for_an_active_prompt() -> Result<()> {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    for end in [
        InputEnd::Eof,
        InputEnd::Cancelled,
        InputEnd::Failed("transport".into()),
    ] {
        let (send, receive) = watch::channel(None);
        let mut status = Some(receive);
        let mut cancellation = Box::pin(input_ended(&mut status));
        poll_fn(|context| {
            assert!(cancellation.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        send.send_replace(Some(end));
        let result = tokio::time::timeout(Duration::from_secs(5), cancellation).await?;
        assert!(result.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn already_closed_input_wins_over_ready_work() {
    for end in [
        InputEnd::Eof,
        InputEnd::Cancelled,
        InputEnd::Failed("transport".into()),
    ] {
        let (_send, receive) = watch::channel(Some(end));
        assert!(check_input(&receive).is_err());
        let mut status = Some(receive);
        let result = tokio::select! {
            biased;
            result = input_ended(&mut status) => result,
            () = std::future::ready(()) => panic!("cancelled input released ready work"),
        };
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn abandoned_input_status_fails_closed() {
    let (send, receive) = watch::channel(None);
    drop(send);
    assert!(input_ended(&mut Some(receive)).await.is_err());
}
