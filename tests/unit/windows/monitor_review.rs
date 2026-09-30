use super::*;
use crate::behavior::BehaviorAnalyzer;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

fn observation() -> ThreatDetection {
    BehaviorAnalyzer::new()
        .analyze_event(&Event {
            timestamp: chrono::Utc::now(),
            event_type: EventType::RegistryAccess,
            details: r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run".into(),
        })
        .expect("registry persistence observation should request review")
}

fn hook_review() -> Review {
    Review::Hook {
        description: "operation-1".into(),
        risk: RiskScore {
            score: 85,
            category: crate::analysis::ThreatCategory::High,
        },
    }
}

async fn assert_pending(mut future: Pin<&mut impl Future>) {
    poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[test]
fn observation_and_hook_choices_keep_their_distinct_meanings() {
    let behavior = Review::Observation(observation());
    for (input, decision) in [
        (" a \r\n", UserDecision::Allow),
        ("B", UserDecision::Block),
        ("c", UserDecision::Continue),
        ("T", UserDecision::Terminate),
    ] {
        assert_eq!(behavior.parse_decision(input), Some(decision));
    }
    assert_eq!(behavior.parse_decision(""), None);
    assert_eq!(behavior.parse_decision("unknown"), None);
    assert_eq!(
        hook_review().parse_decision("A"),
        Some(UserDecision::AllowAll)
    );
    assert_eq!(hook_review().parse_decision("Y"), Some(UserDecision::Allow));
    assert_eq!(hook_review().parse_decision(""), Some(UserDecision::Block));
}

#[tokio::test]
async fn only_interactive_should_pause_observations_queue_a_review() -> Result<()> {
    for (interactive, should_pause) in [(false, false), (false, true), (true, false)] {
        let config = SandboxConfig {
            interactive_mode: interactive,
            ..SandboxConfig::default()
        };
        let mut threat = observation();
        threat.should_pause = should_pause;
        let (client, mut broker) = channel();
        assert_eq!(client.observation(&config, &threat).await?, None);
        assert!(matches!(
            broker.receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn automatic_critical_termination_precedes_interactive_review() {
    let config = SandboxConfig {
        auto_terminate_on_critical: true,
        ..SandboxConfig::default()
    };
    let mut threat = observation();
    threat.level = ThreatLevel::Critical;
    let (client, mut broker) = channel();
    assert!(client.observation(&config, &threat).await.is_err());
    assert!(matches!(
        broker.receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn blocking_an_observation_only_flags_it_and_termination_is_explicit() -> Result<()> {
    let threat = observation();
    for decision in [UserDecision::Block, UserDecision::BlockAll] {
        let mut events = Vec::new();
        apply_observation_decision(&threat, Some(decision), &mut events)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::Suspicious);
        assert!(!events
            .iter()
            .any(|event| event.event_type == EventType::HookBlocked));
    }
    let mut events = Vec::new();
    for decision in [
        None,
        Some(UserDecision::Allow),
        Some(UserDecision::Continue),
    ] {
        apply_observation_decision(&threat, decision, &mut events)?;
    }
    assert!(events.is_empty());
    assert!(
        apply_observation_decision(&threat, Some(UserDecision::Terminate), &mut events).is_err()
    );
    assert!(events.is_empty());
    Ok(())
}

#[tokio::test]
async fn hook_and_behavior_reviews_share_one_serial_decider() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, broker) = channel();
        let config = SandboxConfig::default();
        let threat = observation();
        let active = AtomicUsize::new(0);
        let started = AtomicUsize::new(0);
        let (release, mut released) = oneshot::channel();
        let mut service = Box::pin(broker.dispatch(async |review| {
            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
            let index = started.fetch_add(1, Ordering::SeqCst);
            review.write_prompt(&mut Vec::new())?;
            let decision = match review {
                Review::Hook { .. } => {
                    assert_eq!(index, 0);
                    (&mut released).await?;
                    UserDecision::Allow
                }
                Review::Observation(threat) => {
                    assert_eq!(index, 1);
                    assert!(threat.should_pause);
                    UserDecision::Terminate
                }
            };
            assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
            Ok(decision)
        }));
        let Review::Hook { description, risk } = hook_review() else {
            unreachable!()
        };
        let mut hook = Box::pin(client.hook(description, risk));
        assert_pending(hook.as_mut()).await;
        assert_pending(service.as_mut()).await;
        let mut behavior = Box::pin(client.observation(&config, &threat));
        assert_pending(behavior.as_mut()).await;
        assert_eq!(client.sender.capacity(), 0);
        assert_pending(service.as_mut()).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        release
            .send(())
            .expect("active review must retain its decision receiver");

        let completed = async {
            let (hook, behavior) = tokio::join!(hook, behavior);
            assert_eq!(hook?, UserDecision::Allow);
            assert_eq!(behavior?, Some(UserDecision::Terminate));
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            result = &mut service => { result?; bail!("review service ended before both replies"); }
            result = completed => result?,
        }
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("serialized review deadline")?
}

#[tokio::test]
async fn input_failure_rejects_active_and_queued_reviews() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, broker) = channel();
        let config = SandboxConfig::default();
        let threat = observation();
        let Review::Hook { description, risk } = hook_review() else {
            unreachable!()
        };
        let hook = client.hook(description, risk);
        let behavior = client.observation(&config, &threat);
        let service = broker.dispatch(async |_| {
            Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
        });
        let (hook, behavior, service) = tokio::join!(hook, behavior, service);
        assert!(hook.is_err());
        assert!(behavior.is_err());
        assert!(service.is_err());
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("failed review teardown deadline")?
}

#[tokio::test]
async fn cancellation_drops_the_active_input_future() {
    struct DropSignal<'a>(&'a AtomicBool);
    impl Drop for DropSignal<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = AtomicBool::new(false);
    let (client, broker) = channel();
    let mut service = Box::pin(broker.dispatch(async |_| {
        let _signal = DropSignal(&dropped);
        std::future::pending::<Result<UserDecision>>().await
    }));
    let Review::Hook { description, risk } = hook_review() else {
        unreachable!()
    };
    let mut hook = Box::pin(client.hook(description, risk));
    assert_pending(hook.as_mut()).await;
    assert_pending(service.as_mut()).await;
    drop(hook);
    drop(service);
    assert!(dropped.load(Ordering::SeqCst));
}
