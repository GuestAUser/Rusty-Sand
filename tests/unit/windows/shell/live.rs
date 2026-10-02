#[path = "control.rs"]
mod control;
#[path = "fixture.rs"]
pub(crate) mod fixture;
#[path = "ownership.rs"]
mod ownership;

use super::*;
use crate::report::EventType;
use fixture::{Fixture, UI_LOCK};
use std::time::Duration;

#[tokio::test]
async fn shell_static_inspection_is_read_only_and_does_not_launch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("candidate.exe");
    let bytes = b"MZ\0bounded static inspection fixture";
    std::fs::write(&executable, bytes)?;

    let session = LiveSession::new(
        executable
            .to_str()
            .context("candidate path is not Unicode")?,
        &[],
        SandboxConfig::default(),
    )?;
    let report = session.inspect()?;

    assert_eq!(report.size_bytes, bytes.len() as u64);
    assert_eq!(std::fs::read(executable)?, bytes);
    assert_eq!(session.state(), RunState::Idle);
    assert_eq!(session.process_id(), None);
    assert!(!session.has_active_run());
    assert!(session.completed_report().is_none());
    Ok(())
}

#[tokio::test]
async fn shell_live_rejects_second_run_and_exposes_active_telemetry() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    let pid = session.run().await?;
    fixture.running(&session).await?;

    assert!(session.run().await.is_err());
    assert_eq!(session.process_id(), Some(pid));
    assert_eq!(session.state(), RunState::Running);
    assert!(session.completed_report().is_none());

    let events = session.events(MAX_EVENT_PAGE).await;
    assert!(events
        .iter()
        .any(|event| event.event_type == EventType::SandboxStarted));
    assert!(!events
        .iter()
        .any(|event| event.event_type == EventType::SandboxStopped));
    assert!(session.events(1).await.len() <= 1);
    assert!(session.events(usize::MAX).await.len() <= MAX_EVENT_PAGE);
    assert!(session.events(0).await.is_empty());

    session.stop().await?;

    let report = session.completed_report().context("stop lost its report")?;
    assert!(!report.config.interactive_mode);
    assert!(!report.config.cancel_on_stdin_eof);
    assert_eq!(
        report.config.restricted_token,
        fixture.config().restricted_token
    );
    assert!(report
        .events
        .iter()
        .any(|event| event.event_type == EventType::SandboxStopped));
    Ok(())
}

#[tokio::test]
async fn shell_restricted_token_setting_is_preserved() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut config = fixture.config();
    config.restricted_token = true;

    let mut session = LiveSession::new(
        fixture
            .executable()
            .to_str()
            .context("fixture path is not Unicode")?,
        &fixture.args(),
        config,
    )?;

    session.run().await?;
    fixture.running(&session).await?;
    session.stop().await?;

    assert!(
        session
            .completed_report()
            .context("report missing")?
            .config
            .restricted_token
    );
    Ok(())
}

#[tokio::test]
async fn shell_cancelled_wait_keeps_execution_owned() -> Result<()> {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    let pid = session.run().await?;
    fixture.running(&session).await?;

    let mut wait = Box::pin(session.wait());
    poll_fn(|context| {
        assert!(wait.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(wait);

    assert_eq!(session.process_id(), Some(pid));
    assert!(session.has_active_run());

    tokio::time::timeout(Duration::from_secs(10), session.stop()).await??;
    Ok(())
}
