use super::fixture::{process_completion, Fixture, UI_LOCK};
use crate::behavior::assessment::assess_events;
use crate::live::RunState;
use crate::sandbox::process::create_sandboxed_process;
use anyhow::{Context, Result};
use std::time::Duration;

#[tokio::test]
async fn shell_stop_joins_only_its_job_and_preserves_completed_reports() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    fixture.running(&session).await?;

    /*
     * This independent target stays initially suspended and is not monitored,
     * so it does not compete for the process-wide UI activity owner.
     */
    let outsider = create_sandboxed_process(
        fixture
            .executable()
            .to_str()
            .context("fixture path is not Unicode")?,
        &fixture.args(),
        &fixture.config(),
    )?;
    let mut completion = process_completion(&session)?;

    session.stop().await?;
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    completion.close()?;

    assert_eq!(outsider.exit_code()?, None);
    assert_eq!(session.process_id(), None);
    assert_eq!(session.state(), RunState::Completed);

    let before = serde_json::to_value(
        session
            .completed_report()
            .context("completed report missing")?,
    )?;

    session.stop().await?;

    assert_eq!(
        serde_json::to_value(
            session
                .completed_report()
                .context("repeated stop lost report")?
        )?,
        before,
    );

    let first = session.save_report()?;
    let first_bytes = std::fs::read(&first)?;
    let second = session.save_report()?;
    assert_ne!(first, second);
    assert_eq!(std::fs::read(&first)?, first_bytes);
    assert_eq!(std::fs::read(second)?, first_bytes);

    let saved: serde_json::Value = serde_json::from_slice(&first_bytes)?;
    let report = session.completed_report().context("saving lost report")?;

    assert_eq!(saved["report"], serde_json::to_value(report)?);
    assert_eq!(
        saved["assessment"],
        serde_json::to_value(assess_events(&report.events))?,
    );

    drop(outsider);
    Ok(())
}

#[tokio::test]
async fn shell_natural_completion_survives_a_later_launch_failure() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    fixture.running(&session).await?;

    fixture.release()?;
    tokio::time::timeout(Duration::from_secs(10), session.wait()).await??;

    let before = serde_json::to_value(
        session
            .completed_report()
            .context("natural completion lost report")?,
    )?;
    assert_eq!(
        session
            .completed_report()
            .context("report missing")?
            .exit_code,
        0
    );

    std::fs::remove_file(fixture.executable())?;
    assert!(session.run().await.is_err());
    assert!(!session.has_active_run());
    assert_eq!(
        serde_json::to_value(
            session
                .completed_report()
                .context("failed launch lost report")?
        )?,
        before,
    );

    Ok(())
}

#[tokio::test]
async fn shell_drop_stops_and_joins_owned_execution() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    fixture.running(&session).await?;
    let mut completion = process_completion(&session)?;

    drop(session);

    /* Drop already joined; collect the previously registered OS exit signal. */
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    completion.close()?;
    Ok(())
}

#[tokio::test]
async fn shell_early_stop_joins_without_an_input_owner() -> Result<()> {
    let _ui = UI_LOCK.lock().await;
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    session.run().await?;
    let mut completion = process_completion(&session)?;

    tokio::time::timeout(Duration::from_secs(10), session.stop()).await??;
    tokio::time::timeout(Duration::from_secs(5), completion.wait()).await??;
    completion.close()?;

    let report = session
        .completed_report()
        .context("early stop lost report")?;
    assert_eq!(report.exit_code, 1);
    assert!(!report.config.interactive_mode);
    assert!(!report.config.cancel_on_stdin_eof);
    Ok(())
}
