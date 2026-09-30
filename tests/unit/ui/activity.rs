use super::*;
use crate::ui::activity::Command;
use std::time::Duration;

#[test]
fn acknowledged_ticks_show_elapsed_work_without_completing_it() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();

    activity.tick(Duration::from_secs(37));
    let first = capture.text();
    activity.tick(Duration::from_secs(38));
    let second = capture.text();

    assert!(first.contains("37s"));
    assert!(second.contains("38s"));
    assert!(second.len() > first.len());
    assert!(terminal.shared.lock().unwrap().active.is_some());
    assert!(!second.contains("[DONE]"));
    activity.finish("RESULT_SENTINEL", Tone::Success).unwrap();
}

#[test]
fn prompt_pauses_effect_and_release_resumes_the_same_activity() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();
    activity.tick(Duration::from_secs(1));
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    activity.tick(Duration::from_secs(2));
    assert_eq!(capture.text(), before);
    assert!(!terminal.shared.lock().unwrap().transient);
    prompt.finish(PromptEnd::Answered).unwrap();
    activity.tick(Duration::from_secs(3));

    assert!(capture.text().contains("3s"));
    activity.finish("RESULT_SENTINEL", Tone::Success).unwrap();
}

#[test]
fn finish_joins_worker_and_cleans_transient_before_printing_result() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();
    let worker = activity.worker_sender().unwrap();
    activity.tick(Duration::from_secs(1));

    activity.finish("RESULT_SENTINEL", Tone::Success).unwrap();

    assert!(worker.send(Command::Stop).is_err());
    let state = terminal.shared.lock().unwrap();
    assert!(state.active.is_none());
    assert!(!state.transient);
    assert!(capture.text().contains("RESULT_SENTINEL"));
}

#[test]
fn drop_joins_worker_without_faking_success() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();
    let worker = activity.worker_sender().unwrap();
    activity.tick(Duration::from_secs(1));

    drop(activity);

    assert!(worker.send(Command::Stop).is_err());
    let state = terminal.shared.lock().unwrap();
    assert!(state.active.is_none());
    assert!(!state.transient);
    let output = capture.text();
    assert!(output.contains("[WARNING]"));
    assert!(!output.contains("[DONE]"));
}

#[test]
fn finishing_during_prompt_defers_result_and_stops_worker() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();
    let worker = activity.worker_sender().unwrap();
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    activity.finish("RESULT_SENTINEL", Tone::Success).unwrap();

    assert!(worker.send(Command::Stop).is_err());
    assert_eq!(capture.text(), before);
    prompt.finish(PromptEnd::Answered).unwrap();
    assert!(capture.text().contains("RESULT_SENTINEL"));
}

#[test]
fn static_modes_have_truthful_stages_and_no_worker() {
    for policy in [
        OutputPolicy {
            plain: true,
            ..policy()
        },
        OutputPolicy {
            color: ColorMode::Never,
            ..policy()
        },
        OutputPolicy {
            reduced_motion: true,
            ..policy()
        },
        OutputPolicy {
            tty: false,
            ..policy()
        },
    ] {
        let (terminal, capture) = fixture(policy);
        let activity = terminal.activity("WORK_SENTINEL").unwrap();
        assert!(activity.worker_sender().is_none());
        activity.finish("RESULT_SENTINEL", Tone::Success).unwrap();
        let output = capture.text();

        assert!(output.contains("WORK_SENTINEL"));
        assert!(output.contains("RESULT_SENTINEL"));
        assert!(!output.contains('\r'));

        if policy.plain || policy.color == ColorMode::Never {
            assert!(!output.contains('\x1b'));
        }
    }
}

#[test]
fn overlapping_activities_are_rejected_without_spawning_another_worker() {
    let (terminal, _) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();

    assert_eq!(
        terminal.activity("OVERLAP_SENTINEL").err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        terminal.configure(policy()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(activity);
    terminal
        .activity("NEXT_SENTINEL")
        .unwrap()
        .finish("RESULT_SENTINEL", Tone::Normal)
        .unwrap();
}

#[test]
fn failed_worker_is_joined_and_activity_state_is_released() {
    let (terminal, capture) = fixture(policy());
    let activity = terminal.activity("WORK_SENTINEL").unwrap();
    let worker = activity.worker_sender().unwrap();
    let (acknowledge, observed) = std::sync::mpsc::sync_channel(1);
    capture.fail.store(true, Ordering::SeqCst);

    worker
        .send(Command::Tick(Duration::from_secs(1), acknowledge))
        .unwrap();
    assert!(matches!(
        observed.recv_timeout(Duration::from_secs(5)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    capture.fail.store(false, Ordering::SeqCst);

    assert_eq!(
        activity
            .finish("RESULT_SENTINEL", Tone::Warning)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(terminal.shared.lock().unwrap().active.is_none());
    assert!(worker.send(Command::Stop).is_err());
}
