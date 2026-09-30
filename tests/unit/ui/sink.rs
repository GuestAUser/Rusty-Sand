use super::*;
use crate::ui::sink::{MAX_BYTES, MAX_ENTRIES};

#[test]
fn diagnostics_wait_for_prompt_and_flush_in_fifo_order() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    terminal.diagnostic(log::Level::Warn, "LOG_SENTINEL_A");
    terminal.diagnostic(log::Level::Error, "LOG_SENTINEL_B");
    terminal.status("STAGE_SENTINEL", Tone::Heading).unwrap();
    assert_eq!(capture.text(), before);
    prompt.finish(PromptEnd::Answered).unwrap();

    let output = capture.text();
    let first = output.find("LOG_SENTINEL_A").unwrap();
    let second = output.find("LOG_SENTINEL_B").unwrap();
    let third = output.find("STAGE_SENTINEL").unwrap();
    assert!(first < second && second < third);
}

#[test]
fn prompt_queue_bounds_entries_and_reports_loss_after_release() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();

    for index in 0..MAX_ENTRIES + 7 {
        terminal.diagnostic(log::Level::Warn, &format!("ENTRY_{index:04}"));
    }

    {
        let state = terminal.shared.lock().unwrap();
        assert_eq!(state.queue.len(), MAX_ENTRIES);
        assert_eq!(state.dropped, 7);
    }

    prompt.finish(PromptEnd::Answered).unwrap();
    let output = capture.text();
    assert!(!output.contains("ENTRY_0000"));
    assert!(output.contains("ENTRY_0007"));
    let final_line = output.lines().rev().find(|line| !line.is_empty()).unwrap();
    assert!(final_line.contains('7'));
    assert!(final_line.contains("[WARNING]"));
}

#[test]
fn escaped_bytes_not_raw_bytes_count_toward_prompt_budget() {
    let (terminal, _) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();

    for _ in 0..200 {
        terminal.diagnostic(log::Level::Warn, &"\x1b".repeat(100));
    }

    {
        let state = terminal.shared.lock().unwrap();
        assert!(state.queued_bytes <= MAX_BYTES);
        assert!(state.queue.len() < 200);
        assert!(state.dropped > 0);
        assert_eq!(
            state.queued_bytes,
            state
                .queue
                .iter()
                .map(|entry| entry.text.len())
                .sum::<usize>()
        );
    }

    prompt.finish(PromptEnd::Answered).unwrap();
}

#[test]
fn oversized_diagnostic_is_counted_without_retaining_partial_evidence() {
    let (terminal, _) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    terminal.diagnostic(log::Level::Error, &"X".repeat(MAX_BYTES + 1));

    let state = terminal.shared.lock().unwrap();
    assert_eq!(state.queued_bytes, 0);
    assert!(state.queue.is_empty());
    assert_eq!(state.dropped, 1);
    drop(state);
    drop(prompt);
}

#[test]
fn dropping_prompt_releases_ownership_and_queued_warnings() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    terminal.diagnostic(log::Level::Warn, "DROP_SENTINEL");

    drop(prompt);

    assert!(terminal.shared.lock().unwrap().prompt.is_none());
    assert!(capture.text().contains("DROP_SENTINEL"));
    terminal
        .begin_prompt(&panel())
        .unwrap()
        .finish(PromptEnd::Answered)
        .unwrap();
}

#[test]
fn exclusive_prompt_rejects_panels_and_configuration_without_output() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    assert_eq!(
        terminal.panel(&panel()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        terminal.begin_prompt(&panel()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        terminal.configure(policy()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(capture.text(), before);
    drop(prompt);
}

#[test]
fn native_echo_is_sanitized_and_diagnostics_never_split_it() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    terminal
        .input(InputEdit::Append("AB\x1b\u{202e}".into()))
        .unwrap();
    terminal.input(InputEdit::Backspace).unwrap();
    terminal.diagnostic(log::Level::Warn, "ECHO_LOG_SENTINEL");
    terminal.input(InputEdit::Newline).unwrap();

    let before_release = capture.text();
    assert!(!before_release.contains("ECHO_LOG_SENTINEL"));
    assert!(!before_release.contains('\u{202e}'));
    assert!(before_release.ends_with("> AB\\u{1b}\n"));
    prompt.finish(PromptEnd::Answered).unwrap();
    assert!(capture.text().contains("ECHO_LOG_SENTINEL"));
}

#[test]
fn redirected_input_is_never_application_echoed() {
    let (terminal, capture) = fixture(OutputPolicy {
        tty: false,
        ..policy()
    });
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    terminal
        .input(InputEdit::Append("SECRET_SENTINEL".into()))
        .unwrap();
    terminal.input(InputEdit::Newline).unwrap();

    assert_eq!(capture.text(), before);
    drop(prompt);
}

#[test]
fn concurrent_diagnostics_are_serialized_while_prompt_guard_holds_no_lock() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    let before = capture.text();

    std::thread::scope(|scope| {
        for index in 0..8 {
            let terminal = &terminal;
            scope.spawn(move || {
                terminal.diagnostic(log::Level::Warn, &format!("THREAD_{index:02}"))
            });
        }
    });

    assert_eq!(capture.text(), before);
    prompt.finish(PromptEnd::Answered).unwrap();
    let output = capture.text();

    for index in 0..8 {
        assert_eq!(output.matches(&format!("THREAD_{index:02}")).count(), 1);
    }
}

#[test]
fn asynchronous_diagnostic_failure_is_returned_by_next_fallible_call() {
    let (terminal, capture) = fixture(policy());
    capture.fail.store(true, Ordering::SeqCst);
    terminal.diagnostic(log::Level::Error, "ERROR_SENTINEL");
    capture.fail.store(false, Ordering::SeqCst);

    assert_eq!(
        terminal
            .status("NEXT_SENTINEL", Tone::Normal)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn prompt_drop_failure_is_retained_but_does_not_leave_prompt_owned() {
    let (terminal, capture) = fixture(policy());
    let prompt = terminal.begin_prompt(&panel()).unwrap();
    capture.fail.store(true, Ordering::SeqCst);

    drop(prompt);
    capture.fail.store(false, Ordering::SeqCst);

    assert!(terminal.shared.lock().unwrap().prompt.is_none());
    assert_eq!(
        terminal
            .status("NEXT_SENTINEL", Tone::Normal)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}
