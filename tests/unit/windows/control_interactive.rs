use super::*;
use crate::behavior::ThreatLevel;
use std::io::Cursor;

fn event(event_type: EventType) -> Event {
    Event {
        timestamp: "2026-09-30T12:00:00Z".parse().expect("valid timestamp"),
        event_type,
        details: "observed operation".to_string(),
    }
}

#[test]
fn parses_only_explicit_choices() {
    for (input, expected) in [
        (" a \r\n", UserDecision::Allow),
        ("aa", UserDecision::AllowAll),
        ("B", UserDecision::Block),
        ("bB", UserDecision::BlockAll),
        ("T", UserDecision::Terminate),
        ("c", UserDecision::Continue),
    ] {
        assert_eq!(parse_decision(input, true), Some(expected));
    }

    for input in ["", " ", "yes", "allow", "A B", "unknown"] {
        assert_eq!(parse_decision(input, true), None);
    }

    assert_eq!(parse_decision("AA", false), None);
    assert_eq!(parse_decision("BB", false), None);
}

#[test]
fn invalid_input_requires_an_explicit_decision() {
    let mut input = Cursor::new(b"invalid\n\n b\n");
    assert_eq!(
        read_decision(&mut input, &mut Vec::new(), true).unwrap(),
        UserDecision::Block
    );
}

#[test]
fn cached_type_decisions_are_consistent_and_do_not_touch_io() {
    for (input, decision, status) in [
        ("AA\n", UserDecision::AllowAll, (false, true, false)),
        ("BB\n", UserDecision::BlockAll, (false, false, true)),
        ("C\n", UserDecision::Continue, (false, false, false)),
    ] {
        let mut controller = InteractiveController::new();
        let event = event(EventType::FileCreated);
        assert_eq!(
            controller
                .prompt_for_event_with_io(&event, &mut Cursor::new(input), &mut Vec::new())
                .unwrap(),
            decision
        );
        assert_eq!(controller.check_event_status(&event.event_type), status);
        assert_eq!(
            controller.check_event_status(&EventType::FileDeleted),
            (true, false, false)
        );
        assert_eq!(
            controller
                .prompt_for_event_with_io(&event, &mut FailingIo, &mut FailingIo)
                .unwrap(),
            decision
        );
    }
}

#[test]
fn individual_choices_do_not_create_policy() {
    for input in ["A\n", "B\n", "T\n"] {
        let mut controller = InteractiveController::new();
        let event = event(EventType::FileCreated);
        controller
            .prompt_for_event_with_io(&event, &mut Cursor::new(input), &mut Vec::new())
            .unwrap();
        assert_eq!(
            controller.check_event_status(&event.event_type),
            (true, false, false)
        );
    }
}

#[test]
fn global_modes_are_exclusive_and_restore_type_policy_when_disabled() {
    let mut controller = InteractiveController::new();
    let event = event(EventType::FileCreated);
    controller
        .prompt_for_event_with_io(&event, &mut Cursor::new(b"BB\n"), &mut Vec::new())
        .unwrap();
    controller.set_auto_allow(true);
    assert_eq!(
        controller.check_event_status(&event.event_type),
        (false, true, false)
    );
    assert_eq!(
        controller
            .prompt_for_event_with_io(&event, &mut FailingIo, &mut FailingIo)
            .unwrap(),
        UserDecision::AllowAll
    );
    controller.set_auto_block(true);
    controller.set_auto_allow(false);
    assert_eq!(
        controller.check_event_status(&EventType::FileDeleted),
        (false, false, true)
    );
    controller.set_auto_block(false);
    assert_eq!(
        controller.check_event_status(&event.event_type),
        (false, false, true)
    );
    assert!(controller.should_prompt(&EventType::FileDeleted));
}

struct FailingIo;

impl io::Read for FailingIo {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}

impl BufRead for FailingIo {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::other("read failed"))
    }

    fn consume(&mut self, _: usize) {}
}

impl Write for FailingIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

struct FlushFailure(Vec<u8>);

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

#[test]
fn input_output_and_eof_failures_never_grant_permission_or_cache_policy() {
    let mut controller = InteractiveController::new();
    let event = event(EventType::FileCreated);
    let results = [
        controller.prompt_for_event_with_io(&event, &mut FailingIo, &mut Vec::new()),
        controller.prompt_for_event_with_io(&event, &mut Cursor::new(b"AA\n"), &mut FailingIo),
        controller.prompt_for_event_with_io(
            &event,
            &mut Cursor::new(b"AA\n"),
            &mut FlushFailure(Vec::new()),
        ),
        controller.prompt_for_event_with_io(&event, &mut Cursor::new(b""), &mut Vec::new()),
        controller.prompt_for_event_with_io(
            &event,
            &mut Cursor::new(b"invalid\n"),
            &mut Vec::new(),
        ),
    ];

    for result in results {
        assert!(result.is_err());
        assert_eq!(fail_closed(result), UserDecision::Terminate);
    }

    assert!(controller.should_prompt(&event.event_type));
}

#[test]
fn threat_prompt_uses_explicit_decisions_and_global_policy() {
    let threat = ThreatDetection {
        threat_type: "test".to_string(),
        level: ThreatLevel::High,
        description: "detected activity".to_string(),
        evidence: vec!["observation".to_string()],
        should_pause: true,
    };
    let mut controller = InteractiveController::new();
    assert_eq!(
        controller
            .prompt_user_with_io(&threat, &mut Cursor::new(b"BB\nB\n"), &mut Vec::new())
            .unwrap(),
        UserDecision::Block
    );
    assert_eq!(
        fail_closed(controller.prompt_user_with_io(&threat, &mut FailingIo, &mut Vec::new())),
        UserDecision::Terminate
    );
    controller.set_auto_allow(true);
    assert_eq!(
        controller
            .prompt_user_with_io(&threat, &mut FailingIo, &mut FailingIo)
            .unwrap(),
        UserDecision::Allow
    );
    controller.set_auto_block(true);
    assert_eq!(
        controller
            .prompt_user_with_io(&threat, &mut FailingIo, &mut FailingIo)
            .unwrap(),
        UserDecision::Block
    );
}
