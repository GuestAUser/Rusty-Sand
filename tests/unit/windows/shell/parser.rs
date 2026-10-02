use super::*;

#[test]
fn shell_parser_accepts_the_defined_commands() -> Result<()> {
    for (line, expected) in [
        ("help", Command::Help),
        ("info", Command::Analysis),
        ("analysis", Command::Analysis),
        ("run", Command::Run),
        ("status", Command::Status),
        ("events", Command::Events(20)),
        ("events 1", Command::Events(1)),
        ("events 100", Command::Events(100)),
        ("pause", Command::Pause),
        ("resume", Command::Resume),
        ("stop", Command::Stop),
        ("report", Command::Report),
        ("quit", Command::Quit),
    ] {
        assert_eq!(parse(line)?, Some(expected));
    }

    assert_eq!(parse("")?, None);
    assert_eq!(parse("   ")?, None);
    assert_eq!(parse("  status  ")?, Some(Command::Status));
    Ok(())
}

#[test]
fn shell_parser_rejects_host_commands_attachment_and_invalid_arguments() {
    for line in [
        "cmd",
        "powershell",
        "!dir",
        "attach 123",
        "run another.exe",
        "pause 123",
        "stop 123",
        "report another.json",
        "events 0",
        "events 101",
        "events -1",
        "events nope",
        "events 1 2",
        "status extra",
        "quit extra",
        "help; run",
        "status\nrun",
        "status\0",
        "events\t2",
    ] {
        assert!(parse(line).is_err(), "{line:?}");
    }

    assert!(parse(&"x".repeat(65)).is_err());
    assert!(parse(&"\u{1f600}".repeat(33)).is_err());
}
