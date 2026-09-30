use super::summary::EventCounts;
use super::*;

fn report(types: &[EventType]) -> SandboxReport {
    let timestamp = DateTime::from_timestamp(0, 0).unwrap();

    SandboxReport {
        executable: "sample.exe".into(),
        start_time: timestamp,
        end_time: timestamp,
        duration_seconds: 0,
        events: types
            .iter()
            .map(|event_type| Event {
                timestamp,
                event_type: event_type.clone(),
                details: String::new(),
            })
            .collect(),
        exit_code: 0,
        config: SandboxConfig::new(),
    }
}

#[test]
fn file_projection_includes_every_hook_file_operation_in_order() {
    let types = [
        EventType::FileCreated,
        EventType::FileModified,
        EventType::FileDeleted,
        EventType::HookFileCreate,
        EventType::HookFileWrite,
        EventType::HookFileDelete,
        EventType::HookFileRead,
        EventType::HookFileMove,
        EventType::HookFileCopy,
        EventType::HookFileAttributeChange,
    ];
    let mut report = report(&types);
    report
        .events
        .extend(self::report(&[EventType::HookFolderCreate, EventType::HookBlocked]).events);

    let selected: Vec<_> = report
        .get_file_events()
        .into_iter()
        .map(|event| event.event_type.clone())
        .collect();

    assert_eq!(selected, types);
    assert_eq!(EventCounts::from_events(&report.events).files, types.len());
}

#[test]
fn network_requests_are_not_denials() {
    let types = [
        EventType::NetworkConnection,
        EventType::DnsQuery,
        EventType::HookNetworkConnect,
        EventType::HookNetworkSend,
        EventType::HookNetworkReceive,
    ];
    let mut report = report(&types);

    assert_eq!(report.get_network_events().len(), types.len());
    assert_eq!(EventCounts::from_events(&report.events).network_blocked, 0);

    report
        .events
        .extend(self::report(&[EventType::NetworkBlocked, EventType::HookBlocked]).events);
    let counts = EventCounts::from_events(&report.events);

    assert_eq!(counts.network, types.len() + 1);
    assert_eq!(counts.network_blocked, 1);
    assert_eq!(counts.hook_blocked, 1);
    assert_eq!(report.get_network_events().len(), types.len() + 1);
}

#[test]
fn report_round_trip_preserves_event_tags_and_configuration() {
    let report = report(&[
        EventType::HookFileRead,
        EventType::HookNetworkConnect,
        EventType::HookBlocked,
    ]);
    let json = report.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(value["events"][0]["event_type"], "HookFileRead");
    assert_eq!(value["events"][1]["event_type"], "HookNetworkConnect");
    assert_eq!(value["events"][2]["event_type"], "HookBlocked");

    let decoded: SandboxReport = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
}

#[test]
fn summary_handles_empty_and_truncated_histories() {
    report(&[]).print_summary();
    report(&vec![EventType::HookNetworkConnect; 101]).print_summary();
}

fn summary_policy(color: crate::ui::ColorMode) -> crate::ui::OutputPolicy {
    crate::ui::OutputPolicy {
        color,
        plain: false,
        reduced_motion: true,
        tty: true,
        columns: 100,
    }
}

#[test]
fn summary_respects_color_policy_and_escapes_untrusted_terminal_controls() {
    use crate::ui::ColorMode;

    let mut report = report(&[EventType::HookFileWrite]);
    report.executable = "target\x1b[2J.exe".into();
    report.events[0].details = "payload\x1b]0;spoof\x07".into();
    let json_before = report.to_json().unwrap();
    for color in [ColorMode::Never, ColorMode::Always] {
        let mut output = Vec::new();
        report
            .write_summary(&mut output, &summary_policy(color))
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.contains('\x1b'), color == ColorMode::Always);
        assert!(!output.contains("\x1b[2J"));
        assert!(!output.contains("\x1b]0;"));
        assert!(!output.contains('\x07'));
        assert_eq!(report.to_json().unwrap(), json_before);
    }
}

#[test]
fn summary_returns_destination_failures() {
    struct FailedWriter;
    impl std::io::Write for FailedWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = report(&[])
        .write_summary(
            &mut FailedWriter,
            &summary_policy(crate::ui::ColorMode::Never),
        )
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
fn summary_retains_only_last_one_hundred_event_payloads() {
    let mut report = report(&vec![EventType::HookFileWrite; 101]);
    report.events[0].details = "discarded-sentinel-0".into();
    report.events[1].details = "retained-sentinel-1".into();
    report.events[100].details = "retained-sentinel-100".into();
    let mut output = Vec::new();
    report
        .write_summary(&mut output, &summary_policy(crate::ui::ColorMode::Never))
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains("discarded-sentinel-0"));
    assert!(output.contains("retained-sentinel-1"));
    assert!(output.contains("retained-sentinel-100"));
}
