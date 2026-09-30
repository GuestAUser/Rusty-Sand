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
