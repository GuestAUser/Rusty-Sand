use super::*;
use chrono::DateTime;

fn event(event_type: EventType, details: &str) -> Event {
    Event {
        timestamp: DateTime::from_timestamp(0, 0).unwrap(),
        event_type,
        details: details.into(),
    }
}

#[test]
fn file_volume_threshold_counts_observations_not_hook_requests() {
    let mut analyzer = BehaviorAnalyzer::new();

    for _ in 0..50 {
        assert!(analyzer
            .analyze_event(&event(EventType::HookFileCreate, "document.txt"))
            .is_none());
        assert!(analyzer
            .analyze_event(&event(EventType::FileCreated, "document.txt"))
            .is_none());
    }

    let detection = analyzer
        .analyze_event(&event(EventType::FileCreated, "document.txt"))
        .unwrap();

    assert_eq!(detection.level, ThreatLevel::Critical);
    assert!(detection.should_pause);
    assert_eq!(analyzer.file_operations, 51);
    assert_eq!(analyzer.file_creation_count, 51);
}

#[test]
fn windows_matching_ignores_case_but_preserves_evidence() {
    for (event_type, details, level) in [
        (
            EventType::FileCreated,
            r"C:\TEMP\PAYLOAD.EXE",
            ThreatLevel::Medium,
        ),
        (
            EventType::FileCreated,
            r"C:\DATA\REPORT.LOCKED",
            ThreatLevel::High,
        ),
        (
            EventType::FolderDeleted,
            r"c:\windows\system32",
            ThreatLevel::Critical,
        ),
        (
            EventType::RegistryAccess,
            r"HKCU\software\RunOnce",
            ThreatLevel::High,
        ),
        (
            EventType::ProcessCreated,
            "POWERSHELL.EXE -ENC Zg==",
            ThreatLevel::Critical,
        ),
    ] {
        let detection = BehaviorAnalyzer::new()
            .analyze_event(&event(event_type, details))
            .unwrap();

        assert_eq!(detection.level, level);
        assert_eq!(detection.evidence, [details]);
    }
}

#[test]
fn registry_components_and_ports_have_boundaries() {
    let mut analyzer = BehaviorAnalyzer::new();

    assert!(analyzer
        .analyze_event(&event(EventType::RegistryAccess, r"HKCU\Runtime"))
        .is_none());
    assert!(analyzer
        .analyze_event(&event(EventType::NetworkConnection, "192.0.2.1:44440"))
        .is_none());
    assert!(analyzer
        .analyze_event(&event(EventType::NetworkConnection, "192.0.2.1:4444"))
        .is_some());
    assert_eq!(analyzer.registry_operations, 1);
    assert_eq!(analyzer.network_connections, 2);
}

#[test]
fn network_detection_uses_remote_port_not_local_port_or_address_segments() {
    for details in [
        "TCP: 127.0.0.1:4444 -> 192.0.2.1:443",
        "TCP: [2001:db8:4444::1]:12345 -> [2001:db8::2]:443",
        "UDP: 0.0.0.0:4444",
    ] {
        let detection =
            BehaviorAnalyzer::new().analyze_event(&event(EventType::NetworkConnection, details));

        assert!(detection.is_none(), "{details}");
    }

    let detection = BehaviorAnalyzer::new().analyze_event(&event(
        EventType::NetworkConnection,
        "TCP: [::1]:12345 -> [2001:db8::2]:4444",
    ));

    assert_eq!(detection.unwrap().level, ThreatLevel::High);
}

#[test]
fn network_detection_accepts_monitor_state_annotations() {
    let detection = BehaviorAnalyzer::new().analyze_event(&event(
        EventType::NetworkConnection,
        "Observed TCP endpoint for PID 42: 127.0.0.1:12345 -> 192.0.2.1:4444 (state 5)",
    ));

    assert_eq!(detection.unwrap().level, ThreatLevel::High);
}

#[test]
fn file_modifications_and_deletions_are_counted() {
    let mut analyzer = BehaviorAnalyzer::new();

    for event_type in [EventType::FileModified, EventType::FileDeleted] {
        assert!(analyzer
            .analyze_event(&event(event_type, "document.txt"))
            .is_none());
    }

    assert_eq!(analyzer.file_operations, 2);
    assert_eq!(analyzer.file_creation_count, 0);
}
