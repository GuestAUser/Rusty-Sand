use super::*;
use crate::report::EventType;
use serde_json::json;

fn execution(events: Vec<Event>) -> SandboxReport {
    let now = Utc::now();

    SandboxReport {
        executable: "fixture.exe".into(),
        start_time: now,
        end_time: now,
        duration_seconds: 0,
        events,
        exit_code: 7,
        config: SandboxConfig::default(),
    }
}

#[test]
fn preserves_static_and_original_behavior_evidence_without_changing_execution_report() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.bin");
    std::fs::write(&input, b"ordinary bytes https://example.invalid/fixture").unwrap();

    let mut analysis = AnalysisReport::inspect(input.to_str().unwrap(), AnalysisMode::Execute);
    let static_before = serde_json::to_value(&analysis.static_analysis).unwrap();
    let report = execution(vec![Event {
        timestamp: Utc::now(),
        event_type: EventType::HookNetworkConnect,
        details: "Denied hook request from PID 10: Connect to example.invalid:443 (policy)".into(),
    }]);
    let original = serde_json::to_value(&report).unwrap();

    analysis.record_execution(&report);

    let artifact = directory.path().join("analysis.json");
    analysis.save_json(&artifact).unwrap();
    let bytes = std::fs::read(&artifact).unwrap();
    let restored: AnalysisReport = serde_json::from_slice(&bytes).unwrap();
    let value = serde_json::to_value(restored).unwrap();

    assert_eq!(serde_json::to_value(&report).unwrap(), original);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["mode"], "execute");
    assert_eq!(value["execution"], json!({"status": "exited", "code": 7}));
    assert_eq!(value["static_analysis"], static_before);
    assert_eq!(value["events"], original["events"]);
    assert_eq!(value["behavior"]["status"], "collected");
    assert_eq!(value["behavior"]["report"]["coverage"]["input_events"], 1);
    assert_eq!(
        value["behavior"]["report"]["findings"][0]["status"],
        "denied"
    );
    assert_eq!(
        value["behavior"]["report"]["findings"][0]["evidence"][0]["event_index"],
        0
    );
}

#[test]
fn disabled_behavior_is_unavailable_not_an_empty_clean_assessment() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.bin");
    std::fs::write(&input, b"fixture").unwrap();

    let mut analysis = AnalysisReport::inspect(input.to_str().unwrap(), AnalysisMode::Execute);
    let mut report = execution(vec![Event {
        timestamp: Utc::now(),
        event_type: EventType::NetworkBlocked,
        details: "fixture endpoint".into(),
    }]);
    report.config.enable_behavior_detection = false;

    analysis.record_execution(&report);

    let value = serde_json::to_value(&analysis).unwrap();

    assert_eq!(value["behavior"]["status"], "unavailable");
    assert_eq!(
        value["events"],
        serde_json::to_value(&report.events).unwrap()
    );
    assert!(value["behavior"].get("report").is_none());
}

#[test]
fn failed_static_inspection_does_not_claim_collection_or_execution() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("missing");
    let analysis = AnalysisReport::inspect(input.to_str().unwrap(), AnalysisMode::Static);
    let value = serde_json::to_value(analysis).unwrap();

    assert_eq!(value["static_analysis"]["status"], "failed");
    assert_eq!(value["execution"]["status"], "not_requested");
    assert_eq!(value["behavior"]["status"], "unavailable");
    assert!(value["static_analysis"].get("report").is_none());
    assert_eq!(value["events"], json!([]));
}

#[test]
fn recording_execution_failure_retains_successful_static_inspection() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.bin");
    std::fs::write(&input, b"fixture").unwrap();

    let mut analysis = AnalysisReport::inspect(input.to_str().unwrap(), AnalysisMode::Debug);
    let before = serde_json::to_value(&analysis.static_analysis).unwrap();
    analysis.execution = ExecutionOutcome::Failed {
        error: "backend failure".into(),
    };
    let value = serde_json::to_value(analysis).unwrap();

    assert_eq!(value["execution"]["status"], "failed");
    assert_eq!(value["static_analysis"], before);
    assert_eq!(value["behavior"]["status"], "unavailable");
}

#[test]
fn malformed_pe_coverage_is_preserved_in_collected_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("malformed.exe");
    std::fs::write(&input, b"MZ").unwrap();

    let analysis = AnalysisReport::inspect(input.to_str().unwrap(), AnalysisMode::Static);
    let value = serde_json::to_value(analysis).unwrap();

    assert_eq!(value["static_analysis"]["status"], "collected");
    assert_eq!(
        value["static_analysis"]["report"]["coverage"]["pe_status"],
        "malformed"
    );
    assert!(value["static_analysis"]["report"]["pe"].is_null());
    assert_eq!(value["execution"]["status"], "not_requested");
}
