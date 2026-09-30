use super::*;

#[test]
fn category_boundaries_are_inclusive() {
    for (score, category) in [
        (0, ThreatCategory::Low),
        (30, ThreatCategory::Low),
        (31, ThreatCategory::Medium),
        (60, ThreatCategory::Medium),
        (61, ThreatCategory::High),
        (85, ThreatCategory::High),
        (86, ThreatCategory::Critical),
        (100, ThreatCategory::Critical),
    ] {
        assert_eq!(ThreatCategory::from_score(score), category);
    }
}

#[test]
fn overlapping_indicators_saturate_instead_of_overflowing() {
    let operations = [
        HookOperation::ProcessCreate {
            executable: r"C:\Temp\powershell-wscript.exe".into(),
            args: "-enc Zg== DownloadString -nop -w hidden".into(),
            creation_flags: 0,
        },
        HookOperation::RegistryDelete {
            key: r"HKCU\Run\Environment\windir\Windows Defender\Policies\System".into(),
        },
        HookOperation::FileCreate {
            path: r"C:\Windows\System32\Startup\Program Files\Temp\file.crypt.exe".into(),
            access_rights: 0,
            share_mode: 0,
            creation_disposition: 0,
            flags_and_attributes: 0,
        },
    ];

    for operation in operations {
        let risk = analyze_operation(&operation);

        assert_eq!(risk.score, 100);
        assert_eq!(risk.category, ThreatCategory::Critical);
    }
}

#[test]
fn memory_protection_modifiers_preserve_base_risk() {
    for protection in [0x10, 0x20, 0x40, 0x80] {
        assert_eq!(
            analyze_memory_allocate(protection, 4096),
            analyze_memory_allocate(protection | 0x100, 4096)
        );
        assert_eq!(
            analyze_memory_protect(0x04, protection),
            analyze_memory_protect(0x04, protection | 0x100)
        );
        assert!(analyze_memory_protect(0x04, protection) >= 80);
    }

    assert_eq!(analyze_memory_protect(0x20, 0x20), 35);
    assert_eq!(analyze_memory_allocate(0x04, 4096), 30);
    assert_eq!(analyze_memory_allocate(0x40, 10_000_000), 95);
    assert_eq!(analyze_memory_allocate(0x40, 10_000_001), 115);
}

#[test]
fn network_address_and_transfer_boundaries() {
    for address in [
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "127.0.0.1",
        "::1",
        "fd00::1",
        "::ffff:192.168.0.1",
    ] {
        assert_eq!(analyze_network_connect(address, 443), 10, "{address}");
    }

    for address in [
        "172.15.255.255",
        "172.32.0.0",
        "192.0.2.1",
        "not-an-ip",
        "10.0.0.999",
        "2001:db8::1",
    ] {
        assert_eq!(analyze_network_connect(address, 443), 45, "{address}");
    }

    assert_eq!(analyze_network_send(443, 100_000), 15);
    assert_eq!(analyze_network_send(443, 100_001), 35);
    assert_eq!(analyze_network_send(443, 1_000_000), 35);
    assert_eq!(analyze_network_send(443, 1_000_001), 55);
}

#[test]
fn registry_startup_keys_require_component_boundaries() {
    assert_eq!(analyze_registry_set(r"HKCU\Software\Runtime", 0), 25);
    assert_eq!(analyze_registry_set(r"HKCU\Software\RUNONCE", 0), 90);
    assert_eq!(analyze_registry_open(r"HKCU\Run", 0x20019), 5);
}

#[test]
fn test_risk_categories() {
    assert_eq!(ThreatCategory::from_score(15), ThreatCategory::Low);
    assert_eq!(ThreatCategory::from_score(45), ThreatCategory::Medium);
    assert_eq!(ThreatCategory::from_score(75), ThreatCategory::High);
    assert_eq!(ThreatCategory::from_score(95), ThreatCategory::Critical);
}

#[test]
fn test_suspicious_operations() {
    let op = HookOperation::ThreadCreateRemote {
        target_process_id: 1234,
        start_address: 0x12345678,
    };
    let risk = analyze_operation(&op);
    assert!(risk.score >= 90);
    assert_eq!(risk.category, ThreatCategory::Critical);
}

#[test]
fn memory_write_without_origin_does_not_assume_monitor_owns_the_request() {
    let operation = HookOperation::MemoryWrite {
        target_process_id: std::process::id(),
        base_address: 4096,
        bytes_to_write: 8,
    };

    let risk = analyze_operation(&operation);

    assert_eq!(risk.score, 85);
    assert_eq!(risk.category, ThreatCategory::High);
}

#[test]
fn request_scoring_distinguishes_self_writes_from_foreign_writes() {
    let monitor_pid = std::process::id();
    let foreign_pid = if monitor_pid == 1 { 2 } else { 1 };

    for (origin, target, expected_score) in [
        (42, 42, 35),
        (42, 43, 85),
        (0, 0, 85),
        (foreign_pid, monitor_pid, 85),
    ] {
        let request = HookRequest {
            operation: HookOperation::MemoryWrite {
                target_process_id: target,
                base_address: 4096,
                bytes_to_write: 8,
            },
            pid: origin,
            tid: 1,
        };

        let risk = analyze_request(&request);

        assert_eq!(risk.score, expected_score);
        assert_eq!(risk.category, ThreatCategory::from_score(expected_score));
    }
}

#[test]
fn test_read_operations_low_risk() {
    let op = HookOperation::FileRead {
        path: "C:\\Users\\test\\document.txt".to_string(),
    };
    let risk = analyze_operation(&op);
    assert!(risk.score <= 30);
}
