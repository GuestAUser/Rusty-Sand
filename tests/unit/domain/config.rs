use super::*;

#[test]
fn default_configuration_does_not_request_unsupported_enforcement() {
    assert_eq!(SandboxConfig::new().validate(), Ok(()));
}

#[test]
fn stdin_control_requires_runtime_opt_in_and_is_not_serialized_policy() {
    let mut config = SandboxConfig::new();
    assert!(!config.cancel_on_stdin_eof);
    config.cancel_on_stdin_eof = true;

    let policy = serde_json::to_value(&config).unwrap();
    assert!(policy.get("cancel_on_stdin_eof").is_none());
    let decoded: SandboxConfig = serde_json::from_value(policy).unwrap();
    assert!(!decoded.cancel_on_stdin_eof);
}

#[test]
fn filesystem_allowlist_is_rejected_instead_of_silently_ignored() {
    let config = SandboxConfig {
        allowed_file_patterns: vec![r"C:\Allowed\*".into()],
        ..SandboxConfig::default()
    };

    assert_eq!(config.validate(), Err(ConfigError::UnsupportedFilePatterns));
}

#[test]
fn internet_builder_preserves_independent_dns_policy() {
    let default = SandboxConfig::new();
    assert!(!default.allow_internet);
    assert!(!default.allow_dns);

    let enabled = default.with_internet(true);
    assert!(enabled.allow_internet);
    assert!(enabled.allow_dns);

    let disabled = enabled.with_internet(false);
    assert!(!disabled.allow_internet);
    assert!(disabled.allow_dns);
}

#[test]
fn configuration_round_trip_preserves_units_and_paths() {
    let config = SandboxConfig::new()
        .with_timeout(Duration::new(12, 345))
        .with_memory_limit(0)
        .with_working_dir(PathBuf::from("work"))
        .with_output_dir(PathBuf::from("output"));
    let json = serde_json::to_value(&config).unwrap();
    let decoded: SandboxConfig = serde_json::from_value(json.clone()).unwrap();

    assert_eq!(decoded.timeout, Duration::new(12, 345));
    assert_eq!(decoded.max_memory_mb, 0);
    assert_eq!(decoded.working_dir, Some(PathBuf::from("work")));
    assert_eq!(serde_json::to_value(decoded).unwrap(), json);
}
