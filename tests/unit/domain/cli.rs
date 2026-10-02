use super::*;
use clap::error::ErrorKind;

#[test]
fn preserves_defaults_when_only_executable_is_given() {
    let command = ["rusty_sand", "notepad.exe"];

    let args = Args::try_parse_from(command).expect("valid executable");

    assert_eq!(args.executable, "notepad.exe");
    assert!(args.args.is_empty());
    assert_eq!(args.timeout, 300);
    assert_eq!(args.max_memory, 1024);
    assert_eq!(args.format, ReportFormat::Both);
    assert_eq!(args.output_dir, PathBuf::from("./sandbox_output"));
    assert_eq!(args.working_dir, None);
    assert!(!args.internet);
    assert!(!args.dns);
    assert!(!args.verbose);
    assert_eq!(args.color, ColorChoice::Auto);
    assert!(!args.plain);
    assert!(!args.reduced_motion);
    assert!(!args.log_network);
    assert!(!args.no_registry);
    assert!(!args.no_interactive);
    assert!(!args.no_behavior_detection);
}

#[test]
fn rejects_unknown_report_format() {
    let command = ["rusty_sand", "notepad.exe", "--format", "xml"];

    let error = Args::try_parse_from(command).expect_err("unknown format");

    assert_eq!(error.kind(), ErrorKind::InvalidValue);
}

#[test]
fn analysis_modes_preserve_execution_as_the_default() {
    let defaults = Args::try_parse_from(["rusty_sand", "sample.exe"]).unwrap();

    assert_eq!(defaults.mode(), AnalysisMode::Execute);
    assert!(!defaults.static_only);
    assert!(!defaults.debug_mode);
    assert!(!defaults.shell_mode);
    assert!(!defaults.restricted);
}

#[test]
fn analysis_modes_are_mutually_exclusive() {
    for modes in [
        ["--static", "--debug"],
        ["--static", "--shell"],
        ["--debug", "--shell"],
        ["--static", "--restricted"],
    ] {
        let error =
            Args::try_parse_from(["rusty_sand", "sample.exe", modes[0], modes[1]]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }
}

#[test]
fn analysis_flags_after_separator_remain_target_arguments() {
    let args = Args::try_parse_from([
        "rusty_sand",
        "sample.exe",
        "--",
        "--static",
        "--debug",
        "--shell",
        "--restricted",
    ])
    .unwrap();

    assert!(!args.static_only);
    assert!(!args.debug_mode);
    assert!(!args.shell_mode);
    assert!(!args.restricted);
    assert_eq!(
        args.args,
        ["--static", "--debug", "--shell", "--restricted"]
    );
}

#[test]
fn restricted_execution_is_available_in_debug_and_shell_modes() {
    for mode in ["--debug", "--shell"] {
        let args =
            Args::try_parse_from(["rusty_sand", "sample.exe", mode, "--restricted"]).unwrap();

        assert!(args.restricted);
        assert_eq!(args.debug_mode, mode == "--debug");
        assert_eq!(args.shell_mode, mode == "--shell");
    }
}

#[test]
fn selects_the_backend_mode_without_reinterpreting_target_arguments() {
    for (flag, expected) in [
        ("--static", AnalysisMode::Static),
        ("--debug", AnalysisMode::Debug),
        ("--shell", AnalysisMode::Shell),
    ] {
        let args = Args::try_parse_from([
            "rusty_sand",
            "sample.exe",
            flag,
            "--",
            "--debug",
            "--restricted",
        ])
        .unwrap();

        assert_eq!(args.mode(), expected);
        assert_eq!(args.args, ["--debug", "--restricted"]);
        assert!(!args.restricted);
    }
}

#[test]
fn restricted_policy_reaches_every_execution_configuration() {
    for mode in [None, Some("--debug"), Some("--shell")] {
        let mut command = vec![
            "rusty_sand",
            "sample.exe",
            "--restricted",
            "--no-interactive",
        ];

        if let Some(mode) = mode {
            command.push(mode);
        }

        let args = Args::try_parse_from(command).unwrap();
        let config = args.sandbox_config();

        assert!(config.restricted_token);
        assert!(!config.interactive_mode);
        assert_eq!(config.enable_api_hooks, mode != Some("--debug"));
        assert_eq!(config.enable_behavior_detection, mode != Some("--debug"));
    }

    let args = Args::try_parse_from(["rusty_sand", "sample.exe"]).unwrap();

    assert!(!args.sandbox_config().restricted_token);
}

#[test]
fn execution_configuration_preserves_existing_options() {
    let args = Args::try_parse_from([
        "rusty_sand",
        "sample.exe",
        "--internet",
        "--timeout",
        "17",
        "--memory",
        "64",
        "--workdir",
        "work",
        "--output",
        "reports",
        "--verbose",
        "--log-network",
        "--no-registry",
        "--no-behavior-detection",
    ])
    .unwrap();
    let config = args.sandbox_config();

    assert!(config.allow_internet);
    assert!(config.allow_dns);
    assert_eq!(config.timeout.as_secs(), 17);
    assert_eq!(config.max_memory_mb, 64);
    assert_eq!(config.working_dir, Some(PathBuf::from("work")));
    assert_eq!(config.output_dir, PathBuf::from("reports"));
    assert!(config.verbose);
    assert!(config.log_network_packets);
    assert!(!config.allow_registry);
    assert!(!config.enable_behavior_detection);
    assert!(config.enable_api_hooks);
    assert!(config.interactive_mode);
}

#[test]
fn unknown_flags_are_rejected_in_every_mode() {
    for mode in [None, Some("--static"), Some("--debug"), Some("--shell")] {
        let mut command = vec!["rusty_sand", "sample.exe", "--unknown-analysis-option"];

        if let Some(mode) = mode {
            command.push(mode);
        }

        let error = Args::try_parse_from(command).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }
}

#[test]
fn accepts_each_report_format() {
    for (value, expected) in [
        ("console", ReportFormat::Console),
        ("json", ReportFormat::Json),
        ("both", ReportFormat::Both),
    ] {
        let command = ["rusty_sand", "notepad.exe", "--format", value];

        let args = Args::try_parse_from(command).expect("supported format");

        assert_eq!(args.format, expected);
    }
}

#[test]
fn forwards_arguments_after_separator_without_parsing_them() {
    let command = [
        "rusty_sand",
        "target.exe",
        "--timeout",
        "60",
        "--",
        "--format",
        "xml",
        "--internet",
        "a b",
        "",
        "--",
    ];

    let args = Args::try_parse_from(command).expect("target arguments");

    assert_eq!(
        args.args,
        ["--format", "xml", "--internet", "a b", "", "--"]
    );
    assert_eq!(args.timeout, 60);
    assert_eq!(args.format, ReportFormat::Both);
    assert!(!args.internet);
}

#[test]
fn rejects_malformed_numeric_arguments() {
    for option in ["--timeout", "--memory"] {
        let command = ["rusty_sand", "notepad.exe", option, "invalid"];

        let error = Args::try_parse_from(command).expect_err("invalid number");

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }
}

#[test]
fn presentation_options_preserve_explicit_policy() {
    for (value, expected) in [
        ("auto", ColorMode::Auto),
        ("always", ColorMode::Always),
        ("never", ColorMode::Never),
    ] {
        let args = Args::try_parse_from([
            "rusty_sand",
            "target.exe",
            "--color",
            value,
            "--plain",
            "--reduced-motion",
        ])
        .unwrap();
        let policy = args.output_policy();
        assert_eq!(policy.color, expected);
        assert!(policy.plain);
        assert!(policy.reduced_motion);
    }

    let error =
        Args::try_parse_from(["rusty_sand", "target.exe", "--color", "rainbow"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidValue);
}

#[test]
fn presentation_flags_after_separator_belong_to_target() {
    let args = Args::try_parse_from([
        "rusty_sand",
        "target.exe",
        "--",
        "--color",
        "never",
        "--plain",
    ])
    .unwrap();
    assert_eq!(args.color, ColorChoice::Auto);
    assert!(!args.plain);
    assert_eq!(args.args, ["--color", "never", "--plain"]);
}
