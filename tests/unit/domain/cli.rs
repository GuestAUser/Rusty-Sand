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
