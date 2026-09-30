mod cli;

use clap::Parser;
use cli::Args;
use rusty_sand::ui::{self, Panel, Tone};
use std::process::ExitCode;

#[cfg(not(windows))]
fn main() -> ExitCode {
    let args = Args::parse();
    finish(
        ui::configure(args.output_policy())
            .map_err(anyhow::Error::from)
            .and_then(|()| {
                anyhow::bail!("Rusty Sand execution requires Windows; from WSL use ./rusty-sand")
            }),
    )
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> ExitCode {
    finish(run(Args::parse()).await)
}

fn finish(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let panel = Panel {
                title: "Session ended".into(),
                tone: Tone::Danger,
                fields: vec![("Reason".into(), format!("{error:#}"))],
                notes: vec![],
            };

            if let Err(output_error) = ui::terminal().panel(&panel) {
                eprintln!("Cannot render session error: {output_error}; session error: {error:#}");
            }

            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
struct RendererLogger(env_logger::Logger);

#[cfg(windows)]
impl log::Log for RendererLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        log::Log::enabled(&self.0, metadata)
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.0.matches(record) {
            ui::terminal().diagnostic(record.level(), &record.args().to_string());
        }
    }

    fn flush(&self) {}
}

#[cfg(windows)]
async fn run(args: Args) -> anyhow::Result<()> {
    use anyhow::Context;
    use cli::ReportFormat;
    use rusty_sand::{execute_sandboxed, SandboxConfig};
    use std::time::Duration;

    let policy = args.output_policy();
    ui::configure(policy)?;

    /* env_logger remains the filter parser, including module directives and
     * regex filtering. Only its sink is replaced, so diagnostics participate
     * in the renderer's short-held prompt/output synchronization. */
    let logger = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "info" }),
    )
    .build();
    let filter = logger.filter();
    log::set_boxed_logger(Box::new(RendererLogger(logger)))
        .context("Failed to initialize logging")?;
    log::set_max_level(filter);

    let mut config = SandboxConfig::new()
        .with_internet(args.internet)
        .with_timeout(Duration::from_secs(args.timeout))
        .with_output_dir(args.output_dir.clone())
        .with_memory_limit(args.max_memory)
        .with_verbose(args.verbose);

    config.working_dir = args.working_dir;
    config.allow_dns = args.dns || args.internet;
    config.log_network_packets = args.log_network;
    config.allow_registry = !args.no_registry;
    config.interactive_mode = !args.no_interactive;
    config.cancel_on_stdin_eof = std::env::var("RUSTY_SAND_STDIN_CONTROL").as_deref() == Ok("1");
    config.enable_behavior_detection = !args.no_behavior_detection;

    ui::terminal().panel(&Panel {
        title: "Effective configuration".into(),
        tone: Tone::Heading,
        fields: vec![
            ("Target".into(), args.executable.clone()),
            ("Arguments".into(), format!("{:?}", args.args)),
            ("Reports".into(), config.output_dir.display().to_string()),
            ("Working directory".into(), config.working_dir.as_ref().map_or_else(|| "Inherited".into(), |path| path.display().to_string())),
            ("Timeout".into(), format!("{} seconds", config.timeout.as_secs())),
            ("Memory limit".into(), format!("{} MB (0 = unlimited)", config.max_memory_mb)),
            ("CPU limit".into(), format!("{} seconds (0 = unlimited)", config.max_cpu_time)),
            ("Internet / DNS".into(), format!("{} / {}", if config.allow_internet { "ALLOW" } else { "DENY" }, if config.allow_dns { "ALLOW" } else { "DENY" })),
            ("Registry".into(), if config.allow_registry { "ALLOW" } else { "DENY" }.into()),
            ("Hooks / interactive".into(), format!("{} / {}", if config.enable_api_hooks { "ON" } else { "OFF" }, if config.interactive_mode { "ON" } else { "OFF" })),
            ("Behavior analysis".into(), if config.enable_behavior_detection { "ON" } else { "OFF" }.into()),
        ],
        notes: vec![
            "Monitoring is not a security boundary. Use a disposable Windows VM for untrusted programs.".into(),
            "Ctrl-C cancels the session and cleans up the target. Interactive input EOF also cancels.".into(),
        ],
    })?;

    let mut report = execute_sandboxed(&args.executable, &args.args, config)
        .await
        .with_context(|| format!("Failed to execute {}", args.executable))?;
    report.executable = args.executable;

    if matches!(args.format, ReportFormat::Console | ReportFormat::Both) {
        report.write_summary(&mut std::io::stderr().lock(), &policy)?;
    }

    if args.format == ReportFormat::Json {
        ui::terminal().status(
            &format!(
                "Target exit code {}; {} recorded events",
                report.exit_code,
                report.events.len()
            ),
            if report.exit_code == 0 {
                Tone::Success
            } else {
                Tone::Warning
            },
        )?;
    }

    if matches!(args.format, ReportFormat::Json | ReportFormat::Both) {
        let json_path = args.output_dir.join("report.json");
        report
            .save_json(&json_path)
            .with_context(|| format!("Failed to save report to {}", json_path.display()))?;
        ui::terminal().status(
            &format!("JSON report saved to: {}", json_path.display()),
            Tone::Success,
        )?;
    }

    Ok(())
}
