mod cli;
mod commands;

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
            .and_then(|()| commands::run_portable(&args)),
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
    use rusty_sand::report::analysis::AnalysisMode;

    let policy = args.output_policy();
    ui::configure(policy)?;

    if args.mode() == AnalysisMode::Static {
        return commands::run_static(&args);
    }

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

    let config = args.sandbox_config();

    ui::terminal().panel(&Panel {
        title: "Effective configuration".into(),
        tone: Tone::Heading,
        fields: vec![
            ("Mode".into(), format!("{:?}", args.mode())),
            ("Target".into(), args.executable.clone()),
            ("Arguments".into(), format!("{:?}", args.args)),
            ("Reports".into(), config.output_dir.display().to_string()),
            ("Working directory".into(), config.working_dir.as_ref().map_or_else(|| "Inherited".into(), |path| path.display().to_string())),
            ("Timeout".into(), format!("{} seconds", config.timeout.as_secs())),
            ("Memory limit".into(), format!("{} MB (0 = unlimited)", config.max_memory_mb)),
            ("CPU limit".into(), format!("{} seconds (0 = unlimited)", config.max_cpu_time)),
            ("Requested internet / DNS".into(), format!("{} / {}", if config.allow_internet { "ALLOW" } else { "DENY" }, if config.allow_dns { "ALLOW" } else { "DENY" })),
            ("Requested registry policy".into(), if config.allow_registry { "ALLOW" } else { "DENY" }.into()),
            ("Hooks / interactive".into(), format!("{} / {}", if config.enable_api_hooks { "ON" } else { "OFF" }, if config.interactive_mode { "ON" } else { "OFF" })),
            ("Behavior analysis".into(), if config.enable_behavior_detection { "ON" } else { "OFF" }.into()),
            ("Restricted token".into(), if config.restricted_token { "REQUIRED" } else { "OFF" }.into()),
        ],
        notes: vec![
            "Monitoring is not a security boundary. Use a disposable Windows VM for untrusted programs.".into(),
            "Ctrl-C cancels the session and cleans up the target. Interactive input EOF also cancels.".into(),
            "Debug mode does not inject hooks or enforce hook-based internet, DNS, registry, or filesystem policy.".into(),
        ],
    })?;

    commands::run_windows(args, config, policy).await
}
