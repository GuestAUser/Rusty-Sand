mod cli;

use clap::Parser;
use cli::Args;

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    Args::parse();

    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Rusty Sand execution requires Windows",
    )
    .into())
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use cli::ReportFormat;
    use rusty_sand::{execute_sandboxed, SandboxConfig};
    use std::time::Duration;

    let args = Args::parse();
    let log_level = if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .try_init()
        .context("Failed to initialize logging")?;

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
    config.enable_behavior_detection = !args.no_behavior_detection;

    eprintln!("Monitoring is not a security boundary. Use a disposable Windows VM for untrusted programs.");
    log::info!("Starting execution: {}", args.executable);

    let mut report = execute_sandboxed(&args.executable, &args.args, config)
        .await
        .with_context(|| format!("Failed to execute {}", args.executable))?;
    report.executable = args.executable;

    match args.format {
        ReportFormat::Console => report.print_summary(),
        ReportFormat::Json => {}
        ReportFormat::Both => report.print_summary(),
    }

    match args.format {
        ReportFormat::Console => {}
        ReportFormat::Json | ReportFormat::Both => {
            let json_path = args.output_dir.join("report.json");
            report
                .save_json(&json_path)
                .with_context(|| format!("Failed to save report to {}", json_path.display()))?;
            println!("JSON report saved to: {}", json_path.display());
        }
    }

    Ok(())
}
