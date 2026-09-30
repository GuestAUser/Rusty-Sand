//! Observe a benign PowerShell process listing and inspect recorded events.
//!
//! Run manually on Windows with: cargo run --example advanced_monitoring
//! Event counts describe observations, not complete system activity or proof
//! that an operation was prevented. Run untrusted programs in a disposable VM.

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "This example requires Windows",
    )
    .into())
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use rusty_sand::report::EventType;
    use rusty_sand::{execute_sandboxed, SandboxConfig};
    use std::path::PathBuf;
    use std::time::Duration;

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .context("Failed to initialize logging")?;

    let mut config = SandboxConfig::new()
        .with_internet(false)
        .with_timeout(Duration::from_secs(60))
        .with_memory_limit(256)
        .with_verbose(true)
        .with_output_dir(PathBuf::from("./advanced_output"));

    /*
     * This demonstration uses observational monitors without DLL hooks. Turning
     * off approval also avoids implying that observations can stop an action.
     */
    config.enable_api_hooks = false;
    config.interactive_mode = false;
    config.max_cpu_time = 30;

    let executable = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let args = vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        "Get-Process | Select-Object -First 5".to_string(),
    ];

    println!("Running a PowerShell process listing with observational monitoring.");
    println!("No API hooks are installed; the network policy is not containment.");

    let report = execute_sandboxed(executable, &args, config).await?;
    let network_events = report.get_network_events();
    println!("Network events recorded: {}", network_events.len());

    for event in network_events {
        println!("  {:?}: {}", event.event_type, event.details);
    }

    let file_events = report.get_file_events();
    let created = file_events
        .iter()
        .filter(|event| matches!(event.event_type, EventType::FileCreated))
        .count();
    let modified = file_events
        .iter()
        .filter(|event| matches!(event.event_type, EventType::FileModified))
        .count();
    let deleted = file_events
        .iter()
        .filter(|event| matches!(event.event_type, EventType::FileDeleted))
        .count();

    println!("File events recorded: {}", file_events.len());
    println!("  Created: {created}");
    println!("  Modified: {modified}");
    println!("  Deleted: {deleted}");
    println!("A missing event does not establish that no activity occurred.");

    report.print_summary();

    Ok(())
}
