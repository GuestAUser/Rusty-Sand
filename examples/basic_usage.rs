//! Launch Notepad and save the observed activity to example_report.json.
//!
//! Run manually on Windows with: cargo run --example basic_usage
//! Monitoring is incomplete and is not a security boundary. Use a disposable VM
//! when adapting this example to untrusted programs.

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
    use rusty_sand::{execute_sandboxed, SandboxConfig};
    use std::path::Path;
    use std::time::Duration;

    env_logger::try_init().context("Failed to initialize logging")?;

    let config = SandboxConfig::new()
        .with_internet(false)
        .with_timeout(Duration::from_secs(30))
        .with_memory_limit(512)
        .with_verbose(true);

    println!("Launching Notepad. Close its window to finish the demonstration.");
    println!("The network policy does not guarantee network isolation.");

    let report = execute_sandboxed(r"C:\Windows\System32\notepad.exe", &[], config).await?;

    println!("Events recorded: {}", report.events.len());
    println!("Duration: {} seconds", report.duration_seconds);
    println!("Exit code: {}", report.exit_code);

    let file_events = report.get_file_events();
    println!("File events: {}", file_events.len());

    for event in file_events.iter().take(5) {
        println!("  {:?}: {}", event.event_type, event.details);
    }

    let network_events = report.get_network_events();
    println!("Network events: {}", network_events.len());

    for event in network_events {
        println!("  {:?}: {}", event.event_type, event.details);
    }

    let json_path = Path::new("./example_report.json");
    report.save_json(json_path)?;
    println!("Report saved to: {}", json_path.display());

    Ok(())
}
