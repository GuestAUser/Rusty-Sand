//! Example: Basic usage of Rusty Sand library
//!
//! This example demonstrates how to use Rusty Sand as a library
//! to execute a program in a sandboxed environment and analyze the results.
//!
//! Run with: cargo run --example basic_usage

use rusty_sand::{execute_sandboxed, SandboxConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🏖️  Rusty Sand - Basic Usage Example\n");

    // Configure the sandbox
    let config = SandboxConfig::new()
        .with_internet(false) // No internet access (secure default)
        .with_timeout(Duration::from_secs(30))
        .with_memory_limit(512) // 512 MB memory limit
        .with_verbose(true);

    println!("Executing notepad.exe in sandbox...\n");

    // Execute notepad in the sandbox
    let report = execute_sandboxed(
        "C:\\Windows\\System32\\notepad.exe",
        &[],
        config,
    )
    .await?;

    // Analyze the results
    println!("\n📊 Analysis Results:");
    println!("═══════════════════════════════════════");
    println!("Total events captured: {}", report.events.len());
    println!("Duration: {} seconds", report.duration_seconds);
    println!("Exit code: {}", report.exit_code);

    // Get specific event types
    let file_events = report.get_file_events();
    let network_events = report.get_network_events();

    println!("\n📁 File Operations: {}", file_events.len());
    for event in file_events.iter().take(5) {
        println!("  - {:?}: {}", event.event_type, event.details);
    }

    println!("\n🌐 Network Activity: {}", network_events.len());
    for event in network_events {
        println!("  - {:?}: {}", event.event_type, event.details);
    }

    // Save detailed JSON report
    let json_path = std::path::Path::new("./example_report.json");
    report.save_json(json_path)?;
    println!("\n✅ Full report saved to: {}", json_path.display());

    Ok(())
}
