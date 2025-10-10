//! Example: Advanced monitoring and analysis
//!
//! This example demonstrates advanced features like:
//! - Custom security policies
//! - Event filtering and analysis
//! - Threat detection patterns
//!
//! Run with: cargo run --example advanced_monitoring

use rusty_sand::{execute_sandboxed, SandboxConfig};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    println!("🔬 Rusty Sand - Advanced Monitoring Example\n");

    // Strict security configuration
    let mut config = SandboxConfig::new()
        .with_internet(false)
        .with_timeout(Duration::from_secs(60))
        .with_working_dir(PathBuf::from("C:\\Temp"))
        .with_memory_limit(256)
        .with_verbose(true)
        .with_output_dir(PathBuf::from("./advanced_output"));

    // Additional configuration
    config.allow_dns = false;
    config.allow_registry = true; // Monitor but allow
    config.allowed_file_patterns = vec![
        "*.txt".to_string(),
        "*.log".to_string(),
    ];
    config.max_cpu_time = 30;
    config.log_network_packets = true;
    config.enable_api_hooks = false;

    println!("⚙️  Security Configuration:");
    println!("  Internet: BLOCKED");
    println!("  Memory Limit: {} MB", config.max_memory_mb);
    println!("  CPU Limit: {} seconds", config.max_cpu_time);
    println!("  Network Logging: {}", config.log_network_packets);
    println!();

    // Example: Analyze a PowerShell script
    let executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    let args = vec![
        "-Command".to_string(),
        "Get-Process | Select-Object -First 5".to_string(),
    ];

    println!("🚀 Executing: {} with args", executable);
    println!();

    let report = execute_sandboxed(executable, &args, config).await?;

    // Advanced analysis
    println!("\n🔍 Advanced Analysis:");
    println!("═══════════════════════════════════════");

    // Check for suspicious patterns
    let suspicious_keywords = vec![
        "Download",
        "Invoke-WebRequest",
        "curl",
        "wget",
        "Start-Process",
        "IEX",
        "Invoke-Expression",
    ];

    let mut suspicious_count = 0;
    for event in &report.events {
        for keyword in &suspicious_keywords {
            if event.details.contains(keyword) {
                suspicious_count += 1;
                println!("⚠️  Suspicious activity detected: {}", event.details);
            }
        }
    }

    if suspicious_count == 0 {
        println!("✅ No suspicious patterns detected");
    }

    // Network analysis
    let network_events = report.get_network_events();
    if !network_events.is_empty() {
        println!("\n🌐 Network Activity Analysis:");
        for event in network_events {
            println!("  {:?}: {}", event.event_type, event.details);
        }
    } else {
        println!("\n✅ No network activity detected");
    }

    // File system analysis
    let file_events = report.get_file_events();
    println!("\n📁 File System Activity:");
    println!("  Total file operations: {}", file_events.len());

    let mut created = 0;
    let mut modified = 0;
    let mut deleted = 0;

    for event in file_events {
        match event.event_type {
            rusty_sand::report::EventType::FileCreated => created += 1,
            rusty_sand::report::EventType::FileModified => modified += 1,
            rusty_sand::report::EventType::FileDeleted => deleted += 1,
            _ => {}
        }
    }

    println!("  Created: {}", created);
    println!("  Modified: {}", modified);
    println!("  Deleted: {}", deleted);

    // Generate risk score
    let risk_score = calculate_risk_score(&report);
    println!("\n📊 Risk Assessment:");
    println!("  Risk Score: {} / 100", risk_score);
    println!(
        "  Risk Level: {}",
        match risk_score {
            0..=30 => "LOW ✅",
            31..=60 => "MEDIUM ⚠️",
            61..=80 => "HIGH 🔶",
            _ => "CRITICAL 🚨",
        }
    );

    // Save report
    report.print_summary();

    Ok(())
}

fn calculate_risk_score(report: &rusty_sand::SandboxReport) -> u32 {
    let mut score = 0u32;

    // Network attempts when blocked
    for event in &report.events {
        match event.event_type {
            rusty_sand::report::EventType::NetworkBlocked => score += 15,
            rusty_sand::report::EventType::ProcessCreated => score += 5,
            rusty_sand::report::EventType::FileDeleted => score += 3,
            _ => {}
        }
    }

    // Cap at 100
    score.min(100)
}
