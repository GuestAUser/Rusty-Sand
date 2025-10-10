use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use log::info;
use rusty_sand::{execute_sandboxed, SandboxConfig};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "rusty_sand")]
#[command(author = "GuestAUser")]
#[command(version = "0.1.0")]
#[command(about = "Advanced Windows sandbox with Host Intrusion Prevention System (HIPS)")]
#[command(long_about = "Rusty Sand - nice executable sandbox for security analysis

Features:
  • Host Intrusion Prevention System (HIPS) - pause on EVERY operation
  • Interactive control - approve/block file, registry, network, and process operations
  • Behavioral threat detection - ransomware, persistence, UAC bypass, etc.
  • Real-time monitoring - file system, registry, network, processes
  • Process isolation using Windows Job Objects
  • Comprehensive JSON reporting

Examples:
  # Run with interactive prompts (default)
  rusty_sand suspicious.exe

  # Run with internet access disabled (recommended)
  rusty_sand malware.exe --no-internet

  # Run with custom timeout and memory limit
  rusty_sand test.exe -t 60 -m 512

  # Disable interactive mode (passive monitoring only)
  rusty_sand app.exe --no-interactive

Default: Internet OFF, Interactive ON, Behavior Detection ON")]
struct Args {
    /// Path to executable to run in sandbox (can be absolute or relative path)
    #[arg(value_name = "EXECUTABLE")]
    executable: String,

    /// Arguments to pass to the sandboxed executable
    #[arg(value_name = "ARGS", last = true)]
    args: Vec<String>,

    /// Enable internet access (⚠️ DEFAULT: DISABLED for security)
    #[arg(short = 'i', long = "internet")]
    internet: bool,

    /// Enable DNS resolution (automatically enabled with --internet)
    #[arg(short = 'd', long = "dns")]
    dns: bool,

    /// Maximum execution time in seconds before forceful termination
    #[arg(short = 't', long = "timeout", default_value = "300")]
    timeout: u64,

    /// Working directory for the sandboxed process
    #[arg(short = 'w', long = "workdir")]
    working_dir: Option<PathBuf>,

    /// Output directory where reports will be saved
    #[arg(short = 'o', long = "output", default_value = "./sandbox_output")]
    output_dir: PathBuf,

    /// Report output format: 'console', 'json', or 'both'
    #[arg(short = 'f', long = "format", default_value = "both")]
    format: String,

    /// Maximum memory limit in megabytes (MB)
    #[arg(short = 'm', long = "memory", default_value = "1024")]
    max_memory: u64,

    /// Enable verbose debug output (shows all internal operations)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Enable detailed network packet logging
    #[arg(long = "log-network")]
    log_network: bool,

    /// Completely disable registry access monitoring
    #[arg(long = "no-registry")]
    no_registry: bool,

    /// Disable HIPS interactive mode (run in passive monitoring mode instead of prompting for every operation)
    #[arg(long = "no-interactive")]
    no_interactive: bool,

    /// Disable behavioral threat detection (ransomware, persistence, etc.)
    #[arg(long = "no-behavior-detection")]
    no_behavior_detection: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    print_banner();

    // Build configuration
    let config = SandboxConfig::new()
        .with_internet(args.internet)
        .with_timeout(Duration::from_secs(args.timeout))
        .with_output_dir(args.output_dir.clone())
        .with_memory_limit(args.max_memory)
        .with_verbose(args.verbose);

    let config = if let Some(wd) = args.working_dir {
        config.with_working_dir(wd)
    } else {
        config
    };

    let mut config = config;
    config.allow_dns = args.dns || args.internet;
    config.log_network_packets = args.log_network;
    config.allow_registry = !args.no_registry;
    config.interactive_mode = !args.no_interactive;  // Inverted: true by default, false if --no-interactive
    config.enable_behavior_detection = !args.no_behavior_detection;

    // Print configuration
    println!("{}", "╔════════════════════ CONFIGURATION ════════════════════╗".bright_cyan().bold());
    println!("  📂 Executable:        {}", args.executable.bright_white().bold());
    if !args.args.is_empty() {
        println!("     Arguments:         {}", args.args.join(" ").bright_white());
    }
    println!(
        "  🌐 Internet Access:   {}",
        if config.allow_internet {
            "ENABLED ⚠️ ".bright_red().bold()
        } else {
            "DISABLED ✓".bright_green().bold()
        }
    );
    println!(
        "  🛡️  Interactive Mode:  {}",
        if config.interactive_mode {
            "ENABLED (HIPS)".bright_green().bold()
        } else {
            "DISABLED (Passive)".bright_yellow()
        }
    );
    println!(
        "  🔍 Threat Detection:  {}",
        if config.enable_behavior_detection {
            "ENABLED".bright_green().bold()
        } else {
            "DISABLED".bright_yellow()
        }
    );
    println!("  ⏱️  Timeout:           {} seconds", args.timeout.to_string().bright_white());
    println!("  💾 Memory Limit:      {} MB", args.max_memory.to_string().bright_white());
    println!("  📝 Output Directory:  {}", args.output_dir.display().to_string().bright_white());
    println!("{}", "╚═══════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();

    if config.allow_internet {
        println!(
            "{}",
            "⚠️  WARNING: Internet access is ENABLED!".bright_red().bold()
        );
        println!(
            "{}",
            "   The process will be able to make network connections.".bright_yellow()
        );
        println!();
    }

    // Inform user about separate console window
    println!("{}", "╔═══════════════════════════════════════════════════════╗".bright_cyan().bold());
    println!("{}", "║              📺 CONSOLE SEPARATION 📺                 ".bright_cyan().bold());
    println!("{}", "╚═══════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();
    println!("{}",  "  ℹ️  The target process will open in a SEPARATE window.".bright_blue());
    println!("{}",  "     This keeps monitoring prompts clean and organized.".bright_blue());
    println!();
    println!("{}",  "  👁️  Watch for the new console window to see process output.".bright_yellow());
    println!();

    // Execute in sandbox
    info!("Starting sandbox execution...");
    let mut report = execute_sandboxed(&args.executable, &args.args, config).await?;
    report.executable = args.executable.clone();

    // Output results
    match args.format.as_str() {
        "json" => {
            let json_path = args.output_dir.join("report.json");
            report.save_json(&json_path)?;
            println!("Report saved to: {}", json_path.display());
        }
        "console" => {
            report.print_summary();
        }
        "both" => {
            report.print_summary();
            let json_path = args.output_dir.join("report.json");
            report.save_json(&json_path)?;
            println!("JSON report saved to: {}", json_path.display());
        }
        _ => {
            // Default to both if unknown format
            report.print_summary();
            let json_path = args.output_dir.join("report.json");
            report.save_json(&json_path)?;
            println!("JSON report saved to: {}", json_path.display());
        }
    }

    Ok(())
}

fn print_banner() {
    println!();
    println!("{}", "╔═════════════════════════════════════════════════════════════════╗".bright_cyan().bold());
    println!("{}", "║                                                                 ║".bright_cyan().bold());
    println!("{}", "║                       🏖️  RUSTY SAND  🏖️                         ".bright_cyan().bold());
    println!("{}", "║                                                                 ║".bright_cyan().bold());
    println!("{}", "║               Clean Windows Sandbox & HIPS v0.1.0               ║".bright_cyan());
    println!("{}", "║                                                                 ║".bright_cyan());
    println!("{}", "║  Features: Process Isolation • HIPS Control • Threat Detection  ║".bright_cyan());
    println!("{}", "║            Real-time Monitoring • Behavioral Analysis           ║".bright_cyan());
    println!("{}", "║                                                                 ║".bright_cyan());
    println!("{}", "╚═════════════════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();
}
