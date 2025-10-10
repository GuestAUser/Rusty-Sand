// Interactive user prompts and decisions

use colored::Colorize;

pub fn display_threat_banner() {
    println!("\n{}", "╔═══════════════════════════════════════════════════════╗".bright_red());
    println!("{}", "║           ⚠️  SUSPICIOUS ACTIVITY DETECTED ⚠️           ║".bright_red().bold());
    println!("{}", "╚═══════════════════════════════════════════════════════╝".bright_red());
}

pub fn display_action_menu() {
    println!("\n{}", "Available Actions:".bright_cyan().bold());
    println!("  {} Allow and continue", "[A]".bright_green());
    println!("  {} Block this action", "[B]".bright_red());
    println!("  {} Terminate process", "[T]".bright_red().bold());
    println!("  {} Continue monitoring", "[C]".bright_yellow());
}

pub fn display_statistics(
    total_threats: usize,
    blocked: usize,
    allowed: usize,
    terminated: bool,
) {
    println!("\n{}", "═══ Session Statistics ═══".bright_cyan());
    println!("Total threats detected: {}", total_threats);
    println!("Actions blocked: {}", blocked);
    println!("Actions allowed: {}", allowed);
    if terminated {
        println!("{}", "Process was terminated".bright_red().bold());
    }
}
