use crate::config::SandboxConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub executable: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
    pub events: Vec<Event>,
    pub exit_code: u32,
    pub config: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    SandboxStarted,
    SandboxStopped,
    ProcessCreated,
    ProcessTerminated,
    FileCreated,
    FileModified,
    FileDeleted,
    FolderCreated,
    FolderDeleted,
    NetworkConnection,
    NetworkBlocked,
    RegistryAccess,
    RegistryBlocked,
    DnsQuery,
    ApiCall,
    Suspicious,
}

impl SandboxReport {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print_summary(&self) {
        use colored::Colorize;

        println!("\n{}", "═══════════════════════════════════════════════════".bright_cyan());
        println!("{}", "           SANDBOX EXECUTION REPORT".bright_cyan().bold());
        println!("{}", "═══════════════════════════════════════════════════".bright_cyan());

        println!("\n{}", "📋 EXECUTION DETAILS".bright_yellow().bold());
        println!("  Executable:     {}", self.executable.bright_white());
        println!("  Start Time:     {}", self.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  End Time:       {}", self.end_time.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  Duration:       {} seconds", self.duration_seconds);
        println!("  Exit Code:      {}", self.exit_code);

        println!("\n{}", "🔐 SECURITY CONFIGURATION".bright_yellow().bold());
        println!(
            "  Internet:       {}",
            if self.config.allow_internet {
                "ENABLED ⚠️".bright_red()
            } else {
                "DISABLED ✓".bright_green()
            }
        );
        println!(
            "  Registry:       {}",
            if self.config.allow_registry {
                "MONITORED".bright_yellow()
            } else {
                "BLOCKED".bright_green()
            }
        );
        println!("  Memory Limit:   {} MB", self.config.max_memory_mb);
        println!("  CPU Limit:      {} seconds", self.config.max_cpu_time);

        // Event statistics
        let mut file_ops = 0;
        let mut network_ops = 0;
        let mut network_blocked = 0;
        let mut process_ops = 0;
        let mut registry_ops = 0;

        for event in &self.events {
            match event.event_type {
                EventType::FileCreated | EventType::FileModified | EventType::FileDeleted => {
                    file_ops += 1
                }
                EventType::NetworkConnection => network_ops += 1,
                EventType::NetworkBlocked => network_blocked += 1,
                EventType::ProcessCreated => process_ops += 1,
                EventType::RegistryAccess => registry_ops += 1,
                _ => {}
            }
        }

        println!("\n{}", "📊 EVENT SUMMARY".bright_yellow().bold());
        println!("  Total Events:        {}", self.events.len());
        println!("  File Operations:     {}", file_ops);
        println!("  Network Connections: {}", network_ops);
        if network_blocked > 0 {
            println!(
                "  Network Blocked:     {}",
                format!("{} ⚠️", network_blocked).bright_red()
            );
        }
        println!("  Process Created:     {}", process_ops);
        println!("  Registry Access:     {}", registry_ops);

        // Show all events (or limit to last 100 if too many)
        if !self.events.is_empty() {
            let display_count = self.events.len().min(100);
            println!(
                "\n{}",
                format!("📝 EVENTS (Showing last {})", display_count).bright_yellow().bold()
            );
            let recent_events: Vec<_> = self.events.iter().rev().take(display_count).collect();

            for event in recent_events.iter().rev() {
                let icon = match event.event_type {
                    EventType::FileCreated => "📄",
                    EventType::FileModified => "✏️",
                    EventType::FileDeleted => "🗑️",
                    EventType::NetworkConnection => "🌐",
                    EventType::NetworkBlocked => "🚫",
                    EventType::ProcessCreated => "⚙️",
                    EventType::RegistryAccess => "📋",
                    EventType::Suspicious => "⚠️",
                    _ => "•",
                };

                let time = event.timestamp.format("%H:%M:%S");
                let event_str = format!("{:?}", event.event_type);

                println!(
                    "  {} [{}] {}: {}",
                    icon,
                    time,
                    event_str.bright_cyan(),
                    event.details
                );
            }
        }

        println!("\n{}", "═══════════════════════════════════════════════════".bright_cyan());
        println!();
    }

    pub fn get_suspicious_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    EventType::Suspicious | EventType::NetworkBlocked
                )
            })
            .collect()
    }

    pub fn get_network_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    EventType::NetworkConnection | EventType::NetworkBlocked | EventType::DnsQuery
                )
            })
            .collect()
    }

    pub fn get_file_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    EventType::FileCreated | EventType::FileModified | EventType::FileDeleted
                )
            })
            .collect()
    }
}
