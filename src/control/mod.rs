pub mod suspension;
pub mod interactive;

use crate::behavior::ThreatDetection;
use anyhow::Result;
use colored::Colorize;
use log::info;
use std::collections::HashSet;
use std::io::{self, Write};
use windows::Win32::System::Threading::{
    SuspendThread, ResumeThread, OpenThread, THREAD_SUSPEND_RESUME,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
    TH32CS_SNAPTHREAD,
};

pub struct ProcessController {
    target_pid: u32,
    suspended: bool,
}

impl ProcessController {
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            suspended: false,
        }
    }

    /// Suspend all threads in the target process
    ///
    /// Uses Windows Toolhelp32 API to enumerate ALL threads belonging to the target process
    /// and calls SuspendThread on each one. This effectively freezes the entire process,
    /// preventing any code execution until resume_process() is called.
    ///
    /// This is critical for HIPS functionality - we suspend the process before asking the user
    /// for a decision to prevent the operation from completing while the prompt is shown.
    ///
    /// # Safety
    /// Uses unsafe Windows APIs. Handles are properly opened and closed.
    ///
    /// # Returns
    /// Ok(()) if suspension succeeded, Err if snapshot or thread enumeration failed
    pub fn suspend_process(&mut self) -> Result<()> {
        if self.suspended {
            return Ok(());
        }

        info!("🛑 Suspending process {}", self.target_pid);

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;

            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == self.target_pid {
                        if let Ok(thread_handle) = OpenThread(
                            THREAD_SUSPEND_RESUME,
                            false,
                            entry.th32ThreadID,
                        ) {
                            let _ = SuspendThread(thread_handle);
                            let _ = windows::Win32::Foundation::CloseHandle(thread_handle);
                        }
                    }

                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }

        self.suspended = true;
        Ok(())
    }

    /// Resume all threads in the target process
    pub fn resume_process(&mut self) -> Result<()> {
        if !self.suspended {
            return Ok(());
        }

        info!("▶️  Resuming process {}", self.target_pid);

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;

            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == self.target_pid {
                        if let Ok(thread_handle) = OpenThread(
                            THREAD_SUSPEND_RESUME,
                            false,
                            entry.th32ThreadID,
                        ) {
                            let _ = ResumeThread(thread_handle);
                            let _ = windows::Win32::Foundation::CloseHandle(thread_handle);
                        }
                    }

                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }

        self.suspended = false;
        Ok(())
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserDecision {
    Allow,           // Allow this one operation
    AllowAll,        // Allow all operations of this type
    Block,           // Block this one operation
    BlockAll,        // Block all operations of this type
    Terminate,       // Terminate the process
    Continue,        // Skip asking for this event type
}

use crate::report::EventType;

pub struct InteractiveController {
    auto_allow: bool,
    auto_block: bool,
    allowed_event_types: HashSet<EventType>,
    blocked_event_types: HashSet<EventType>,
    // Statistics for better user awareness
    total_prompts: u32,
    total_allowed: u32,
    total_blocked: u32,
}

impl InteractiveController {
    pub fn new() -> Self {
        Self {
            auto_allow: false,
            auto_block: false,
            allowed_event_types: HashSet::new(),
            blocked_event_types: HashSet::new(),
            total_prompts: 0,
            total_allowed: 0,
            total_blocked: 0,
        }
    }

    pub fn should_prompt(&self, event_type: &EventType) -> bool {
        // Don't prompt if this event type is auto-allowed or auto-blocked
        !self.allowed_event_types.contains(event_type) && !self.blocked_event_types.contains(event_type)
    }

    pub fn is_allowed(&self, event_type: &EventType) -> bool {
        self.allowed_event_types.contains(event_type)
    }

    pub fn is_blocked(&self, event_type: &EventType) -> bool {
        self.blocked_event_types.contains(event_type)
    }

    /// Efficient check for event handling - returns (should_prompt, is_allowed, is_blocked)
    /// This avoids multiple mutex locks by checking everything at once
    pub fn check_event_status(&self, event_type: &EventType) -> (bool, bool, bool) {
        let is_allowed = self.allowed_event_types.contains(event_type);
        let is_blocked = self.blocked_event_types.contains(event_type);
        let should_prompt = !is_allowed && !is_blocked;
        (should_prompt, is_allowed, is_blocked)
    }

    /// Prompt user for ANY event (not just threats)
    pub fn prompt_for_event(&mut self, event: &crate::report::Event) -> UserDecision {
        self.total_prompts += 1;

        // Clear screen for better visibility (optional, can be removed if distracting)
        println!("\n\n");

        println!("{}", "╔═══════════════════════════════════════════════════════════════╗".bright_yellow().bold());
        println!("{}", "║                  ⚠️  OPERATION DETECTED ⚠️                     ║".bright_yellow().bold());
        println!("{}", "╚═══════════════════════════════════════════════════════════════╝".bright_yellow().bold());

        // IMPORTANT: Be honest about detection timing
        println!("\n{}", "⚠️  NOTE: This operation was ALREADY COMPLETED before detection.".bright_yellow());
        println!("{}", "    User-mode monitoring can only detect operations AFTER they happen.".bright_yellow());
        println!("{}", "    You can now decide whether to allow future similar operations.".bright_white());

        let (event_icon, risk_color) = match event.event_type {
            EventType::FileCreated => ("📄", "green"),
            EventType::FileModified => ("✏️", "yellow"),
            EventType::FileDeleted => ("🗑️", "red"),
            EventType::FolderCreated => ("📁", "green"),
            EventType::FolderDeleted => ("🗂️", "red"),
            EventType::NetworkConnection => ("🌐", "yellow"),
            EventType::NetworkBlocked => ("🚫", "red"),
            EventType::ProcessCreated => ("⚙️", "yellow"),
            EventType::RegistryAccess => ("📋", "yellow"),
            _ => ("•", "white"),
        };

        let risk_indicator = match risk_color {
            "green" => "LOW RISK".bright_green(),
            "yellow" => "MEDIUM RISK".bright_yellow(),
            "red" => "HIGH RISK".bright_red(),
            _ => "UNKNOWN".white(),
        };

        println!("\n{} Operation Type: {}", event_icon, format!("{:?}", event.event_type).bright_cyan().bold());
        println!("   Risk Level:      {}", risk_indicator);
        println!("   Details:         {}", event.details.bright_white());
        println!("   Time:            {}", event.timestamp.format("%H:%M:%S UTC").to_string().bright_black());

        // Show statistics
        println!("\n{}", "┌─ Session Statistics ─────────────────────────────────────────┐".bright_black());
        println!("{}  Prompts: {}  │  Allowed: {}  │  Blocked: {}",
            "│".bright_black(),
            format!("{:3}", self.total_prompts).bright_cyan(),
            format!("{:3}", self.total_allowed).bright_green(),
            format!("{:3}", self.total_blocked).bright_red()
        );
        println!("{}", "└───────────────────────────────────────────────────────────────┘".bright_black());

        println!("\n{}", "Options:".bright_white().bold());
        println!("  {}  Accept and continue execution", "[A] ".bright_green().bold());
        println!("  {}  Accept ALL {:?} operations (no more prompts)", "[AA]".bright_green().bold(), event.event_type);
        println!("  {}  Note as suspicious, but continue", "[B] ".bright_red().bold());
        println!("  {}  Auto-flag ALL {:?} as suspicious", "[BB]".bright_red().bold(), event.event_type);
        println!("  {}  Terminate process now (prevent further operations)", "[T] ".bright_red().bold());
        println!("  {}  Continue monitoring without prompts for this type", "[C] ".bright_yellow().bold());

        println!("\n{}", "───────────────────────────────────────────────────────────────".bright_black());
        print!("{}", "Your decision: ".bright_white().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return UserDecision::Continue;
        }

        let decision = match input.trim().to_uppercase().as_str() {
            "A" => {
                self.total_allowed += 1;
                println!("\n{} {}\n", "✅".bright_green(), "Continuing execution...".bright_green().bold());
                UserDecision::Allow
            }
            "AA" => {
                self.total_allowed += 1;
                println!("\n{} {}\n", "✅".bright_green(), format!("Auto-accepting all {:?} operations from now on", event.event_type).bright_green().bold());
                self.allowed_event_types.insert(event.event_type.clone());
                UserDecision::AllowAll
            }
            "B" => {
                self.total_blocked += 1;
                println!("\n{} {}\n", "⚠️ ".bright_red(), "Flagged as SUSPICIOUS - continuing with caution".bright_red().bold());
                UserDecision::Block
            }
            "BB" => {
                self.total_blocked += 1;
                println!("\n{} {}\n", "⚠️ ".bright_red(), format!("Auto-flagging all {:?} operations as SUSPICIOUS", event.event_type).bright_red().bold());
                self.blocked_event_types.insert(event.event_type.clone());
                UserDecision::BlockAll
            }
            "T" => {
                println!("\n{} {}\n", "☠️ ".bright_red(), "TERMINATING process immediately".bright_red().bold());
                UserDecision::Terminate
            }
            _ => {
                println!("\n{} {}\n", "👁️ ".bright_yellow(), format!("Silent monitoring for {:?} operations", event.event_type).bright_yellow().bold());
                UserDecision::Continue
            }
        };

        decision
    }

    pub fn prompt_user(&mut self, threat: &ThreatDetection) -> UserDecision {
        // Print threat alert
        println!("\n{}", "═══════════════════════════════════════════════════".bright_red().bold());
        println!("{}", "⚠️  THREAT DETECTED ⚠️".bright_red().bold());
        println!("{}", "═══════════════════════════════════════════════════".bright_red().bold());

        let level_str = match threat.level {
            crate::behavior::ThreatLevel::Critical => "CRITICAL".bright_red().bold(),
            crate::behavior::ThreatLevel::High => "HIGH".red().bold(),
            crate::behavior::ThreatLevel::Medium => "MEDIUM".yellow().bold(),
            crate::behavior::ThreatLevel::Low => "LOW".bright_yellow(),
        };

        println!("Threat Type:  {}", threat.threat_type.bright_yellow());
        println!("Threat Level: {}", level_str);
        println!("Description:  {}", threat.description);

        if !threat.evidence.is_empty() {
            println!("\nEvidence:");
            for evidence in &threat.evidence {
                println!("  • {}", evidence.bright_cyan());
            }
        }

        println!("\n{}", "─────────────────────────────────────────────────".bright_black());
        println!("What would you like to do?");
        println!("  [A] ALLOW - Continue execution");
        println!("  [B] BLOCK - Block this specific action");
        println!("  [T] TERMINATE - Kill the process immediately");
        println!("  [C] CONTINUE - Continue monitoring (default)");
        println!("{}", "─────────────────────────────────────────────────".bright_black());

        print!("Your decision [A/B/T/C]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return UserDecision::Continue;
        }

        match input.trim().to_uppercase().as_str() {
            "A" => {
                println!("✅ Action ALLOWED\n");
                UserDecision::Allow
            }
            "B" => {
                println!("🚫 Action BLOCKED\n");
                UserDecision::Block
            }
            "T" => {
                println!("☠️  Process will be TERMINATED\n");
                UserDecision::Terminate
            }
            _ => {
                println!("👁️  Continuing monitoring\n");
                UserDecision::Continue
            }
        }
    }

    pub fn set_auto_allow(&mut self, enabled: bool) {
        self.auto_allow = enabled;
    }

    pub fn set_auto_block(&mut self, enabled: bool) {
        self.auto_block = enabled;
    }
}

impl Default for InteractiveController {
    fn default() -> Self {
        Self::new()
    }
}
