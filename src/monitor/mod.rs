pub mod filesystem;
pub mod network;
pub mod process;
pub mod registry;
pub mod etw_registry;

use crate::behavior::BehaviorAnalyzer;
use crate::config::SandboxConfig;
use crate::control::{InteractiveController, ProcessController, UserDecision};
use crate::report::{Event, EventType, SandboxReport};
use crate::sandbox::process::ProcessHandle;
use anyhow::{anyhow, Result};
use chrono::Utc;
use colored::Colorize;
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

// Global synchronization for prompts to prevent overlap
static PROMPT_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct MonitoringEngine {
    config: SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
    start_time: chrono::DateTime<Utc>,
    behavior_analyzer: Arc<Mutex<BehaviorAnalyzer>>,
    interactive_controller: Arc<Mutex<InteractiveController>>,
    process_controller: Option<Arc<Mutex<ProcessController>>>,
}

impl MonitoringEngine {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Ok(Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            start_time: Utc::now(),
            behavior_analyzer: Arc::new(Mutex::new(BehaviorAnalyzer::new())),
            interactive_controller: Arc::new(Mutex::new(InteractiveController::new())),
            process_controller: None,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting monitoring engine");
        self.log_event(EventType::SandboxStarted, "Sandbox initialized".to_string())
            .await;
        Ok(())
    }

    pub async fn monitor_process(&mut self, mut proc_handle: ProcessHandle) -> Result<SandboxReport> {
        info!("Monitoring process PID: {}", proc_handle.process_id);

        // CREATE SHUTDOWN FLAG FIRST
        let shutdown = Arc::new(AtomicBool::new(false));

        // START IPC SERVER FIRST (before DLL injection!)
        let ipc_task = if self.config.enable_api_hooks {
            let controller_ipc = self.interactive_controller.clone();
            let config_ipc = self.config.clone();
            let shutdown_ipc = shutdown.clone();
            let events_ipc = self.events.clone();  // NEW: Pass events for logging

            let task = tokio::spawn(async move {
                Self::ipc_server_loop(controller_ipc, config_ipc, shutdown_ipc, events_ipc).await
            });

            // Give IPC server time to start listening
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            info!("✅ IPC server started and listening");
            Some(task)
        } else {
            None
        };

        // NOW inject hook DLL (it can connect immediately to the waiting server)
        if self.config.enable_api_hooks && proc_handle.is_suspended {
            info!("🔧 API hooking is ENABLED - injecting hook DLL...");
            match crate::injection::ensure_hook_dll_exists() {
                Ok(dll_path) => {
                    match crate::injection::inject_dll(proc_handle.process_handle, &dll_path) {
                        Ok(_) => info!("✅ Hook DLL injected successfully - API interception active!"),
                        Err(e) => {
                            warn!("⚠️  Failed to inject hook DLL: {} - continuing without API hooks", e);
                            warn!("   Note: Real-time prevention will not be available");
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️  Hook DLL not found: {} - continuing without API hooks", e);
                }
            }
        }

        // If process is suspended (HIPS mode), prompt user before allowing execution
        if proc_handle.is_suspended && self.config.interactive_mode {
            println!("\n{}", "╔═══════════════════════════════════════════════════════════════╗".bright_red().bold());
            println!("{}", "║               ⚠️  INITIAL EXECUTION APPROVAL ⚠️                ║".bright_red().bold());
            println!("{}", "╚═══════════════════════════════════════════════════════════════╝".bright_red().bold());
            println!("\n{} {}", "🔒".bright_yellow(), "The process is currently SUSPENDED.".bright_white().bold());
            println!("   {}", "No code has executed yet - this is your first line of defense.".bright_white());
            println!("\n{} {}", "📋".bright_cyan(), format!("Process: PID {}", proc_handle.process_id).bright_white());
            println!("\n{}", "─────────────────────────────────────────────────────────────".bright_black());
            println!("{}", "Do you want to ALLOW this process to start executing?".bright_white().bold());
            println!("  {} Allow execution (process will start running)", "[Y]".bright_green().bold());
            println!("  {} Terminate immediately (kill before any code runs)", "[N]".bright_red().bold());
            println!("{}", "─────────────────────────────────────────────────────────────".bright_black());
            print!("{}", "\nYour decision [Y/N]: ".bright_white().bold());
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            match input.trim().to_uppercase().as_str() {
                "Y" => {
                    println!("\n{} {}\n", "✅".bright_green(), "Process execution APPROVED - resuming...".bright_green().bold());
                    proc_handle.resume_initial_thread()?;
                }
                _ => {
                    println!("\n{} {}\n", "🚫".bright_red(), "Process execution DENIED - terminating...".bright_red().bold());
                    return Err(anyhow!("User denied process execution"));
                }
            }
        }

        // Set up process controller for suspension/resume
        let process_controller = Arc::new(Mutex::new(ProcessController::new(proc_handle.process_id)));
        self.process_controller = Some(process_controller.clone());

        // Start filesystem monitoring
        let fs_monitor = filesystem::FileSystemMonitor::new(
            self.config.clone(),
            self.events.clone(),
        )?;

        // Start network monitoring
        let net_monitor = network::NetworkMonitor::new(
            self.config.clone(),
            self.events.clone(),
            proc_handle.process_id,
        )?;

        // Start OLD registry monitoring (passive) - DEPRECATED, keeping for compatibility
        let reg_monitor = registry::RegistryMonitor::new(
            self.config.clone(),
            self.events.clone(),
        )?;

        // Start NEW real-time registry monitoring with shutdown support
        let real_reg_monitor = etw_registry::RealRegistryMonitor::new(
            self.events.clone(),
            shutdown.clone(),
        );

        // Start process monitoring
        let proc_monitor = process::ProcessMonitor::new(
            proc_handle.process_id,
            self.events.clone(),
        )?;

        // Start all monitors - keep handles so we can abort them on shutdown
        let fs_task = tokio::spawn(async move {
            fs_monitor.start().await
        });

        let net_task = tokio::spawn(async move {
            net_monitor.monitor().await
        });

        let reg_task = tokio::spawn(async move {
            reg_monitor.start().await
        });

        // Start REAL registry monitoring with shutdown support (NOW ENABLED!)
        let real_reg_task = tokio::spawn(async move {
            real_reg_monitor.monitor().await
        });

        let proc_task = tokio::spawn(async move {
            proc_monitor.monitor().await
        });

        // Start behavior analysis loop (shutdown was already created at top of function)
        let events_clone = self.events.clone();
        let analyzer_clone = self.behavior_analyzer.clone();
        let controller_clone = self.interactive_controller.clone();
        let proc_ctrl_clone = process_controller.clone();
        let config_clone = self.config.clone();
        let shutdown_clone = shutdown.clone();

        let analysis_task = tokio::spawn(async move {
            Self::behavior_analysis_loop(
                events_clone,
                analyzer_clone,
                controller_clone,
                proc_ctrl_clone,
                config_clone,
                shutdown_clone,
            ).await
        });

        // IPC server already started at top of function (before DLL injection)

        // Wait for process with periodic shutdown checks
        let process_handle_raw = proc_handle.process_handle;
        let shutdown_check = shutdown.clone();

        let wait_result = tokio::task::spawn_blocking(move || {
            loop {
                // Check for shutdown signal
                if shutdown_check.load(Ordering::SeqCst) {
                    info!("🛑 Shutdown signal detected - terminating process...");
                    unsafe {
                        use windows::Win32::System::Threading::TerminateProcess;
                        let _ = TerminateProcess(process_handle_raw, 999);
                    }
                    return Ok::<u32, anyhow::Error>(999);
                }

                // Wait for process (short timeout for responsiveness)
                unsafe {
                    use windows::Win32::System::Threading::WaitForSingleObject;
                    let result = WaitForSingleObject(process_handle_raw, 100);

                    // If process exited, return
                    if result.0 == 0 { // WAIT_OBJECT_0
                        use windows::Win32::System::Threading::GetExitCodeProcess;
                        let mut exit_code = 0u32;
                        let _ = GetExitCodeProcess(process_handle_raw, &mut exit_code);
                        return Ok(exit_code);
                    }
                }
            }
        })
        .await??;

        info!("Process finished with exit code: {}", wait_result);

        // Signal shutdown to all background tasks
        info!("🛑 Process exited - signaling shutdown to all monitoring tasks...");
        shutdown.store(true, Ordering::SeqCst);

        // Give tasks a moment to finish gracefully
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Force abort any tasks that haven't stopped
        fs_task.abort();
        net_task.abort();
        reg_task.abort();
        real_reg_task.abort();
        proc_task.abort();
        analysis_task.abort();
        if let Some(task) = ipc_task {
            task.abort();
        }

        info!("✅ All monitoring tasks stopped");

        // Stop monitoring
        self.log_event(EventType::SandboxStopped, "Process execution completed".to_string())
            .await;

        // Generate report
        let events = self.events.lock().await.clone();
        let end_time = Utc::now();

        Ok(SandboxReport {
            executable: "".to_string(), // Will be set by caller
            start_time: self.start_time,
            end_time,
            duration_seconds: (end_time - self.start_time).num_seconds() as u64,
            events,
            exit_code: wait_result,
            config: self.config.clone(),
        })
    }

    /// Core HIPS behavior analysis loop
    ///
    /// This function runs continuously in a background task and implements the Host Intrusion
    /// Prevention System (HIPS) functionality. It:
    ///
    /// 1. Polls for new events every 100ms
    /// 2. For each event, checks if it should be prompted (single mutex lock optimization)
    /// 3. If already allowed/blocked, fast-path continues without suspension
    /// 4. Otherwise: suspends process → prompts user → handles decision
    /// 5. Also runs behavioral threat analysis in background
    ///
    /// Performance optimizations:
    /// - Single mutex lock per event (check_event_status)
    /// - Fast-path for auto-allowed/blocked events
    /// - Async/await for non-blocking operation
    async fn behavior_analysis_loop(
        events: Arc<Mutex<Vec<Event>>>,
        analyzer: Arc<Mutex<BehaviorAnalyzer>>,
        interactive_controller: Arc<Mutex<InteractiveController>>,
        process_controller: Arc<Mutex<ProcessController>>,
        config: SandboxConfig,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut last_analyzed_count = 0;

        loop {
            // Check for shutdown signal
            if shutdown.load(Ordering::SeqCst) {
                info!("🛑 Behavior analysis loop shutting down...");
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            if !config.enable_behavior_detection {
                continue;
            }

            // Get new events to analyze
            let new_events: Vec<Event> = {
                let events_list = events.lock().await;
                let current_count = events_list.len();

                if current_count > last_analyzed_count {
                    let new_events = events_list[last_analyzed_count..].to_vec();
                    last_analyzed_count = current_count;
                    new_events
                } else {
                    Vec::new()
                }
            };

            // Analyze each new event - HIPS style: prompt for EVERY operation
            for event in new_events {
                // Filter out internal events that should never be prompted
                // These are metadata events from the sandbox itself, not operations by the target process
                let is_internal_event = matches!(
                    event.event_type,
                    EventType::SandboxStarted | EventType::SandboxStopped
                );

                // Also filter events with internal sandbox messages
                // These are metadata messages from the sandbox itself, not target process operations
                let is_internal_message = event.details.contains("Sandbox initialized")
                    || event.details.contains("Process execution completed");

                if is_internal_event || is_internal_message {
                    debug!("Skipping internal event: {:?} - {}", event.event_type, event.details);
                    continue;
                }

                // Efficient single-lock check for event status
                let (should_prompt, is_allowed, is_blocked) = {
                    let controller = interactive_controller.lock().await;
                    controller.check_event_status(&event.event_type)
                };

                // Fast path: auto-allowed events
                if is_allowed {
                    debug!("✅ Auto-allowed: {:?}", event.event_type);
                    continue;
                }

                // Fast path: auto-blocked events
                if is_blocked {
                    warn!("🚫 Auto-blocked: {:?} - {}", event.event_type, event.details);
                    continue;
                }

                // Prompt user for EVERY operation (HIPS behavior)
                // BUT: Skip behavioral prompts when API hooking is enabled
                // (API hooks are superior - they catch operations BEFORE execution)
                if config.interactive_mode && should_prompt && !config.enable_api_hooks {
                    // Suspend the process before asking
                    let mut proc_ctrl = process_controller.lock().await;
                    if let Err(e) = proc_ctrl.suspend_process() {
                        warn!("Failed to suspend process: {}", e);
                    }
                    drop(proc_ctrl);

                    // Prompt user for this specific event
                    let mut controller = interactive_controller.lock().await;
                    let decision = controller.prompt_for_event(&event);
                    drop(controller);

                    // Handle decision
                    let mut proc_ctrl = process_controller.lock().await;
                    match decision {
                        UserDecision::Allow => {
                            info!("✅ Operation allowed");
                            if let Err(e) = proc_ctrl.resume_process() {
                                warn!("Failed to resume process: {}", e);
                            }
                        }
                        UserDecision::AllowAll => {
                            info!("✅ All {:?} operations allowed", event.event_type);
                            if let Err(e) = proc_ctrl.resume_process() {
                                warn!("Failed to resume process: {}", e);
                            }
                        }
                        UserDecision::Block => {
                            warn!("🚫 Operation blocked");
                            if let Err(e) = proc_ctrl.resume_process() {
                                warn!("Failed to resume process: {}", e);
                            }
                        }
                        UserDecision::BlockAll => {
                            warn!("🚫 All {:?} operations blocked", event.event_type);
                            if let Err(e) = proc_ctrl.resume_process() {
                                warn!("Failed to resume process: {}", e);
                            }
                        }
                        UserDecision::Terminate => {
                            warn!("☠️  User terminated process");
                            shutdown.store(true, Ordering::SeqCst);
                            return;
                        }
                        UserDecision::Continue => {
                            info!("👁️  Won't ask about {:?} anymore", event.event_type);
                            if let Err(e) = proc_ctrl.resume_process() {
                                warn!("Failed to resume process: {}", e);
                            }
                        }
                    }
                }

                // Also run threat analysis in background for informational purposes
                if config.enable_behavior_detection {
                    let mut analyzer_guard = analyzer.lock().await;
                    let threat_option = analyzer_guard.analyze_event(&event);
                    drop(analyzer_guard);

                    if let Some(threat) = threat_option {
                        warn!("🚨 THREAT DETECTED: {} (Level: {:?})", threat.threat_type, threat.level);
                        for evidence in &threat.evidence {
                            warn!("   Evidence: {}", evidence);
                        }
                    }
                }
            }
        }
    }

    /// IPC server loop for handling hook requests from injected DLL
    ///
    /// This loop listens for API hook requests from the DLL and prompts the user
    /// for approval, implementing TRUE real-time prevention.
    ///
    /// CRITICAL: Now logs ALL hook interceptions as events (allowed OR denied)
    async fn ipc_server_loop(
        _interactive_controller: Arc<Mutex<InteractiveController>>,
        config: SandboxConfig,
        shutdown: Arc<AtomicBool>,
        events: Arc<Mutex<Vec<Event>>>,  // NEW: Event logging
    ) {
        use crate::ipc::{HookIpcServer, HookOperation, HookResponse};
        use std::collections::HashMap;

        info!("🎯 Starting IPC server for hook DLL communication...");

        // Track auto-allowed and auto-denied operation types
        let mut auto_allowed: HashMap<String, bool> = HashMap::new();
        let mut auto_denied: HashMap<String, bool> = HashMap::new();

        // Create IPC server
        let server = match HookIpcServer::new() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create IPC server: {}", e);
                return;
            }
        };

        info!("✅ IPC server listening for hook requests...");

        loop {
            // Check for shutdown signal
            if shutdown.load(Ordering::SeqCst) {
                info!("🛑 IPC server loop shutting down...");
                break;
            }

            // Wait for client connection
            if let Err(e) = server.wait_for_connection() {
                warn!("Failed to wait for client: {}", e);
                continue;
            }

            info!("🔗 Hook DLL connected via IPC");

            // Handle requests from this client
            loop {
                // Check for shutdown signal in inner loop too
                if shutdown.load(Ordering::SeqCst) {
                    info!("🛑 IPC request handler shutting down...");
                    break;
                }
                // Read request
                let request = match server.read_request() {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("IPC read error (client disconnected?): {}", e);
                        break;
                    }
                };

                // Convert hook operation to clear description
                let (operation_name, target_details) = match &request.operation {
                    HookOperation::FileCreate { path } => ("CREATE FILE", path.clone()),
                    HookOperation::FileWrite { path } => ("WRITE FILE", path.clone()),
                    HookOperation::FileDelete { path } => ("DELETE FILE", path.clone()),
                    HookOperation::FolderCreate { path } => ("CREATE FOLDER", path.clone()),
                    HookOperation::FolderDelete { path } => ("DELETE FOLDER", path.clone()),
                    HookOperation::RegistrySet { key, value } => {
                        ("SET REGISTRY", format!("{} = {}", key, value))
                    }
                    HookOperation::RegistryDelete { key } => ("DELETE REGISTRY", key.clone()),
                    HookOperation::RegistryRead { key, value } => {
                        ("READ REGISTRY", format!("{} -> {}", key, value))
                    }
                    HookOperation::RegistryOpen { key } => ("OPEN REGISTRY", key.clone()),
                    HookOperation::NetworkConnect { remote_addr, port } => {
                        ("NETWORK CONNECT", format!("{}:{}", remote_addr, port))
                    }
                    HookOperation::ProcessCreate { executable, args } => {
                        ("START PROCESS", format!("{} {}", executable, args))
                    }
                };

                // Check if this operation type is auto-allowed or auto-denied
                let (allowed, should_terminate) = if config.interactive_mode {
                    if auto_allowed.get(operation_name).copied().unwrap_or(false) {
                        // Auto-allowed - skip prompt
                        (true, false)
                    } else if auto_denied.get(operation_name).copied().unwrap_or(false) {
                        // Auto-denied - skip prompt
                        (false, false)
                    } else {
                        // Increment and get prompt number
                        let prompt_num = PROMPT_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;

                        // Clear separation
                        println!("\n\n");
                        println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_yellow());
                        println!("{} #{}", "⚠️  INTERCEPTED OPERATION".bright_red().bold(), prompt_num);
                        println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_yellow());
                        println!();
                        println!("  {} {}", "ACTION:".bright_white().bold(), operation_name.bright_yellow().bold());
                        println!("  {} {}", "TARGET:".bright_white().bold(), target_details.bright_cyan());
                        println!();
                        println!("  🛑 {} ", "BLOCKED - Waiting for your decision...".bright_red());
                        println!();
                        print!("  {} ", "[Y]es / [A]llow All / [N]o / [D]eny All / [T]erminate >".bright_white().bold());
                        std::io::Write::flush(&mut std::io::stdout()).unwrap();

                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).ok();

                        match input.trim().to_uppercase().as_str() {
                            "Y" => {
                                println!("  {} ALLOWED", "✅".bright_green());
                                (true, false)
                            }
                            "A" => {
                                println!("  {} ALLOWED - All '{}' operations auto-approved", "✅".bright_green(), operation_name.bright_cyan());
                                auto_allowed.insert(operation_name.to_string(), true);
                                (true, false)
                            }
                            "D" => {
                                println!("  {} BLOCKED - All '{}' operations auto-denied", "🚫".bright_red(), operation_name.bright_cyan());
                                auto_denied.insert(operation_name.to_string(), true);
                                (false, false)
                            }
                            "T" => {
                                println!("  {} TERMINATING PROCESS", "☠️".bright_magenta());
                                (false, true)
                            }
                            _ => {
                                // DENIED (N or anything else)
                                println!("  {} BLOCKED", "🚫".bright_red());
                                println!();
                                print!("  {} ", "[C]ontinue / [T]erminate >".bright_white().bold());
                                std::io::Write::flush(&mut std::io::stdout()).unwrap();

                                let mut input2 = String::new();
                                std::io::stdin().read_line(&mut input2).ok();

                                if input2.trim().to_uppercase().as_str() == "T" {
                                    println!("  {} TERMINATING PROCESS", "☠️".bright_magenta());
                                    (false, true)
                                } else {
                                    println!("  {} Continuing...", "▶️".bright_green());
                                    (false, false)
                                }
                            }
                        }
                    }
                } else {
                    (true, false)
                };

                // NEW: Log hook interception as event (REGARDLESS of allow/deny)
                let event_type = match &request.operation {
                    HookOperation::FileCreate { .. } => EventType::HookFileCreate,
                    HookOperation::FileWrite { .. } => EventType::HookFileWrite,
                    HookOperation::FileDelete { .. } => EventType::HookFileDelete,
                    HookOperation::FolderCreate { .. } => EventType::HookFolderCreate,
                    HookOperation::FolderDelete { .. } => EventType::HookFolderDelete,
                    HookOperation::RegistrySet { .. } => EventType::HookRegistrySet,
                    HookOperation::RegistryDelete { .. } => EventType::HookRegistryDelete,
                    HookOperation::RegistryRead { .. } => EventType::HookRegistryRead,
                    HookOperation::RegistryOpen { .. } => EventType::HookRegistryOpen,
                    HookOperation::NetworkConnect { .. } => EventType::HookNetworkConnect,
                    HookOperation::ProcessCreate { .. } => EventType::HookProcessCreate,
                };

                let event_details = if allowed {
                    format!("✅ ALLOWED: {} - {}", operation_name, target_details)
                } else {
                    format!("🚫 BLOCKED: {} - {}", operation_name, target_details)
                };

                let event = Event {
                    timestamp: Utc::now(),
                    event_type,
                    details: event_details,
                };

                events.lock().await.push(event);

                // Send response
                let response = HookResponse {
                    allowed,
                    reason: if allowed {
                        Some("User approved".to_string())
                    } else {
                        Some("User denied".to_string())
                    },
                };

                if let Err(e) = server.send_response(&response) {
                    warn!("Failed to send IPC response: {}", e);
                    break;
                }

                // If user chose to terminate, signal shutdown immediately
                if should_terminate {
                    warn!("🔴 User requested process termination");
                    shutdown.store(true, Ordering::SeqCst);
                    break;
                }
            }

            // Client disconnected
            let _ = server.disconnect();
            info!("🔌 Hook DLL disconnected");
        }
    }

    pub async fn log_event(&self, event_type: EventType, details: String) {
        let event = Event {
            timestamp: Utc::now(),
            event_type,
            details,
        };

        if self.config.verbose {
            debug!("[EVENT] {:?}: {}", event.event_type, event.details);
        }

        // Event rate limiting: keep only the most recent 10,000 events to prevent memory overflow
        const MAX_EVENTS: usize = 10_000;
        let mut events = self.events.lock().await;

        if events.len() >= MAX_EVENTS {
            // Remove oldest 1000 events when limit is reached
            warn!("Event buffer limit reached ({}), removing oldest 1000 events", MAX_EVENTS);
            events.drain(0..1000);
        }

        events.push(event);
    }
}
