use crate::report::{Event, EventType};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashSet;
use std::sync::Arc;
use sysinfo::{ProcessRefreshKind, System};
use tokio::sync::Mutex;

#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;

pub struct ProcessMonitor {
    target_pid: u32,
    events: Arc<Mutex<Vec<Event>>>,
    tracked_children: Arc<Mutex<HashSet<u32>>>,
}

impl ProcessMonitor {
    pub fn new(target_pid: u32, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        Ok(Self {
            target_pid,
            events,
            tracked_children: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub async fn monitor(self) -> Result<()> {
        debug!("Starting process monitor for PID {}", self.target_pid);

        let mut sys = System::new_all();

        loop {
            // Poll much faster - 50ms instead of 500ms
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            sys.refresh_processes_specifics(
                ProcessRefreshKind::new()
                    .with_memory()
                    .with_cpu()
            );

            // Check if main process still exists
            if sys.process(sysinfo::Pid::from_u32(self.target_pid)).is_none() {
                info!("Target process {} has exited", self.target_pid);
                break;
            }

            // Check for child processes using both methods
            self.check_child_processes(&sys).await;

            #[cfg(windows)]
            self.check_child_processes_windows().await;

            // Monitor resource usage
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(self.target_pid)) {
                let memory_mb = process.memory() / 1024 / 1024;
                let cpu_usage = process.cpu_usage();

                if memory_mb > 0 {
                    debug!(
                        "Process {} - Memory: {} MB, CPU: {:.2}%",
                        self.target_pid, memory_mb, cpu_usage
                    );
                }
            }
        }

        Ok(())
    }

    async fn check_child_processes(&self, sys: &System) {
        let parent_pid = sysinfo::Pid::from_u32(self.target_pid);

        for (pid, process) in sys.processes() {
            if let Some(parent) = process.parent() {
                if parent == parent_pid {
                    let pid_u32 = pid.as_u32();
                    let mut tracked = self.tracked_children.lock().await;

                    if !tracked.contains(&pid_u32) {
                        tracked.insert(pid_u32);
                        drop(tracked);

                        let details = format!(
                            "Child process created: PID {} ({})",
                            pid_u32,
                            process.name()
                        );

                        info!("{}", details);

                        let event = Event {
                            timestamp: chrono::Utc::now(),
                            event_type: EventType::ProcessCreated,
                            details,
                        };

                        self.events.lock().await.push(event);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    async fn check_child_processes_windows(&self) {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(handle) => handle,
                Err(_) => return,
            };

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            // First pass: collect all processes and their parents
            let mut process_map: std::collections::HashMap<u32, (u32, String)> = std::collections::HashMap::new();

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let parent_pid = entry.th32ParentProcessID;

                    let name_len = entry.szExeFile.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let process_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                    process_map.insert(pid, (parent_pid, process_name));

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);

            // Second pass: find all descendants (children, grandchildren, etc.)
            let mut to_check = vec![self.target_pid];
            let mut descendants = HashSet::new();

            while let Some(current_pid) = to_check.pop() {
                for (pid, (parent_pid, _)) in &process_map {
                    if *parent_pid == current_pid && !descendants.contains(pid) {
                        descendants.insert(*pid);
                        to_check.push(*pid);
                    }
                }
            }

            // Log any new descendants
            for pid in descendants {
                let mut tracked = self.tracked_children.lock().await;

                if !tracked.contains(&pid) {
                    tracked.insert(pid);
                    drop(tracked);

                    if let Some((parent_pid, process_name)) = process_map.get(&pid) {
                        let details = format!(
                            "Descendant process created: PID {} ({}) - Parent PID {}",
                            pid, process_name, parent_pid
                        );

                        info!("{}", details);

                        let event = Event {
                            timestamp: chrono::Utc::now(),
                            event_type: EventType::ProcessCreated,
                            details,
                        };

                        self.events.lock().await.push(event);
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    async fn check_child_processes_windows(&self) {
        // Not available on non-Windows platforms
    }
}
