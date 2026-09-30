use super::{Event, EventType, SandboxReport};

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct EventCounts {
    pub files: usize,
    pub folders: usize,
    pub network: usize,
    pub network_blocked: usize,
    pub processes: usize,
    pub registry: usize,
    pub hook_blocked: usize,
}

impl EventCounts {
    pub(super) fn from_events(events: &[Event]) -> Self {
        let mut counts = Self::default();

        /*
         * Counts describe recorded events, not unique completed operations. A
         * hook request and a monitor observation may describe the same action.
         * HookBlocked has no typed operation payload, so free-form details
         * cannot reliably attribute a denial to a particular event category.
         */
        for event in events {
            counts.files += usize::from(event.event_type.is_file());
            counts.network += usize::from(event.event_type.is_network());

            match event.event_type {
                EventType::FolderCreated
                | EventType::FolderDeleted
                | EventType::HookFolderCreate
                | EventType::HookFolderDelete => counts.folders += 1,
                EventType::NetworkBlocked => counts.network_blocked += 1,
                EventType::ProcessCreated | EventType::HookProcessCreate => counts.processes += 1,
                EventType::RegistryAccess
                | EventType::RegistryBlocked
                | EventType::HookRegistrySet
                | EventType::HookRegistryDelete
                | EventType::HookRegistryRead
                | EventType::HookRegistryOpen => counts.registry += 1,
                EventType::HookBlocked => counts.hook_blocked += 1,
                _ => {}
            }
        }

        counts
    }
}

impl SandboxReport {
    pub fn print_summary(&self) {
        let counts = EventCounts::from_events(&self.events);

        println!("\nSandbox execution report");
        println!("  Executable: {}", self.executable);
        println!("  Start: {}", self.start_time);
        println!("  End: {}", self.end_time);
        println!("  Duration: {} seconds", self.duration_seconds);
        println!("  Exit code: {}", self.exit_code);

        println!("\nConfigured policy (not a containment guarantee)");
        println!("  Allow internet: {}", self.config.allow_internet);
        println!("  Allow DNS: {}", self.config.allow_dns);
        println!("  Allow registry: {}", self.config.allow_registry);
        println!(
            "  Memory limit: {} MB (0 = unlimited)",
            self.config.max_memory_mb
        );
        println!(
            "  CPU limit: {} seconds (0 = unlimited)",
            self.config.max_cpu_time
        );

        println!("\nRecorded events");
        println!("  Total: {}", self.events.len());
        println!("  File: {}", counts.files);
        println!("  Folder: {}", counts.folders);
        println!("  Network: {}", counts.network);
        println!("  Network reported blocked: {}", counts.network_blocked);
        println!("  Process creation: {}", counts.processes);
        println!("  Registry: {}", counts.registry);
        println!("  Hook denials: {}", counts.hook_blocked);

        let first = self.events.len().saturating_sub(100);

        for event in &self.events[first..] {
            println!(
                "  [{}] {:?}: {}",
                event.timestamp.format("%H:%M:%S"),
                event.event_type,
                event.details
            );
        }
    }
}
