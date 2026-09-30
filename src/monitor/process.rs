use crate::report::{Event, EventType};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, System};
use tokio::sync::Mutex;

#[path = "observations/process_snapshot.rs"]
mod process_snapshot;
use process_snapshot::{descendants, missing, Process};

pub struct ProcessMonitor {
    target_pid: u32,
    events: Arc<Mutex<Vec<Event>>>,
}

impl ProcessMonitor {
    pub fn new(target_pid: u32, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        Ok(Self { target_pid, events })
    }

    pub async fn monitor(self) -> Result<()> {
        let mut system = System::new();
        let mut root = None;
        let mut tracked = BTreeSet::new();
        let mut memory_alert = None;
        let mut cpu_alert = None;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            system = tokio::task::spawn_blocking(move || {
                system.refresh_processes_specifics(
                    ProcessRefreshKind::new().with_memory().with_cpu(),
                );
                system
            })
            .await?;

            let processes: BTreeMap<_, _> = system
                .processes()
                .iter()
                .map(|(pid, process)| {
                    (
                        pid.as_u32(),
                        Process {
                            pid: pid.as_u32(),
                            parent: process.parent().map(|parent| parent.as_u32()),
                            started: process.start_time(),
                            name: process.name().to_owned(),
                        },
                    )
                })
                .collect();

            let mut events = self.events.lock().await;

            for (pid, started) in missing(&tracked, &processes) {
                tracked.remove(&(pid, started));
                events.push(event(EventType::ProcessTerminated, format!(
                    "Previously observed descendant PID {pid} (start {started}) is absent from the process snapshot"
                )));
            }

            let Some(target) = processes.get(&self.target_pid) else {
                break;
            };
            let identity = (target.pid, target.started);

            if root.is_some_and(|previous| previous != identity) {
                break;
            }

            root = Some(identity);

            /* One coherent snapshot supplies both discovery and disappearance.
            Combining independent providers can invent exits between snapshots.
            Snapshot polling cannot establish exact creation or exit times. */
            for child in descendants(identity, &processes) {
                if tracked.insert(child) {
                    if let Some(process) = processes.get(&child.0) {
                        events.push(event(
                            EventType::ProcessCreated,
                            format!(
                                "Observed descendant PID {} ({}) with parent PID {:?} (start {})",
                                process.pid, process.name, process.parent, process.started
                            ),
                        ));
                    }
                }
            }

            if let Some(process) = system.process(sysinfo::Pid::from_u32(self.target_pid)) {
                let memory_mb = process.memory() / 1024 / 1024;
                let cpu = process.cpu_usage();
                let now = Instant::now();

                if memory_mb > 100 && alert_due(&mut memory_alert, now) {
                    events.push(event(
                        EventType::HighMemoryUsage,
                        format!("PID {} using {memory_mb} MiB memory", self.target_pid),
                    ));
                }

                if cpu > 50.0 && alert_due(&mut cpu_alert, now) {
                    events.push(event(
                        EventType::HighCpuUsage,
                        format!("PID {} using {cpu:.2}% CPU", self.target_pid),
                    ));
                }
            }
        }

        Ok(())
    }
}

fn event(event_type: EventType, details: String) -> Event {
    Event {
        timestamp: chrono::Utc::now(),
        event_type,
        details,
    }
}

fn alert_due(previous: &mut Option<Instant>, now: Instant) -> bool {
    if previous.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(30)) {
        *previous = Some(now);
        true
    } else {
        false
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_process.rs"]
mod tests;
