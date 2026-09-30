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
    /// Print a plain summary to stdout for existing library callers.
    pub fn print_summary(&self) {
        use crate::ui::{ColorMode, OutputPolicy};

        let policy = OutputPolicy {
            color: ColorMode::Never,
            plain: true,
            reduced_motion: true,
            tty: false,
            columns: 80,
        };

        if let Err(error) = self.write_summary(&mut std::io::stdout().lock(), &policy) {
            log::error!("Cannot write execution summary: {error}");
        }
    }

    /// Write a styled human summary without changing the JSON report schema.
    ///
    /// # Errors
    /// Returns any destination write or flush failure.
    pub fn write_summary(
        &self,
        writer: &mut impl std::io::Write,
        policy: &crate::ui::OutputPolicy,
    ) -> std::io::Result<()> {
        use crate::ui::{render_panel, Panel, Tone};

        let counts = EventCounts::from_events(&self.events);
        render_panel(writer, &Panel {
            title: "Execution report".into(),
            tone: if self.exit_code == 0 { Tone::Success } else { Tone::Warning },
            fields: vec![
                ("Executable".into(), self.executable.clone()),
                ("Outcome".into(), if self.exit_code == 0 { "Target exited successfully".into() } else { "Target exited with a nonzero status".into() }),
                ("Exit code".into(), self.exit_code.to_string()),
                ("Start".into(), self.start_time.to_string()),
                ("End".into(), self.end_time.to_string()),
                ("Duration".into(), format!("{} seconds", self.duration_seconds)),
                ("Total events".into(), self.events.len().to_string()),
                ("File / folder".into(), format!("{} / {}", counts.files, counts.folders)),
                ("Network / reported blocked".into(), format!("{} / {}", counts.network, counts.network_blocked)),
                ("Process / registry".into(), format!("{} / {}", counts.processes, counts.registry)),
                ("Hook denials".into(), counts.hook_blocked.to_string()),
            ],
            notes: vec!["Counts are recorded evidence, not unique completed operations or a safety verdict.".into()],
        }, policy)?;

        render_panel(
            writer,
            &Panel {
                title: "Configured policy / not a containment guarantee".into(),
                tone: Tone::Normal,
                fields: vec![
                    (
                        "Internet / DNS".into(),
                        format!(
                            "{} / {}",
                            if self.config.allow_internet {
                                "ALLOW"
                            } else {
                                "DENY"
                            },
                            if self.config.allow_dns {
                                "ALLOW"
                            } else {
                                "DENY"
                            }
                        ),
                    ),
                    (
                        "Registry".into(),
                        if self.config.allow_registry {
                            "ALLOW"
                        } else {
                            "DENY"
                        }
                        .into(),
                    ),
                    (
                        "Memory limit".into(),
                        format!("{} MB (0 = unlimited)", self.config.max_memory_mb),
                    ),
                    (
                        "CPU limit".into(),
                        format!("{} seconds (0 = unlimited)", self.config.max_cpu_time),
                    ),
                ],
                notes: vec![],
            },
            policy,
        )?;

        if !self.events.is_empty() {
            let first = self.events.len().saturating_sub(100);
            render_panel(
                writer,
                &Panel {
                    title: "Recent recorded events / last 100 at most".into(),
                    tone: Tone::Normal,
                    fields: vec![],
                    notes: self.events[first..]
                        .iter()
                        .map(|event| {
                            format!(
                                "[{}] {:?}: {}",
                                event.timestamp.format("%H:%M:%S"),
                                event.event_type,
                                event.details
                            )
                        })
                        .collect(),
                },
                policy,
            )?;
        }

        Ok(())
    }
}
