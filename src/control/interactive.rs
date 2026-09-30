use crate::behavior::ThreatDetection;
use crate::report::{Event, EventType};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDecision {
    Allow,
    AllowAll,
    Block,
    BlockAll,
    Terminate,
    Continue,
}

fn parse_decision(input: &str, allow_cached: bool) -> Option<UserDecision> {
    match input.trim().to_ascii_uppercase().as_str() {
        "A" => Some(UserDecision::Allow),
        "AA" if allow_cached => Some(UserDecision::AllowAll),
        "B" => Some(UserDecision::Block),
        "BB" if allow_cached => Some(UserDecision::BlockAll),
        "T" => Some(UserDecision::Terminate),
        "C" => Some(UserDecision::Continue),
        _ => None,
    }
}

fn read_decision(
    input: &mut impl BufRead,
    output: &mut impl Write,
    allow_cached: bool,
) -> io::Result<UserDecision> {
    loop {
        write!(output, "Decision: ")?;
        output.flush()?;

        let mut line = String::new();

        if input.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Decision input closed",
            ));
        }

        if let Some(decision) = parse_decision(&line, allow_cached) {
            return Ok(decision);
        }

        writeln!(
            output,
            "Unrecognized decision; enter one of the listed options."
        )?;
    }
}

fn fail_closed(result: io::Result<UserDecision>) -> UserDecision {
    match result {
        Ok(decision) => decision,
        Err(error) => {
            log::error!("Cannot obtain a user decision; requesting termination: {error}");
            UserDecision::Terminate
        }
    }
}

#[derive(Default)]
pub struct InteractiveController {
    automatic: Option<UserDecision>,
    policies: HashMap<EventType, UserDecision>,
}

impl InteractiveController {
    pub fn new() -> Self {
        Self::default()
    }

    fn cached_decision(&self, event_type: &EventType) -> Option<UserDecision> {
        self.automatic
            .or_else(|| self.policies.get(event_type).copied())
    }

    pub fn should_prompt(&self, event_type: &EventType) -> bool {
        self.cached_decision(event_type).is_none()
    }

    pub fn is_allowed(&self, event_type: &EventType) -> bool {
        matches!(
            self.cached_decision(event_type),
            Some(UserDecision::AllowAll)
        )
    }

    pub fn is_blocked(&self, event_type: &EventType) -> bool {
        matches!(
            self.cached_decision(event_type),
            Some(UserDecision::BlockAll)
        )
    }

    pub fn check_event_status(&self, event_type: &EventType) -> (bool, bool, bool) {
        (
            self.should_prompt(event_type),
            self.is_allowed(event_type),
            self.is_blocked(event_type),
        )
    }

    pub fn prompt_for_event(&mut self, event: &Event) -> UserDecision {
        fail_closed(self.prompt_for_event_with_io(
            event,
            &mut io::stdin().lock(),
            &mut io::stdout().lock(),
        ))
    }

    pub fn prompt_for_event_with_io(
        &mut self,
        event: &Event,
        input: &mut impl BufRead,
        output: &mut impl Write,
    ) -> io::Result<UserDecision> {
        if let Some(decision) = self.cached_decision(&event.event_type) {
            return Ok(decision);
        }

        writeln!(output, "\nObserved event: {:?}", event.event_type)?;
        writeln!(output, "Details: {}", event.details)?;
        writeln!(output, "Time: {}", event.timestamp)?;
        writeln!(
            output,
            "This is a post-event review, not a prevention or undo mechanism."
        )?;
        write_menu(output)?;
        writeln!(
            output,
            "[AA] Accept future events of this type without prompting"
        )?;
        writeln!(
            output,
            "[BB] Mark future events of this type suspicious without prompting"
        )?;
        writeln!(
            output,
            "[C] Continue monitoring this type without prompting"
        )?;

        let decision = read_decision(input, output, true)?;

        if matches!(
            decision,
            UserDecision::AllowAll | UserDecision::BlockAll | UserDecision::Continue
        ) {
            self.policies.insert(event.event_type.clone(), decision);
        }

        Ok(decision)
    }

    pub fn prompt_user(&mut self, threat: &ThreatDetection) -> UserDecision {
        fail_closed(self.prompt_user_with_io(
            threat,
            &mut io::stdin().lock(),
            &mut io::stdout().lock(),
        ))
    }

    pub fn prompt_user_with_io(
        &mut self,
        threat: &ThreatDetection,
        input: &mut impl BufRead,
        output: &mut impl Write,
    ) -> io::Result<UserDecision> {
        if let Some(decision) = self.automatic {
            return Ok(match decision {
                UserDecision::AllowAll => UserDecision::Allow,
                UserDecision::BlockAll => UserDecision::Block,
                other => other,
            });
        }

        writeln!(
            output,
            "\nThreat: {} ({:?})",
            threat.threat_type, threat.level
        )?;
        writeln!(output, "{}", threat.description)?;

        for evidence in &threat.evidence {
            writeln!(output, "Evidence: {evidence}")?;
        }

        writeln!(
            output,
            "Reviewing detected activity cannot undo or prevent it."
        )?;
        write_menu(output)?;
        writeln!(output, "[C] Continue monitoring")?;
        read_decision(input, output, false)
    }

    /** Global policy overrides per-type choices; the most recently enabled mode wins. */
    pub fn set_auto_allow(&mut self, enabled: bool) {
        if enabled {
            self.automatic = Some(UserDecision::AllowAll);
        } else if self.automatic == Some(UserDecision::AllowAll) {
            self.automatic = None;
        }
    }

    pub fn set_auto_block(&mut self, enabled: bool) {
        if enabled {
            self.automatic = Some(UserDecision::BlockAll);
        } else if self.automatic == Some(UserDecision::BlockAll) {
            self.automatic = None;
        }
    }
}

fn write_menu(output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "[A] Accept this observation and continue")?;
    writeln!(
        output,
        "[B] Mark this observation suspicious and continue (does not block it)"
    )?;
    writeln!(output, "[T] Request process termination")
}

#[cfg(test)]
#[path = "../../tests/unit/windows/control_interactive.rs"]
mod tests;
