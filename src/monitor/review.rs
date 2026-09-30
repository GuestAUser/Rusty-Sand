#[cfg(windows)]
use super::input::ConsoleInput;
use crate::analysis::RiskScore;
use crate::behavior::{ThreatDetection, ThreatLevel};
use crate::config::SandboxConfig;
use crate::control::UserDecision;
use crate::report::{Event, EventType};
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::ops::AsyncFnMut;
use tokio::sync::{mpsc, oneshot};

pub(super) enum Review {
    Hook {
        description: String,
        risk: RiskScore,
    },
    Observation(ThreatDetection),
}

struct Request {
    review: Review,
    reply: oneshot::Sender<UserDecision>,
}

pub(super) struct ReviewClient {
    sender: mpsc::Sender<Request>,
}

pub(super) struct ReviewBroker {
    receiver: mpsc::Receiver<Request>,
}

/** Both producers await their decision. One queued request plus one active
prompt bounds pending work without sharing a console lock across user input. */
pub(super) fn channel() -> (ReviewClient, ReviewBroker) {
    let (sender, receiver) = mpsc::channel(1);
    (ReviewClient { sender }, ReviewBroker { receiver })
}

impl ReviewClient {
    pub(super) async fn hook(&self, description: String, risk: RiskScore) -> Result<UserDecision> {
        self.request(Review::Hook { description, risk }).await
    }

    pub(super) async fn observation(
        &self,
        config: &SandboxConfig,
        threat: &ThreatDetection,
    ) -> Result<Option<UserDecision>> {
        if config.auto_terminate_on_critical && threat.level == ThreatLevel::Critical {
            bail!(
                "critical observed behavior requires process termination: {}",
                threat.threat_type
            );
        }
        if !config.interactive_mode || !threat.should_pause {
            return Ok(None);
        }
        self.request(Review::Observation(threat.clone()))
            .await
            .map(Some)
    }

    async fn request(&self, review: Review) -> Result<UserDecision> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(Request { review, reply })
            .await
            .context("queue interactive review")?;
        receive
            .await
            .context("interactive review ended without a decision")
    }
}

impl ReviewBroker {
    #[cfg(windows)]
    pub(super) async fn run(self, mut input: Option<&mut ConsoleInput>) -> Result<()> {
        self.dispatch(async |review| {
            let input = input
                .as_deref_mut()
                .context("interactive review has no console reader")?;
            review.write_prompt(&mut std::io::stdout())?;
            loop {
                std::io::stdout().flush()?;
                let line = input.read_line().await?;
                if let Some(decision) = review.parse_decision(&line) {
                    return Ok(decision);
                }
                print!("Unrecognized decision; enter A, B, C, or T: ");
            }
        })
        .await
    }

    pub(super) async fn dispatch(
        mut self,
        mut decide: impl AsyncFnMut(&Review) -> Result<UserDecision>,
    ) -> Result<()> {
        while let Some(Request { review, reply }) = self.receiver.recv().await {
            if reply.is_closed() {
                continue;
            }
            let decision = decide(&review).await?;
            if reply.send(decision).is_err() {
                log::debug!("Interactive review requester was cancelled");
            }
        }
        Ok(())
    }
}

impl Review {
    fn write_prompt(&self, output: &mut impl Write) -> std::io::Result<()> {
        match self {
            Self::Hook { description, risk } => {
                writeln!(
                    output,
                    "\nHook request: {description}\nRisk: {}/100 ({})",
                    risk.score,
                    risk.category.as_str()
                )?;
                writeln!(
                    output,
                    "[Y]es / [A]llow this type / [N]o / [D]eny this type / [T]erminate"
                )
            }
            Self::Observation(threat) => {
                writeln!(
                    output,
                    "\nObserved behavior: {} ({:?})\n{}",
                    threat.threat_type, threat.level, threat.description
                )?;
                for evidence in &threat.evidence {
                    writeln!(output, "Evidence: {evidence}")?;
                }
                writeln!(
                    output,
                    "This is a post-event review; the target continues running."
                )?;
                writeln!(
                    output,
                    "Block cannot undo or prevent previously observed activity."
                )?;
                writeln!(
                    output,
                    "[A]ccept / [B] Flag suspicious / [C]ontinue / [T]erminate"
                )
            }
        }
    }

    fn parse_decision(&self, input: &str) -> Option<UserDecision> {
        match self {
            Self::Hook { .. } => Some(match input.trim().to_ascii_uppercase().as_str() {
                "Y" => UserDecision::Allow,
                "A" => UserDecision::AllowAll,
                "D" => UserDecision::BlockAll,
                "T" => UserDecision::Terminate,
                _ => UserDecision::Block,
            }),
            Self::Observation(_) => match input.trim().to_ascii_uppercase().as_str() {
                "A" => Some(UserDecision::Allow),
                "B" => Some(UserDecision::Block),
                "C" => Some(UserDecision::Continue),
                "T" => Some(UserDecision::Terminate),
                _ => None,
            },
        }
    }
}

pub(super) fn apply_observation_decision(
    threat: &ThreatDetection,
    decision: Option<UserDecision>,
    events: &mut Vec<Event>,
) -> Result<()> {
    match decision {
        Some(UserDecision::Terminate) => bail!("user requested termination after observing {}", threat.threat_type),
        Some(UserDecision::Block | UserDecision::BlockAll) => events.push(Event {
            timestamp: chrono::Utc::now(),
            event_type: EventType::Suspicious,
            details: format!("User flagged observed {}: {}. Previously observed activity was not blocked or undone.", threat.threat_type, threat.description),
        }),
        None | Some(UserDecision::Allow | UserDecision::AllowAll | UserDecision::Continue) => {}
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_review.rs"]
mod tests;
