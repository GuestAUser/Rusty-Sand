#[cfg(windows)]
use super::input::ConsoleInput;
use crate::analysis::RiskScore;
use crate::behavior::{ThreatDetection, ThreatLevel};
use crate::config::SandboxConfig;
use crate::control::UserDecision;
use crate::report::{Event, EventType};
use crate::ui::{self, Panel, PromptEnd, Tone};
use anyhow::{bail, Context, Result};
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
            loop {
                let status = input.status();
                let answer = input.read_line();
                let prompt = ui::terminal().begin_prompt(&review.panel())?;
                let line = answer.await?;
                tokio::task::yield_now().await;
                super::lifecycle::check_input(&status)?;
                prompt.finish(PromptEnd::Answered)?;

                if let Some(decision) = review.parse_decision(&line) {
                    if matches!(review, Review::Hook { .. }) {
                        let (selection, tone) = match decision {
                            UserDecision::Allow => ("Allow this operation", Tone::Success),
                            UserDecision::AllowAll => ("Allow this operation type", Tone::Success),
                            UserDecision::Block | UserDecision::Continue => {
                                ("Deny this operation", Tone::Danger)
                            }
                            UserDecision::BlockAll => ("Deny this operation type", Tone::Danger),
                            UserDecision::Terminate => ("Terminate the target", Tone::Danger),
                        };
                        ui::terminal().status(&format!("Decision: {selection}"), tone)?;
                    }
                    return Ok(decision);
                }

                ui::terminal().status(
                    "Unrecognized decision; use one of the listed keys.",
                    Tone::Warning,
                )?;
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
    fn panel(&self) -> Panel {
        match self {
            Self::Hook { description, risk } => Panel {
                title: "Intercepted operation / approval required".into(),
                tone: if risk.score > 60 {
                    Tone::Danger
                } else {
                    Tone::Warning
                },
                fields: vec![
                    ("Operation".into(), description.clone()),
                    (
                        "Risk".into(),
                        format!("{}/100 ({})", risk.score, risk.category.as_str()),
                    ),
                ],
                notes: vec![
                    "[Y] Yes / [A] Allow this type / [N] No / [D] Deny this type / [T] Terminate"
                        .into(),
                    "Only Y or A approves. Empty or unknown input denies. Ctrl-C cancels.".into(),
                ],
            },
            Self::Observation(threat) => {
                let mut notes = threat
                    .evidence
                    .iter()
                    .map(|evidence| format!("Evidence: {evidence}"))
                    .collect::<Vec<_>>();
                notes.extend([
                    "Post-event review: the target continues running. Flagging cannot undo or prevent observed activity.".into(),
                    "[A] Accept / [B] Flag suspicious / [C] Continue / [T] Terminate. Ctrl-C cancels.".into(),
                ]);

                Panel {
                    title: "Observed behavior / review".into(),
                    tone: Tone::Warning,
                    fields: vec![
                        ("Observation".into(), threat.threat_type.clone()),
                        ("Level".into(), format!("{:?}", threat.level)),
                        ("Details".into(), threat.description.clone()),
                    ],
                    notes,
                }
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
