use super::{emit, Shell};
use crate::live::RunState;
use crate::monitor::input::{ConsoleInput, InputEnd, LineRead};
use crate::ui::{self, Panel, PromptEnd, Tone};
use anyhow::{bail, Context, Result};
use tokio::sync::watch;

impl Shell {
    pub(super) async fn read_command(
        &mut self,
        input: &mut ConsoleInput,
    ) -> Result<Option<String>> {
        let mut execution = self.session.subscribe();

        /* Reserve input before rendering; unarmed typeahead is discarded. */
        let answer = input.read_line_event();
        tokio::pin!(answer);

        let prompt = ui::terminal().begin_prompt(&Panel {
            title: "Analyst command".into(),
            tone: Tone::Normal,
            fields: vec![("State".into(), format!("{:?}", self.session.state()))],
            notes: Vec::new(),
        })?;

        #[cfg(test)]
        if let Some(armed) = &self.armed {
            armed
                .try_send(())
                .context("publish shell input readiness")?;
        }

        let line = loop {
            tokio::select! {
                biased;
                result = execution_ended(&mut execution) => {
                    result?;
                    self.session.refresh().await?;
                    execution = None;

                    /*
                     * Keep the same armed answer and prompt. Completion must
                     * not discard a partially typed command or re-arm stdin.
                     */
                    emit("Owned monitoring completed and joined", Tone::Success)?;
                }
                result = &mut answer => {
                    match result? {
                        LineRead::Line(line) => break Some(line),
                        LineRead::End(end) => {
                            check_end(end)?;
                            break None;
                        }
                    }
                }
            }
        };

        prompt.finish(if line.is_some() {
            PromptEnd::Answered
        } else {
            PromptEnd::Cancelled
        })?;
        Ok(line)
    }
}

async fn execution_ended(execution: &mut Option<watch::Receiver<RunState>>) -> Result<()> {
    let Some(state) = execution else {
        return std::future::pending().await;
    };

    state
        .wait_for(|state| state.is_finished())
        .await
        .context("execution state publisher ended unexpectedly")?;

    Ok(())
}

pub(super) async fn input_ended(status: &mut watch::Receiver<Option<InputEnd>>) -> Result<()> {
    let end = status
        .wait_for(|end| end.is_some())
        .await
        .context("shell input status channel closed")?
        .clone()
        .context("shell input completion disappeared")?;

    check_end(end)
}

fn check_end(end: InputEnd) -> Result<()> {
    match end {
        InputEnd::Eof | InputEnd::Cancelled => Ok(()),
        InputEnd::Failed(error) => bail!("shell input failed: {error}"),
    }
}
