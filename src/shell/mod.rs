//! A bounded analyst command loop, not an operating-system command shell.

mod command;
mod dispatch;
mod input;
mod output;

use crate::config::SandboxConfig;
use crate::live::LiveSession;
use crate::monitor::input::ConsoleInput;
use crate::sandbox::resource::with_cleanup;
use crate::ui::{self, Tone};
use anyhow::{Context, Result};
use input::input_ended;

const MAX_OUTPUT_CHARACTERS: usize = 16_384;

/** Run an analyst shell for one configured executable.

Only `run` launches the target. Execution uses automatic hook policy and never
competes for stdin. No command attaches to arbitrary PIDs or invokes a host
command processor. Pause is snapshot-based, not an atomic process freeze.
*/
pub async fn run_shell(executable: &str, args: &[String], config: SandboxConfig) -> Result<()> {
    let session = LiveSession::new(executable, args, config)?;
    let mut shell = Shell {
        session,
        #[cfg(test)]
        armed: None,
    };
    let mut input = ConsoleInput::new()?;

    shell.serve(&mut input).await
}

struct Shell {
    session: LiveSession,
    #[cfg(test)]
    armed: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Shell {
    async fn serve(&mut self, input: &mut ConsoleInput) -> Result<()> {
        let mut status = input.status();

        let result = async {
            let mut signal = tokio::signal::windows::ctrl_c().context("register shell Ctrl-C")?;

            emit(
                "Analyst shell. Use help. Inspection does not execute the sample. \
                 Run permits monitored startup with automatic hook policy. \
                 Pause is a root-thread snapshot, not an atomic freeze.",
                Tone::Heading,
            )?;

            tokio::select! {
                biased;
                _ = signal.recv() => Ok(()),
                result = input_ended(&mut status) => result,
                result = self.commands(input) => result,
            }
        }
        .await;

        /*
         * Signal execution first, then close the reader even if checked
         * monitor teardown subsequently fails. Never abort or detach it.
         */
        self.session.request_stop();
        let input_closed = input.close();
        let stopped = self.session.stop().await;

        with_cleanup(with_cleanup(result, input_closed), stopped)
    }

    async fn commands(&mut self, input: &mut ConsoleInput) -> Result<()> {
        loop {
            let Some(line) = self.read_command(input).await? else {
                return Ok(());
            };
            self.session.refresh().await?;

            let command = match command::parse(&line) {
                Ok(Some(command)) => command,
                Ok(None) => continue,
                Err(error) => {
                    emit(&format!("{error:#}"), Tone::Warning)?;
                    continue;
                }
            };

            /*
             * Invalid commands and operational command errors are displayed.
             * Transport, terminal and asynchronous monitor failures instead
             * leave through serve's unconditional owner cleanup.
             */
            match self.dispatch(command).await {
                Ok(Some(message)) => output::emit(command, &message)?,
                Ok(None) => return Ok(()),
                Err(error) => emit(&format!("{error:#}"), Tone::Warning)?,
            }
        }
    }
}

fn emit(text: &str, tone: Tone) -> Result<()> {
    let text = output::bounded(text);

    ui::terminal().status(&text, tone)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/shell/input.rs"]
mod tests;
