use super::command::Command;
use super::MAX_OUTPUT_CHARACTERS;
use crate::ui::{self, Panel, Tone};
use anyhow::Result;

const TRUNCATION_NOTICE: &str = "[display truncated; saved report artifacts are not truncated]";

pub(super) fn emit(command: Command, text: &str) -> Result<()> {
    match command_panel(command, text) {
        Some(panel) => {
            ui::terminal().panel(&panel)?;
            Ok(())
        }
        None => super::emit(text, Tone::Normal),
    }
}

fn command_panel(command: Command, text: &str) -> Option<Panel> {
    let title = match command {
        Command::Help => "Analyst commands",
        Command::Analysis => "Static analysis",
        Command::Status => "Execution status",
        Command::Events(_) => "Retained events",
        _ => return None,
    };

    /*
     * Only these command formatters generate trusted structural LF separators:
     * help/static coverage text and serde's pretty JSON. JSON string values
     * already escape embedded LF, including filenames, event details and errors.
     *
     * Do not infer structure from arbitrary messages containing newlines.
     * Operational paths and errors still go through status() as one escaped
     * value. Split only LF here; CR and all other controls remain data for the
     * existing panel sanitizer to escape.
     */
    let text = bounded(text);

    Some(Panel {
        title: title.into(),
        tone: Tone::Normal,
        fields: Vec::new(),
        notes: text.split('\n').map(str::to_owned).collect(),
    })
}

pub(super) fn bounded(text: &str) -> String {
    /*
     * Retain the existing character budget plus a fixed truncation notice.
     * The notice itself is single-line, including on the status/error path.
     * Neither presentation path retains command or output history.
     */
    match text.char_indices().nth(MAX_OUTPUT_CHARACTERS) {
        Some((boundary, _)) => format!("{} {TRUNCATION_NOTICE}", &text[..boundary]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/shell/output.rs"]
mod tests;
