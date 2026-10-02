use crate::live::MAX_EVENT_PAGE;
use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Command {
    Help,
    Analysis,
    Run,
    Status,
    Events(usize),
    Pause,
    Resume,
    Stop,
    Report,
    Quit,
}

pub(super) fn parse(line: &str) -> Result<Option<Command>> {
    /*
     * Match the input reader's existing UTF-16 boundary for direct callers.
     * Embedded controls never become separators for additional commands.
     */
    if line.encode_utf16().count() > 64 {
        bail!("command exceeds 64 UTF-16 units");
    }

    if line.chars().any(char::is_control) {
        bail!("control characters are not commands");
    }

    let mut words = line.split_whitespace();
    let Some(name) = words.next() else {
        return Ok(None);
    };

    let command = match name {
        "help" => Command::Help,
        "info" | "analysis" => Command::Analysis,
        "run" => Command::Run,
        "status" => Command::Status,
        "events" => {
            let count = match words.next() {
                Some(value) => value.parse::<usize>().context("events requires a count")?,
                None => 20,
            };

            if !(1..=MAX_EVENT_PAGE).contains(&count) {
                bail!("event count must be between 1 and {MAX_EVENT_PAGE}");
            }

            Command::Events(count)
        }
        "pause" => Command::Pause,
        "resume" => Command::Resume,
        "stop" => Command::Stop,
        "report" => Command::Report,
        "quit" => Command::Quit,
        _ => bail!("unknown analyst command; use help"),
    };

    if words.next().is_some() {
        bail!("unexpected command arguments");
    }

    Ok(Some(command))
}

#[cfg(test)]
#[path = "../../tests/unit/windows/shell/parser.rs"]
mod shell_parser_tests;
