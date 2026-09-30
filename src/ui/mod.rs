//! Scrolling, stderr-only human output with serialized prompt and activity ownership.
//!
//! Dynamic text is escaped at the rendering boundary. Guards own lifecycle state,
//! not mutex guards, so callers can wait for input or await work without locking
//! the output sink. No alternate screen or cursor hiding is used.

mod activity;
mod layout;
mod policy;
mod sink;
mod text;

pub use activity::ActivityGuard;
pub use layout::render_panel;
pub use sink::{PromptGuard, Terminal};

use std::io::{self, IsTerminal};
use std::sync::OnceLock;

/// Explicit color preference; `Never` also disables terminal effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Semantic styling. Color is always accompanied by a textual label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tone {
    Normal,
    Heading,
    Success,
    Warning,
    Danger,
}

/// Native console edits. Redirected input must not be application-echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEdit {
    Append(String),
    Backspace,
    Newline,
}

/// Whether the caller obtained an answer or abandoned the prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptEnd {
    Answered,
    Cancelled,
}

/// Output capabilities provided by the launcher or native console detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputPolicy {
    pub color: ColorMode,
    pub plain: bool,
    pub reduced_motion: bool,
    pub tty: bool,
    pub columns: usize,
}

/// A decision or evidence panel. All strings are treated as untrusted text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Panel {
    pub title: String,
    pub tone: Tone,
    pub fields: Vec<(String, String)>,
    pub notes: Vec<String>,
}

/// The process-wide human-output sink. Machine output remains on stdout.
pub fn terminal() -> &'static Terminal {
    static TERMINAL: OnceLock<Terminal> = OnceLock::new();

    TERMINAL.get_or_init(|| {
        let policy = OutputPolicy {
            color: ColorMode::Auto,
            plain: false,
            reduced_motion: false,
            tty: io::stderr().is_terminal(),
            columns: 80,
        };

        Terminal::new(io::stderr(), policy.resolved())
    })
}

/// Resolve environment overrides once and configure the shared sink.
///
/// # Errors
/// Returns an I/O error, or `WouldBlock` if a prompt or activity is active.
pub fn configure(policy: OutputPolicy) -> io::Result<()> {
    terminal().configure(policy.resolved())
}

#[cfg(test)]
#[path = "../../tests/unit/ui/mod.rs"]
mod tests;
