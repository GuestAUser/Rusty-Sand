use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use super::activity::{Active, ActivityGuard};
use super::layout;
use super::text::{sanitize, width};
use super::{InputEdit, OutputPolicy, Panel, PromptEnd, Tone};

pub(super) const MAX_ENTRIES: usize = 256;
pub(super) const MAX_BYTES: usize = 64 * 1024;

/// A serialized human-output destination. No method holds its lock across a wait.
pub struct Terminal {
    pub(super) shared: Arc<Mutex<State>>,
}

pub(super) struct State {
    pub(super) writer: Box<dyn Write + Send>,
    pub(super) policy: OutputPolicy,
    pub(super) prompt: Option<Prompt>,
    pub(super) active: Option<Active>,
    pub(super) transient: bool,
    pub(super) queue: VecDeque<Entry>,
    pub(super) queued_bytes: usize,
    pub(super) dropped: usize,
    error: Option<io::Error>,
}

pub(super) struct Prompt {
    input: Vec<String>,
    line_open: bool,
}

pub(super) struct Entry {
    pub(super) text: String,
    tone: Tone,
}

impl Terminal {
    pub(super) fn new(writer: impl Write + Send + 'static, policy: OutputPolicy) -> Self {
        Self {
            shared: Arc::new(Mutex::new(State {
                writer: Box::new(writer),
                policy,
                prompt: None,
                active: None,
                transient: false,
                queue: VecDeque::new(),
                queued_bytes: 0,
                dropped: 0,
                error: None,
            })),
        }
    }

    pub(super) fn configure(&self, policy: OutputPolicy) -> io::Result<()> {
        let mut state = lock(&self.shared)?;
        state.check_error()?;

        if state.prompt.is_some() || state.active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "terminal is in use",
            ));
        }

        state.clear_transient()?;
        state.policy = policy;
        Ok(())
    }

    /// Write a complete panel atomically, without interrupting a prompt.
    ///
    /// # Errors
    /// Returns `WouldBlock` during a prompt, or a destination I/O error.
    pub fn panel(&self, panel: &Panel) -> io::Result<()> {
        let mut state = lock(&self.shared)?;
        state.check_error()?;

        if state.prompt.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "prompt owns output",
            ));
        }

        state.clear_transient()?;
        let policy = state.policy;
        layout::render_resolved(&mut state.writer, panel, &policy)
    }

    /// Emit a diagnostic, or retain it in the bounded prompt queue.
    /// Writer failures are retained and returned by the next fallible operation.
    pub fn diagnostic(&self, level: log::Level, text: &str) {
        let tone = match level {
            log::Level::Error => Tone::Danger,
            log::Level::Warn => Tone::Warning,
            log::Level::Info | log::Level::Debug | log::Level::Trace => Tone::Normal,
        };
        let entry = Entry {
            text: format!("[{level}] {}", sanitize(text)),
            tone,
        };
        let result = (|| {
            let mut state = lock(&self.shared)?;
            state.emit(entry)
        })();

        if let Err(error) = result {
            record_error(&self.shared, error);
        }
    }

    /// Start an exclusive decision prompt; diagnostics pause until its guard ends.
    ///
    /// # Errors
    /// Returns `WouldBlock` for a second prompt, or a destination I/O error.
    pub fn begin_prompt(&self, panel: &Panel) -> io::Result<PromptGuard> {
        let mut state = lock(&self.shared)?;
        state.check_error()?;

        if state.prompt.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "prompt already active",
            ));
        }

        state.clear_transient()?;
        let policy = state.policy;
        layout::render_resolved(&mut state.writer, panel, &policy)?;
        state.writer.write_all(b"> ")?;
        state.writer.flush()?;
        state.prompt = Some(Prompt {
            input: Vec::new(),
            line_open: true,
        });

        Ok(PromptGuard {
            shared: Arc::clone(&self.shared),
            finished: false,
        })
    }

    /// Echo native input through the same sink as prompts and diagnostics.
    /// Redirected input is never echoed.
    ///
    /// # Errors
    /// Returns `NotConnected` without a prompt, or a destination I/O error.
    pub fn input(&self, edit: InputEdit) -> io::Result<()> {
        let mut state = lock(&self.shared)?;
        state.check_error()?;

        if !state.policy.tty {
            return Ok(());
        }

        let State {
            writer,
            policy,
            prompt,
            ..
        } = &mut *state;
        let prompt = prompt
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no active prompt"))?;

        if !prompt.line_open {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input line already ended",
            ));
        }

        match edit {
            InputEdit::Append(text) => {
                for character in text.chars() {
                    let escaped = sanitize(&character.to_string());

                    if !policy.styled() {
                        writer.write_all(escaped.as_bytes())?;
                    }

                    prompt.input.push(escaped);
                }

                if policy.styled() {
                    redraw_input(writer, prompt, policy.width())?;
                }
            }
            InputEdit::Backspace => {
                if let Some(removed) = prompt.input.pop() {
                    if policy.styled() {
                        redraw_input(writer, prompt, policy.width())?;
                    } else {
                        for _ in 0..width(&removed) {
                            writer.write_all(b"\x08 \x08")?;
                        }
                    }
                }
            }
            InputEdit::Newline => {
                /* Retain the full answer, not only the visible input viewport. */
                if policy.styled() {
                    writer.write_all(b"\r\x1b[2K> ")?;
                    writer.write_all(prompt.input.concat().as_bytes())?;
                }

                writeln!(writer)?;
                prompt.line_open = false;
            }
        }

        writer.flush()
    }

    /// Emit a truthful stage or result, retaining it while a prompt owns output.
    ///
    /// # Errors
    /// Propagates destination I/O errors, including retained asynchronous errors.
    pub fn status(&self, text: &str, tone: Tone) -> io::Result<()> {
        let entry = Entry {
            text: format!("[{}] {}", tone.label(), sanitize(text)),
            tone,
        };
        let mut state = lock(&self.shared)?;
        state.check_error()?;
        state.emit(entry)
    }

    /// Start a single real-work activity, with an optional elapsed-time effect.
    ///
    /// # Errors
    /// Returns `WouldBlock` for overlapping activities, or an I/O/spawn error.
    pub fn activity(&self, text: &str) -> io::Result<ActivityGuard> {
        ActivityGuard::start(Arc::clone(&self.shared), text)
    }
}

impl State {
    pub(super) fn check_error(&mut self) -> io::Result<()> {
        match self.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn clear_transient(&mut self) -> io::Result<()> {
        if self.transient {
            self.writer.write_all(b"\r\x1b[2K")?;
            self.transient = false;
        }

        Ok(())
    }

    pub(super) fn emit(&mut self, entry: Entry) -> io::Result<()> {
        if self.prompt.is_some() {
            self.enqueue(entry);
            return Ok(());
        }

        self.clear_transient()?;
        layout::styled_lines(&mut self.writer, &entry.text, entry.tone, &self.policy)?;
        self.writer.flush()
    }

    pub(super) fn stage(&mut self, text: &str, tone: Tone) -> io::Result<()> {
        self.emit(Entry {
            text: format!("[{}] {}", tone.label(), sanitize(text)),
            tone,
        })
    }

    /* The byte budget counts escaped text, not raw input. Oversized entries are
     * reported as dropped rather than truncated into misleading evidence. FIFO
     * eviction retains recent diagnostics; the count makes every loss visible. */
    fn enqueue(&mut self, entry: Entry) {
        if entry.text.len() > MAX_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }

        while self.queue.len() >= MAX_ENTRIES || self.queued_bytes + entry.text.len() > MAX_BYTES {
            if let Some(old) = self.queue.pop_front() {
                self.queued_bytes -= old.text.len();
                self.dropped = self.dropped.saturating_add(1);
            }
        }

        self.queued_bytes += entry.text.len();
        self.queue.push_back(entry);
    }

    fn end_prompt(&mut self, end: PromptEnd) -> io::Result<()> {
        let Some(prompt) = self.prompt.take() else {
            return Ok(());
        };

        if prompt.line_open {
            writeln!(self.writer)?;
        }

        match end {
            PromptEnd::Answered => {}
            PromptEnd::Cancelled => {
                self.stage("Decision cancelled; no approval recorded", Tone::Warning)?
            }
        }

        while let Some(entry) = self.queue.pop_front() {
            self.queued_bytes -= entry.text.len();
            self.emit(entry)?;
        }

        if self.dropped != 0 {
            self.stage(
                &format!(
                    "{} diagnostic entries dropped during the prompt",
                    self.dropped
                ),
                Tone::Warning,
            )?;
            self.dropped = 0;
        }

        self.writer.flush()
    }
}

/// Exclusive prompt ownership. Drop cancels the prompt and releases diagnostics.
#[must_use = "retain the prompt guard until input completes"]
pub struct PromptGuard {
    shared: Arc<Mutex<State>>,
    finished: bool,
}

impl PromptGuard {
    /// End the prompt and flush deferred diagnostics in order.
    ///
    /// # Errors
    /// Propagates destination I/O errors.
    pub fn finish(mut self, end: PromptEnd) -> io::Result<()> {
        self.finished = true;
        lock(&self.shared)?.end_prompt(end)
    }
}

impl Drop for PromptGuard {
    fn drop(&mut self) {
        if !self.finished {
            let result =
                lock(&self.shared).and_then(|mut state| state.end_prompt(PromptEnd::Cancelled));

            if let Err(error) = result {
                record_error(&self.shared, error);
            }
        }
    }
}

pub(super) fn lock(shared: &Mutex<State>) -> io::Result<MutexGuard<'_, State>> {
    shared
        .lock()
        .map_err(|_| io::Error::other("terminal output lock poisoned"))
}

pub(super) fn record_error(shared: &Mutex<State>, error: io::Error) {
    /* Retain the failure without resuming a partially written frame. */
    let mut state = match shared.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };

    if state.error.is_none() {
        state.error = Some(error);
    }
}

fn redraw_input(writer: &mut impl Write, prompt: &Prompt, columns: usize) -> io::Result<()> {
    let answer = prompt.input.concat();
    let available = columns.saturating_sub(2);
    let mut tail = answer.as_str();

    while width(tail) > available {
        let Some(character) = tail.chars().next() else {
            break;
        };
        tail = &tail[character.len_utf8()..];
    }

    let prefix = if tail.len() == answer.len() {
        "> "
    } else {
        "< "
    };
    write!(writer, "\r\x1b[2K{}{tail}", &prefix[..columns.min(2)])
}
