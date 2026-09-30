use super::*;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

mod activity;
mod layout;
mod sink;

#[derive(Clone, Default)]
struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture failure"));
        }

        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture failure"));
        }

        Ok(())
    }
}

fn policy() -> OutputPolicy {
    OutputPolicy {
        color: ColorMode::Always,
        plain: false,
        reduced_motion: false,
        tty: true,
        columns: 80,
    }
}

fn panel() -> Panel {
    Panel {
        title: "PROMPT_SENTINEL".into(),
        tone: Tone::Warning,
        fields: vec![("FIELD_SENTINEL".into(), "VALUE_SENTINEL".into())],
        notes: vec!["CHOICE_A / CHOICE_B".into()],
    }
}

fn fixture(policy: OutputPolicy) -> (Terminal, Capture) {
    let capture = Capture::default();
    let terminal = Terminal::new(capture.clone(), policy);
    (terminal, capture)
}
