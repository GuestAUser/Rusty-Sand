use std::io::{self, Write};

use super::text::{sanitize, width, wrap};
use super::{OutputPolicy, Panel, Tone};

/// Render a scrolling panel without retaining a screen or changing cursor state.
///
/// # Errors
/// Propagates the destination writer's I/O errors.
pub fn render_panel(
    writer: &mut impl Write,
    panel: &Panel,
    policy: &OutputPolicy,
) -> io::Result<()> {
    render_resolved(writer, panel, &policy.resolved())
}

pub(super) fn render_resolved(
    writer: &mut impl Write,
    panel: &Panel,
    policy: &OutputPolicy,
) -> io::Result<()> {
    let columns = policy.width();
    let title = format!(
        "RUSTY SAND / [{}] {}",
        panel.tone.label(),
        sanitize(&panel.title)
    );

    writeln!(writer)?;
    styled_lines(writer, &title, panel.tone, policy)?;
    writeln!(writer, "{}", "-".repeat(columns.min(72)))?;

    let fields: Vec<_> = panel
        .fields
        .iter()
        .map(|(label, value)| (sanitize(label), sanitize(value)))
        .collect();
    let label_width = fields
        .iter()
        .map(|(label, _)| width(label))
        .max()
        .unwrap_or(0);
    let stacked = policy.columns < 80 || label_width > columns / 3;

    for (label, value) in fields {
        if stacked {
            plain_lines(writer, &format!("{label}:"), columns)?;
            indented_lines(writer, &value, 2, columns)?;
        } else {
            let prefix = format!("  {label}{} : ", " ".repeat(label_width - width(&label)));
            let indent = width(&prefix);
            let lines = wrap(&value, columns.saturating_sub(indent).max(1));

            for (index, line) in lines.iter().enumerate() {
                if index == 0 {
                    writeln!(writer, "{prefix}{line}")?;
                } else {
                    writeln!(writer, "{}{line}", " ".repeat(indent))?;
                }
            }
        }
    }

    if !panel.notes.is_empty() {
        writeln!(writer)?;

        for note in &panel.notes {
            indented_lines(writer, &sanitize(note), 2, columns)?;
        }
    }

    writeln!(writer)?;
    writer.flush()
}

pub(super) fn styled_lines(
    writer: &mut impl Write,
    text: &str,
    tone: Tone,
    policy: &OutputPolicy,
) -> io::Result<()> {
    for line in wrap(text, policy.width()) {
        if policy.styled() {
            writeln!(writer, "{}{line}\x1b[0m", tone.ansi())?;
        } else {
            writeln!(writer, "{line}")?;
        }
    }

    Ok(())
}

fn plain_lines(writer: &mut impl Write, text: &str, columns: usize) -> io::Result<()> {
    for line in wrap(text, columns) {
        writeln!(writer, "{line}")?;
    }

    Ok(())
}

fn indented_lines(
    writer: &mut impl Write,
    text: &str,
    indent: usize,
    columns: usize,
) -> io::Result<()> {
    let indent = indent.min(columns.saturating_sub(1));

    for line in wrap(text, columns - indent) {
        writeln!(writer, "{}{line}", " ".repeat(indent))?;
    }

    Ok(())
}
