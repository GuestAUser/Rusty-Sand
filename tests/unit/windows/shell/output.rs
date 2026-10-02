use super::*;
use crate::ui::{ColorMode, OutputPolicy};
use anyhow::Context;

fn render(command: Command, text: &str) -> Result<String> {
    let panel = command_panel(command, text).context("command did not produce a panel")?;
    let mut bytes = Vec::new();

    ui::render_panel(
        &mut bytes,
        &panel,
        &OutputPolicy {
            color: ColorMode::Never,
            plain: true,
            reduced_motion: true,
            tty: false,
            columns: 160,
        },
    )?;

    Ok(String::from_utf8(bytes)?)
}

#[test]
fn shell_pretty_json_renders_as_lines_without_exposing_payload_controls() -> Result<()> {
    let payload = "a\n\x1b[31m.exe";

    for (command, value) in [
        (
            Command::Status,
            serde_json::json!({ "executable": payload }),
        ),
        (
            Command::Events(20),
            serde_json::json!([{ "details": payload }]),
        ),
    ] {
        let formatted = serde_json::to_string_pretty(&value)?;
        let rendered = render(command, &formatted)?;

        /*
         * Parse the actual renderer's JSON body. Literal escaped formatting
         * newlines would fail this round trip, while payload LF/ESC must remain
         * encoded inside JSON strings until parsed.
         */
        let body = rendered
            .lines()
            .skip_while(|line| !matches!(line.trim(), "{" | "["))
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(serde_json::from_str::<serde_json::Value>(&body)?, value);
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains("\\u{a}"));
        assert!(!rendered.contains(payload));
    }

    Ok(())
}

#[test]
fn shell_trusted_line_boundaries_do_not_disable_control_escaping() -> Result<()> {
    for command in [Command::Help, Command::Analysis] {
        let rendered = render(
            command,
            "RS_OUTPUT_FIRST\r\x1b[31m\u{202e}\nRS_OUTPUT_SECOND",
        )?;

        assert!(rendered
            .lines()
            .any(|line| line.trim() == "RS_OUTPUT_SECOND"));
        assert!(rendered.contains("\\u{d}"));
        assert!(rendered.contains("\\u{1b}"));
        assert!(rendered.contains("\\u{202e}"));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains("\\u{a}"));
    }

    Ok(())
}

#[test]
fn shell_operational_payloads_cannot_select_multiline_presentation() {
    for command in [
        Command::Run,
        Command::Pause,
        Command::Resume,
        Command::Stop,
        Command::Report,
        Command::Quit,
    ] {
        assert!(command_panel(command, "RS_PATH\n\x1b[31m.exe").is_none());
    }
}

#[test]
fn shell_panel_and_status_text_share_the_existing_unicode_bound() -> Result<()> {
    let text = "\u{1f600}".repeat(MAX_OUTPUT_CHARACTERS + 1);
    let expected_prefix = "\u{1f600}".repeat(MAX_OUTPUT_CHARACTERS);
    let limited = bounded(&text);

    assert!(limited.starts_with(&expected_prefix));
    assert_eq!(
        limited.chars().count(),
        MAX_OUTPUT_CHARACTERS + 1 + TRUNCATION_NOTICE.chars().count(),
    );
    assert!(!limited.contains('\n'));

    let panel = command_panel(Command::Analysis, &text).context("missing analysis panel")?;
    assert_eq!(panel.notes.join("\n"), limited);
    Ok(())
}
