use super::*;
use crate::ui::text::{sanitize, width, wrap};

#[test]
fn auto_capabilities_obey_explicit_environment_inputs() {
    for tty in [false, true] {
        for no_color in [false, true] {
            for dumb in [false, true] {
                let resolved = OutputPolicy {
                    color: ColorMode::Auto,
                    tty,
                    ..policy()
                }
                .resolve_environment(no_color, dumb);

                assert_eq!(resolved.styled(), tty && !no_color && !dumb);
                assert_eq!(resolved.animated(), tty && !no_color && !dumb);
            }
        }
    }
}

#[test]
fn forced_color_does_not_force_motion_when_redirected_or_dumb() {
    for (tty, dumb) in [(false, false), (true, true)] {
        let resolved = OutputPolicy { tty, ..policy() }.resolve_environment(true, dumb);

        assert!(resolved.styled());
        assert!(!resolved.animated());
    }
}

#[test]
fn plain_never_and_reduced_motion_have_distinct_capabilities() {
    for policy in [
        OutputPolicy {
            plain: true,
            ..policy()
        },
        OutputPolicy {
            color: ColorMode::Never,
            ..policy()
        },
    ] {
        let resolved = policy.resolve_environment(false, false);
        assert!(!resolved.styled());
        assert!(!resolved.animated());
    }

    let reduced = OutputPolicy {
        reduced_motion: true,
        ..policy()
    }
    .resolve_environment(false, false);
    assert!(reduced.styled());
    assert!(!reduced.animated());
}

#[test]
fn controls_and_bidi_are_visible_escapes_not_terminal_instructions() {
    let controls: String = (0..=0x9f)
        .filter_map(char::from_u32)
        .filter(|ch| ch.is_control())
        .collect();
    let bidi = "\u{061c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}";
    let clean = sanitize(&format!("{controls}{bidi}C:\\資料\\café.exe"));

    assert!(!clean.chars().any(char::is_control));
    assert!(controls
        .chars()
        .chain(bidi.chars())
        .all(|ch| clean.contains(&ch.escape_unicode().to_string())));
    assert!(clean.ends_with("C:\\資料\\café.exe"));
}

#[test]
fn unicode_wrapping_measures_display_cells_and_keeps_evidence() {
    let evidence = "C:\\資料\\e\u{301}vidence\\👩\u{200d}💻.exe";
    let lines = wrap(evidence, 12);

    assert_eq!(lines.concat(), evidence);
    assert!(lines.iter().all(|line| width(line) <= 12));
    assert_eq!(width("資料e\u{301}"), 5);
    assert_eq!(width("👩\u{200d}💻"), 2);
}

#[test]
fn wrapping_prefers_word_boundaries_without_discarding_evidence() {
    let text = "one two three";
    let lines = wrap(text, 9);

    assert_eq!(lines.concat(), text);
    assert_eq!(lines, ["one two ", "three"]);
    assert!(lines.iter().all(|line| width(line) <= 9));
}

#[test]
fn panels_fit_narrow_and_wide_destinations_without_losing_fields_or_choices() {
    for columns in [1, 2, 12, 40, 79, 80, 120] {
        let policy = OutputPolicy {
            color: ColorMode::Never,
            columns,
            ..policy()
        };
        let mut bytes = Vec::new();
        render_panel(&mut bytes, &panel(), &policy).unwrap();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.lines().all(|line| width(line) <= policy.width()));
        let joined: String = output.chars().filter(|ch| !ch.is_whitespace()).collect();

        for sentinel in [
            "PROMPT_SENTINEL",
            "FIELD_SENTINEL",
            "VALUE_SENTINEL",
            "CHOICE_A",
            "CHOICE_B",
        ] {
            assert!(
                joined.contains(sentinel),
                "missing {sentinel} at width {columns}"
            );
        }
    }
}

#[test]
fn plain_and_never_output_contain_no_ansi_even_in_untrusted_titles_and_notes() {
    let mut panel = panel();
    panel.title = "\x1b[2JTITLE\u{202e}".into();
    panel
        .fields
        .push(("\x07LABEL".into(), "\x1b]0;ATTACK\x07".into()));
    panel.notes.push("\u{9b}31mNOTE".into());

    for policy in [
        OutputPolicy {
            plain: true,
            ..policy()
        },
        OutputPolicy {
            color: ColorMode::Never,
            ..policy()
        },
    ] {
        let mut bytes = Vec::new();
        render_panel(&mut bytes, &panel, &policy).unwrap();
        let output = String::from_utf8(bytes).unwrap();

        assert!(!output.contains('\x1b'));
        assert!(!output.contains('\u{202e}'));
        assert!(output.chars().all(|ch| !ch.is_control() || ch == '\n'));
    }
}

#[test]
fn palette_is_semantic_and_never_changes_background() {
    for (tone, color) in [
        (Tone::Heading, "\x1b[1;38;5;208m"),
        (Tone::Success, "\x1b[1;32m"),
        (Tone::Warning, "\x1b[1;33m"),
        (Tone::Danger, "\x1b[1;31m"),
    ] {
        let mut panel = panel();
        panel.tone = tone;
        let mut bytes = Vec::new();
        render_panel(&mut bytes, &panel, &policy()).unwrap();
        let output = String::from_utf8(bytes).unwrap();

        assert!(output.contains(color));
        assert!(output.contains(&format!("[{}]", tone.label())));
        assert!(output.contains("\x1b[0m"));
    }
}

#[test]
fn panel_propagates_writer_errors() {
    let mut capture = Capture::default();
    capture.fail.store(true, Ordering::SeqCst);

    assert_eq!(
        render_panel(&mut capture, &panel(), &policy())
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}
