use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Escape controls rather than deleting them: the evidence remains inspectable.
pub(super) fn sanitize(text: &str) -> String {
    let mut clean = String::with_capacity(text.len());

    for character in text.chars() {
        if character.is_control()
            || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            clean.extend(character.escape_unicode());
        } else {
            clean.push(character);
        }
    }

    clean
}

pub(super) fn width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/* Keep Unicode text intact, including combining marks. Recompute the string
 * width rather than summing scalar widths: emoji and joined sequences can have
 * a different width from their components. A scalar wider than the entire
 * terminal is escaped so even a one-column destination retains its evidence. */
pub(super) fn wrap(text: &str, columns: usize) -> Vec<String> {
    let columns = columns.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();

    for character in text.chars() {
        if UnicodeWidthChar::width(character).unwrap_or(0) > columns {
            for escaped in character.escape_unicode() {
                push_wrapped(&mut lines, &mut line, escaped, columns);
            }
        } else {
            push_wrapped(&mut lines, &mut line, character, columns);
        }
    }

    lines.push(line);
    lines
}

fn push_wrapped(lines: &mut Vec<String>, line: &mut String, character: char, columns: usize) {
    let previous_len = line.len();
    line.push(character);

    if width(line) > columns && previous_len != 0 {
        let boundary = line[..previous_len]
            .char_indices()
            .rev()
            .find(|(_, character)| character.is_whitespace())
            .map(|(index, character)| index + character.len_utf8());

        if let Some(boundary) = boundary {
            if width(&line[boundary..]) <= columns {
                let remainder = line.split_off(boundary);
                lines.push(std::mem::replace(line, remainder));
                return;
            }
        }

        line.truncate(previous_len);
        lines.push(std::mem::take(line));
        line.push(character);
    }
}
