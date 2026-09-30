use anyhow::{bail, Result};

/** Encode arguments for the Microsoft C runtime command-line parser.

Backslashes are literal except immediately before a quote or the closing
delimiter. `argv[0]` has different parsing rules, so a quoted executable name
must not itself contain a quote.

Leave simple tokens unquoted. Unnecessary quoting changes the option grammar
of programs such as cmd.exe even when a C runtime would accept both forms.
*/
pub(super) fn command_line(executable: &str, args: &[String]) -> Result<Vec<u16>> {
    if executable.is_empty() || executable.contains(['\0', '"']) {
        bail!("executable must be nonempty and contain neither NUL nor quotes");
    }

    let mut command = format!("\"{executable}\"");
    for arg in args {
        if arg.contains('\0') {
            bail!("process argument contains NUL");
        }
        command.push(' ');
        command.push_str(&quote_argument(arg));
    }

    let mut wide: Vec<u16> = command.encode_utf16().collect();
    wide.push(0);
    if wide.len() > 32_767 {
        bail!("command line exceeds the CreateProcessW limit of 32767 UTF-16 units");
    }
    Ok(wide)
}

fn quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .chars()
            .all(|character| !character.is_whitespace() && character != '"')
    {
        return argument.to_owned();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        let count = if character == '"' {
            backslashes * 2 + 1
        } else {
            backslashes
        };
        quoted.extend(std::iter::repeat_n('\\', count));
        quoted.push(character);
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
#[path = "../../tests/unit/windows/sandbox_command_line.rs"]
mod tests;
