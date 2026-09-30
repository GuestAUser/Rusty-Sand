use anyhow::{bail, Context, Result};

pub(super) enum Edit {
    Append(char),
    Backspace,
    Line(String),
    Cancel,
}

/** Decode transport fragments before editing Unicode scalars. The security
limit remains UTF-16 units, matching the native Windows approval contract. */
#[derive(Default)]
pub(super) struct Line {
    text: String,
    units: usize,
    utf8: Vec<u8>,
    high: Option<u16>,
    cr: bool,
}

impl Line {
    pub(super) fn partial(&self) -> bool {
        !self.text.is_empty() || !self.utf8.is_empty() || self.high.is_some()
    }

    pub(super) fn end(&self) -> Result<()> {
        if self.partial() {
            bail!("input ended with an incomplete approval line");
        }
        Ok(())
    }

    pub(super) fn byte(&mut self, byte: u8) -> Result<Option<Edit>> {
        self.utf8.push(byte);
        match std::str::from_utf8(&self.utf8) {
            Ok(text) => {
                let character = text.chars().next().context("empty UTF-8 input")?;
                self.utf8.clear();
                self.character(character)
            }
            Err(error) if error.error_len().is_none() && self.utf8.len() < 4 => Ok(None),
            Err(error) => Err(error).context("invalid UTF-8 approval input"),
        }
    }

    pub(super) fn unit(&mut self, unit: u16) -> Result<Option<Edit>> {
        if unit == 0 {
            return Ok(None);
        }
        if unit == 8 && self.high.take().is_some() {
            return Ok(None);
        }
        if let Some(high) = self.high.take() {
            if !(0xdc00..=0xdfff).contains(&unit) {
                bail!("invalid console Unicode surrogate pair");
            }
            let scalar = 0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(unit) - 0xdc00;
            return self.character(char::from_u32(scalar).context("invalid console Unicode")?);
        }
        if (0xd800..=0xdbff).contains(&unit) {
            if self.units >= 64 {
                bail!("approval exceeds 64 UTF-16 units");
            }
            self.high = Some(unit);
            return Ok(None);
        }
        self.character(char::from_u32(u32::from(unit)).context("invalid console Unicode")?)
    }

    fn character(&mut self, character: char) -> Result<Option<Edit>> {
        let after_cr = std::mem::replace(&mut self.cr, character == '\r');
        match character {
            '\n' if after_cr => Ok(None),
            '\r' | '\n' => {
                self.units = 0;
                Ok(Some(Edit::Line(std::mem::take(&mut self.text))))
            }
            '\u{8}' | '\u{7f}' => {
                if let Some(removed) = self.text.pop() {
                    self.units -= removed.len_utf16();
                    Ok(Some(Edit::Backspace))
                } else {
                    Ok(None)
                }
            }
            '\u{3}' | '\u{4}' | '\u{1a}' => Ok(Some(Edit::Cancel)),
            character if character.is_control() => {
                bail!("unsupported control character in approval")
            }
            character => {
                self.units += character.len_utf16();
                if self.units > 64 {
                    bail!("approval exceeds 64 UTF-16 units");
                }
                self.text.push(character);
                Ok(Some(Edit::Append(character)))
            }
        }
    }
}
