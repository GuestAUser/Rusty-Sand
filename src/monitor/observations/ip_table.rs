use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    InvalidLength,
    TruncatedRows,
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid IP table buffer length"),
            Self::TruncatedRows => f.write_str("IP table row count exceeds returned buffer"),
        }
    }
}

impl std::error::Error for TableError {}

/* IPv4 owner-PID tables contain a DWORD count followed by DWORD-only rows.
Decode words without referencing the C struct's single-element array. */
pub fn rows(words: &[u32], byte_len: usize, row_words: usize) -> Result<&[u32], TableError> {
    if byte_len < 4 || !byte_len.is_multiple_of(4) || byte_len / 4 > words.len() || row_words == 0 {
        return Err(TableError::InvalidLength);
    }

    let count = words[0] as usize;
    let available = byte_len / 4 - 1;

    if count > available / row_words {
        return Err(TableError::TruncatedRows);
    }

    Ok(&words[1..1 + count * row_words])
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/monitor_ip_table.rs"]
mod tests;
