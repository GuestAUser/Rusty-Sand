use crate::types::MAX_MESSAGE_SIZE;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Empty,
    InvalidUtf8(std::str::Utf8Error),
    PartialWrite { expected: usize, actual: u32 },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "pipe message exceeds {MAX_MESSAGE_SIZE} bytes"),
            Self::Empty => f.write_str("empty pipe message or disconnected peer"),
            Self::InvalidUtf8(error) => write!(f, "invalid pipe UTF-8: {error}"),
            Self::PartialWrite { expected, actual } => {
                write!(f, "pipe wrote {actual} of {expected} bytes")
            }
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::InvalidUtf8(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

pub fn check_size(length: usize) -> Result<(), FrameError> {
    if length == 0 {
        Err(FrameError::Empty)
    } else if length > MAX_MESSAGE_SIZE {
        Err(FrameError::TooLarge)
    } else {
        Ok(())
    }
}

pub fn message_text(bytes: &[u8]) -> Result<&str, FrameError> {
    check_size(bytes.len())?;
    std::str::from_utf8(bytes).map_err(FrameError::InvalidUtf8)
}

pub fn check_write(expected: usize, actual: u32) -> Result<(), FrameError> {
    if expected == actual as usize {
        Ok(())
    } else {
        Err(FrameError::PartialWrite { expected, actual })
    }
}

#[cfg(test)]
#[path = "../tests/unit/framing.rs"]
mod tests;
