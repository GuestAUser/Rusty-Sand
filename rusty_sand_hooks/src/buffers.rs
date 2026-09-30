use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Eq)]
pub enum BufferError {
    NullPointer,
    MisalignedWideString,
    InvalidLength,
    UnterminatedString,
    InvalidUtf16,
    UnsupportedAddressFamily(u16),
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullPointer => f.write_str("null pointer with a nonzero buffer length"),
            Self::MisalignedWideString => f.write_str("unaligned UTF-16 input"),
            Self::InvalidLength => f.write_str("invalid buffer length"),
            Self::UnterminatedString => f.write_str("UTF-16 input exceeds the string limit"),
            Self::InvalidUtf16 => f.write_str("invalid UTF-16 input"),
            Self::UnsupportedAddressFamily(family) => {
                write!(f, "unsupported address family {family}")
            }
        }
    }
}

impl std::error::Error for BufferError {}

pub fn start_address(
    start: Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
) -> u64 {
    start.map_or(0, |routine| (routine as *const ()).addr() as u64)
}

pub fn validate_pointer_length(address: usize, length: usize) -> Result<(), BufferError> {
    if address == 0 && length != 0 {
        Err(BufferError::NullPointer)
    } else if address.checked_add(length).is_none() {
        Err(BufferError::InvalidLength)
    } else {
        Ok(())
    }
}

pub fn validate_wide_address(address: usize) -> Result<(), BufferError> {
    if !address.is_multiple_of(2) {
        Err(BufferError::MisalignedWideString)
    } else {
        Ok(())
    }
}

pub fn utf16_from_bytes(bytes: &[u8]) -> Result<String, BufferError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(BufferError::InvalidLength);
    }
    let words = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(words)
        .map(|character| character.map_err(|_| BufferError::InvalidUtf16))
        .collect()
}

pub fn append_wide_chunk(
    output: &mut Vec<u8>,
    chunk: &[u8],
    max_wchars: usize,
) -> Result<bool, BufferError> {
    if !chunk.len().is_multiple_of(2) {
        return Err(BufferError::InvalidLength);
    }
    for pair in chunk.as_chunks::<2>().0 {
        if *pair == [0, 0] {
            return Ok(true);
        }
        if output.len() / 2 >= max_wchars {
            return Err(BufferError::UnterminatedString);
        }
        output.extend_from_slice(pair);
    }
    Ok(false)
}

pub fn registry_name(bytes: &[u8]) -> Result<String, BufferError> {
    let header: [u8; 4] = bytes
        .get(..4)
        .ok_or(BufferError::InvalidLength)?
        .try_into()
        .map_err(|_| BufferError::InvalidLength)?;
    let length = u32::from_le_bytes(header) as usize;
    let name = bytes.get(4..).and_then(|tail| tail.get(..length));
    utf16_from_bytes(name.ok_or(BufferError::InvalidLength)?)
}

pub fn socket_address(bytes: &[u8]) -> Result<(String, u16, bool), BufferError> {
    let family = bytes.get(..2).ok_or(BufferError::InvalidLength)?;
    let family = u16::from_le_bytes([family[0], family[1]]);
    let required = socket_address_length(family)?;
    if bytes.len() < required {
        return Err(BufferError::InvalidLength);
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        2 => Ok((
            Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]).to_string(),
            port,
            false,
        )),
        23 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let address = Ipv6Addr::from(octets);
            let scope = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            let address = if scope == 0 {
                address.to_string()
            } else {
                format!("{address}%{scope}")
            };
            Ok((address, port, true))
        }
        _ => Err(BufferError::UnsupportedAddressFamily(family)),
    }
}

pub fn socket_address_length(family: u16) -> Result<usize, BufferError> {
    match family {
        2 => Ok(16),
        23 => Ok(28),
        _ => Err(BufferError::UnsupportedAddressFamily(family)),
    }
}

#[cfg(test)]
#[path = "../tests/unit/buffers.rs"]
mod tests;
