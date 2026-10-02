use super::super::model::*;
use super::{rva_add, ParseError, Parsed};

#[derive(Clone, Copy)]
pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn slice(self, offset: usize, length: usize) -> Parsed<&'a [u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| ParseError::malformed("File range arithmetic overflow").at(offset))?;

        self.bytes
            .get(offset..end)
            .ok_or_else(|| ParseError::malformed("File range exceeds available bytes").at(offset))
    }

    pub(super) fn u16(self, offset: usize) -> Parsed<u16> {
        let bytes = self.slice(offset, 2)?;

        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(self, offset: usize) -> Parsed<u32> {
        let bytes = self.slice(offset, 4)?;

        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u64(self, offset: usize) -> Parsed<u64> {
        let bytes = self.slice(offset, 8)?;

        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn pointer(self, offset: usize, kind: PeKind) -> Parsed<u64> {
        match kind {
            PeKind::Pe32 => self.u32(offset).map(u64::from),
            PeKind::Pe32Plus => self.u64(offset),
        }
    }
}

pub(super) struct Image<'a> {
    pub(super) reader: Reader<'a>,
    pub(super) headers: u32,
    pub(super) sections: &'a [Section],
}

impl Image<'_> {
    /*
     * Only file-backed bytes are mapped. Virtual zero-fill must never become
     * fabricated parser input. Section overlap is rejected before this mapper
     * is constructed, so each accepted RVA has at most one interpretation.
     */
    pub(super) fn map(&self, rva: u32, length: usize) -> Parsed<usize> {
        let end = rva_add(rva, length)?;

        if rva < self.headers && end <= self.headers {
            self.reader.slice(rva as usize, length)?;
            return Ok(rva as usize);
        }

        for section in self.sections {
            if let Some(delta) = rva.checked_sub(section.virtual_address) {
                if u64::from(delta) + length as u64 <= u64::from(section.raw_size) {
                    let offset = u64::from(section.raw_offset) + u64::from(delta);
                    let offset = usize::try_from(offset)
                        .map_err(|_| ParseError::malformed("File offset exceeds usize"))?;

                    self.reader.slice(offset, length)?;
                    return Ok(offset);
                }
            }
        }

        Err(ParseError::malformed(
            "RVA is not backed by a contiguous file range",
        ))
    }

    fn available(&self, rva: u32) -> Parsed<(usize, usize)> {
        let offset = self.map(rva, 1)?;

        if rva < self.headers {
            return Ok((offset, (self.headers - rva) as usize));
        }

        for section in self.sections {
            if let Some(delta) = rva.checked_sub(section.virtual_address) {
                if delta < section.raw_size {
                    return Ok((offset, (section.raw_size - delta) as usize));
                }
            }
        }

        Err(ParseError::malformed("Name RVA has no backing range"))
    }

    pub(super) fn name(&self, rva: u32) -> Parsed<String> {
        let (offset, available) = self.available(rva)?;
        let bytes = self
            .reader
            .slice(offset, available.min(MAX_NAME_BYTES + 1))?;
        let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
            return Err(if available > MAX_NAME_BYTES {
                ParseError::limited("PE name exceeds the name byte limit").at(offset)
            } else {
                ParseError::malformed("Unterminated PE name").at(offset)
            });
        };

        if end == 0 {
            return Err(ParseError::malformed("Empty PE name").at(offset));
        }

        if !bytes[..end].iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Err(ParseError::unsupported(
                "Non-printable or non-ASCII PE names are not decoded",
            )
            .at(offset));
        }

        Ok(bytes[..end].iter().map(|byte| char::from(*byte)).collect())
    }
}
