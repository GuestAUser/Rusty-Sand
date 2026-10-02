use super::super::entropy;
use super::super::model::*;
use super::{ParseError, Parsed, Reader};

pub(super) fn read_sections(
    reader: Reader<'_>,
    table: usize,
    count: usize,
    headers: u32,
    image_size: u32,
) -> Parsed<Vec<Section>> {
    let mut sections: Vec<Section> = Vec::with_capacity(count);

    for index in 0..count {
        let offset = table + index * 40;
        let name_bytes = reader.slice(offset, 8)?;
        let name_end = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let virtual_size = reader.u32(offset + 8)?;
        let virtual_address = reader.u32(offset + 12)?;
        let raw_size = reader.u32(offset + 16)?;
        let raw_offset = reader.u32(offset + 20)?;
        let characteristics = reader.u32(offset + 36)?;
        let virtual_span = virtual_size.max(raw_size);
        let virtual_end = virtual_address.checked_add(virtual_span).ok_or_else(|| {
            ParseError::malformed("Section virtual range overflows").at(offset + 12)
        })?;
        let raw_end = raw_offset
            .checked_add(raw_size)
            .ok_or_else(|| ParseError::malformed("Section file range overflows").at(offset + 20))?;

        if virtual_span != 0 && (virtual_address < headers || virtual_end > image_size) {
            return Err(
                ParseError::malformed("Section lies outside the declared image").at(offset + 12),
            );
        }

        if raw_size != 0 && raw_offset < headers {
            return Err(ParseError::malformed("Section data overlaps PE headers").at(offset + 20));
        }

        for previous in &sections {
            let previous_virtual_end =
                previous.virtual_address + previous.virtual_size.max(previous.raw_size);
            let previous_raw_end = previous.raw_offset + previous.raw_size;

            if virtual_span != 0
                && previous.virtual_size.max(previous.raw_size) != 0
                && virtual_address < previous_virtual_end
                && previous.virtual_address < virtual_end
            {
                return Err(ParseError::malformed("Overlapping section virtual ranges").at(offset));
            }

            if raw_size != 0
                && previous.raw_size != 0
                && raw_offset < previous_raw_end
                && previous.raw_offset < raw_end
            {
                return Err(ParseError::malformed("Overlapping section file ranges").at(offset));
            }
        }

        let section_entropy = if raw_size == 0 {
            None
        } else {
            Some(entropy(
                reader.slice(raw_offset as usize, raw_size as usize)?,
            ))
        };

        sections.push(Section {
            name,
            header_offset: offset as u64,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
            readable: characteristics & 0x4000_0000 != 0,
            writable: characteristics & 0x8000_0000 != 0,
            executable: characteristics & 0x2000_0000 != 0,
            entropy: section_entropy,
        });
    }

    Ok(sections)
}
