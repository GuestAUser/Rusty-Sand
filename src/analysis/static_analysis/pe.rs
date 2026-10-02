use super::model::*;

mod directories;
mod image;
mod sections;
mod symbols;

use directories::{read_directories, read_security, read_tls};
use image::{Image, Reader};
use sections::read_sections;
use symbols::{read_exports, read_imports};

type Parsed<T> = Result<T, ParseError>;

#[derive(Debug)]
pub(super) struct ParseError {
    pub status: PeStatus,
    pub offset: Option<u64>,
    pub message: &'static str,
}

impl ParseError {
    fn malformed(message: &'static str) -> Self {
        Self {
            status: PeStatus::Malformed,
            offset: None,
            message,
        }
    }

    fn limited(message: &'static str) -> Self {
        Self {
            status: PeStatus::Limited,
            offset: None,
            message,
        }
    }

    fn unsupported(message: &'static str) -> Self {
        Self {
            status: PeStatus::Unsupported,
            offset: None,
            message,
        }
    }

    fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset as u64);
        self
    }
}

fn rva_add(rva: u32, displacement: usize) -> Parsed<u32> {
    let displacement = u32::try_from(displacement)
        .map_err(|_| ParseError::malformed("RVA displacement exceeds 32 bits"))?;

    rva.checked_add(displacement)
        .ok_or_else(|| ParseError::malformed("RVA arithmetic overflow"))
}

fn width(kind: PeKind) -> usize {
    match kind {
        PeKind::Pe32 => 4,
        PeKind::Pe32Plus => 8,
    }
}

pub(super) fn parse(bytes: &[u8]) -> Parsed<PeMetadata> {
    let reader = Reader { bytes };

    if reader.slice(0, 2)? != b"MZ" {
        return Err(ParseError::malformed("PE candidate has no DOS signature").at(0));
    }

    reader.slice(0, 64)?;

    let pe_offset = reader.u32(0x3c)? as usize;

    if pe_offset < 64 {
        return Err(ParseError::malformed("PE header overlaps the DOS header").at(0x3c));
    }

    reader.slice(pe_offset, 24)?;

    if reader.slice(pe_offset, 4)? != b"PE\0\0" {
        return Err(
            ParseError::malformed("DOS header does not reference a PE signature").at(pe_offset),
        );
    }

    let coff = pe_offset + 4;
    let section_count = reader.u16(coff + 2)? as usize;

    if section_count == 0 {
        return Err(ParseError::malformed("PE has no sections").at(coff + 2));
    }

    if section_count > MAX_SECTIONS {
        return Err(ParseError::limited("PE section count exceeds the limit").at(coff + 2));
    }

    let optional = coff + 20;
    let optional_size = reader.u16(coff + 16)? as usize;

    reader.slice(optional, optional_size)?;

    if optional_size < 2 {
        return Err(ParseError::malformed("Missing PE optional header").at(optional));
    }

    let (kind, fixed_size) = match reader.u16(optional)? {
        0x10b => (PeKind::Pe32, 96),
        0x20b => (PeKind::Pe32Plus, 112),
        _ => {
            return Err(
                ParseError::unsupported("Unsupported PE optional-header magic").at(optional),
            );
        }
    };

    if optional_size < fixed_size {
        return Err(ParseError::malformed("Truncated PE optional header").at(optional));
    }

    let directory_count = reader.u32(optional + fixed_size - 4)? as usize;

    if directory_count > MAX_DIRECTORIES {
        return Err(ParseError::limited("PE directory count exceeds the limit")
            .at(optional + fixed_size - 4));
    }

    if fixed_size + directory_count * 8 > optional_size {
        return Err(
            ParseError::malformed("Directories exceed the optional header")
                .at(optional + fixed_size),
        );
    }

    let size_of_headers = reader.u32(optional + 60)?;
    let size_of_image = reader.u32(optional + 56)?;
    let table = optional + optional_size;

    reader.slice(table, section_count * 40)?;

    if (size_of_headers as usize) < table + section_count * 40 || size_of_headers > size_of_image {
        return Err(ParseError::malformed("Invalid PE header or image size").at(optional + 56));
    }

    reader.slice(0, size_of_headers as usize)?;

    let sections = read_sections(reader, table, section_count, size_of_headers, size_of_image)?;
    let image = Image {
        reader,
        headers: size_of_headers,
        sections: &sections,
    };
    let directories = read_directories(&image, optional + fixed_size, directory_count)?;
    let image_base = match kind {
        PeKind::Pe32 => u64::from(reader.u32(optional + 28)?),
        PeKind::Pe32Plus => reader.u64(optional + 24)?,
    };
    let entry_point_rva = reader.u32(optional + 16)?;
    let entry_point_offset = if entry_point_rva == 0 {
        None
    } else {
        image
            .map(entry_point_rva, 1)
            .ok()
            .map(|offset| offset as u64)
    };
    let imports = read_imports(&image, &directories, kind)?;
    let exports = read_exports(&image, &directories)?;
    let tls = read_tls(&image, &directories, kind, image_base)?;
    let mapped_end = sections
        .iter()
        .filter(|section| section.raw_size != 0)
        .map(|section| u64::from(section.raw_offset) + u64::from(section.raw_size))
        .max()
        .unwrap_or(u64::from(size_of_headers))
        .max(u64::from(size_of_headers));
    let security = read_security(reader, &directories, mapped_end)?;
    let mut overlay = Vec::new();
    let mut overlay_start = mapped_end;

    if let Some(certificate_table) = &security {
        if certificate_table.offset > overlay_start {
            overlay.push(FileRange {
                offset: overlay_start,
                size: certificate_table.offset - overlay_start,
            });
        }

        overlay_start = certificate_table.offset + certificate_table.size;
    }

    if overlay_start < bytes.len() as u64 {
        overlay.push(FileRange {
            offset: overlay_start,
            size: bytes.len() as u64 - overlay_start,
        });
    }

    Ok(PeMetadata {
        kind,
        machine: reader.u16(coff)?,
        timestamp: reader.u32(coff + 4)?,
        characteristics: reader.u16(coff + 18)?,
        subsystem: reader.u16(optional + 68)?,
        dll_characteristics: reader.u16(optional + 70)?,
        image_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        entry_point_offset,
        sections,
        directories,
        imports,
        exports,
        tls,
        security,
        overlay,
    })
}
