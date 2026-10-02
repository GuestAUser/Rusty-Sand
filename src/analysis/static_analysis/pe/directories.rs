use super::super::model::*;
use super::{rva_add, width, Image, ParseError, Parsed, Reader};

pub(super) fn read_directories(
    image: &Image<'_>,
    table: usize,
    count: usize,
) -> Parsed<Vec<DataDirectory>> {
    let mut directories = Vec::with_capacity(count);

    for index in 0..count {
        let address = image.reader.u32(table + index * 8)?;
        let size = image.reader.u32(table + index * 8 + 4)?;

        if address == 0 && size != 0 {
            return Err(
                ParseError::malformed("Nonempty directory has a zero address")
                    .at(table + index * 8),
            );
        }

        let file_offset = if address == 0 {
            None
        } else if index == 4 {
            if size == 0 {
                return Err(ParseError::malformed(
                    "Empty certificate directory has an address",
                ));
            }

            address
                .checked_add(size)
                .ok_or_else(|| ParseError::malformed("Certificate file range overflows"))?;
            image.reader.slice(address as usize, size as usize)?;

            Some(u64::from(address))
        } else {
            /*
             * IMAGE_DIRECTORY_ENTRY_GLOBALPTR may legitimately have size zero.
             * Other present directories need a real bounded range.
             */
            if size == 0 && index != 8 {
                return Err(
                    ParseError::malformed("Present directory has zero size").at(table + index * 8)
                );
            }

            Some(image.map(address, (size as usize).max(1))? as u64)
        };

        directories.push(DataDirectory {
            index: index as u8,
            address,
            size,
            is_file_offset: index == 4,
            file_offset,
        });
    }

    Ok(directories)
}

pub(super) fn directory(directories: &[DataDirectory], index: usize) -> Option<&DataDirectory> {
    directories.get(index).filter(|entry| entry.address != 0)
}

pub(super) fn read_tls(
    image: &Image<'_>,
    directories: &[DataDirectory],
    kind: PeKind,
    image_base: u64,
) -> Parsed<Option<TlsMetadata>> {
    let Some(directory) = directory(directories, 9) else {
        return Ok(None);
    };
    let pointer_width = width(kind);
    let required = pointer_width * 4 + 8;

    if (directory.size as usize) < required {
        return Err(ParseError::malformed("Truncated TLS directory"));
    }

    let offset = image.map(directory.address, required)?;
    let raw_data_start_va = image.reader.pointer(offset, kind)?;
    let raw_data_end_va = image.reader.pointer(offset + pointer_width, kind)?;
    let index_va = image.reader.pointer(offset + pointer_width * 2, kind)?;
    let callbacks_va = image.reader.pointer(offset + pointer_width * 3, kind)?;
    let mut callbacks = Vec::new();

    if raw_data_end_va < raw_data_start_va {
        return Err(ParseError::malformed("Reversed TLS raw-data range"));
    }

    if callbacks_va != 0 {
        let callbacks_rva = callbacks_va
            .checked_sub(image_base)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| ParseError::malformed("TLS callback table VA is outside RVA space"))?;

        for index in 0..=MAX_TLS_CALLBACKS {
            let callback_offset = image.map(
                rva_add(callbacks_rva, index * pointer_width)?,
                pointer_width,
            )?;
            let callback = image.reader.pointer(callback_offset, kind)?;

            if callback == 0 {
                break;
            }

            if index == MAX_TLS_CALLBACKS {
                return Err(ParseError::limited("TLS callback count exceeds the limit"));
            }

            callbacks.push(callback);
        }
    }

    Ok(Some(TlsMetadata {
        raw_data_start_va,
        raw_data_end_va,
        index_va,
        callbacks_va,
        zero_fill_bytes: image.reader.u32(offset + pointer_width * 4)?,
        characteristics: image.reader.u32(offset + pointer_width * 4 + 4)?,
        callbacks,
    }))
}

pub(super) fn read_security(
    reader: Reader<'_>,
    directories: &[DataDirectory],
    mapped_end: u64,
) -> Parsed<Option<SecurityMetadata>> {
    let Some(directory) = directory(directories, 4) else {
        return Ok(None);
    };
    let start = directory.address as usize;
    let size = directory.size as usize;

    if !start.is_multiple_of(8) || (start as u64) < mapped_end {
        return Err(ParseError::malformed(
            "Certificate table is unaligned or overlaps mapped image bytes",
        )
        .at(start));
    }

    reader.slice(start, size)?;

    let mut consumed = 0;
    let mut certificates = Vec::new();

    while consumed < size {
        if certificates.len() == MAX_CERTIFICATES {
            return Err(ParseError::limited("Certificate count exceeds the limit"));
        }

        if size - consumed < 8 {
            return Err(ParseError::malformed("Truncated certificate record").at(start + consumed));
        }

        let offset = start + consumed;
        let length = reader.u32(offset)?;

        if length < 8 || length as usize > size - consumed {
            return Err(ParseError::malformed("Invalid certificate record length").at(offset));
        }

        let padded_length = (length as usize + 7) & !7;

        if padded_length > size - consumed {
            return Err(
                ParseError::malformed("Certificate padding exceeds the directory").at(offset),
            );
        }

        certificates.push(CertificateMetadata {
            offset: offset as u64,
            length,
            revision: reader.u16(offset + 4)?,
            certificate_type: reader.u16(offset + 6)?,
        });
        consumed += padded_length;
    }

    Ok(Some(SecurityMetadata {
        offset: start as u64,
        size: size as u64,
        certificates,
    }))
}
