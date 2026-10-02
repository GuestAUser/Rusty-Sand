use super::super::model::*;
use super::directories::directory;
use super::{rva_add, width, Image, ParseError, Parsed};

pub(super) fn read_imports(
    image: &Image<'_>,
    directories: &[DataDirectory],
    kind: PeKind,
) -> Parsed<Vec<Import>> {
    let Some(directory) = directory(directories, 1) else {
        return Ok(Vec::new());
    };
    let mut imports = Vec::new();
    let pointer_width = width(kind);

    for library_index in 0..=MAX_IMPORT_LIBRARIES {
        let displacement = library_index * 20;

        if displacement + 20 > directory.size as usize {
            return Err(ParseError::malformed(
                "Import descriptors have no bounded terminator",
            ));
        }

        let offset = image.map(rva_add(directory.address, displacement)?, 20)?;

        if image
            .reader
            .slice(offset, 20)?
            .iter()
            .all(|byte| *byte == 0)
        {
            return Ok(imports);
        }

        if library_index == MAX_IMPORT_LIBRARIES {
            return Err(ParseError::limited(
                "Import library count exceeds the limit",
            ));
        }

        let original_thunk = image.reader.u32(offset)?;
        let library = image.name(image.reader.u32(offset + 12)?)?;
        let first_thunk = image.reader.u32(offset + 16)?;
        let thunk_rva = if original_thunk == 0 {
            first_thunk
        } else {
            original_thunk
        };

        if thunk_rva == 0 {
            return Err(ParseError::malformed("Import descriptor has no thunk table").at(offset));
        }

        for thunk_index in 0..=MAX_IMPORTS {
            let thunk_offset = image.map(
                rva_add(thunk_rva, thunk_index * pointer_width)?,
                pointer_width,
            )?;
            let value = image.reader.pointer(thunk_offset, kind)?;

            if value == 0 {
                break;
            }

            if imports.len() == MAX_IMPORTS {
                return Err(ParseError::limited("Import count exceeds the limit").at(thunk_offset));
            }

            let ordinal_flag = 1u64 << (pointer_width * 8 - 1);
            let (name, ordinal, hint) = if value & ordinal_flag != 0 {
                if value & !(ordinal_flag | 0xffff) != 0 {
                    return Err(
                        ParseError::malformed("Ordinal import has reserved bits set")
                            .at(thunk_offset),
                    );
                }

                (None, Some(value as u16), None)
            } else {
                let name_rva = u32::try_from(value).map_err(|_| {
                    ParseError::malformed("Import name RVA exceeds 32 bits").at(thunk_offset)
                })?;
                let hint_offset = image.map(name_rva, 2)?;
                let hint = image.reader.u16(hint_offset)?;
                let name = image.name(rva_add(name_rva, 2)?)?;

                (Some(name), None, Some(hint))
            };

            imports.push(Import {
                library: library.clone(),
                name,
                ordinal,
                hint,
                thunk_offset: thunk_offset as u64,
            });
        }
    }

    Err(ParseError::limited(
        "Import library count exceeds the limit",
    ))
}

pub(super) fn read_exports(
    image: &Image<'_>,
    directories: &[DataDirectory],
) -> Parsed<Vec<Export>> {
    let Some(directory) = directory(directories, 0) else {
        return Ok(Vec::new());
    };

    if directory.size < 40 {
        return Err(ParseError::malformed("Truncated export directory"));
    }

    let offset = image.map(directory.address, 40)?;
    let base = image.reader.u32(offset + 16)?;
    let function_count = image.reader.u32(offset + 20)? as usize;
    let name_count = image.reader.u32(offset + 24)? as usize;

    if function_count > MAX_EXPORTS || name_count > MAX_EXPORT_NAMES {
        return Err(ParseError::limited("Export table count exceeds the limit"));
    }

    let functions_rva = image.reader.u32(offset + 28)?;
    let names_rva = image.reader.u32(offset + 32)?;
    let ordinals_rva = image.reader.u32(offset + 36)?;
    let mut exports = Vec::with_capacity(function_count);
    let directory_end = rva_add(directory.address, directory.size as usize)?;

    if function_count != 0 {
        if functions_rva == 0 {
            return Err(ParseError::malformed("Export address table has a zero RVA"));
        }

        image.map(functions_rva, function_count * 4)?;
    }

    for index in 0..function_count {
        let function_offset = image.map(rva_add(functions_rva, index * 4)?, 4)?;
        let rva = image.reader.u32(function_offset)?;
        let ordinal = base
            .checked_add(index as u32)
            .ok_or_else(|| ParseError::malformed("Export ordinal overflow"))?;
        let forwarder = if rva >= directory.address && rva < directory_end {
            let name = image.name(rva)?;

            if name.len() + 1 > (directory_end - rva) as usize {
                return Err(ParseError::malformed(
                    "Forwarder exceeds the export directory",
                ));
            }

            Some(name)
        } else {
            None
        };

        exports.push(Export {
            ordinal,
            rva,
            names: Vec::new(),
            forwarder,
            file_offset: if rva == 0 {
                None
            } else {
                image.map(rva, 1).ok().map(|offset| offset as u64)
            },
        });
    }

    if name_count != 0 {
        if names_rva == 0 || ordinals_rva == 0 {
            return Err(ParseError::malformed("Export name table has a zero RVA"));
        }

        image.map(names_rva, name_count * 4)?;
        image.map(ordinals_rva, name_count * 2)?;
    }

    for index in 0..name_count {
        let name_offset = image.map(rva_add(names_rva, index * 4)?, 4)?;
        let ordinal_offset = image.map(rva_add(ordinals_rva, index * 2)?, 2)?;
        let ordinal_index = image.reader.u16(ordinal_offset)? as usize;
        let export = exports
            .get_mut(ordinal_index)
            .ok_or_else(|| ParseError::malformed("Export name ordinal is out of range"))?;

        if export.rva == 0 {
            return Err(ParseError::malformed(
                "Export name references an empty address slot",
            ));
        }

        export
            .names
            .push(image.name(image.reader.u32(name_offset)?)?);
    }

    exports.retain(|export| export.rva != 0);

    Ok(exports)
}
