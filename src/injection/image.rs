use anyhow::{bail, Context, Result};

pub(super) fn initializer_rva(image: &[u8]) -> Result<u32> {
    if image.get(..2) != Some(b"MZ") {
        bail!("hook library has no DOS header");
    }
    let pe = word(image, 0x3c)? as usize;
    if image.get(pe..pe.checked_add(4).context("PE offset overflow")?) != Some(b"PE\0\0") {
        bail!("hook library has no PE signature");
    }
    if half(image, pe + 4)? != 0x8664 || half(image, pe + 24)? != 0x20b {
        bail!("hook injection supports native AMD64 PE32+ libraries only");
    }
    if half(image, pe + 22)? & 0x2000 == 0 {
        bail!("hook library is not marked as a DLL");
    }
    let count = half(image, pe + 6)? as usize;
    let optional_size = half(image, pe + 20)? as usize;
    if count == 0 || count > 96 || optional_size < 120 {
        bail!("unsupported PE section or optional-header layout");
    }
    let section_start = pe + 24 + optional_size;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let section = section_start + index * 40;
        sections.push(Section {
            virtual_size: word(image, section + 8)?,
            address: word(image, section + 12)?,
            raw_size: word(image, section + 16)?,
            raw_offset: word(image, section + 20)?,
            flags: word(image, section + 36)?,
        });
    }
    let export_rva = word(image, pe + 24 + 112)?;
    let export_size = word(image, pe + 24 + 116)?;
    let export_end = export_rva
        .checked_add(export_size)
        .context("export directory overflow")?;
    if export_rva == 0 || export_size < 40 {
        bail!("hook library has no export directory");
    }
    let export = offset(image, &sections, export_rva, 40)?;
    let function_count = word(image, export + 20)?;
    let name_count = word(image, export + 24)?;
    if function_count > 65_536 || name_count > 65_536 {
        bail!("export table exceeds supported bounds");
    }
    let functions = word(image, export + 28)?;
    let names = word(image, export + 32)?;
    let ordinals = word(image, export + 36)?;
    for index in 0..name_count {
        let name_entry = offset(image, &sections, add(names, index, 4)?, 4)?;
        let name_rva = word(image, name_entry)?;
        let name = offset(image, &sections, name_rva, 1)?;
        if !image[name..].starts_with(b"RustySandInitialize\0") {
            continue;
        }
        let ordinal_entry = offset(image, &sections, add(ordinals, index, 2)?, 2)?;
        let ordinal = u32::from(half(image, ordinal_entry)?);
        if ordinal >= function_count {
            bail!("initializer export ordinal is out of range");
        }
        let function_entry = offset(image, &sections, add(functions, ordinal, 4)?, 4)?;
        let rva = word(image, function_entry)?;
        if (export_rva..export_end).contains(&rva) {
            bail!("forwarded hook initializers are unsupported");
        }
        offset(image, &sections, rva, 1)?;
        if !sections
            .iter()
            .any(|section| section.contains(rva) && section.flags & 0x2000_0000 != 0)
        {
            bail!("hook initializer is not in an executable section");
        }
        return Ok(rva);
    }
    bail!("hook library does not export RustySandInitialize")
}

struct Section {
    virtual_size: u32,
    address: u32,
    raw_size: u32,
    raw_offset: u32,
    flags: u32,
}

impl Section {
    fn contains(&self, rva: u32) -> bool {
        rva.checked_sub(self.address)
            .is_some_and(|delta| delta < self.virtual_size.max(self.raw_size))
    }
}

fn offset(image: &[u8], sections: &[Section], rva: u32, size: usize) -> Result<usize> {
    for section in sections {
        if let Some(delta) = rva.checked_sub(section.address) {
            let end = (delta as usize)
                .checked_add(size)
                .context("RVA range overflow")?;
            if end <= section.raw_size as usize {
                let start = (section.raw_offset as usize)
                    .checked_add(delta as usize)
                    .context("file offset overflow")?;
                let end = start.checked_add(size).context("file range overflow")?;
                if image.get(start..end).is_some() {
                    return Ok(start);
                }
            }
        }
    }
    bail!("PE RVA {rva:#x} lies outside file-backed sections")
}

fn add(base: u32, index: u32, width: u32) -> Result<u32> {
    index
        .checked_mul(width)
        .and_then(|offset| base.checked_add(offset))
        .context("export table offset overflow")
}

fn half(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.checked_add(2).context("header offset overflow")?)
        .context("truncated PE header")?;
    Ok(u16::from_le_bytes(value.try_into()?))
}

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.checked_add(4).context("header offset overflow")?)
        .context("truncated PE header")?;
    Ok(u32::from_le_bytes(value.try_into()?))
}

#[cfg(test)]
#[path = "../../tests/unit/windows/injection_image.rs"]
mod tests;
