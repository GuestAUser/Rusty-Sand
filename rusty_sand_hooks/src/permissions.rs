#[derive(Debug, PartialEq, Eq)]
pub enum FileIntent {
    Create,
    Write,
    Read,
}

pub fn file_intent(access: u32, disposition: u32, flags: u32) -> FileIntent {
    /* OPEN_ALWAYS can create a file even with read-only access. Backup semantics
    permit directory handles, but do not prove the path names a directory. */
    if matches!(disposition, 1 | 2 | 4) {
        FileIntent::Create
    } else if disposition == 5 || flags & 0x0400_0000 != 0 || has_write_access(access) {
        FileIntent::Write
    } else {
        FileIntent::Read
    }
}

fn has_write_access(access: u32) -> bool {
    /*
     * Only known read, execute, query, and synchronization rights may bypass
     * approval. Security-descriptor access, maximum access, and unknown bits
     * are not evidence of a read-only handle.
     */
    const READ_RIGHTS: u32 =
        0x8000_0000 | 0x2000_0000 | 0x0002_0000 | 0x0010_0000 | 0x0001 | 0x0008 | 0x0020 | 0x0080;

    access & !READ_RIGHTS != 0
}

pub fn readable_region(state: u32, protection: u32) -> bool {
    state == 0x1000
        && protection & 0x100 == 0
        && matches!(protection & 0xff, 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)
}

pub fn prior_protection(state: u32, protection: u32) -> u32 {
    /* MEMORY_BASIC_INFORMATION.Protect is undefined for reserved/free pages.
    Zero is not a PAGE_* access mode and represents unknown on the wire. */
    if state == 0x1000 {
        protection
    } else {
        0
    }
}

#[cfg(test)]
#[path = "../tests/unit/permissions.rs"]
mod tests;
