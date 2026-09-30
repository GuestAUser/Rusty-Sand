pub(super) fn analyze_process_create(executable: &str, args: &str) -> u8 {
    let mut score = 30u8;

    let exe_lower = executable.to_lowercase();
    let args_lower = args.to_lowercase();

    if exe_lower.contains("powershell") {
        score = score.saturating_add(40);

        if args_lower.contains("-enc") || args_lower.contains("-e ") {
            score = score.saturating_add(50);
        }
        if args_lower.contains("downloadstring") || args_lower.contains("invoke-expression") {
            score = score.saturating_add(45);
        }
        if args_lower.contains("-nop") || args_lower.contains("-w hidden") {
            score = score.saturating_add(35);
        }
    }

    if exe_lower.contains("cmd.exe") && args_lower.contains("/c") {
        score = score.saturating_add(20);
    }

    if exe_lower.contains("wscript")
        || exe_lower.contains("cscript")
        || exe_lower.contains("mshta")
        || exe_lower.contains("regsvr32")
    {
        score = score.saturating_add(40);
    }

    if exe_lower.contains("\\temp\\") || exe_lower.contains("\\appdata\\local\\temp") {
        score = score.saturating_add(35);
    }

    score
}

pub(super) fn analyze_dll_load(dll_path: &str) -> u8 {
    let mut score = 25u8;

    let path_lower = dll_path.to_lowercase();

    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp") {
        score = score.saturating_add(45);
    }

    if (path_lower.ends_with("kernel32.dll")
        || path_lower.ends_with("ntdll.dll")
        || path_lower.ends_with("user32.dll"))
        && !path_lower.contains("\\windows\\system32")
    {
        score = score.saturating_add(65);
    }

    score
}

pub(super) fn analyze_memory_allocate(protection: u32, size: usize) -> u8 {
    /*
     * Win32 stores one base protection in the low byte. PAGE_GUARD and cache
     * modifiers must not hide executable memory from the scoring policy.
     */
    let protection = protection & 0xff;
    let mut score = 30u8;

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    if protection == PAGE_EXECUTE_READWRITE {
        score = score.saturating_add(65);
    }

    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    if matches!(protection, PAGE_EXECUTE | PAGE_EXECUTE_READ | 0x80) {
        score = score.saturating_add(40);
    }

    if size > 10_000_000 {
        score = score.saturating_add(20);
    }

    score
}

pub(super) fn analyze_memory_protect(old_protection: u32, new_protection: u32) -> u8 {
    let old_protection = old_protection & 0xff;
    let new_protection = new_protection & 0xff;
    let mut score = 35u8;

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    if new_protection == PAGE_EXECUTE_READWRITE {
        score = score.saturating_add(60);
    }

    const PAGE_EXECUTE: u32 = 0x10;
    if matches!(new_protection, PAGE_EXECUTE | 0x20 | 0x80)
        && !matches!(old_protection, 0x10 | 0x20 | 0x40 | 0x80)
    {
        score = score.saturating_add(45);
    }

    score
}
