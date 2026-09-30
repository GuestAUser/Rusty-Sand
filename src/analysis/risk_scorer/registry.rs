pub(super) fn analyze_registry_set(key: &str, _data_type: u32) -> u8 {
    let mut score = 25u8;

    let key_lower = key.to_lowercase();

    if is_startup_key(&key_lower) {
        score = score.saturating_add(65);
    }

    if key_lower.contains("\\environment\\windir") || key_lower.contains("ms-settings") {
        score = score.saturating_add(70);
    }

    if key_lower.contains("windows defender")
        || key_lower.contains("firewall")
        || key_lower.contains("security center")
    {
        score = score.saturating_add(70);
    }

    if key_lower.contains("\\policies\\system") || key_lower.contains("\\control\\lsa") {
        score = score.saturating_add(55);
    }

    score
}

pub(super) fn analyze_registry_delete(key: &str) -> u8 {
    analyze_registry_set(key, 0).saturating_add(10u8)
}

pub(super) fn analyze_registry_open(key: &str, access_rights: u32) -> u8 {
    const KEY_READ: u32 = 0x20019;

    if access_rights == KEY_READ {
        return 5;
    }

    let mut score = 15u8;

    if is_startup_key(&key.to_lowercase()) {
        score = score.saturating_add(20);
    }

    score
}

fn is_startup_key(key: &str) -> bool {
    key.split('\\')
        .any(|component| matches!(component, "run" | "runonce" | "runservices"))
}
