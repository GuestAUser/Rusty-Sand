pub(super) fn analyze_file_create(path: &str, _flags: u32) -> u8 {
    let mut score = 20u8;

    let path_lower = path.to_lowercase();

    if path_lower.contains("\\windows\\system32") || path_lower.contains("\\windows\\syswow64") {
        score = score.saturating_add(50);
    }

    if path_lower.contains("\\startup") || path_lower.contains("\\start menu\\programs\\startup") {
        score = score.saturating_add(60);
    }

    if path_lower.contains("\\program files") {
        score = score.saturating_add(30);
    }

    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp") {
        if path_lower.ends_with(".exe") || path_lower.ends_with(".dll") {
            score = score.saturating_add(40);
        } else if path_lower.ends_with(".bat")
            || path_lower.ends_with(".vbs")
            || path_lower.ends_with(".ps1")
        {
            score = score.saturating_add(35);
        }
    }

    if path_lower.ends_with(".exe") || path_lower.ends_with(".dll") || path_lower.ends_with(".sys")
    {
        score = score.saturating_add(15);
    }

    if path_lower.ends_with(".encrypted")
        || path_lower.ends_with(".locked")
        || path_lower.contains(".crypt")
        || path_lower.ends_with("readme.txt")
    {
        score = score.saturating_add(70);
    }

    score
}

pub(super) fn analyze_file_write(path: &str) -> u8 {
    let mut score = 15u8;

    let path_lower = path.to_lowercase();

    if path_lower.contains("\\windows\\") {
        score = score.saturating_add(40);
    }

    if path_lower.contains("\\documents") || path_lower.contains("\\desktop") {
        score = score.saturating_add(10);
    }

    score
}

pub(super) fn analyze_file_delete(path: &str) -> u8 {
    let mut score = 30u8;

    let path_lower = path.to_lowercase();

    if path_lower.contains("\\windows\\system32") {
        score = score.saturating_add(65);
    }

    if path_lower.contains("\\documents")
        || path_lower.contains("\\desktop")
        || path_lower.contains("\\pictures")
    {
        score = score.saturating_add(50);
    }

    if path_lower.ends_with(".doc")
        || path_lower.ends_with(".pdf")
        || path_lower.ends_with(".jpg")
        || path_lower.ends_with(".png")
    {
        score = score.saturating_add(20);
    }

    score
}

pub(super) fn analyze_file_move(_source: &str, destination: &str) -> u8 {
    let mut score = 25u8;
    let destination = destination.to_lowercase();

    if destination.contains("\\startup") {
        score = score.saturating_add(55);
    }

    if destination.contains("\\temp\\") && destination.ends_with(".exe") {
        score = score.saturating_add(40);
    }

    score
}

pub(super) fn analyze_file_copy(_source: &str, destination: &str) -> u8 {
    analyze_file_move(_source, destination).saturating_sub(5u8)
}

pub(super) fn analyze_file_attribute_change(path: &str) -> u8 {
    let mut score = 20u8;

    if path.to_lowercase().contains("\\system") {
        score = score.saturating_add(30);
    }

    score
}

pub(super) fn analyze_folder_create(path: &str) -> u8 {
    let mut score = 15u8;

    let path_lower = path.to_lowercase();

    if path_lower.contains("\\programdata\\") && !path_lower.contains("microsoft") {
        score = score.saturating_add(30);
    }

    if path
        .split('\\')
        .next_back()
        .is_some_and(|name| name.starts_with('.'))
    {
        score = score.saturating_add(25);
    }

    score
}

pub(super) fn analyze_folder_delete(path: &str) -> u8 {
    let mut score = 35u8;

    let path_lower = path.to_lowercase();

    if path_lower.contains("\\windows\\system32") || path_lower.contains("\\program files") {
        score = score.saturating_add(60);
    }

    if path_lower.contains("\\documents")
        || path_lower.contains("\\desktop")
        || path_lower.contains("\\downloads")
    {
        score = score.saturating_add(50);
    }

    score
}
