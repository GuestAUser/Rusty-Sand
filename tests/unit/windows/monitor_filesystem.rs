use super::*;

#[test]
fn deletion_uses_notification_type_not_missing_metadata() {
    let path = Path::new("missing-directory");
    let mut known = HashMap::new();
    assert!(matches!(
        classify(EventKind::Remove(RemoveKind::Folder), path, &mut known),
        Some(EventType::FolderDeleted)
    ));
    assert!(matches!(
        classify(EventKind::Remove(RemoveKind::File), path, &mut known),
        Some(EventType::FileDeleted)
    ));
    assert!(classify(EventKind::Remove(RemoveKind::Any), path, &mut known).is_none());
}

#[test]
fn untyped_removal_uses_observed_type_and_forgets_descendants() {
    let path = Path::new("removed-directory");
    let mut known = HashMap::from([(path.to_owned(), true), (path.join("file"), false)]);

    assert!(matches!(
        classify(EventKind::Remove(RemoveKind::Any), path, &mut known),
        Some(EventType::FolderDeleted)
    ));
    assert!(known.is_empty());
}

#[test]
fn rename_does_not_claim_content_was_modified() {
    let event = EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::Both));
    assert!(classify(event, Path::new("renamed"), &mut HashMap::new()).is_none());
}
