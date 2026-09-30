use super::*;

#[test]
fn file_creation_and_truncation_are_not_read_operations() {
    for disposition in [1, 2, 4] {
        assert_eq!(file_intent(0x8000_0000, disposition, 0), FileIntent::Create);
    }
    assert_eq!(file_intent(0, 5, 0), FileIntent::Write);
    assert_eq!(file_intent(0, 3, 0x0400_0000), FileIntent::Write);
    assert_eq!(file_intent(0x8000_0000, 3, 0x0200_0000), FileIntent::Read);
}

#[test]
fn file_specific_and_standard_write_rights_are_detected() {
    for access in [
        0x4000_0000,
        0x1000_0000,
        0x0200_0000,
        0x10000,
        0x40000,
        0x80000,
        2,
        4,
        16,
        64,
        256,
    ] {
        assert_eq!(file_intent(access, 3, 0), FileIntent::Write);
    }
    assert_eq!(
        file_intent(0x8000_0000 | 0x20000 | 0x100000 | 1, 3, 0),
        FileIntent::Read
    );
}

#[test]
fn security_and_unknown_file_rights_are_not_read_only() {
    for access in [0x0100_0000, 0x0080_0000, 0x8000_0000 | 0x0100_0000] {
        assert_eq!(file_intent(access, 3, 0), FileIntent::Write);
    }
}

#[test]
fn only_committed_readable_unguarded_pages_can_be_inspected() {
    for protection in [2, 4, 8, 0x20, 0x40, 0x80] {
        assert!(readable_region(0x1000, protection));
        assert!(!readable_region(0x2000, protection));
        assert!(!readable_region(0x10000, protection));
        assert!(!readable_region(0x1000, protection | 0x100));
    }
    assert!(!readable_region(0x1000, 1));
    assert!(!readable_region(0x1000, 0x10));
}

#[test]
fn unknown_protection_is_not_fabricated_from_reserved_pages() {
    assert_eq!(prior_protection(0x1000, 0x104), 0x104);
    assert_eq!(prior_protection(0x2000, 0x40), 0);
    assert_eq!(prior_protection(0x10000, 0x40), 0);
}
