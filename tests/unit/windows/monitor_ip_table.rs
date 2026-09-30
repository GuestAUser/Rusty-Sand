use super::*;

#[test]
fn respects_returned_length_instead_of_allocation() {
    assert_eq!(
        rows(&[2, 1, 2, 3, 4], 12, 2),
        Err(TableError::TruncatedRows)
    );
    assert_eq!(rows(&[1, 1, 2, 99, 99], 12, 2), Ok(&[1, 2][..]));
}

#[test]
fn rejects_missing_header_partial_word_and_overflowing_count() {
    assert_eq!(rows(&[], 0, 6), Err(TableError::InvalidLength));
    assert_eq!(rows(&[0], 3, 6), Err(TableError::InvalidLength));
    assert_eq!(rows(&[0], 8, 6), Err(TableError::InvalidLength));
    assert_eq!(rows(&[u32::MAX], 4, 6), Err(TableError::TruncatedRows));
    assert_eq!(rows(&[0], 4, 6), Ok(&[][..]));
}
