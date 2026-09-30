use super::*;

#[test]
fn frame_limit_is_inclusive_but_empty_messages_fail() {
    assert_eq!(check_size(MAX_MESSAGE_SIZE), Ok(()));
    assert_eq!(check_size(MAX_MESSAGE_SIZE + 1), Err(FrameError::TooLarge));
    assert_eq!(message_text(&[]), Err(FrameError::Empty));
    assert_eq!(
        message_text(&vec![b' '; MAX_MESSAGE_SIZE + 1]),
        Err(FrameError::TooLarge)
    );
}

#[test]
fn invalid_utf8_is_not_replaced_even_in_unknown_fields() {
    assert!(matches!(
        message_text(b"{\"allowed\":true,\"extra\":\"\xff\"}"),
        Err(FrameError::InvalidUtf8(_))
    ));
    assert_eq!(
        message_text(b"{\"allowed\":false}"),
        Ok("{\"allowed\":false}")
    );
}

#[test]
fn partial_writes_never_complete_an_exchange() {
    assert_eq!(check_write(30, 30), Ok(()));
    for actual in [0, 29, 31] {
        assert_eq!(
            check_write(30, actual),
            Err(FrameError::PartialWrite {
                expected: 30,
                actual
            })
        );
    }
}
