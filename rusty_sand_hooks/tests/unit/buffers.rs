use super::*;

#[test]
fn nullable_thread_routines_preserve_the_abi_sentinel() {
    unsafe extern "system" fn start(_parameter: *mut core::ffi::c_void) -> u32 {
        0
    }

    let routine: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = start;
    let expected = (routine as *const ()).addr() as u64;

    assert_eq!(start_address(None), 0);
    assert_ne!(expected, 0);
    assert_eq!(start_address(Some(routine)), expected);
}

#[test]
fn pointer_count_contract_and_alignment() {
    assert_eq!(validate_pointer_length(0, 0), Ok(()));
    assert_eq!(validate_pointer_length(0, 2), Err(BufferError::NullPointer));
    assert_eq!(
        validate_pointer_length(usize::MAX, 2),
        Err(BufferError::InvalidLength)
    );
    assert_eq!(
        validate_wide_address(1),
        Err(BufferError::MisalignedWideString)
    );
    assert_eq!(validate_wide_address(2), Ok(()));
}

#[test]
fn byte_conversion_never_requires_wchar_alignment() {
    let storage = [0, b'A', 0, 0x3d, 0xd8, 0x00, 0xde];
    assert_eq!(utf16_from_bytes(&storage[1..]), Ok("A\u{1f600}".into()));
    assert_eq!(utf16_from_bytes(&[0]), Err(BufferError::InvalidLength));
    assert_eq!(utf16_from_bytes(&[0, 0xd8]), Err(BufferError::InvalidUtf16));
}

#[test]
fn registry_lengths_are_bytes_not_wchars() {
    assert_eq!(registry_name(&[2, 0, 0, 0, b'A', 0]), Ok("A".into()));
    assert_eq!(
        registry_name(&[4, 0, 0, 0, b'A', 0]),
        Err(BufferError::InvalidLength)
    );
    assert_eq!(
        registry_name(&[1, 0, 0, 0, b'A']),
        Err(BufferError::InvalidLength)
    );
    assert_eq!(registry_name(&[]), Err(BufferError::InvalidLength));
}

#[test]
fn socket_buffers_respect_family_lengths_and_byte_order() {
    let mut ipv4 = [0; 16];
    ipv4[..8].copy_from_slice(&[2, 0, 1, 0xbb, 127, 0, 0, 1]);
    assert_eq!(socket_address(&ipv4), Ok(("127.0.0.1".into(), 443, false)));
    let mut ipv6 = [0; 28];
    ipv6[..4].copy_from_slice(&[23, 0, 0, 80]);
    ipv6[23] = 1;
    ipv6[24] = 7;
    assert_eq!(socket_address(&ipv6), Ok(("::1%7".into(), 80, true)));
    assert_eq!(socket_address(&ipv6[..16]), Err(BufferError::InvalidLength));
    assert_eq!(socket_address(&[]), Err(BufferError::InvalidLength));
    assert_eq!(
        socket_address_length(1),
        Err(BufferError::UnsupportedAddressFamily(1))
    );
}

#[test]
fn wide_chunks_stop_at_terminators_and_enforce_the_limit() {
    let mut output = Vec::new();
    assert_eq!(append_wide_chunk(&mut output, &[b'A', 0], 2), Ok(false));
    assert_eq!(append_wide_chunk(&mut output, &[b'B', 0], 2), Ok(false));
    assert_eq!(
        append_wide_chunk(&mut output, &[0, 0, 0, 0xd8], 2),
        Ok(true)
    );
    assert_eq!(utf16_from_bytes(&output), Ok("AB".into()));
    assert_eq!(
        append_wide_chunk(&mut output, &[b'C', 0], 2),
        Err(BufferError::UnterminatedString)
    );
    assert_eq!(
        append_wide_chunk(&mut output, &[1], 2),
        Err(BufferError::InvalidLength)
    );
}
