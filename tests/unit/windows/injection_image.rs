use super::*;

fn image() -> Vec<u8> {
    let mut image = vec![0u8; 0x600];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (offset, value) in [
        (0x84, 0x8664u16),
        (0x86, 1),
        (0x94, 240),
        (0x96, 0x2000),
        (0x98, 0x20b),
    ] {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (0x108, 0x1000u32),
        (0x10c, 0x80),
        (0x190, 0x400),
        (0x194, 0x1000),
        (0x198, 0x400),
        (0x19c, 0x200),
        (0x1ac, 0x2000_0000),
        (0x214, 1),
        (0x218, 1),
        (0x21c, 0x1040),
        (0x220, 0x1044),
        (0x224, 0x1048),
        (0x240, 0x1100),
        (0x244, 0x1050),
    ] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image[0x250..0x264].copy_from_slice(b"RustySandInitialize\0");
    image[0x300] = 0xc3;
    image
}

#[test]
fn accepts_only_a_native_executable_nonforwarded_initializer_export() {
    let mut bytes = image();
    assert_eq!(initializer_rva(&bytes).unwrap(), 0x1100);
    bytes[0x240..0x244].copy_from_slice(&0x1050u32.to_le_bytes());
    assert!(initializer_rva(&bytes).is_err());
    let mut bytes = image();
    bytes[0x1ac..0x1b0].fill(0);
    assert!(initializer_rva(&bytes).is_err());
    let mut bytes = image();
    bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    assert!(initializer_rva(&bytes).is_err());
    let mut bytes = image();
    bytes[0x248..0x24a].copy_from_slice(&1u16.to_le_bytes());
    assert!(initializer_rva(&bytes).is_err());
}

#[test]
fn malformed_images_and_rva_overflows_are_rejected() {
    for bytes in [vec![], b"not a DLL".to_vec(), vec![0; 4096]] {
        assert!(initializer_rva(&bytes).is_err());
    }
    let mut image = vec![0; 64];
    image[..2].copy_from_slice(b"MZ");
    image[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(initializer_rva(&image).is_err());
    assert!(add(u32::MAX, 1, 4).is_err());
    assert!(add(0, u32::MAX, 4).is_err());
}
