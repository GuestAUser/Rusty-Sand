use rusty_sand_protocol::{HookOperation, OperationCriticality};

fn assert_registry_policy(access_rights: u32, expected_read_only: bool) {
    let operation = HookOperation::RegistryOpen {
        key: "HKCU\\Software".to_owned(),
        access_rights,
    };
    let criticality = if expected_read_only {
        OperationCriticality::Low
    } else {
        OperationCriticality::Medium
    };

    assert_eq!(
        operation.is_read_only(),
        expected_read_only,
        "{access_rights:#010x}"
    );
    assert_eq!(
        operation.criticality(),
        criticality,
        "{access_rights:#010x}"
    );
}

#[test]
fn all_read_right_subsets_and_view_modifiers_are_classified() {
    let read_bits = [0x0001, 0x0008, 0x0010, 0x0002_0000];

    for subset in 0..16 {
        let mut rights = 0;

        for (index, bit) in read_bits.iter().enumerate() {
            if subset & (1 << index) != 0 {
                rights |= bit;
            }
        }

        for view in [0, 0x0100, 0x0200, 0x0300] {
            assert_registry_policy(rights | view, subset != 0 && view != 0x0300);
        }
    }
}

#[test]
fn every_non_read_bit_requires_approval_even_when_combined_with_key_read() {
    for shift in 0..32 {
        let bit = 1_u32 << shift;

        if bit & 0x0002_0319 != 0 {
            continue;
        }

        for view in [0, 0x0100, 0x0200] {
            assert_registry_policy(bit | view, false);
            assert_registry_policy(0x0002_0019 | bit | view, false);
        }
    }
}

#[test]
fn write_delete_generic_and_maximal_access_require_approval() {
    for rights in [
        0x0002,      /* KEY_SET_VALUE */
        0x0004,      /* KEY_CREATE_SUB_KEY */
        0x0020,      /* KEY_CREATE_LINK */
        0x0001_0000, /* DELETE */
        0x0004_0000, /* WRITE_DAC */
        0x0008_0000, /* WRITE_OWNER */
        0x0002_0006, /* KEY_WRITE */
        0x000f_003f, /* KEY_ALL_ACCESS */
        0x0100_0000, /* ACCESS_SYSTEM_SECURITY */
        0x0200_0000, /* MAXIMUM_ALLOWED */
        0x1000_0000, /* GENERIC_ALL */
        0x2000_0000, /* GENERIC_EXECUTE */
        0x4000_0000, /* GENERIC_WRITE */
        0x8000_0000, /* GENERIC_READ needs mapping before approval */
        u32::MAX,
    ] {
        assert_registry_policy(rights, false);
    }
}
