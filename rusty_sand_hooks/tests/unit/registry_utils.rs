use super::*;

#[test]
fn test_hkey_to_root_name() {
    assert_eq!(
        predefined_root(0x8000_0002_u32 as i32 as isize),
        Some("HKLM")
    );
    assert_eq!(
        predefined_root(0x8000_0001_u32 as i32 as isize),
        Some("HKCU")
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(predefined_root(0x8000_0002_u32 as isize), None);
    assert_eq!(predefined_root(0x1234), None);
}

#[test]
fn test_build_registry_path() {
    assert_eq!(
        join_path("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    );
    assert_eq!(join_path("HKCU", ""), "HKCU");
}

#[test]
fn native_paths_preserve_identity_and_component_boundaries() {
    assert_eq!(
        display_native_path(r"\REGISTRY\MACHINE\Software"),
        r"HKLM\Software"
    );
    assert_eq!(
        display_native_path(r"\Registry\User\S-1-5-21\Software"),
        r"HKU\S-1-5-21\Software"
    );
    assert_eq!(
        display_native_path(r"\REGISTRY\MACHINERY"),
        r"\REGISTRY\MACHINERY"
    );
}

#[test]
fn test_is_sensitive_registry_key() {
    assert!(is_sensitive_registry_key(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    ));
    assert!(is_sensitive_registry_key(
        r"HKCU\Software\Microsoft\Windows Defender"
    ));
    assert!(!is_sensitive_registry_key(r"HKCU\Software\MyApp\Settings"));
    assert!(!is_sensitive_registry_key(r"HKCU\Software\Runtime"));
}

#[test]
fn test_reg_type_to_string() {
    assert_eq!(reg_type_to_string(1), "REG_SZ");
    assert_eq!(reg_type_to_string(4), "REG_DWORD");
    assert_eq!(reg_type_to_string(11), "REG_QWORD");
}

#[cfg(windows)]
#[test]
fn resolves_real_opened_key_without_a_handle_cache() -> Result<(), Box<dyn std::error::Error>> {
    use windows::core::w;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
    };
    let mut key = HKEY::default();
    /* SAFETY: Input is static UTF-16, key is writable local storage, and
    every successfully opened handle is closed after the query. */
    unsafe {
        RegOpenKeyExW(HKEY_CURRENT_USER, w!("Software"), 0, KEY_READ, &mut key)?;
    }
    let resolved = hkey_to_root_name(key);
    /* SAFETY: This test owns the valid handle returned above. */
    unsafe {
        RegCloseKey(key)?;
    }
    let resolved = resolved?;
    assert!(resolved.starts_with("HKU\\"), "{resolved}");
    assert!(resolved.ends_with("\\Software"), "{resolved}");
    Ok(())
}
