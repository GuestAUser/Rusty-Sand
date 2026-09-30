use super::*;

#[test]
fn quotes_empty_whitespace_quotes_and_trailing_backslashes() {
    let cases = [
        ("/D", "/D"),
        ("/C", "/C"),
        ("plain", "plain"),
        ("", "\"\""),
        ("two words", "\"two words\""),
        ("tab\tvalue", "\"tab\tvalue\""),
        ("a\"b", "\"a\\\"b\""),
        ("a\\\"b", "\"a\\\\\\\"b\""),
        ("C:\\folder\\", "C:\\folder\\"),
        ("C:\\space folder\\", "\"C:\\space folder\\\\\""),
    ];
    for (argument, expected) in cases {
        assert_eq!(quote_argument(argument), expected);
    }
}

#[test]
fn rejects_nul_and_invalid_executable_without_spawning() {
    assert!(command_line("", &[]).is_err());
    assert!(command_line("bad\"name", &[]).is_err());
    assert!(command_line("bad\0name", &[]).is_err());
    assert!(command_line("valid.exe", &["bad\0arg".into()]).is_err());
    assert!(command_line("valid.exe", &["x".repeat(32_767)]).is_err());
    assert_eq!(
        command_line("a.exe", &["".into()]).unwrap().last(),
        Some(&0)
    );
}
