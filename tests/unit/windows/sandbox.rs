use super::*;
use crate::config::ConfigError;

#[test]
fn invalid_configuration_is_rejected_before_creating_output_directories() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let output = temporary.path().join("not-created");
    let config = SandboxConfig {
        allowed_file_patterns: vec![r"C:\Allowed\*".into()],
        output_dir: output.clone(),
        ..SandboxConfig::default()
    };

    let error = Sandbox::new(config)
        .err()
        .context("unsupported configuration was accepted")?;
    assert_eq!(
        error.downcast_ref::<ConfigError>(),
        Some(&ConfigError::UnsupportedFilePatterns)
    );
    assert!(!output.exists());
    Ok(())
}
