use std::env;
use std::error::Error;
use std::io;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=tests/fixtures/debugger_benign.c");

    /*
     * Cargo does not expose whether a build script is running for unit tests.
     * Build the fixture for the supported debugger target, but embed its bytes
     * only in the cfg(test) module. Host-only builds need no Windows compiler.
     */
    if env::var("CARGO_CFG_TARGET_OS")? != "windows"
        || env::var("CARGO_CFG_TARGET_ARCH")? != "x86_64"
    {
        return Ok(());
    }

    let source = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| io::Error::other("Cargo did not provide CARGO_MANIFEST_DIR"))?,
    )
    .join("tests/fixtures/debugger_benign.c");
    let output_directory = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?,
    );

    /*
     * Use cc's target-aware compiler discovery, environment and flags, rather
     * than assuming a host compiler or treating the Rust linker as a C compiler.
     * The returned command compiles and links an executable, not a Cargo library.
     */
    let compiler = cc::Build::new()
        .debug(false)
        .opt_level(1)
        .static_crt(true)
        .try_get_compiler()?;
    let mut command = compiler.to_command();
    command.current_dir(&output_directory).arg(&source);

    if compiler.is_like_msvc() {
        command
            .arg("/Fedebugger_benign.exe")
            .arg("/Fodebugger_benign.obj")
            .arg("/link")
            .arg("/SUBSYSTEM:CONSOLE")
            .arg("kernel32.lib");
    } else {
        command
            .arg("-municode")
            .arg("-o")
            .arg("debugger_benign.exe")
            .arg("-lkernel32");
    }

    let status = command.status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "building the benign debugger fixture failed: {status}"
        ))
        .into());
    }

    Ok(())
}
