//! ADR-011 guard: the `test-support` code may only be compiled when Cargo itself enables the
//! `test-support` feature (tests). Compiler flags can also turn on `cfg(feature = "test-support")`
//! (`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_TARGET_<triple>_RUSTFLAGS`, `build.rustflags` /
//! `target.*.rustflags` in `.cargo/config*`), which bypasses the dependency graph entirely.
//!
//! Cargo hands this script the final flags for the crate, whatever their source, in
//! `CARGO_ENCODED_RUSTFLAGS`. We ask `rustc` itself which cfgs those flags set (so quoting, escapes
//! and spacing are interpreted exactly as the real compile will) and refuse to build if they
//! set the feature cfg. Anything we cannot evaluate fails the build (fail closed).

use std::env;
use std::process::Command;

const FEATURE_CFG: &str = "feature=\"test-support\"";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let target = env::var("TARGET").unwrap_or_default();
    let target_var = format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        target.to_ascii_uppercase().replace(['-', '.'], "_")
    );
    println!("cargo:rerun-if-env-changed={target_var}");

    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let flags: Vec<&str> = encoded
        .split('\x1f')
        .filter(|flag| !flag.is_empty())
        .collect();
    if flags.is_empty() {
        return;
    }
    let Ok(rustc) = env::var("RUSTC") else {
        panic!("ADR-011: RUSTC is not set; cannot check compiler flags for test-support");
    };
    let mut command = Command::new(rustc);
    command.args(["--print", "cfg"]);
    if !target.is_empty() {
        command.args(["--target", &target]);
    }
    let output = match command.args(&flags).output() {
        Ok(output) if output.status.success() => output,
        _ => panic!(
            "ADR-011: cannot evaluate the compiler flags for secure-web-security; refusing to build"
        ),
    };
    let cfgs = String::from_utf8_lossy(&output.stdout);
    if cfgs.lines().any(|line| line.trim() == FEATURE_CFG) {
        panic!(
            "ADR-011: compiler flags set cfg({FEATURE_CFG}); the test-only fixture allowance \
             may only be enabled through the cargo feature by test builds"
        );
    }
}
