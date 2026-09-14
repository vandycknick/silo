use std::path::PathBuf;
use std::process::Command;
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use krun::RosettaLaunchConfig;

const ENV_ROSETTA_CONFIG: &str = "SILO_ROSETTA_CONFIG";

fn helper() -> Command {
    Command::new(env!("CARGO_BIN_EXE_krun"))
}

fn encoded_config() -> String {
    RosettaLaunchConfig::new(
        PathBuf::from("/synthetic/translator/root"),
        [0x42; 32],
        7,
        [0x5a; 1024],
    )
    .expect("valid synthetic Rosetta config")
    .encode()
    .expect("encode synthetic Rosetta config")
}

#[test]
fn help_ignores_malformed_rosetta_environment() {
    let output = helper()
        .arg("--help")
        .env(ENV_ROSETTA_CONFIG, "PAYLOAD_MUST_NOT_LEAK{")
        .output()
        .expect("run helper help");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--rosetta"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PAYLOAD_MUST_NOT_LEAK"));
}

#[test]
fn real_helper_rejects_flag_without_value_before_host_admission() {
    let output = helper()
        .args(["--rosetta", "--kernel", "/missing/kernel"])
        .env_remove(ENV_ROSETTA_CONFIG)
        .output()
        .expect("run helper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("--rosetta requires SILO_ROSETTA_CONFIG"));
    assert!(!stderr.contains("host check failed"));
}

#[test]
fn real_helper_rejects_value_without_flag_before_host_admission() {
    let output = helper()
        .args(["--kernel", "/missing/kernel"])
        .env(ENV_ROSETTA_CONFIG, encoded_config())
        .output()
        .expect("run helper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("SILO_ROSETTA_CONFIG requires --rosetta"));
    assert!(!stderr.contains("host check failed"));
}

#[test]
fn real_helper_rejects_malformed_value_without_echoing_it() {
    let marker = "PAYLOAD_MUST_NOT_LEAK";
    let output = helper()
        .args(["--rosetta", "--kernel", "/missing/kernel"])
        .env(ENV_ROSETTA_CONFIG, format!("{{{marker}"))
        .output()
        .expect("run helper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("invalid SILO_ROSETTA_CONFIG"));
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains("host check failed"));
}

#[test]
fn real_helper_rejects_non_utf8_environment_without_echoing_it() {
    let output = helper()
        .args(["--rosetta", "--kernel", "/missing/kernel"])
        .env(
            ENV_ROSETTA_CONFIG,
            OsString::from_vec(vec![b'{', b'X', 0xff]),
        )
        .output()
        .expect("run helper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("not a valid Rosetta configuration"));
    assert!(!stderr.contains("host check failed"));
}

#[test]
fn real_helper_rejects_duplicate_enable_flag() {
    let output = helper()
        .args(["--rosetta", "--rosetta", "--kernel", "/missing/kernel"])
        .env(ENV_ROSETTA_CONFIG, encoded_config())
        .output()
        .expect("run helper");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used multiple times"));
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn real_helper_rejects_rosetta_on_an_unsupported_host_before_admission() {
    let output = helper()
        .args(["--rosetta", "--kernel", "/missing/kernel"])
        .env(ENV_ROSETTA_CONFIG, encoded_config())
        .output()
        .expect("run helper");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("supported only on macOS aarch64 hosts"));
    assert!(!stderr.contains("host check failed"));
}
