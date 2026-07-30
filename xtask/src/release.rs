use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::command;

pub const MACOS_DEPLOYMENT_TARGET: &str = "26.0";

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("release tool {tool} was not found in PATH")]
    MissingTool { tool: &'static str },
    #[error("xcrun returned invalid UTF-8 for {tool}")]
    InvalidXcrunPath { tool: &'static str },
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn tool(tool: &'static str) -> Result<PathBuf, ReleaseError> {
    let path = env::var_os("PATH").ok_or(ReleaseError::MissingTool { tool })?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(tool);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(ReleaseError::MissingTool { tool })
}

pub fn tool_output(path: &Path, args: &[&str]) -> Result<String, ReleaseError> {
    let mut command = Command::new(path);
    command.args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn configure_command(
    command: &mut Command,
    profile_is_release: bool,
) -> Result<(), ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return Ok(());
    }

    command
        .env("SDKROOT", xcrun_sdk_path()?)
        .env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET)
        .env("CC", xcrun("clang")?)
        .env("CXX", xcrun("clang++")?)
        .env("LD", xcrun("ld")?)
        .env("AR", xcrun("ar")?)
        .env("RUSTFLAGS", "-C strip=symbols")
        .env("CARGO_ENCODED_RUSTFLAGS", "-C\u{1f}strip=symbols");
    Ok(())
}

pub fn configure_guest_init_command(command: &mut Command, profile_is_release: bool) {
    let mut flags = vec!["-C", "panic=abort"];
    if profile_is_release && env::consts::OS == "macos" {
        flags.extend(["-C", "strip=symbols"]);
    }
    command
        .env("RUSTFLAGS", flags.join(" "))
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
}

pub fn set_macos_build_version(path: &Path) -> Result<(), ReleaseError> {
    let temporary = path.with_extension("vtool");
    let mut vtool = Command::new("/usr/bin/vtool");
    vtool
        .args([
            "-arch",
            "arm64",
            "-set-build-version",
            "macos",
            MACOS_DEPLOYMENT_TARGET,
            MACOS_DEPLOYMENT_TARGET,
            "-replace",
            "-output",
        ])
        .arg(&temporary)
        .arg(path);
    command::run(vtool)?;
    fs::rename(&temporary, path).map_err(|source| ReleaseError::Io {
        action: "install Mach-O with macOS build version",
        path: path.to_path_buf(),
        source,
    })
}

fn xcrun(tool: &'static str) -> Result<PathBuf, ReleaseError> {
    let mut command = Command::new("/usr/bin/xcrun");
    command
        .env_remove("DEVELOPER_DIR")
        .env_remove("SDKROOT")
        .args(["--sdk", "macosx", "--find", tool]);
    let output = command::output(command)?;
    let path = String::from_utf8(output.stdout)
        .map_err(|_| ReleaseError::InvalidXcrunPath { tool })?
        .trim()
        .to_string();
    Ok(PathBuf::from(path))
}

fn xcrun_sdk_path() -> Result<PathBuf, ReleaseError> {
    let mut command = Command::new("/usr/bin/xcrun");
    command
        .env_remove("DEVELOPER_DIR")
        .env_remove("SDKROOT")
        .args(["--sdk", "macosx", "--show-sdk-path"]);
    let output = command::output(command)?;
    let path = String::from_utf8(output.stdout)
        .map_err(|_| ReleaseError::InvalidXcrunPath { tool: "SDK path" })?
        .trim()
        .to_string();
    Ok(PathBuf::from(path))
}
