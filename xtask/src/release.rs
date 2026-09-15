use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::command;

const APPLE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
pub const MACOS_DEPLOYMENT_TARGET: &str = "26.0";

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("release tool {tool} was not found in PATH")]
    MissingTool { tool: &'static str },
    #[error(
        "macOS release Go candidate {path} resolves into /nix/store; put an upstream Go toolchain on PATH"
    )]
    NixMacosGo { path: PathBuf },
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

pub fn go_program(profile_is_release: bool) -> Result<PathBuf, ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return tool("go");
    }

    let path = env::var_os("PATH").ok_or(ReleaseError::MissingTool { tool: "go" })?;
    let mut nix_program = None;
    for directory in env::split_paths(&path) {
        let program = directory.join("go");
        if !program.is_file() {
            continue;
        }
        let resolved = fs::canonicalize(&program).map_err(|source| ReleaseError::Io {
            action: "resolve macOS Go toolchain",
            path: program.clone(),
            source,
        })?;
        if resolved.starts_with("/nix/store") {
            nix_program.get_or_insert(resolved);
            continue;
        }
        return Ok(program);
    }
    match nix_program {
        Some(path) => Err(ReleaseError::NixMacosGo { path }),
        None => Err(ReleaseError::MissingTool { tool: "go" }),
    }
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
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return Ok(());
    }

    let mut flags = remapped_rustflag_parts(workspace_root, target_dir);
    let clang = xcrun("clang")?;
    flags.extend(["-C".to_string(), "strip=symbols".to_string()]);
    command
        .env("SDKROOT", xcrun_sdk_path()?)
        .env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET)
        .env("CC", &clang)
        .env("CXX", xcrun("clang++")?)
        .env("LD", xcrun("ld")?)
        .env("AR", xcrun("ar")?)
        .env("CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", clang)
        .env("RUSTFLAGS", flags.join(" "))
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
    Ok(())
}

pub fn configure_guest_init_command(
    command: &mut Command,
    profile_is_release: bool,
    workspace_root: &Path,
    target_dir: &Path,
) {
    let mut flags = vec!["-C".to_string(), "panic=abort".to_string()];
    if profile_is_release && env::consts::OS == "macos" {
        flags.extend(remapped_rustflag_parts(workspace_root, target_dir));
        flags.extend(["-C".to_string(), "strip=symbols".to_string()]);
    }
    command
        .env("RUSTFLAGS", flags.join(" "))
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
}

fn remapped_rustflag_parts(workspace_root: &Path, target_dir: &Path) -> Vec<String> {
    let mut flags = vec![format!(
        "--remap-path-prefix={}=/usr/src/silo",
        workspace_root.display()
    )];
    push_canonical_remap(&mut flags, workspace_root, "/usr/src/silo");
    if let Some(cargo_home) = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
    {
        flags.push(format!(
            "--remap-path-prefix={}=/usr/src/cargo",
            cargo_home.display()
        ));
        push_canonical_remap(&mut flags, &cargo_home, "/usr/src/cargo");
    }
    flags.push("--remap-path-prefix=/nix/store=/usr/src/toolchain".to_string());
    flags.push(format!(
        "--remap-path-prefix={}=/usr/build",
        target_dir.display()
    ));
    push_canonical_remap(&mut flags, target_dir, "/usr/build");
    flags
}

fn push_canonical_remap(flags: &mut Vec<String>, path: &Path, replacement: &str) {
    if let Ok(canonical) = fs::canonicalize(path) {
        if canonical != path {
            flags.push(format!(
                "--remap-path-prefix={}={replacement}",
                canonical.display()
            ));
        }
    }
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
    command.env_clear().env("PATH", APPLE_PATH).args([
        "--no-cache",
        "--sdk",
        "macosx",
        "--find",
        tool,
    ]);
    let output = command::output(command)?;
    let path = String::from_utf8(output.stdout)
        .map_err(|_| ReleaseError::InvalidXcrunPath { tool })?
        .trim()
        .to_string();
    Ok(PathBuf::from(path))
}

fn xcrun_sdk_path() -> Result<PathBuf, ReleaseError> {
    let mut command = Command::new("/usr/bin/xcrun");
    command.env_clear().env("PATH", APPLE_PATH).args([
        "--no-cache",
        "--sdk",
        "macosx",
        "--show-sdk-path",
    ]);
    let output = command::output(command)?;
    let path = String::from_utf8(output.stdout)
        .map_err(|_| ReleaseError::InvalidXcrunPath { tool: "SDK path" })?
        .trim()
        .to_string();
    Ok(PathBuf::from(path))
}
