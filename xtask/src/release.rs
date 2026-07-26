use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;

const APPLE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const GO_VERSION: &str = "1.26.5";
const GO_DARWIN_ARM64_SHA256: &str =
    "efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a";
const SCRUBBED_ENVIRONMENT: [&str; 32] = [
    "CC",
    "CXX",
    "AR",
    "LD",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "SDKROOT",
    "DEVELOPER_DIR",
    "MACOSX_DEPLOYMENT_TARGET",
    "NIX_CC",
    "NIX_CFLAGS_COMPILE",
    "NIX_CFLAGS_LINK",
    "NIX_LDFLAGS",
    "NIX_DONT_SET_RPATH",
    "NIX_ENFORCE_NO_NATIVE",
    "NIX_ENFORCE_PURITY",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
    "LIBRARY_PATH",
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "BINDGEN_EXTRA_CLANG_ARGS",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
];

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error("release tool {tool} was not found in PATH")]
    MissingTool { tool: &'static str },
    #[error("release tool {tool} has no parent directory: {path}")]
    ToolWithoutParent { tool: &'static str, path: PathBuf },
    #[error("xcrun returned invalid UTF-8 for {tool}")]
    InvalidXcrunPath { tool: &'static str },
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("official Go archive digest mismatch for {path}: expected {expected}, got {actual}")]
    GoDigest {
        path: PathBuf,
        expected: &'static str,
        actual: String,
    },
}

pub fn go_program(target_dir: &Path, profile_is_release: bool) -> Result<PathBuf, ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return tool("go", false);
    }
    let release_root = target_dir.parent().and_then(Path::parent).ok_or_else(|| {
        ReleaseError::ToolWithoutParent {
            tool: "release target",
            path: target_dir.to_path_buf(),
        }
    })?;
    let toolchain = release_root
        .join("release-tools")
        .join(format!("go-{GO_VERSION}"));
    let program = toolchain.join("go/bin/go");
    if program.is_file() {
        return Ok(program);
    }
    let archive = toolchain.with_extension("tar.gz");
    let temporary = toolchain.with_extension(format!("tmp-{}", std::process::id()));
    fs::create_dir_all(release_root.join("release-tools")).map_err(|source| ReleaseError::Io {
        action: "create release tool directory",
        path: release_root.join("release-tools"),
        source,
    })?;
    let mut curl = Command::new("/usr/bin/curl");
    curl.args([
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--output",
    ])
    .arg(&archive)
    .arg(format!(
        "https://go.dev/dl/go{GO_VERSION}.darwin-arm64.tar.gz"
    ));
    command::run(curl)?;
    verify_go_digest(&archive)?;
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|source| ReleaseError::Io {
            action: "remove temporary Go toolchain",
            path: temporary.clone(),
            source,
        })?;
    }
    fs::create_dir_all(&temporary).map_err(|source| ReleaseError::Io {
        action: "create temporary Go toolchain",
        path: temporary.clone(),
        source,
    })?;
    let mut extract = Command::new("/usr/bin/tar");
    extract
        .args(["-xzf"])
        .arg(&archive)
        .args(["-C"])
        .arg(&temporary);
    command::run(extract)?;
    fs::rename(&temporary, &toolchain).map_err(|source| ReleaseError::Io {
        action: "install Go toolchain",
        path: toolchain.clone(),
        source,
    })?;
    fs::remove_file(&archive).map_err(|source| ReleaseError::Io {
        action: "remove verified Go archive",
        path: archive,
        source,
    })?;
    Ok(program)
}

pub fn tool(tool: &'static str, clean_macos_release: bool) -> Result<PathBuf, ReleaseError> {
    let path = env::var_os("PATH").ok_or(ReleaseError::MissingTool { tool })?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(tool);
        if candidate.is_file() {
            if !clean_macos_release || candidate.starts_with("/nix/store") {
                return Ok(candidate);
            }
            return Ok(candidate);
        }
    }
    Err(ReleaseError::MissingTool { tool })
}

pub fn configure_command(
    command: &mut Command,
    profile_is_release: bool,
    program: &Path,
    workspace_root: &Path,
    target_dir: &Path,
) -> Result<(), ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return Ok(());
    }

    let clang = xcrun("clang")?;
    let linker = xcrun("ld")?;
    let archiver = xcrun("ar")?;
    let sdk = xcrun_sdk_path()?;
    let mut paths = vec![program_directory(program, "build program")?];
    for name in ["cargo", "cargo-zigbuild", "go", "zig"] {
        if let Ok(tool) = tool(name, true) {
            let directory = program_directory(&tool, name)?;
            if !paths.contains(&directory) {
                paths.push(directory);
            }
        }
    }
    paths.extend(env::split_paths(&OsString::from(APPLE_PATH)));

    command.env_clear();
    for name in ["HOME", "USER", "LOGNAME", "TERM"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env(
            "PATH",
            env::join_paths(paths).map_err(|_| ReleaseError::InvalidXcrunPath { tool: "PATH" })?,
        )
        .env("SDKROOT", sdk)
        .env("MACOSX_DEPLOYMENT_TARGET", "26.0")
        .env("CC", clang)
        .env("CXX", xcrun("clang++")?)
        .env("LD", linker)
        .env("AR", archiver)
        .env("RUSTFLAGS", remapped_rustflags(workspace_root, target_dir))
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            remapped_rustflags_encoded(workspace_root, target_dir),
        );
    for name in SCRUBBED_ENVIRONMENT {
        if !matches!(
            name,
            "CC" | "CXX"
                | "AR"
                | "LD"
                | "RUSTFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "SDKROOT"
                | "MACOSX_DEPLOYMENT_TARGET"
        ) {
            command.env_remove(name);
        }
    }
    Ok(())
}

pub fn configure_guest_init_command(
    command: &mut Command,
    profile_is_release: bool,
    workspace_root: &Path,
    target_dir: &Path,
) {
    if !profile_is_release || env::consts::OS != "macos" {
        return;
    }
    let mut flags = vec!["-C".to_string(), "panic=abort".to_string()];
    flags.extend(remapped_rustflag_parts(workspace_root, target_dir));
    command
        .env("RUSTFLAGS", flags.join(" "))
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"));
}

fn remapped_rustflags(workspace_root: &Path, target_dir: &Path) -> String {
    remapped_rustflag_parts(workspace_root, target_dir).join(" ")
}

fn remapped_rustflags_encoded(workspace_root: &Path, target_dir: &Path) -> String {
    remapped_rustflag_parts(workspace_root, target_dir).join("\u{1f}")
}

fn remapped_rustflag_parts(workspace_root: &Path, target_dir: &Path) -> Vec<String> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let mut flags = vec![
        "-C".to_string(),
        "strip=symbols".to_string(),
        "--remap-path-prefix=/nix/store=/usr/src".to_string(),
        format!(
            "--remap-path-prefix={}=/usr/src/silo",
            workspace_root.display()
        ),
        format!("--remap-path-prefix={}=/usr/build", target_dir.display()),
    ];
    if let Some(cargo_home) = cargo_home {
        flags.push(format!(
            "--remap-path-prefix={}=/usr/src/cargo",
            cargo_home.display()
        ));
    }
    flags
}

fn verify_go_digest(path: &Path) -> Result<(), ReleaseError> {
    let mut file = fs::File::open(path).map_err(|source| ReleaseError::Io {
        action: "open Go archive",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| ReleaseError::Io {
            action: "read Go archive",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != GO_DARWIN_ARM64_SHA256 {
        return Err(ReleaseError::GoDigest {
            path: path.to_path_buf(),
            expected: GO_DARWIN_ARM64_SHA256,
            actual,
        });
    }
    Ok(())
}

fn program_directory(program: &Path, tool: &'static str) -> Result<PathBuf, ReleaseError> {
    program
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ReleaseError::ToolWithoutParent {
            tool,
            path: program.to_path_buf(),
        })
}

fn xcrun(tool: &'static str) -> Result<PathBuf, ReleaseError> {
    let mut command = Command::new("/usr/bin/xcrun");
    command
        .env_clear()
        .env("PATH", APPLE_PATH)
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
        .env_clear()
        .env("PATH", APPLE_PATH)
        .args(["--sdk", "macosx", "--show-sdk-path"]);
    let output = command::output(command)?;
    let path = String::from_utf8(output.stdout)
        .map_err(|_| ReleaseError::InvalidXcrunPath { tool: "SDK path" })?
        .trim()
        .to_string();
    Ok(PathBuf::from(path))
}
