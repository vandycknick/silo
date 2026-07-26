use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::unistd::{getgid, getuid};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::command;
use crate::kernel::KernelOptions;
use crate::targets::HostTarget;

const APPLE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
pub const CONTAINER_MARKER: &str = "SILO_RELEASE_CONTAINER";

#[derive(Debug)]
pub struct Toolchains {
    values: BTreeMap<String, String>,
}

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
    #[error("release toolchain record is invalid: {reason}")]
    Toolchains { reason: String },
    #[error("release tool {tool} at {path} reported {actual:?}, expected {expected}")]
    ToolVersion {
        tool: &'static str,
        path: PathBuf,
        actual: String,
        expected: String,
    },
    #[error(
        "Docker is required for Linux release builds; start a native Docker daemon or run on macOS"
    )]
    DockerUnavailable,
    #[error("Docker daemon architecture {actual:?} is not native {expected}")]
    NonNativeDocker {
        actual: String,
        expected: &'static str,
    },
    #[error("failed to {action} {path}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("official archive digest mismatch for {path}: expected {expected}, got {actual}")]
    Digest {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

impl Toolchains {
    pub fn value(&self, key: &str) -> Result<&str, ReleaseError> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| ReleaseError::Toolchains {
                reason: format!("missing {key} in release/toolchains.toml"),
            })
    }

    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
}

pub fn toolchains(workspace_root: &Path) -> Result<Toolchains, ReleaseError> {
    let path = workspace_root.join("release/toolchains.toml");
    let contents = fs::read_to_string(&path).map_err(|source| ReleaseError::Io {
        action: "read release toolchain record",
        path: path.clone(),
        source,
    })?;
    let mut section = String::new();
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_string();
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            return Err(ReleaseError::Toolchains {
                reason: format!("cannot parse {line:?}"),
            });
        };
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return Err(ReleaseError::Toolchains {
                reason: format!("{key} is not a quoted string"),
            });
        };
        values.insert(format!("{section}.{key}"), value.to_string());
    }
    for key in [
        "release.ubuntu_image",
        "release.ubuntu_release",
        "release.glibc",
        "tools.rust",
        "tools.rustup",
        "tools.rustup_linux_amd64_sha256",
        "tools.rustup_linux_arm64_sha256",
        "tools.go",
        "tools.go_darwin_arm64_sha256",
        "tools.go_linux_amd64_sha256",
        "tools.go_linux_arm64_sha256",
        "tools.zig",
        "tools.zig_linux_amd64_sha256",
        "tools.zig_linux_arm64_sha256",
        "tools.cargo_zigbuild",
        "tools.cargo_zigbuild_sha256",
        "tools.oras",
        "tools.oras_linux_amd64_sha256",
        "tools.oras_linux_arm64_sha256",
    ] {
        if !values.contains_key(key) {
            return Err(ReleaseError::Toolchains {
                reason: format!("missing {key} in release/toolchains.toml"),
            });
        }
    }
    Ok(Toolchains { values })
}

pub fn go_program(
    target_dir: &Path,
    workspace_root: &Path,
    profile_is_release: bool,
) -> Result<PathBuf, ReleaseError> {
    if !profile_is_release || env::consts::OS != "macos" {
        return tool("go");
    }
    let toolchains = toolchains(workspace_root)?;
    let version = toolchains.value("tools.go")?;
    let digest = toolchains.value("tools.go_darwin_arm64_sha256")?;
    let release_root = target_dir.parent().and_then(Path::parent).ok_or_else(|| {
        ReleaseError::ToolWithoutParent {
            tool: "release target",
            path: target_dir.to_path_buf(),
        }
    })?;
    let tools = release_root.join("release-tools");
    let toolchain = tools.join(format!("go-{version}"));
    let archive = tools.join(format!("go-{version}.darwin-arm64.tar.gz"));
    fs::create_dir_all(&tools).map_err(|source| ReleaseError::Io {
        action: "create release tool directory",
        path: tools.clone(),
        source,
    })?;
    if !archive.is_file() {
        download(
            &format!("https://go.dev/dl/go{version}.darwin-arm64.tar.gz"),
            &archive,
        )?;
    }
    verify_digest(&archive, digest)?;
    let program = toolchain.join("go/bin/go");
    if !program.is_file() {
        let temporary = toolchain.with_extension(format!("tmp-{}", std::process::id()));
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
    }
    verify_tool("go", &program, ["version"], &format!("go{version}"))?;
    Ok(program)
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

pub fn tool_version(path: &Path, args: &[&str]) -> Result<String, ReleaseError> {
    let mut command = Command::new(path);
    command.args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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

    let toolchains = toolchains(workspace_root)?;
    verify_macos_tools(&toolchains)?;
    let clang = xcrun("clang")?;
    let linker = xcrun("ld")?;
    let archiver = xcrun("ar")?;
    let sdk = xcrun_sdk_path()?;
    let mut paths = vec![program_directory(program, "build program")?];
    for name in ["cargo", "cargo-zigbuild", "go", "zig"] {
        let tool = tool(name)?;
        let directory = program_directory(&tool, name)?;
        if !paths.contains(&directory) {
            paths.push(directory);
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
        .env(
            "CARGO_HOME",
            release_cache_directory(target_dir, "cargo-home"),
        )
        .env(
            "GOCACHE",
            release_cache_directory(target_dir, "go-build-cache"),
        )
        .env(
            "GOMODCACHE",
            release_cache_directory(target_dir, "go-module-cache"),
        )
        .env("RUSTFLAGS", remapped_rustflags(workspace_root, target_dir))
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            remapped_rustflags_encoded(workspace_root, target_dir),
        );
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

pub fn verify_linux_toolchain(workspace_root: &Path, host: HostTarget) -> Result<(), ReleaseError> {
    let toolchains = toolchains(workspace_root)?;
    let expected_arch = host.oci_architecture();
    let architecture = tool_version(Path::new("/usr/bin/uname"), &["-m"])?;
    let expected_uname = if expected_arch == "amd64" {
        "x86_64"
    } else {
        "aarch64"
    };
    if architecture != expected_uname {
        return Err(ReleaseError::NonNativeDocker {
            actual: architecture,
            expected: expected_uname,
        });
    }
    verify_tool(
        "rustc",
        &tool("rustc")?,
        ["--version"],
        toolchains.value("tools.rust")?,
    )?;
    verify_tool(
        "cargo",
        &tool("cargo")?,
        ["--version"],
        toolchains.value("tools.rust")?,
    )?;
    verify_tool(
        "go",
        &tool("go")?,
        ["version"],
        &format!("go{}", toolchains.value("tools.go")?),
    )?;
    verify_tool(
        "zig",
        &tool("zig")?,
        ["version"],
        toolchains.value("tools.zig")?,
    )?;
    verify_tool(
        "cargo-zigbuild",
        &tool("cargo-zigbuild")?,
        ["--version"],
        toolchains.value("tools.cargo_zigbuild")?,
    )?;
    verify_tool(
        "oras",
        &tool("oras")?,
        ["version"],
        toolchains.value("tools.oras")?,
    )
}

pub fn run_linux_release(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
    make_target: &str,
    kernel_options: Option<&KernelOptions>,
) -> Result<(), ReleaseError> {
    let _ = toolchains(workspace_root)?;
    let architecture = host.oci_architecture();
    let expected_daemon = if architecture == "amd64" {
        "x86_64"
    } else {
        "aarch64"
    };
    let docker = tool("docker").map_err(|_| ReleaseError::DockerUnavailable)?;
    let daemon = docker_output(&docker, ["info", "--format", "{{.Architecture}}"])
        .map_err(|_| ReleaseError::DockerUnavailable)?;
    if !matches_native_architecture(&daemon, architecture) {
        return Err(ReleaseError::NonNativeDocker {
            actual: daemon,
            expected: expected_daemon,
        });
    }
    fs::create_dir_all(target_dir).map_err(|source| ReleaseError::Io {
        action: "create release target directory",
        path: target_dir.to_path_buf(),
        source,
    })?;
    let mut bake = Command::new(&docker);
    bake.current_dir(workspace_root)
        .env("TARGETARCH", architecture)
        .args([
            "buildx",
            "bake",
            "--load",
            "--file",
            "release/docker-bake.hcl",
            "silo-release",
        ]);
    command::run(bake)?;

    let workspace = workspace_root
        .canonicalize()
        .map_err(|source| ReleaseError::Io {
            action: "resolve workspace root",
            path: workspace_root.to_path_buf(),
            source,
        })?;
    let target = target_dir
        .canonicalize()
        .map_err(|source| ReleaseError::Io {
            action: "resolve release target directory",
            path: target_dir.to_path_buf(),
            source,
        })?;
    let cache = format!("silo-release-cache-{architecture}");
    let mut run = Command::new(docker);
    run.args(["run", "--rm", "--user"])
        .arg(format!("{}:{}", getuid().as_raw(), getgid().as_raw()))
        .args(["--mount"])
        .arg(format!(
            "type=bind,source={},target=/workspace,readonly",
            workspace.display()
        ))
        .args(["--mount"])
        .arg(format!(
            "type=bind,source={},target=/release-target",
            target.display()
        ))
        .args(["--mount"])
        .arg(format!("type=volume,source={cache},target=/release-cache"))
        .args([
            "--env",
            "SILO_RELEASE_CONTAINER=1",
            "--env",
            "CARGO_TARGET_DIR=/release-target",
            "--env",
            "CARGO_HOME=/release-cache/cargo",
            "--env",
            "GOMODCACHE=/release-cache/go-mod",
            "--env",
            "GOCACHE=/release-cache/go-build",
            "--workdir",
            "/workspace",
        ]);
    if let Some(kernel_options) = kernel_options {
        run.args([
            "--env",
            &format!("KERNEL_REFERENCE={}", kernel_options.reference()),
        ]);
        if kernel_options.offline() {
            run.args(["--env", "KERNEL_OFFLINE=1"]);
        }
        if let Some(path) = kernel_options.local_path() {
            let path = path.canonicalize().map_err(|source| ReleaseError::Io {
                action: "resolve local kernel path",
                path: path.to_path_buf(),
                source,
            })?;
            run.args(["--mount"])
                .arg(format!(
                    "type=bind,source={},target=/release-kernel,readonly",
                    path.display()
                ))
                .args(["--env", "KERNEL_PATH=/release-kernel"]);
        }
    }
    run.arg(format!("silo-release:linux-{architecture}"))
        .arg("PROFILE=release")
        .arg(make_target);
    command::run(run)?;
    Ok(())
}

fn verify_macos_tools(toolchains: &Toolchains) -> Result<(), ReleaseError> {
    verify_tool(
        "cargo",
        &tool("cargo")?,
        ["--version"],
        toolchains.value("tools.rust")?,
    )?;
    verify_tool(
        "rustc",
        &tool("rustc")?,
        ["--version"],
        toolchains.value("tools.rust")?,
    )?;
    verify_tool(
        "zig",
        &tool("zig")?,
        ["version"],
        toolchains.value("tools.zig")?,
    )?;
    verify_tool(
        "cargo-zigbuild",
        &tool("cargo-zigbuild")?,
        ["--version"],
        toolchains.value("tools.cargo_zigbuild")?,
    )
}

fn verify_tool(
    tool: &'static str,
    path: &Path,
    args: impl IntoIterator<Item = &'static str>,
    expected: &str,
) -> Result<(), ReleaseError> {
    let args = args.into_iter().collect::<Vec<_>>();
    let actual = tool_version(path, &args)?;
    if actual.contains(expected) {
        Ok(())
    } else {
        Err(ReleaseError::ToolVersion {
            tool,
            path: path.to_path_buf(),
            actual,
            expected: expected.to_string(),
        })
    }
}

fn download(url: &str, path: &Path) -> Result<(), ReleaseError> {
    let mut curl = Command::new("/usr/bin/curl");
    curl.args([
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--output",
    ])
    .arg(path)
    .arg(url);
    command::run(curl)?;
    Ok(())
}

fn verify_digest(path: &Path, expected: &str) -> Result<(), ReleaseError> {
    let mut file = fs::File::open(path).map_err(|source| ReleaseError::Io {
        action: "open verified archive",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| ReleaseError::Io {
            action: "read verified archive",
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
    if actual != expected {
        return Err(ReleaseError::Digest {
            path: path.to_path_buf(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

fn docker_output(
    docker: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> Result<String, ReleaseError> {
    let mut command = Command::new(docker);
    command.args(args);
    let output = command::output(command)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn matches_native_architecture(actual: &str, expected: &str) -> bool {
    matches!(
        (actual, expected),
        ("x86_64" | "amd64", "amd64") | ("aarch64" | "arm64", "arm64")
    )
}

fn remapped_rustflags(workspace_root: &Path, target_dir: &Path) -> String {
    remapped_rustflag_parts(workspace_root, target_dir).join(" ")
}

fn remapped_rustflags_encoded(workspace_root: &Path, target_dir: &Path) -> String {
    remapped_rustflag_parts(workspace_root, target_dir).join("\u{1f}")
}

fn remapped_rustflag_parts(workspace_root: &Path, target_dir: &Path) -> Vec<String> {
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
    flags.push(format!(
        "--remap-path-prefix={}=/usr/src/cargo",
        release_cache_directory(target_dir, "cargo-home").display()
    ));
    flags
}

fn release_cache_directory(target_dir: &Path, name: &str) -> PathBuf {
    target_dir
        .parent()
        .map_or_else(|| target_dir.join(name), |parent| parent.join(name))
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
