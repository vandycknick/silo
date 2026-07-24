use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::kernel_oci::{
    exchange_directories, install_directory_noreplace, resolve_kernel, ResolveKernelError,
    ResolveKernelOptions,
};
use crate::release_inspect::{inspect_release, GuestExecutables, ReleaseInspectionError};
use crate::release_target::{BuildProfile, ReleaseTarget, ReleaseTargetDescriptor};
use crate::stage_runtime::{stage_runtime, StageRuntimeError, StageRuntimeOptions};

const RELEASE_MODE: u32 = 0o755;

#[derive(Debug)]
pub(crate) struct ReleaseStageOptions {
    pub(crate) target: ReleaseTarget,
    pub(crate) kernel_reference: String,
    pub(crate) kernel_oci_layout: Option<PathBuf>,
    pub(crate) target_dir: PathBuf,
    pub(crate) workspace_root: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ReleaseStageResult {
    pub(crate) runtime: PathBuf,
    pub(crate) cli: PathBuf,
    pub(crate) metadata: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum ReleaseStageError {
    #[error("release target {requested} must be built on {host}")]
    HostTargetMismatch {
        requested: &'static str,
        host: &'static str,
    },
    #[error("release output already exists; use a clean target directory: {path}")]
    OutputExists { path: PathBuf },
    #[error("release staging requires a clean git worktree; found {status}")]
    DirtyWorktree { status: String },
    #[error("release build output is missing: {path}")]
    MissingBuildOutput { path: PathBuf },
    #[error("failed to run {command}")]
    RunCommand { command: String, source: io::Error },
    #[error("command failed ({command}): {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("invalid command output from {command}: {reason}")]
    InvalidCommandOutput { command: String, reason: String },
    #[error("failed to {operation} {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("failed to encode release metadata: {0}")]
    Metadata(#[from] serde_json::Error),
    #[error(transparent)]
    ResolveKernel(#[from] ResolveKernelError),
    #[error(transparent)]
    StageRuntime(#[from] StageRuntimeError),
    #[error(transparent)]
    Inspection(#[from] ReleaseInspectionError),
}

#[derive(Debug)]
struct SourceIdentity {
    revision: String,
    source_date_epoch: u64,
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(path: PathBuf) -> Result<Self, ReleaseStageError> {
        fs::create_dir(&path).map_err(|source| ReleaseStageError::Io {
            operation: "create temporary release directory",
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn release_stage(
    options: &ReleaseStageOptions,
) -> Result<ReleaseStageResult, ReleaseStageError> {
    let host = host_release_target();
    if options.target != host {
        return Err(ReleaseStageError::HostTargetMismatch {
            requested: options.target.descriptor().name,
            host: host.descriptor().name,
        });
    }
    let descriptor = options.target.descriptor();
    let release_dir = options
        .target_dir
        .join("silo-release")
        .join(descriptor.name)
        .join("release");
    if fs::symlink_metadata(&release_dir).is_ok() {
        return Err(ReleaseStageError::OutputExists { path: release_dir });
    }
    let source = source_identity(&options.workspace_root)?;
    require_clean_worktree(&options.workspace_root)?;

    let component_dir = build_host_components(options, descriptor, &source)?;
    strip_host_components(descriptor, &component_dir)?;
    let input_dir = temporary_input_dir(options)?;
    let assets_dir = input_dir.path().join("assets");
    create_directory(&assets_dir)?;
    let guest = build_guest_assets(options, descriptor, &assets_dir, &source)?;
    let kernel_dir = input_dir.path().join("kernel");
    let resolved_kernel = resolve_kernel(&ResolveKernelOptions {
        target: options.target,
        reference: options.kernel_reference.clone(),
        oci_layout: options.kernel_oci_layout.clone(),
        output_dir: kernel_dir,
    })?;
    let temporary_target = input_dir.path().join("stage-target");
    let staged_runtime = stage_runtime(&StageRuntimeOptions {
        target: options.target,
        profile: BuildProfile::Release,
        kernel: resolved_kernel.kernel,
        target_dir: temporary_target,
        component_dir: Some(component_dir.clone()),
        assets_dir: Some(assets_dir),
    })?;

    let temporary_release = temporary_release_dir(&release_dir)?;
    create_directory(&temporary_release.path().join("bin"))?;
    create_directory(&temporary_release.path().join("metadata"))?;
    let cli = temporary_release.path().join("bin/silo");
    copy_file(&component_dir.join("silo"), &cli, RELEASE_MODE)?;
    let kernel_provenance = temporary_release
        .path()
        .join("metadata/kernel-provenance.json");
    copy_file(&resolved_kernel.provenance, &kernel_provenance, 0o644)?;
    let inspection = inspect_release(
        descriptor,
        &options.workspace_root,
        &component_dir,
        &GuestExecutables {
            init: guest.init,
            agent: guest.agent,
        },
    )?;
    let inspection_path = temporary_release.path().join("metadata/inspection.json");
    write_json(&inspection_path, &inspection)?;
    let metadata = temporary_release.path().join("metadata/release.json");
    write_release_metadata(
        &metadata,
        descriptor,
        &source,
        &staged_runtime,
        &cli,
        &kernel_provenance,
        &inspection,
    )?;
    verify_source_identity(&options.workspace_root, &source)?;
    let runtime = descriptor.stage_dir_in(&options.target_dir, BuildProfile::Release);
    publish_release_transaction(
        &staged_runtime,
        &runtime,
        temporary_release.path(),
        &release_dir,
    )?;

    Ok(ReleaseStageResult {
        runtime,
        cli: release_dir.join("bin/silo"),
        metadata: release_dir.join("metadata/release.json"),
    })
}

fn source_identity(workspace: &Path) -> Result<SourceIdentity, ReleaseStageError> {
    let revision = run_capture(git_command(workspace, ["rev-parse", "HEAD"]))?;
    let epoch = run_capture(git_command(
        workspace,
        ["show", "-s", "--format=%ct", "HEAD"],
    ))?;
    let source_date_epoch =
        epoch
            .parse::<u64>()
            .map_err(|error| ReleaseStageError::InvalidCommandOutput {
                command: "git show -s --format=%ct HEAD".to_string(),
                reason: error.to_string(),
            })?;
    Ok(SourceIdentity {
        revision,
        source_date_epoch,
    })
}

fn require_clean_worktree(workspace: &Path) -> Result<(), ReleaseStageError> {
    let status = run_capture(git_command(workspace, ["status", "--porcelain=v1"]))?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(ReleaseStageError::DirtyWorktree { status })
    }
}

fn verify_source_identity(
    workspace: &Path,
    expected: &SourceIdentity,
) -> Result<(), ReleaseStageError> {
    require_clean_worktree(workspace)?;
    let actual = source_identity(workspace)?;
    if actual.revision == expected.revision
        && actual.source_date_epoch == expected.source_date_epoch
    {
        return Ok(());
    }
    Err(ReleaseStageError::InvalidCommandOutput {
        command: "verify release source identity".to_string(),
        reason: format!(
            "source changed from {} at {} to {} at {} during the build",
            expected.revision,
            expected.source_date_epoch,
            actual.revision,
            actual.source_date_epoch
        ),
    })
}

fn publish_release_transaction(
    staged_runtime: &Path,
    runtime: &Path,
    staged_release: &Path,
    release: &Path,
) -> Result<(), ReleaseStageError> {
    if let Some(parent) = runtime.parent() {
        create_directory(parent)?;
    }
    let replaced_runtime = match fs::symlink_metadata(runtime) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            exchange_directories(staged_runtime, runtime)?;
            true
        }
        Ok(_) => {
            return Err(ReleaseStageError::OutputExists {
                path: runtime.to_path_buf(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            install_directory_noreplace(staged_runtime, runtime)?;
            false
        }
        Err(source) => {
            return Err(ReleaseStageError::Io {
                operation: "inspect canonical runtime output",
                path: runtime.to_path_buf(),
                source,
            });
        }
    };

    if let Err(error) = install_directory_noreplace(staged_release, release) {
        let rollback = if replaced_runtime {
            exchange_directories(staged_runtime, runtime)
        } else {
            fs::rename(runtime, staged_runtime).map_err(|source| ResolveKernelError::Io {
                operation: "roll back canonical runtime publication",
                path: runtime.to_path_buf(),
                source,
            })
        };
        return match rollback {
            Ok(()) => Err(error.into()),
            Err(rollback) => Err(ReleaseStageError::InvalidCommandOutput {
                command: "publish release transaction".to_string(),
                reason: format!(
                    "release install failed: {error}; runtime rollback failed: {rollback}"
                ),
            }),
        };
    }
    Ok(())
}

fn git_command<const N: usize>(workspace: &Path, args: [&str; N]) -> Command {
    let mut command = Command::new("git");
    command.current_dir(workspace).args(args);
    command
}

fn build_host_components(
    options: &ReleaseStageOptions,
    descriptor: ReleaseTargetDescriptor,
    source: &SourceIdentity,
) -> Result<PathBuf, ReleaseStageError> {
    let macos_sdk = if descriptor.macos_minimum_version.is_some() {
        system_macos_sdk()?
    } else {
        PathBuf::new()
    };
    for (package, binary) in [("cli", "silo"), ("vmmon", "vmmon")] {
        run(build_rust_command(
            options, descriptor, source, &macos_sdk, package, binary, false,
        ))?;
    }
    run(build_rust_command(
        options, descriptor, source, &macos_sdk, "krun", "krun", true,
    ))?;
    let component_dir = options
        .target_dir
        .join(descriptor.rust_target)
        .join("release");
    let netd = component_dir.join("netd");
    create_directory(&component_dir)?;
    run(build_netd_command(
        options, descriptor, source, &macos_sdk, &netd,
    ))?;
    for binary in ["silo", "vmmon", "netd", "krun"] {
        require_file(&component_dir.join(binary))?;
    }
    Ok(component_dir)
}

fn build_rust_command(
    options: &ReleaseStageOptions,
    descriptor: ReleaseTargetDescriptor,
    source: &SourceIdentity,
    macos_sdk: &Path,
    package: &str,
    binary: &str,
    krun_features: bool,
) -> Command {
    let mut command = Command::new("cargo");
    if descriptor.glibc_baseline.is_some() {
        command.arg("zigbuild");
    } else {
        command.arg("build");
    }
    command
        .current_dir(&options.workspace_root)
        .env("CARGO_TARGET_DIR", &options.target_dir)
        .env("SOURCE_DATE_EPOCH", source.source_date_epoch.to_string())
        .env("RUSTFLAGS", remap_rustflags(&options.workspace_root, None))
        .args(["--locked", "--release", "--target"])
        .arg(descriptor.zig_target.unwrap_or(descriptor.rust_target))
        .args(["-p", package, "--bin", binary]);
    if krun_features {
        command.args(["--features", "krun-bin"]);
    }
    if let Some(minimum) = descriptor.macos_minimum_version {
        remove_nix_apple_toolchain_environment(&mut command);
        command
            .env("MACOSX_DEPLOYMENT_TARGET", minimum)
            .env("SDKROOT", macos_sdk)
            .env("CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", "/usr/bin/clang")
            .env("CC_aarch64_apple_darwin", "/usr/bin/clang")
            .env("CXX_aarch64_apple_darwin", "/usr/bin/clang++");
    }
    command
}

fn build_netd_command(
    options: &ReleaseStageOptions,
    descriptor: ReleaseTargetDescriptor,
    source: &SourceIdentity,
    macos_sdk: &Path,
    output: &Path,
) -> Command {
    let mut command = Command::new("go");
    command
        .current_dir(options.workspace_root.join("net/netd"))
        .env("GOOS", descriptor.goos)
        .env("GOARCH", descriptor.goarch)
        .env("SOURCE_DATE_EPOCH", source.source_date_epoch.to_string())
        .args(["build", "-mod=readonly", "-trimpath", "-buildvcs=true"]);
    if let Some(minimum) = descriptor.macos_minimum_version {
        remove_nix_apple_toolchain_environment(&mut command);
        command
            .env("CGO_ENABLED", "1")
            .env("CC", "/usr/bin/clang")
            .env("MACOSX_DEPLOYMENT_TARGET", minimum)
            .env("SDKROOT", macos_sdk)
            .args([
                "-ldflags",
                &format!(
                    "-s -w -buildid= -linkmode=external -extldflags=-mmacosx-version-min={minimum}"
                ),
            ]);
    } else {
        command
            .env("CGO_ENABLED", "0")
            .args(["-ldflags", "-s -w -buildid="]);
    }
    command.arg("-o").arg(output).arg("./cmd/netd");
    command
}

fn system_macos_sdk() -> Result<PathBuf, ReleaseStageError> {
    let mut command = Command::new("/usr/bin/xcrun");
    remove_nix_apple_toolchain_environment(&mut command);
    command.args(["--sdk", "macosx", "--show-sdk-path"]);
    let path = PathBuf::from(run_capture(command)?);
    if !path.is_absolute() || path.starts_with("/nix/store") || !path.is_dir() {
        return Err(ReleaseStageError::InvalidCommandOutput {
            command: "/usr/bin/xcrun --sdk macosx --show-sdk-path".to_string(),
            reason: format!("expected an absolute system SDK directory, found {path:?}"),
        });
    }
    Ok(path)
}

fn remove_nix_apple_toolchain_environment(command: &mut Command) {
    for variable in [
        "DEVELOPER_DIR",
        "NIX_CFLAGS_COMPILE",
        "NIX_CFLAGS_COMPILE_FOR_BUILD",
        "NIX_LDFLAGS",
        "NIX_LDFLAGS_FOR_BUILD",
        "SDKROOT",
    ] {
        command.env_remove(variable);
    }
}

fn remap_rustflags(workspace: &Path, extra: Option<&str>) -> String {
    let remap = format!("--remap-path-prefix={}=/usr/src/silo", workspace.display());
    extra.map_or(remap.clone(), |extra| format!("{extra} {remap}"))
}

struct GuestArtifacts {
    init: PathBuf,
    agent: PathBuf,
}

fn build_guest_assets(
    options: &ReleaseStageOptions,
    descriptor: ReleaseTargetDescriptor,
    assets: &Path,
    source: &SourceIdentity,
) -> Result<GuestArtifacts, ReleaseStageError> {
    for (package, rustflags) in [("init", Some("-C panic=abort")), ("agent", None)] {
        let mut command = Command::new("cargo");
        command
            .current_dir(&options.workspace_root)
            .env("CARGO_TARGET_DIR", &options.target_dir)
            .env("SOURCE_DATE_EPOCH", source.source_date_epoch.to_string())
            .args(["zigbuild", "--locked", "--release", "--target"])
            .arg(descriptor.guest_target)
            .args(["-p", package]);
        if let Some(rustflags) = rustflags {
            command.env(
                "RUSTFLAGS",
                remap_rustflags(&options.workspace_root, Some(rustflags)),
            );
        } else {
            command.env("RUSTFLAGS", remap_rustflags(&options.workspace_root, None));
        }
        run(command)?;
    }
    let guest_dir = options
        .target_dir
        .join(descriptor.guest_target)
        .join("release");
    let init = guest_dir.join("init");
    let agent = guest_dir.join("silo-agent");
    require_file(&init)?;
    require_file(&agent)?;
    strip_guest_components([&init, &agent])?;
    copy_file(&agent, &assets.join("agent"), RELEASE_MODE)?;
    crate::initramfs::write_initramfs(&crate::initramfs::InitramfsOptions::new(
        &init,
        assets.join("initramfs"),
    ))
    .map_err(|error| ReleaseStageError::InvalidCommandOutput {
        command: "package release initramfs".to_string(),
        reason: error.to_string(),
    })?;
    Ok(GuestArtifacts { init, agent })
}

fn strip_guest_components(binaries: [&Path; 2]) -> Result<(), ReleaseStageError> {
    for binary in binaries {
        run(guest_strip_command(binary))?;
    }
    Ok(())
}

fn guest_strip_command(binary: &Path) -> Command {
    let mut command = Command::new("strip");
    command.arg("--strip-unneeded").arg(binary);
    command
}

fn strip_host_components(
    descriptor: ReleaseTargetDescriptor,
    component_dir: &Path,
) -> Result<(), ReleaseStageError> {
    for binary in ["silo", "vmmon", "krun"] {
        let path = component_dir.join(binary);
        let mut command = if descriptor.macos_minimum_version.is_some() {
            let mut command = Command::new("/usr/bin/strip");
            command.arg("-x");
            command
        } else {
            let mut command = Command::new("strip");
            command.arg("--strip-unneeded");
            command
        };
        command.arg(path);
        run(command)?;
    }
    Ok(())
}

fn write_release_metadata(
    path: &Path,
    descriptor: ReleaseTargetDescriptor,
    source: &SourceIdentity,
    runtime: &Path,
    cli: &Path,
    kernel_provenance: &Path,
    inspection: &Value,
) -> Result<(), ReleaseStageError> {
    let components = [
        ("silo", "bin/silo", cli.to_path_buf()),
        ("vmmon", "runtime/bin/vmmon", runtime.join("bin/vmmon")),
        ("netd", "runtime/bin/netd", runtime.join("bin/netd")),
        ("krun", "runtime/bin/krun", runtime.join("bin/krun")),
        (
            "kernel-default",
            "runtime/assets/kernel-default",
            runtime.join("assets/kernel-default"),
        ),
        (
            "initramfs",
            "runtime/assets/initramfs",
            runtime.join("assets/initramfs"),
        ),
        (
            "agent",
            "runtime/assets/agent",
            runtime.join("assets/agent"),
        ),
    ]
    .map(|(name, logical_path, path)| component_metadata(name, logical_path, &path))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let kernel: Value =
        serde_json::from_slice(&fs::read(kernel_provenance).map_err(|source| {
            ReleaseStageError::Io {
                operation: "read kernel provenance",
                path: kernel_provenance.to_path_buf(),
                source,
            }
        })?)?;
    let value = serde_json::json!({
        "schemaVersion": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "target": descriptor.name,
        "source": {
            "revision": source.revision,
            "sourceDateEpoch": source.source_date_epoch,
        },
        "runtimeLayout": "portable-v1",
        "components": components,
        "kernel": kernel,
        "inspection": inspection,
    });
    write_json(path, &value)
}

fn write_json(path: &Path, value: &Value) -> Result<(), ReleaseStageError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| ReleaseStageError::Io {
        operation: "write release metadata",
        path: path.to_path_buf(),
        source,
    })
}

fn component_metadata(
    name: &str,
    logical_path: &str,
    path: &Path,
) -> Result<Value, ReleaseStageError> {
    let metadata = fs::metadata(path).map_err(|source| ReleaseStageError::Io {
        operation: "inspect release component",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_json::json!({
        "name": name,
        "path": logical_path,
        "sha256": sha256(path)?,
        "size": metadata.len(),
        "mode": metadata.permissions().mode() & 0o777,
    }))
}

fn sha256(path: &Path) -> Result<String, ReleaseStageError> {
    let mut file = File::open(path).map_err(|source| ReleaseStageError::Io {
        operation: "open release component",
        path: path.to_path_buf(),
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| ReleaseStageError::Io {
                operation: "hash release component",
                path: path.to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn copy_file(source: &Path, destination: &Path, mode: u32) -> Result<(), ReleaseStageError> {
    require_file(source)?;
    fs::copy(source, destination).map_err(|error| ReleaseStageError::Io {
        operation: "copy release component",
        path: destination.to_path_buf(),
        source: error,
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(|source| {
        ReleaseStageError::Io {
            operation: "set release component mode",
            path: destination.to_path_buf(),
            source,
        }
    })
}

fn require_file(path: &Path) -> Result<(), ReleaseStageError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ReleaseStageError::Io {
        operation: "inspect build output",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(ReleaseStageError::MissingBuildOutput {
            path: path.to_path_buf(),
        })
    }
}

fn run(mut command: Command) -> Result<(), ReleaseStageError> {
    let rendered = format!("{command:?}");
    let status = command
        .status()
        .map_err(|source| ReleaseStageError::RunCommand {
            command: rendered.clone(),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ReleaseStageError::CommandFailed {
            command: rendered,
            stderr: format!("exit status {status}"),
        })
    }
}

fn run_capture(command: Command) -> Result<String, ReleaseStageError> {
    let rendered = format!("{command:?}");
    let output = run_output(command, &rendered)?;
    if !output.status.success() {
        return Err(command_failed(rendered, output));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| ReleaseStageError::InvalidCommandOutput {
            command: rendered,
            reason: error.to_string(),
        })
}

fn run_output(mut command: Command, rendered: &str) -> Result<Output, ReleaseStageError> {
    command
        .output()
        .map_err(|source| ReleaseStageError::RunCommand {
            command: rendered.to_string(),
            source,
        })
}

fn command_failed(command: String, output: Output) -> ReleaseStageError {
    ReleaseStageError::CommandFailed {
        command,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

fn create_directory(path: &Path) -> Result<(), ReleaseStageError> {
    fs::create_dir_all(path).map_err(|source| ReleaseStageError::Io {
        operation: "create release directory",
        path: path.to_path_buf(),
        source,
    })
}

fn temporary_input_dir(
    options: &ReleaseStageOptions,
) -> Result<TemporaryDirectory, ReleaseStageError> {
    let parent = options
        .target_dir
        .join("release-inputs")
        .join(options.target.descriptor().name);
    create_directory(&parent)?;
    TemporaryDirectory::new(parent.join(nonce("build")))
}

fn temporary_release_dir(release_dir: &Path) -> Result<TemporaryDirectory, ReleaseStageError> {
    let parent = release_dir
        .parent()
        .ok_or_else(|| ReleaseStageError::InvalidCommandOutput {
            command: "prepare release output".to_string(),
            reason: format!("{} has no parent", release_dir.display()),
        })?;
    create_directory(parent)?;
    TemporaryDirectory::new(parent.join(nonce("release")))
}

fn nonce(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(".{kind}-{}-{nanos}", std::process::id())
}

fn host_release_target() -> ReleaseTarget {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        ReleaseTarget::DarwinArm64
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        ReleaseTarget::LinuxAmd64Gnu
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        ReleaseTarget::LinuxArm64Gnu
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    )))]
    compile_error!("release staging supports only ADR 0012 release hosts");
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::release_stage::{
        build_netd_command, build_rust_command, guest_strip_command, publish_release_transaction,
        sha256, write_release_metadata, SourceIdentity,
    };
    use crate::release_target::ReleaseTarget;

    fn options(target: ReleaseTarget, root: &Path) -> crate::release_stage::ReleaseStageOptions {
        crate::release_stage::ReleaseStageOptions {
            target,
            kernel_reference: "kernel:stable".to_string(),
            kernel_oci_layout: None,
            target_dir: root.join("target"),
            workspace_root: root.to_path_buf(),
        }
    }

    fn source() -> SourceIdentity {
        SourceIdentity {
            revision: "abc123".to_string(),
            source_date_epoch: 1_700_000_000,
        }
    }

    #[test]
    fn release_rust_builds_are_locked_and_targeted() {
        let root = Path::new("/workspace");
        for target in [
            ReleaseTarget::DarwinArm64,
            ReleaseTarget::LinuxAmd64Gnu,
            ReleaseTarget::LinuxArm64Gnu,
        ] {
            let options = options(target, root);
            let command = build_rust_command(
                &options,
                target.descriptor(),
                &source(),
                Path::new(""),
                "vmmon",
                "vmmon",
                false,
            );
            let args = command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<_>>();
            assert!(args.contains(&"--locked".to_string()));
            assert!(args.contains(&"--release".to_string()));
            assert!(
                args.contains(&target.descriptor().rust_target.to_string())
                    || args.contains(
                        &target
                            .descriptor()
                            .zig_target
                            .unwrap_or_default()
                            .to_string()
                    )
            );
        }
    }

    #[test]
    fn netd_build_is_readonly_static_and_reproducible() {
        let root = Path::new("/workspace");
        let target = ReleaseTarget::LinuxAmd64Gnu;
        let options = options(target, root);
        let output = PathBuf::from("/workspace/target/netd");
        let command = build_netd_command(
            &options,
            target.descriptor(),
            &source(),
            Path::new(""),
            &output,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(args.contains(&"-mod=readonly".to_string()));
        assert!(args.contains(&"-trimpath".to_string()));
        assert!(args.contains(&"-s -w -buildid=".to_string()));
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "CGO_ENABLED")
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("0"))
        );
    }

    #[test]
    fn macos_netd_uses_external_linking_at_the_release_floor() {
        let root = Path::new("/workspace");
        let target = ReleaseTarget::DarwinArm64;
        let options = options(target, root);
        let command = build_netd_command(
            &options,
            target.descriptor(),
            &source(),
            Path::new("/AppleSDK"),
            Path::new("/workspace/target/netd"),
        );
        let flags = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .find(|arg| arg.contains("-linkmode=external"))
            .expect("external linker flags");
        assert!(flags.contains("-mmacosx-version-min=26.0"));
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "CGO_ENABLED")
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("1"))
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "CC")
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("/usr/bin/clang"))
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "SDKROOT")
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("/AppleSDK"))
        );
    }

    #[test]
    fn macos_rust_builds_use_a_clean_apple_system_toolchain() {
        let root = Path::new("/workspace");
        let target = ReleaseTarget::DarwinArm64;
        let command = build_rust_command(
            &options(target, root),
            target.descriptor(),
            &source(),
            Path::new("/AppleSDK"),
            "vmmon",
            "vmmon",
            false,
        );
        let environment = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            environment.get(std::ffi::OsStr::new(
                "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"
            )),
            Some(&std::ffi::OsStr::new("/usr/bin/clang"))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("CC_aarch64_apple_darwin")),
            Some(&std::ffi::OsStr::new("/usr/bin/clang"))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("SDKROOT")),
            Some(&std::ffi::OsStr::new("/AppleSDK"))
        );
        for variable in [
            "DEVELOPER_DIR",
            "NIX_CFLAGS_COMPILE",
            "NIX_CFLAGS_COMPILE_FOR_BUILD",
            "NIX_LDFLAGS",
            "NIX_LDFLAGS_FOR_BUILD",
        ] {
            assert!(command
                .get_envs()
                .any(|(name, value)| name == variable && value.is_none()));
        }
    }

    #[test]
    fn guest_stripping_uses_the_nix_llvm_wrapper() {
        let command = guest_strip_command(Path::new("target/guest"));
        assert_eq!(command.get_program(), "strip");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--strip-unneeded", "target/guest"]
        );
    }

    #[test]
    fn sha256_metadata_uses_oci_digest_form() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let file = temp.path().join("component");
        std::fs::write(&file, b"silo").expect("write component");
        let digest = sha256(&file).expect("hash component");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 71);
    }

    #[test]
    fn release_metadata_contains_only_logical_component_paths() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("create temp directory");
        let runtime = temp.path().join("runtime");
        for relative in [
            "bin/vmmon",
            "bin/netd",
            "bin/krun",
            "assets/kernel-default",
            "assets/initramfs",
            "assets/agent",
        ] {
            let path = runtime.join(relative);
            std::fs::create_dir_all(path.parent().expect("component parent"))
                .expect("create component parent");
            std::fs::write(&path, relative).expect("write component");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("set mode");
        }
        let cli = temp.path().join("silo");
        std::fs::write(&cli, b"silo").expect("write cli");
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755))
            .expect("set cli mode");
        let kernel = temp.path().join("kernel.json");
        std::fs::write(&kernel, b"{}\n").expect("write kernel provenance");
        let metadata = temp.path().join("release.json");

        write_release_metadata(
            &metadata,
            ReleaseTarget::DarwinArm64.descriptor(),
            &source(),
            &runtime,
            &cli,
            &kernel,
            &serde_json::json!({"schemaVersion": 1}),
        )
        .expect("write release metadata");

        let contents = std::fs::read_to_string(metadata).expect("read release metadata");
        assert!(!contents.contains(&temp.path().display().to_string()));
        assert!(contents.contains("runtime/bin/vmmon"));
        assert!(contents.contains("bin/silo"));
    }

    #[test]
    fn release_publication_exchanges_and_rolls_back_runtime() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let staged_runtime = temp.path().join("staged-runtime");
        let runtime = temp.path().join("runtime");
        let staged_release = temp.path().join("staged-release");
        let release = temp.path().join("release");
        for (path, marker) in [
            (&staged_runtime, "new"),
            (&runtime, "old"),
            (&staged_release, "release"),
        ] {
            std::fs::create_dir(path).expect("create publication directory");
            std::fs::write(path.join("marker"), marker).expect("write marker");
        }

        publish_release_transaction(&staged_runtime, &runtime, &staged_release, &release)
            .expect("publish release");
        assert_eq!(
            std::fs::read_to_string(runtime.join("marker")).expect("runtime"),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(staged_runtime.join("marker")).expect("old runtime"),
            "old"
        );
        assert_eq!(
            std::fs::read_to_string(release.join("marker")).expect("release"),
            "release"
        );

        let next_runtime = temp.path().join("next-runtime");
        let next_release = temp.path().join("next-release");
        std::fs::create_dir(&next_runtime).expect("create next runtime");
        std::fs::write(next_runtime.join("marker"), "next").expect("write next runtime");
        std::fs::create_dir(&next_release).expect("create next release");
        let error = publish_release_transaction(&next_runtime, &runtime, &next_release, &release)
            .expect_err("existing release must fail");
        assert!(error.to_string().contains("without replacing"));
        assert_eq!(
            std::fs::read_to_string(runtime.join("marker")).expect("runtime"),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(next_runtime.join("marker")).expect("next runtime"),
            "next"
        );
    }
}
