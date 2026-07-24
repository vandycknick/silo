use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::kernel_oci::{resolve_kernel, ResolveKernelOptions};
use crate::release_target::{BuildProfile, ReleaseTarget};
use crate::stage_runtime::{stage_runtime, StageRuntimeOptions};

mod initramfs;
mod kernel_oci;
mod release_target;
mod stage_runtime;

#[cfg(target_arch = "x86_64")]
const DEFAULT_GUEST_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(target_arch = "aarch64")]
const DEFAULT_GUEST_TARGET: &str = "aarch64-unknown-linux-musl";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("xtask guest assets support only x86_64 and aarch64 hosts");
#[derive(Debug, Parser)]
#[command(about = "Silo repository automation")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    GuestAssets(GuestAssetsArgs),
    PackInitramfs(PackInitramfsArgs),
    ReleaseTarget(ReleaseTargetArgs),
    ResolveKernel(ResolveKernelArgs),
    StageRuntime(StageRuntimeArgs),
    SignVmmon(SignVmmonArgs),
}

#[derive(Debug, Parser)]
#[command(about = "Build guest binaries and package initramfs assets")]
struct GuestAssetsArgs {
    #[arg(long, default_value = DEFAULT_GUEST_TARGET)]
    target: String,
    #[arg(long, value_name = "PATH")]
    assets_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    target_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(about = "Package a gzip-compressed newc initramfs archive")]
struct PackInitramfsArgs {
    #[arg(long, value_name = "PATH")]
    init: PathBuf,
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
}

#[derive(Debug, Parser)]
#[command(about = "Print the canonical release target descriptor")]
struct ReleaseTargetArgs {
    #[arg(long, value_enum)]
    target: ReleaseTarget,
    #[arg(long, value_enum, default_value_t = BuildProfile::Release)]
    profile: BuildProfile,
}

#[derive(Debug, Parser)]
#[command(about = "Stage the validated canonical Silo runtime payload")]
struct StageRuntimeArgs {
    #[arg(long, value_enum)]
    target: ReleaseTarget,
    #[arg(long, value_enum, default_value_t = BuildProfile::Release)]
    profile: BuildProfile,
    #[arg(long, value_name = "PATH")]
    kernel: PathBuf,
}

#[derive(Debug, Parser)]
#[command(about = "Resolve and verify a Silo kernel OCI artifact")]
struct ResolveKernelArgs {
    #[arg(long, value_enum)]
    target: ReleaseTarget,
    #[arg(long, value_name = "REFERENCE")]
    reference: String,
    #[arg(long, value_name = "PATH")]
    oci_layout: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    output_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(about = "Ad-hoc sign the vmmon binary on macOS")]
struct SignVmmonArgs {
    #[arg(value_name = "PATH")]
    binary: PathBuf,
}

#[derive(Debug, Error)]
enum XtaskError {
    #[error(transparent)]
    Initramfs(#[from] initramfs::InitramfsError),
    #[error(transparent)]
    StageRuntime(#[from] stage_runtime::StageRuntimeError),
    #[error(transparent)]
    ResolveKernel(#[from] kernel_oci::ResolveKernelError),
    #[error("workspace root has no parent for xtask manifest path {path}")]
    MissingWorkspaceRoot { path: PathBuf },
    #[error("guest binary not found after build: {path}")]
    MissingGuestBinary { path: PathBuf },
    #[error("vmmon binary not found: {path}")]
    MissingVmmonBinary { path: PathBuf },
    #[error("failed to create asset directory {path}")]
    CreateAssetDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to remove existing asset {path}")]
    RemoveExistingAsset {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to copy {from} to {to}")]
    CopyAsset {
        from: PathBuf,
        to: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read release package manifest {path}")]
    ReadReleasePackageManifest {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse release package manifest {path}")]
    ParseReleasePackageManifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("release package manifest {path} has no string version")]
    MissingReleasePackageVersion { path: PathBuf },
    #[error("release package version mismatch in {path}: expected {expected}, found {actual}")]
    ReleasePackageVersionMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("failed to run {program}")]
    RunCommand {
        program: String,
        source: std::io::Error,
    },
    #[error("{program} failed with status {status}")]
    CommandFailed { program: String, status: String },
}

type Result<T> = std::result::Result<T, XtaskError>;

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        let mut source = error.source();
        while let Some(error) = source {
            eprintln!("  caused by: {error}");
            source = error.source();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Args::parse().command {
        Commands::GuestAssets(args) => guest_assets(args),
        Commands::PackInitramfs(args) => pack_initramfs(args),
        Commands::ReleaseTarget(args) => {
            validate_release_versions()?;
            print!("{}", release_target_output(args, &target_dir()?));
            Ok(())
        }
        Commands::ResolveKernel(args) => {
            validate_release_versions()?;
            let target_dir = target_dir()?;
            let output_dir = args.output_dir.unwrap_or_else(|| {
                target_dir
                    .join("release-inputs")
                    .join(args.target.descriptor().name)
            });
            let resolved = resolve_kernel(&ResolveKernelOptions {
                target: args.target,
                reference: args.reference,
                oci_layout: args.oci_layout,
                output_dir,
            })?;
            println!("kernel={}", resolved.kernel.display());
            println!("provenance={}", resolved.provenance.display());
            Ok(())
        }
        Commands::StageRuntime(args) => {
            validate_release_versions()?;
            let target_dir = target_dir()?;
            let stage_dir = stage_runtime(&StageRuntimeOptions {
                target: args.target,
                profile: args.profile,
                kernel: args.kernel,
                target_dir,
            })?;
            println!("{}", stage_dir.display());
            Ok(())
        }
        Commands::SignVmmon(args) => sign_vmmon(args),
    }
}

fn validate_release_versions() -> Result<()> {
    let node_package = workspace_root()?.join("sdk/node/package.json");
    validate_package_version(&node_package, env!("CARGO_PKG_VERSION"))
}

fn validate_package_version(path: &Path, expected: &str) -> Result<()> {
    let contents =
        fs::read_to_string(path).map_err(|source| XtaskError::ReadReleasePackageManifest {
            path: path.to_path_buf(),
            source,
        })?;
    let manifest: serde_json::Value = serde_json::from_str(&contents).map_err(|source| {
        XtaskError::ParseReleasePackageManifest {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let actual = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| XtaskError::MissingReleasePackageVersion {
            path: path.to_path_buf(),
        })?;
    if actual == expected {
        return Ok(());
    }

    Err(XtaskError::ReleasePackageVersionMismatch {
        path: path.to_path_buf(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn release_target_output(args: ReleaseTargetArgs, target_dir: &Path) -> String {
    let descriptor = args.target.descriptor();
    format!(
        concat!(
            "release_version={}\n",
            "silo_target={}\n",
            "rust_target={}\n",
            "zig_target={}\n",
            "glibc_baseline={}\n",
            "macos_minimum_version={}\n",
            "guest_target={}\n",
            "goos={}\n",
            "goarch={}\n",
            "oci_platform={}\n",
            "npm_os={}\n",
            "npm_cpu={}\n",
            "npm_libc={}\n",
            "deb_arch={}\n",
            "rpm_arch={}\n",
            "archlinux_arch={}\n",
            "stage_dir={}\n",
        ),
        env!("CARGO_PKG_VERSION"),
        descriptor.name,
        descriptor.rust_target,
        descriptor.zig_target.unwrap_or_default(),
        descriptor.glibc_baseline.unwrap_or_default(),
        descriptor.macos_minimum_version.unwrap_or_default(),
        descriptor.guest_target,
        descriptor.goos,
        descriptor.goarch,
        descriptor.oci_platform,
        descriptor.npm_os,
        descriptor.npm_cpu,
        descriptor.npm_libc.unwrap_or_default(),
        descriptor.deb_arch,
        descriptor.rpm_arch,
        descriptor.archlinux_arch,
        descriptor.stage_dir_in(target_dir, args.profile).display(),
    )
}

fn target_dir() -> Result<PathBuf> {
    Ok(env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or(workspace_root()?.join("target")))
}

fn guest_assets(args: GuestAssetsArgs) -> Result<()> {
    let workspace_root = workspace_root()?;
    let target_dir = args
        .target_dir
        .or_else(|| env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
        .unwrap_or_else(|| workspace_root.join("target"));
    let assets_dir = args
        .assets_dir
        .unwrap_or_else(|| target_dir.join("resources/assets"));

    build_guest_init(&args.target)?;
    build_guest_agent(&args.target)?;

    fs::create_dir_all(&assets_dir).map_err(|source| XtaskError::CreateAssetDirectory {
        path: assets_dir.clone(),
        source,
    })?;

    let guest_bin_dir = target_dir.join(&args.target).join("release");
    let init_binary = guest_bin_dir.join("init");
    let agent_binary = guest_bin_dir.join("silo-agent");
    ensure_file(&init_binary)?;
    ensure_file(&agent_binary)?;

    copy_asset(&init_binary, &assets_dir.join("init"))?;
    copy_asset(&agent_binary, &assets_dir.join("agent"))?;

    let initramfs = assets_dir.join("initramfs");
    remove_existing(&assets_dir.join("initramfs-no-agent"))?;
    remove_existing(&initramfs)?;
    write_initramfs(&InitramfsOptions::new(&init_binary, &initramfs))?;

    println!("Updated {}", assets_dir.display());
    Ok(())
}

fn build_guest_init(target: &str) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .env("RUSTFLAGS", "-C panic=abort")
        .arg("zigbuild")
        .arg("-p")
        .arg("init")
        .arg("--target")
        .arg(target)
        .arg("--release");
    run_command(command)
}

fn build_guest_agent(target: &str) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .arg("zigbuild")
        .arg("-p")
        .arg("agent")
        .arg("--target")
        .arg(target)
        .arg("--release");
    run_command(command)
}

fn pack_initramfs(args: PackInitramfsArgs) -> Result<()> {
    write_initramfs(&InitramfsOptions::new(args.init, args.out))?;
    Ok(())
}

fn sign_vmmon(args: SignVmmonArgs) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    if !args.binary.is_file() {
        return Err(XtaskError::MissingVmmonBinary { path: args.binary });
    }

    let entitlements = workspace_root()?.join("runtime/vmmon/vmmon.entitlements");
    let mut sign = Command::new("/usr/bin/codesign");
    sign.arg("-f")
        .arg("--entitlements")
        .arg(entitlements)
        .arg("-s")
        .arg("-")
        .arg(&args.binary);
    run_command(sign)?;

    let mut verify = Command::new("/usr/bin/codesign");
    verify.arg("--verify").arg("--verbose=4").arg(args.binary);
    run_command(verify)
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(XtaskError::MissingWorkspaceRoot { path: manifest_dir })
}

fn ensure_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(XtaskError::MissingGuestBinary {
            path: path.to_path_buf(),
        })
    }
}

fn copy_asset(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).map_err(|error| XtaskError::CopyAsset {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: error,
    })?;
    println!("Updated {}", destination.display());
    Ok(())
}

fn remove_existing(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|source| XtaskError::RemoveExistingAsset {
        path: path.to_path_buf(),
        source,
    })
}

fn run_command(mut command: Command) -> Result<()> {
    let program = command.get_program().to_string_lossy().to_string();
    let status = command.status().map_err(|source| XtaskError::RunCommand {
        program: program.clone(),
        source,
    })?;
    ensure_success(&program, status)
}

fn ensure_success(program: &str, status: ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }

    Err(XtaskError::CommandFailed {
        program: program.to_string(),
        status: status_text(status),
    })
}

fn status_text(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated by signal".to_string())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::release_target::{BuildProfile, ReleaseTarget};
    use crate::{
        release_target_output, validate_package_version, Args, Commands, ReleaseTargetArgs,
        XtaskError,
    };

    #[test]
    fn release_target_command_defaults_to_release_profile() {
        let args = Args::try_parse_from(["xtask", "release-target", "--target", "darwin-arm64"])
            .expect("parse release-target command");

        let Commands::ReleaseTarget(args) = args.command else {
            panic!("expected release-target command");
        };
        assert_eq!(args.target, ReleaseTarget::DarwinArm64);
        assert_eq!(args.profile, BuildProfile::Release);
    }

    #[test]
    fn release_target_output_is_stable() {
        let output = release_target_output(
            ReleaseTargetArgs {
                target: ReleaseTarget::DarwinArm64,
                profile: BuildProfile::Debug,
            },
            std::path::Path::new("target"),
        );

        assert_eq!(
            output,
            concat!(
                "release_version=0.1.0\n",
                "silo_target=darwin-arm64\n",
                "rust_target=aarch64-apple-darwin\n",
                "zig_target=\n",
                "glibc_baseline=\n",
                "macos_minimum_version=26.0\n",
                "guest_target=aarch64-unknown-linux-musl\n",
                "goos=darwin\n",
                "goarch=arm64\n",
                "oci_platform=linux/arm64\n",
                "npm_os=darwin\n",
                "npm_cpu=arm64\n",
                "npm_libc=\n",
                "deb_arch=arm64\n",
                "rpm_arch=aarch64\n",
                "archlinux_arch=aarch64\n",
                "stage_dir=target/silo-runtime/darwin-arm64/debug\n",
            )
        );
    }

    #[test]
    fn stage_runtime_command_requires_kernel_and_defaults_to_release() {
        assert!(
            Args::try_parse_from(["xtask", "stage-runtime", "--target", "linux-amd64-gnu"])
                .is_err()
        );

        let args = Args::try_parse_from([
            "xtask",
            "stage-runtime",
            "--target",
            "linux-amd64-gnu",
            "--kernel",
            "/tmp/vmlinux",
        ])
        .expect("parse stage-runtime command");
        let Commands::StageRuntime(args) = args.command else {
            panic!("expected stage-runtime command");
        };
        assert_eq!(args.target, ReleaseTarget::LinuxAmd64Gnu);
        assert_eq!(args.profile, BuildProfile::Release);
        assert_eq!(args.kernel, std::path::PathBuf::from("/tmp/vmlinux"));
    }

    #[test]
    fn resolve_kernel_command_requires_an_explicit_reference() {
        assert!(
            Args::try_parse_from(["xtask", "resolve-kernel", "--target", "darwin-arm64"]).is_err()
        );
        let args = Args::try_parse_from([
            "xtask",
            "resolve-kernel",
            "--target",
            "darwin-arm64",
            "--reference",
            "ghcr.io/example/silo/kernel:stable",
            "--output-dir",
            "/tmp/kernel",
        ])
        .expect("parse resolve-kernel command");
        let Commands::ResolveKernel(args) = args.command else {
            panic!("expected resolve-kernel command");
        };
        assert_eq!(args.target, ReleaseTarget::DarwinArm64);
        assert_eq!(args.reference, "ghcr.io/example/silo/kernel:stable");
        assert_eq!(
            args.output_dir,
            Some(std::path::PathBuf::from("/tmp/kernel"))
        );
    }

    #[test]
    fn package_version_must_match_release_version() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let package = temp.path().join("package.json");
        std::fs::write(&package, r#"{"version":"1.2.3"}"#).expect("write package manifest");

        validate_package_version(&package, "1.2.3").expect("matching version");
        let error = validate_package_version(&package, "1.2.4").expect_err("version mismatch");
        assert!(matches!(
            error,
            XtaskError::ReleasePackageVersionMismatch {
                expected,
                actual,
                ..
            } if expected == "1.2.4" && actual == "1.2.3"
        ));
    }

    #[test]
    fn package_version_must_be_a_string() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let package = temp.path().join("package.json");
        std::fs::write(&package, r#"{"name":"silo"}"#).expect("write package manifest");

        let error = validate_package_version(&package, "1.2.3").expect_err("missing version");
        assert!(matches!(
            error,
            XtaskError::MissingReleasePackageVersion { .. }
        ));
    }
}
