use std::fs;
use std::path::Path;
use std::process::Command;

use clap::ValueEnum;
use thiserror::Error;

use crate::command;
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::profiles::Profile;
use crate::release;
use crate::targets::HostTarget;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Component {
    Cli,
    Vmmon,
    Netd,
    Krun,
    Agent,
    Portd,
    Init,
    Initramfs,
    Rprobe,
    GoFfi,
}

pub struct BuildContext<'a> {
    pub workspace_root: &'a Path,
    pub target_dir: &'a Path,
    pub profile: Profile,
    pub host: HostTarget,
}

#[derive(Debug, Error)]
pub enum ComponentError {
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Initramfs(#[from] crate::initramfs::InitramfsError),
    #[error(transparent)]
    Release(#[from] release::ReleaseError),
    #[error(transparent)]
    Rprobe(#[from] crate::rprobe::RprobeError),
    #[error("failed to create output directory {path}")]
    CreateOutputDirectory {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("vmmon binary not found after build: {path}")]
    MissingVmmonBinary { path: std::path::PathBuf },
    #[error("krun binary not found after build: {path}")]
    MissingKrunBinary { path: std::path::PathBuf },
    #[error("rprobe must be built natively on Linux ARM64")]
    UnsupportedRprobeHost,
    #[error("macOS rprobe packaging requires --rprobe-binary with an owned AArch64 artifact")]
    MissingRprobeBinary,
    #[error("Linux ARM64 rprobe builds are native; --rprobe-binary is only supported on macOS")]
    UnsupportedLinuxRprobeBinary,
    #[error("--rprobe-binary is only valid for component rprobe")]
    UnexpectedRprobeBinary,
    #[error("--rprobe-kernel-provenance requires --rprobe-kernel")]
    MissingRprobeKernel,
    #[error("--rprobe-kernel requires --rprobe-kernel-provenance")]
    MissingRprobeKernelProvenance,
    #[error("failed to remove stale installed rprobe manifest {path}")]
    RemoveRprobeManifest {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn build_all(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    for component in [
        Component::Cli,
        Component::Vmmon,
        Component::Netd,
        Component::Krun,
        Component::Agent,
        Component::Init,
    ] {
        build_component(component, context)?;
    }
    Ok(())
}

pub fn build_component(
    component: Component,
    context: &BuildContext<'_>,
) -> Result<(), ComponentError> {
    build_component_with_rprobe_binary(component, context, None, None, None)
}

pub fn build_component_with_rprobe_binary(
    component: Component,
    context: &BuildContext<'_>,
    rprobe_binary: Option<&Path>,
    rprobe_kernel: Option<&Path>,
    rprobe_kernel_provenance: Option<&Path>,
) -> Result<(), ComponentError> {
    if (rprobe_binary.is_some() || rprobe_kernel.is_some() || rprobe_kernel_provenance.is_some())
        && !matches!(component, Component::Rprobe)
    {
        return Err(ComponentError::UnexpectedRprobeBinary);
    }
    match component {
        Component::Cli => build_cargo_package(context, "cli"),
        Component::Vmmon => build_vmmon(context),
        Component::Netd => build_netd(context),
        Component::Krun => build_krun(context),
        Component::Agent => build_guest_agent(context),
        Component::Portd => build_guest_portd(context),
        Component::Init => build_guest_init(context),
        Component::Initramfs => build_initramfs(context),
        Component::Rprobe => build_rprobe(
            context,
            rprobe_binary,
            rprobe_kernel,
            rprobe_kernel_provenance,
        ),
        Component::GoFfi => build_cargo_package(context, "silo-go-ffi"),
    }
}

pub fn format(workspace_root: &Path, target_dir: &Path) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args(["fmt", "--all", "--", "--check"]);
    command::run(cargo)?;

    let mut gofmt = Command::new("gofmt");
    gofmt
        .current_dir(workspace_root.join("net/netd"))
        .args(["-l", "."]);
    let output = command::output(gofmt)?;
    if output.stdout.is_empty() {
        Ok(())
    } else {
        Err(command::CommandError::FailedWithStderr {
            program: "gofmt".to_string(),
            status: "unformatted files".to_string(),
            stderr: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        })
    }
}

pub fn clippy(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args([
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--all-features",
    ]);
    for member in host.workspace_excludes() {
        cargo.args(["--exclude", member]);
    }
    command::run(cargo)?;

    let mut rprobe = standard_cargo_command(workspace_root, target_dir);
    rprobe.args([
        "clippy",
        "--locked",
        "-p",
        "rprobe",
        "--lib",
        "--no-default-features",
    ]);
    command::run(rprobe)
}

pub fn test_units(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args([
        "test",
        "--locked",
        "--workspace",
        "--lib",
        "--bins",
        "--all-features",
    ]);
    for member in host.workspace_excludes() {
        cargo.args(["--exclude", member]);
    }
    command::run(cargo)?;

    let mut rprobe = standard_cargo_command(workspace_root, target_dir);
    rprobe.args([
        "test",
        "--locked",
        "-p",
        "rprobe",
        "--lib",
        "--no-default-features",
    ]);
    command::run(rprobe)
}

pub fn test_integration(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args([
        "test",
        "--locked",
        "--workspace",
        "--test",
        "*",
        "--all-features",
    ]);
    for member in host.workspace_excludes() {
        cargo.args(["--exclude", member]);
    }
    command::run(cargo)?;

    let mut go = Command::new("go");
    go.current_dir(workspace_root.join("net/netd"))
        .args(["test", "./..."]);
    command::run(go)
}

fn build_cargo_package(context: &BuildContext<'_>, package: &str) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.args(["build", "--locked", "-p", package]);
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    Ok(())
}

fn build_vmmon(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    build_cargo_package(context, "vmmon")?;

    if context.host == HostTarget::MacosArm64 {
        let binary = context
            .target_dir
            .join(context.profile.directory())
            .join("vmmon");
        if !binary.is_file() {
            return Err(ComponentError::MissingVmmonBinary { path: binary });
        }

        let entitlements = context
            .workspace_root
            .join("runtime/vmmon/vmmon.entitlements");
        let mut sign = Command::new("/usr/bin/codesign");
        sign.args(["-f", "--entitlements"])
            .arg(entitlements)
            .args(["-s", "-"])
            .arg(&binary);
        command::run(sign)?;

        let mut verify = Command::new("/usr/bin/codesign");
        verify.args(["--verify", "--verbose=4"]).arg(binary);
        command::run(verify)?;
    }

    Ok(())
}

fn build_netd(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let output_dir = context.target_dir.join(context.profile.directory());
    fs::create_dir_all(&output_dir).map_err(|source| ComponentError::CreateOutputDirectory {
        path: output_dir.clone(),
        source,
    })?;

    let go_program = release::tool("go")?;
    let (goos, goarch) = context.host.go_target();
    let mut go = Command::new(&go_program);
    go.current_dir(context.workspace_root.join("net/netd"))
        .env("CARGO_TARGET_DIR", context.target_dir)
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .args(["build", "-mod=readonly"]);
    release::configure_command(&mut go, context.profile == Profile::Release)?;
    go.env("CARGO_TARGET_DIR", context.target_dir);
    context.profile.apply_go(&mut go);
    let output = output_dir.join("netd");
    go.args(["-o"]).arg(&output).arg("./cmd/netd");
    command::run(go)?;
    if context.profile == Profile::Release && context.host == HostTarget::MacosArm64 {
        release::set_macos_build_version(&output)?;
    }
    Ok(())
}

fn build_krun(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.args([
        "build",
        "--locked",
        "-p",
        "krun",
        "--features",
        "krun-bin",
        "--bin",
        "krun",
    ]);
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;

    let binary = context
        .target_dir
        .join(context.profile.directory())
        .join("krun");
    if !binary.is_file() {
        return Err(ComponentError::MissingKrunBinary { path: binary });
    }

    if context.host == HostTarget::MacosArm64 {
        let entitlements = context
            .workspace_root
            .join("packaging/macos/krun.entitlements");
        let mut sign = Command::new("/usr/bin/codesign");
        sign.args(["-f", "--entitlements"])
            .arg(entitlements)
            .args(["-s", "-"])
            .arg(&binary);
        command::run(sign)?;

        let mut verify = Command::new("/usr/bin/codesign");
        verify.args(["--verify", "--verbose=4"]).arg(&binary);
        command::run(verify)?;
    }

    let mut smoke = Command::new(binary);
    smoke.arg("--help");
    command::output(smoke)?;
    Ok(())
}

fn build_guest_agent(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.args([
        "zigbuild",
        "--locked",
        "-p",
        "agent",
        "--target",
        context.host.guest_target().triple(),
    ]);
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    Ok(())
}

fn build_guest_portd(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.args([
        "zigbuild",
        "--locked",
        "-p",
        "silo-portd",
        "--target",
        context.host.guest_target().triple(),
    ]);
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    Ok(())
}

fn build_guest_init(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.args([
        "zigbuild",
        "--locked",
        "-p",
        "init",
        "--target",
        context.host.guest_target().triple(),
    ]);
    release::configure_guest_init_command(&mut cargo, context.profile == Profile::Release);
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    Ok(())
}

fn build_rprobe(
    context: &BuildContext<'_>,
    supplied_binary: Option<&Path>,
    kernel: Option<&Path>,
    kernel_provenance: Option<&Path>,
) -> Result<(), ComponentError> {
    let binary = match rprobe_binary_source(context.host, supplied_binary)? {
        RprobeBinarySource::NativeBuild => {
            let mut cargo = cargo_command(context)?;
            cargo.args([
                "build",
                "--locked",
                "-p",
                "rprobe",
                "--features",
                "probe-bin",
                "--bin",
                "silo-rprobe",
                "--target",
                "aarch64-unknown-linux-musl",
            ]);
            release::configure_guest_init_command(&mut cargo, context.profile == Profile::Release);
            context.profile.apply_cargo(&mut cargo);
            command::run(cargo)?;
            context
                .target_dir
                .join("aarch64-unknown-linux-musl")
                .join(context.profile.directory())
                .join("silo-rprobe")
        }
        RprobeBinarySource::Supplied(path) => path.to_path_buf(),
    };
    let assets = context
        .target_dir
        .join(context.profile.directory())
        .join("assets");
    match (kernel, kernel_provenance) {
        (Some(kernel), Some(provenance)) => {
            crate::rprobe::package_assets(&binary, kernel, provenance, &assets)?
        }
        (None, None) => {
            let manifest = assets.join("rprobe.json");
            match fs::remove_file(&manifest) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(ComponentError::RemoveRprobeManifest {
                        path: manifest,
                        source,
                    })
                }
            }
            crate::rprobe::package(&binary, &assets.join("rprobe-initramfs"))?
        }
        (Some(_), None) => return Err(ComponentError::MissingRprobeKernelProvenance),
        (None, Some(_)) => return Err(ComponentError::MissingRprobeKernel),
    }
    Ok(())
}

enum RprobeBinarySource<'a> {
    NativeBuild,
    Supplied(&'a Path),
}

fn rprobe_binary_source(
    host: HostTarget,
    supplied_binary: Option<&Path>,
) -> Result<RprobeBinarySource<'_>, ComponentError> {
    match (host, supplied_binary) {
        (HostTarget::LinuxArm64, None) => Ok(RprobeBinarySource::NativeBuild),
        (HostTarget::LinuxArm64, Some(_)) => Err(ComponentError::UnsupportedLinuxRprobeBinary),
        (HostTarget::MacosArm64, Some(path)) => Ok(RprobeBinarySource::Supplied(path)),
        (HostTarget::MacosArm64, None) => Err(ComponentError::MissingRprobeBinary),
        (HostTarget::LinuxX86_64, _) => Err(ComponentError::UnsupportedRprobeHost),
    }
}

fn build_initramfs(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    build_guest_init(context)?;
    let init = context
        .target_dir
        .join(context.host.guest_target().triple())
        .join(context.profile.directory())
        .join("init");
    let output = context
        .target_dir
        .join(context.profile.directory())
        .join("assets/initramfs");
    write_initramfs(&InitramfsOptions::new(init, output))?;
    Ok(())
}

fn cargo_command(context: &BuildContext<'_>) -> Result<Command, ComponentError> {
    let cargo_program = release::tool("cargo")?;
    let mut cargo = Command::new(&cargo_program);
    cargo
        .current_dir(context.workspace_root)
        .env("CARGO_TARGET_DIR", context.target_dir);
    release::configure_command(&mut cargo, context.profile == Profile::Release)?;
    cargo.env("CARGO_TARGET_DIR", context.target_dir);
    Ok(cargo)
}

fn standard_cargo_command(workspace_root: &Path, target_dir: &Path) -> Command {
    let mut cargo = Command::new("cargo");
    cargo
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", target_dir);
    cargo
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::components::{rprobe_binary_source, ComponentError, RprobeBinarySource};
    use crate::targets::HostTarget;

    #[test]
    fn rprobe_binary_selection_is_host_explicit() {
        assert!(matches!(
            rprobe_binary_source(HostTarget::LinuxArm64, None),
            Ok(RprobeBinarySource::NativeBuild)
        ));
        assert!(matches!(
            rprobe_binary_source(HostTarget::LinuxArm64, Some(Path::new("owned-rprobe"))),
            Err(ComponentError::UnsupportedLinuxRprobeBinary)
        ));
        assert!(matches!(
            rprobe_binary_source(HostTarget::MacosArm64, Some(Path::new("owned-rprobe"))),
            Ok(RprobeBinarySource::Supplied(path)) if path == Path::new("owned-rprobe")
        ));
        assert!(matches!(
            rprobe_binary_source(HostTarget::MacosArm64, None),
            Err(ComponentError::MissingRprobeBinary)
        ));
        assert!(matches!(
            rprobe_binary_source(HostTarget::LinuxX86_64, None),
            Err(ComponentError::UnsupportedRprobeHost)
        ));
    }
}
