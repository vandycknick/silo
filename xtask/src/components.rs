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
    Silod,
    SiloVmm,
    Netd,
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
    #[error("silo-vmm binary not found after build: {path}")]
    MissingVmmBinary { path: std::path::PathBuf },
    #[error("rprobe must be built natively on Linux ARM64")]
    UnsupportedRprobeHost,
}

pub fn build_all(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    for component in [
        Component::Cli,
        Component::Silod,
        Component::SiloVmm,
        Component::Netd,
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
    match component {
        Component::Cli => build_cargo_package(context, "cli"),
        Component::Silod => build_cargo_package(context, "silod"),
        Component::SiloVmm => build_vmm(context),
        Component::Netd => build_netd(context),
        Component::Agent => build_guest_agent(context),
        Component::Portd => build_guest_portd(context),
        Component::Init => build_guest_init(context),
        Component::Initramfs => build_initramfs(context),
        Component::Rprobe => build_rprobe(context),
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

fn build_vmm(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    build_cargo_package(context, "silo-vmm")?;

    if context.host == HostTarget::MacosArm64 {
        let binary = context
            .target_dir
            .join(context.profile.directory())
            .join("silo-vmm");
        if !binary.is_file() {
            return Err(ComponentError::MissingVmmBinary { path: binary });
        }

        let entitlements = context
            .workspace_root
            .join("virt/vmm/silo-vmm.entitlements");
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

    let go_program = release::go_program(context.profile == Profile::Release)?;
    let (goos, goarch) = context.host.go_target();
    let mut go = Command::new(&go_program);
    go.current_dir(context.workspace_root.join("net/netd"))
        .env("CARGO_TARGET_DIR", context.target_dir)
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .args(["build", "-mod=readonly"]);
    release::configure_command(
        &mut go,
        context.profile == Profile::Release,
        context.workspace_root,
        context.target_dir,
    )?;
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
    release::configure_guest_init_command(
        &mut cargo,
        context.profile == Profile::Release,
        context.workspace_root,
        context.target_dir,
    );
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    Ok(())
}

fn build_rprobe(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    if context.host != HostTarget::LinuxArm64 {
        return Err(ComponentError::UnsupportedRprobeHost);
    }
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
    release::configure_guest_init_command(
        &mut cargo,
        context.profile == Profile::Release,
        context.workspace_root,
        context.target_dir,
    );
    context.profile.apply_cargo(&mut cargo);
    command::run(cargo)?;
    let binary = context
        .target_dir
        .join("aarch64-unknown-linux-musl")
        .join(context.profile.directory())
        .join("silo-rprobe");
    let profile = context.target_dir.join(context.profile.directory());
    crate::rprobe::build_kernel(
        context.workspace_root,
        &binary,
        &profile.join("rprobe-build"),
        &profile.join("assets"),
    )?;
    Ok(())
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
    release::configure_command(
        &mut cargo,
        context.profile == Profile::Release,
        context.workspace_root,
        context.target_dir,
    )?;
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
    use crate::components::{build_rprobe, BuildContext, ComponentError};
    use crate::profiles::Profile;
    use crate::targets::HostTarget;
    use std::path::Path;

    #[test]
    fn probe_build_requires_native_linux_arm64() {
        for host in [HostTarget::MacosArm64, HostTarget::LinuxX86_64] {
            let context = BuildContext {
                workspace_root: Path::new("."),
                target_dir: Path::new("target"),
                profile: Profile::Debug,
                host,
            };
            assert!(matches!(
                build_rprobe(&context),
                Err(ComponentError::UnsupportedRprobeHost)
            ));
        }
    }
}
