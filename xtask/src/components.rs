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
    Init,
    Initramfs,
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
    #[error("failed to create output directory {path}")]
    CreateOutputDirectory {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("vmmon binary not found after build: {path}")]
    MissingVmmonBinary { path: std::path::PathBuf },
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
    match component {
        Component::Cli => build_cargo_package(context, "cli"),
        Component::Vmmon => build_vmmon(context),
        Component::Netd => build_netd(context),
        Component::Krun => build_krun(context),
        Component::Agent => build_guest_agent(context),
        Component::Init => build_guest_init(context),
        Component::Initramfs => build_initramfs(context),
    }
}

pub fn format(workspace_root: &Path, target_dir: &Path) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args(["fmt", "--all", "--", "--check"]);
    command::run(cargo)
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
    command::run(cargo)
}

pub fn test(
    workspace_root: &Path,
    target_dir: &Path,
    host: HostTarget,
) -> Result<(), command::CommandError> {
    let mut cargo = standard_cargo_command(workspace_root, target_dir);
    cargo.args([
        "test",
        "--locked",
        "--workspace",
        "--all-targets",
        "--all-features",
    ]);
    for member in host.workspace_excludes() {
        cargo.args(["--exclude", member]);
    }
    command::run(cargo)
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

    let go_program = release::go_program(context.target_dir, context.profile == Profile::Release)?;
    let mut go = Command::new(&go_program);
    go.current_dir(context.workspace_root.join("net/netd"))
        .env("CARGO_TARGET_DIR", context.target_dir)
        .args(["build", "-mod=readonly"]);
    release::configure_command(
        &mut go,
        context.profile == Profile::Release,
        &go_program,
        context.workspace_root,
        context.target_dir,
    )?;
    go.env("CARGO_TARGET_DIR", context.target_dir);
    context.profile.apply_go(&mut go);
    go.args(["-o"])
        .arg(output_dir.join("netd"))
        .arg("./cmd/netd");
    command::run(go)?;
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

fn build_guest_init(context: &BuildContext<'_>) -> Result<(), ComponentError> {
    let mut cargo = cargo_command(context)?;
    cargo.env("RUSTFLAGS", "-C panic=abort").args([
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
    let cargo_program = release::tool("cargo", context.profile == Profile::Release)?;
    let mut cargo = Command::new(&cargo_program);
    cargo
        .current_dir(context.workspace_root)
        .env("CARGO_TARGET_DIR", context.target_dir);
    release::configure_command(
        &mut cargo,
        context.profile == Profile::Release,
        &cargo_program,
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
