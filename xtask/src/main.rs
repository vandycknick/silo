use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::initramfs::{write_initramfs, InitramfsOptions};

mod initramfs;

const DEFAULT_GUEST_TARGET: &str = "aarch64-unknown-linux-musl";
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
#[command(about = "Ad-hoc sign the vmmon binary on macOS")]
struct SignVmmonArgs {
    #[arg(value_name = "PATH")]
    binary: PathBuf,
}

#[derive(Debug, Error)]
enum XtaskError {
    #[error(transparent)]
    Initramfs(#[from] initramfs::InitramfsError),
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
        Commands::SignVmmon(args) => sign_vmmon(args),
    }
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
