use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::components::{
    build_all, build_component, clippy, format, test, BuildContext, Component,
};
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::profiles::Profile;
use crate::targets::HostTarget;

mod command;
mod components;
mod initramfs;
mod profiles;
mod targets;
mod version;

#[derive(Debug, Parser)]
#[command(about = "Silo repository automation")]
struct Args {
    #[arg(long, global = true, value_name = "PATH")]
    target_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Build {
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
    },
    Component {
        #[arg(value_enum)]
        component: Component,
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
    },
    Kernel {
        #[arg(long, default_value = "stable")]
        track: String,
    },
    Fmt,
    Clippy,
    Test,
    VersionCheck,
    PackInitramfs {
        #[arg(long, value_name = "PATH")]
        init: PathBuf,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Debug, Error)]
enum XtaskError {
    #[error(transparent)]
    Initramfs(#[from] initramfs::InitramfsError),
    #[error("workspace root has no parent for xtask manifest path {path}")]
    MissingWorkspaceRoot { path: PathBuf },
    #[error("target directory is empty")]
    EmptyTargetDirectory,
}

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

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let workspace_root = workspace_root()?;
    let target_dir = target_directory(&workspace_root, args.target_dir)?;

    match args.command {
        Commands::Build { profile } => {
            let context = build_context(&workspace_root, &target_dir, profile)?;
            build_all(&context)?;
        }
        Commands::Component { component, profile } => {
            let context = build_context(&workspace_root, &target_dir, profile)?;
            build_component(component, &context)?;
        }
        Commands::Kernel { track } => {
            let context = build_context(&workspace_root, &target_dir, Profile::Debug)?;
            components::build_kernel(&context, &track)?;
        }
        Commands::Fmt => format(&workspace_root, &target_dir)?,
        Commands::Clippy => {
            let host = HostTarget::current()?;
            clippy(&workspace_root, &target_dir, host)?;
        }
        Commands::Test => {
            let host = HostTarget::current()?;
            test(&workspace_root, &target_dir, host)?;
        }
        Commands::VersionCheck => version::check(&workspace_root)?,
        Commands::PackInitramfs { init, out } => {
            write_initramfs(&InitramfsOptions::new(init, out))?;
        }
    }

    Ok(())
}

fn build_context<'a>(
    workspace_root: &'a Path,
    target_dir: &'a Path,
    profile: Profile,
) -> Result<BuildContext<'a>, Box<dyn Error>> {
    Ok(BuildContext {
        workspace_root,
        target_dir,
        profile,
        host: HostTarget::current()?,
    })
}

fn workspace_root() -> Result<PathBuf, XtaskError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(XtaskError::MissingWorkspaceRoot { path: manifest_dir })
}

fn target_directory(
    workspace_root: &Path,
    supplied: Option<PathBuf>,
) -> Result<PathBuf, XtaskError> {
    let target_dir = supplied
        .or_else(|| env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
        .unwrap_or_else(|| workspace_root.join("target"));

    if target_dir.as_os_str().is_empty() {
        return Err(XtaskError::EmptyTargetDirectory);
    }

    Ok(if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    })
}
