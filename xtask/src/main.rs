use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::components::{
    build_all, build_component, clippy, format, test, BuildContext, Component,
};
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::kernel::KernelOptions;
use crate::profiles::Profile;
use crate::targets::HostTarget;

mod command;
mod components;
mod initramfs;
mod kernel;
mod profiles;
mod release;
mod release_audit;
mod runtime;
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
        #[command(flatten)]
        kernel: KernelOptions,
    },
    Component {
        #[arg(value_enum)]
        component: Component,
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
    },
    Kernel {
        #[command(flatten)]
        kernel: KernelOptions,
    },
    Stage {
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
        #[command(flatten)]
        kernel: KernelOptions,
    },
    VerifyRuntime {
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
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
        Commands::Build { profile, kernel } => {
            build_release_or_development(&workspace_root, &target_dir, profile, kernel, false)?;
        }
        Commands::Component { component, profile } => {
            let component_target = if profile == Profile::Release {
                clean_release_target(&target_dir)?
            } else {
                target_dir.clone()
            };
            let context = build_context(&workspace_root, &component_target, profile)?;
            build_component(component, &context)?;
        }
        Commands::Kernel { kernel } => {
            let context = build_context(&workspace_root, &target_dir, Profile::Debug)?;
            let kernel = kernel::resolve(&context, &kernel)?;
            println!("{}", kernel.path.display());
        }
        Commands::Stage { profile, kernel } => {
            build_release_or_development(&workspace_root, &target_dir, profile, kernel, true)?;
        }
        Commands::VerifyRuntime { profile } => {
            release_audit::verify(&workspace_root, &target_dir, profile)?
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

fn build_release_or_development(
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
    kernel_options: KernelOptions,
    stage: bool,
) -> Result<(), Box<dyn Error>> {
    if profile == Profile::Debug {
        let context = build_context(workspace_root, target_dir, profile)?;
        build_all(&context)?;
        let kernel = kernel::resolve(&context, &kernel_options)?;
        runtime::assemble_development(&context, &kernel)?;
        if stage {
            runtime::stage(&context)?;
        }
        return Ok(());
    }

    let clean_target = clean_release_target(target_dir)?;
    let clean = build_context(workspace_root, &clean_target, profile)?;
    build_all(&clean)?;
    let kernel = kernel::resolve(&clean, &kernel_options)?;
    runtime::assemble_development(&clean, &kernel)?;

    let public = build_context(workspace_root, target_dir, profile)?;
    runtime::publish_adjacent(&clean, &public)?;
    if stage {
        runtime::stage(&public)?;
    }
    Ok(())
}

fn clean_release_target(target_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let host = HostTarget::current()?;
    let clean_target = target_dir.join("release-build").join(host.runtime_target());
    if clean_target.exists() {
        fs::remove_dir_all(&clean_target)?;
    }
    fs::create_dir_all(&clean_target)?;
    Ok(clean_target)
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

    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    };

    Ok(target_dir)
}
