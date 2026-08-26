use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::components::{
    build_all, build_component, clippy, format, test_integration, test_units, BuildContext,
    Component,
};
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::kernel::KernelOptions;
use crate::profiles::Profile;
use crate::targets::HostTarget;

mod app;
mod archive;
mod command;
mod components;
mod go_sdk;
mod initramfs;
mod kernel;
mod macos;
mod profiles;
mod release;
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
    Archive {
        #[command(flatten)]
        kernel: KernelOptions,
    },
    App {
        #[arg(long, value_name = "NUMBER")]
        build_number: Option<String>,
        #[arg(long, value_name = "IDENTITY")]
        developer_id_application: Option<String>,
        #[command(flatten)]
        kernel: KernelOptions,
    },
    Package {
        #[arg(long, help = "Also create a DMG")]
        dmg: bool,
        #[arg(long, value_name = "NUMBER")]
        build_number: Option<String>,
        #[arg(long, value_name = "IDENTITY")]
        developer_id_application: Option<String>,
        #[command(flatten)]
        kernel: KernelOptions,
    },
    Install {
        #[arg(long, value_name = "PATH", default_value = "/Applications")]
        appdir: PathBuf,
        #[arg(long, value_name = "PATH", default_value = "/usr/local/bin")]
        bindir: PathBuf,
        #[arg(long, value_name = "NUMBER")]
        build_number: Option<String>,
        #[arg(long, value_name = "IDENTITY")]
        developer_id_application: Option<String>,
        #[command(flatten)]
        kernel: KernelOptions,
    },
    Fmt,
    Clippy,
    Test,
    TestUnit,
    TestIntegration,
    VersionCheck,
    AssembleGoSdk {
        #[arg(long, value_name = "PATH")]
        packages_root: Option<PathBuf>,
    },
    GoSdkExample {
        #[arg(value_name = "NAME", default_value = "basic")]
        example: String,
        #[arg(long, value_enum, default_value_t = Profile::Debug)]
        profile: Profile,
        #[command(flatten)]
        kernel: KernelOptions,
    },
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
            let context = build_context(&workspace_root, &target_dir, profile)?;
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
        Commands::Archive { kernel } => {
            build_release_or_development(
                &workspace_root,
                &target_dir,
                Profile::Release,
                kernel,
                true,
            )?;
            archive::produce(&workspace_root, &target_dir)?;
        }
        Commands::App {
            build_number,
            developer_id_application,
            kernel,
        } => {
            let host = HostTarget::current()?;
            if host != HostTarget::MacosArm64 {
                return Err(app::AppError::UnsupportedHost.into());
            }
            build_release_or_development(
                &workspace_root,
                &target_dir,
                Profile::Release,
                kernel,
                true,
            )?;
            app::assemble(
                &workspace_root,
                &target_dir,
                build_number.as_deref(),
                developer_id_application.as_deref(),
            )?;
        }
        Commands::Package {
            dmg,
            build_number,
            developer_id_application,
            kernel,
        } => {
            require_macos_arm64()?;
            build_release_or_development(
                &workspace_root,
                &target_dir,
                Profile::Release,
                kernel,
                true,
            )?;
            app::assemble(
                &workspace_root,
                &target_dir,
                build_number.as_deref(),
                developer_id_application.as_deref(),
            )?;
            if dmg {
                macos::package(
                    &workspace_root,
                    &target_dir,
                    developer_id_application.as_deref(),
                )?;
            }
        }
        Commands::Install {
            appdir,
            bindir,
            build_number,
            developer_id_application,
            kernel,
        } => {
            require_macos_arm64()?;
            build_release_or_development(
                &workspace_root,
                &target_dir,
                Profile::Release,
                kernel,
                true,
            )?;
            app::assemble(
                &workspace_root,
                &target_dir,
                build_number.as_deref(),
                developer_id_application.as_deref(),
            )?;
            macos::install(&workspace_root, &target_dir, &appdir, &bindir)?;
        }
        Commands::Fmt => format(&workspace_root, &target_dir)?,
        Commands::Clippy => {
            let host = HostTarget::current()?;
            clippy(&workspace_root, &target_dir, host)?;
        }
        Commands::Test => {
            let host = HostTarget::current()?;
            test_units(&workspace_root, &target_dir, host)?;
            test_integration(&workspace_root, &target_dir, host)?;
        }
        Commands::TestUnit => {
            let host = HostTarget::current()?;
            test_units(&workspace_root, &target_dir, host)?;
        }
        Commands::TestIntegration => {
            let host = HostTarget::current()?;
            test_integration(&workspace_root, &target_dir, host)?;
        }
        Commands::VersionCheck => version::check(&workspace_root)?,
        Commands::AssembleGoSdk { packages_root } => {
            let packages_root = packages_root
                .map(|path| {
                    if path.is_absolute() {
                        path
                    } else {
                        workspace_root.join(path)
                    }
                })
                .unwrap_or_else(|| target_dir.join("packages"));
            go_sdk::assemble(&workspace_root, &packages_root)?;
        }
        Commands::GoSdkExample {
            example,
            profile,
            kernel,
        } => {
            build_release_or_development(&workspace_root, &target_dir, profile, kernel, true)?;
            let context = build_context(&workspace_root, &target_dir, profile)?;
            build_component(Component::GoFfi, &context)?;
            go_sdk::run_example(&context, &example)?;
        }
        Commands::PackInitramfs { init, out } => {
            write_initramfs(&InitramfsOptions::new(init, out))?;
        }
    }

    Ok(())
}

fn require_macos_arm64() -> Result<(), Box<dyn Error>> {
    if HostTarget::current()? == HostTarget::MacosArm64 {
        Ok(())
    } else {
        Err(app::AppError::UnsupportedHost.into())
    }
}

fn build_release_or_development(
    workspace_root: &Path,
    target_dir: &Path,
    profile: Profile,
    kernel_options: KernelOptions,
    stage: bool,
) -> Result<(), Box<dyn Error>> {
    let context = build_context(workspace_root, target_dir, profile)?;
    build_all(&context)?;
    let kernel = kernel::resolve(&context, &kernel_options)?;
    runtime::assemble_development(&context, &kernel)?;
    if stage {
        runtime::stage(&context)?;
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

    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    };

    Ok(target_dir)
}
