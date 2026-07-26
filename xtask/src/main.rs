use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
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
mod release_record;
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
    CheckRuntimeQualification {
        #[arg(long, value_enum, default_value_t = Profile::Release)]
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
            if profile == Profile::Release && should_use_linux_container()? {
                release::run_linux_release(
                    &workspace_root,
                    &target_dir,
                    HostTarget::current()?,
                    "build",
                    Some(&kernel),
                )?;
                return Ok(());
            }
            build_release_or_development(&workspace_root, &target_dir, profile, kernel, false)?;
        }
        Commands::Component { component, profile } => {
            if profile == Profile::Release && should_use_linux_container()? {
                release::run_linux_release(
                    &workspace_root,
                    &target_dir,
                    HostTarget::current()?,
                    component_make_target(component),
                    None,
                )?;
                return Ok(());
            }
            let component_target = if profile == Profile::Release {
                release_target(&workspace_root, &target_dir)?
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
            if profile == Profile::Release && should_use_linux_container()? {
                release::run_linux_release(
                    &workspace_root,
                    &target_dir,
                    HostTarget::current()?,
                    "stage",
                    Some(&kernel),
                )?;
                return Ok(());
            }
            build_release_or_development(&workspace_root, &target_dir, profile, kernel, true)?;
        }
        Commands::VerifyRuntime { profile } => {
            if profile == Profile::Release && should_use_linux_container()? {
                release::run_linux_release(
                    &workspace_root,
                    &target_dir,
                    HostTarget::current()?,
                    "verify-runtime",
                    None,
                )?;
                return Ok(());
            }
            if profile == Profile::Release
                && matches!(
                    HostTarget::current()?,
                    HostTarget::LinuxX86_64 | HostTarget::LinuxArm64
                )
            {
                release::verify_linux_toolchain(&workspace_root, HostTarget::current()?)?;
            }
            release_audit::verify(&workspace_root, &target_dir, profile)?
        }
        Commands::CheckRuntimeQualification { profile } => {
            if profile != Profile::Release {
                return Err("runtime qualification is only defined for release outputs".into());
            }
            let host = HostTarget::current()?;
            if !release_record::qualification_matches(&target_dir, host)? {
                return Err("release runtime qualification is missing, stale, or artifact-bound bytes changed; run make verify-runtime PROFILE=release".into());
            }
            println!("release runtime qualification is current");
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
    if profile == Profile::Release
        && matches!(
            HostTarget::current()?,
            HostTarget::LinuxX86_64 | HostTarget::LinuxArm64
        )
    {
        release::verify_linux_toolchain(workspace_root, HostTarget::current()?)?;
    }
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

    let host = HostTarget::current()?;
    let source_fingerprint = release_source_fingerprint(workspace_root, profile, host)?;
    let toolchain_fingerprint = release_toolchain_fingerprint(workspace_root)?;
    let release_target = release_target_path(target_dir, host);
    if !release_record::complete_source_matches(&release_target, &source_fingerprint)? {
        prepare_release_target(&release_target, &source_fingerprint)?;
    }
    let clean = build_context(workspace_root, &release_target, profile)?;
    let kernel = kernel::resolve(&clean, &kernel_options)?;
    if release_record::complete_matches(
        &release_target,
        &source_fingerprint,
        &toolchain_fingerprint,
        profile,
        host,
        &kernel.identity,
    )? {
        println!(
            "reusing complete isolated release output: {}",
            release_target.display()
        );
    } else {
        clear_release_target(&release_target)?;
        fs::create_dir_all(&release_target)?;
        let clean = build_context(workspace_root, &release_target, profile)?;
        build_all(&clean)?;
        let kernel = kernel::resolve(&clean, &kernel_options)?;
        runtime::assemble_development(&clean, &kernel)?;
        release_record::write_complete(
            &release_target,
            &source_fingerprint,
            &toolchain_fingerprint,
            profile,
            host,
            &kernel.identity,
        )?;
        let priming = release_target.join(".silo-release-priming");
        if priming.exists() {
            fs::remove_file(priming)?;
        }
    }

    let public = build_context(workspace_root, target_dir, profile)?;
    let qualified = build_context(workspace_root, &release_target, profile)?;
    runtime::publish_adjacent(&qualified, &public)?;
    if stage {
        runtime::stage(&public)?;
    }
    Ok(())
}

fn should_use_linux_container() -> Result<bool, Box<dyn Error>> {
    Ok(matches!(
        HostTarget::current()?,
        HostTarget::LinuxX86_64 | HostTarget::LinuxArm64
    ) && env::var_os(release::CONTAINER_MARKER).is_none())
}

fn component_make_target(component: Component) -> &'static str {
    match component {
        Component::Cli => "cli",
        Component::Vmmon => "vmmon",
        Component::Netd => "netd",
        Component::Krun => "krun",
        Component::Agent => "agent",
        Component::Init => "init",
        Component::Initramfs => "initramfs",
    }
}

fn release_target(workspace_root: &Path, target_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let host = HostTarget::current()?;
    let target = release_target_path(target_dir, host);
    let source_fingerprint = release_source_fingerprint(workspace_root, Profile::Release, host)?;
    if release_record::complete_source_matches(&target, &source_fingerprint)? {
        fs::remove_file(target.join(".silo-release-complete.json"))?;
    }
    prepare_release_target(&target, &source_fingerprint)?;
    Ok(target)
}

fn release_target_path(target_dir: &Path, host: HostTarget) -> PathBuf {
    target_dir.join("release-build").join(host.runtime_target())
}

fn prepare_release_target(target: &Path, source_fingerprint: &str) -> Result<(), Box<dyn Error>> {
    if read_stamp(&target.join(".silo-release-priming"))?.as_deref() == Some(source_fingerprint) {
        return Ok(());
    }
    if release_record::complete_source_matches(target, source_fingerprint)? {
        write_atomically(
            &target.join(".silo-release-priming"),
            source_fingerprint.as_bytes(),
        )?;
        return Ok(());
    }
    clear_release_target(target)?;
    fs::create_dir_all(target)?;
    write_atomically(
        &target.join(".silo-release-priming"),
        source_fingerprint.as_bytes(),
    )
}

fn clear_release_target(target: &Path) -> Result<(), Box<dyn Error>> {
    if target.exists() {
        let kernel_cache = target.join("kernel-cache");
        let preserved_cache = target.with_extension(format!("kernel-cache-{}", std::process::id()));
        if kernel_cache.exists() {
            fs::rename(&kernel_cache, &preserved_cache)?;
        }
        let mut chmod = Command::new("/bin/chmod");
        chmod.args(["-R", "u+w"]).arg(target);
        command::run(chmod)?;
        fs::remove_dir_all(target)?;
        if preserved_cache.exists() {
            fs::create_dir_all(target)?;
            fs::rename(preserved_cache, kernel_cache)?;
        }
    }
    Ok(())
}

fn release_source_fingerprint(
    workspace_root: &Path,
    profile: Profile,
    host: HostTarget,
) -> Result<String, Box<dyn Error>> {
    let mut git = Command::new("git");
    git.current_dir(workspace_root).args(["ls-files", "-z"]);
    let tracked = command::output(git)?;
    let mut hasher = Sha256::new();
    hasher.update(b"silo-release-source-v1\0");
    hasher.update(profile.directory().as_bytes());
    hasher.update([0]);
    hasher.update(host.runtime_target().as_bytes());
    hasher.update([0]);
    for path in tracked
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = PathBuf::from(OsString::from_vec(path.to_vec()));
        let absolute = workspace_root.join(&relative);
        let metadata = fs::symlink_metadata(&absolute)?;
        hasher.update(path);
        hasher.update([0]);
        if metadata.file_type().is_symlink() {
            hasher.update(b"symlink\0");
            hasher.update(fs::read_link(absolute)?.as_os_str().as_bytes());
        } else if metadata.is_file() {
            hasher.update(b"file\0");
            hasher.update(fs::read(absolute)?);
        } else {
            return Err(format!(
                "tracked path is not a file or symlink: {}",
                relative.display()
            )
            .into());
        }
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn release_toolchain_fingerprint(workspace_root: &Path) -> Result<String, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(b"silo-release-toolchain-v1\0");
    for (key, value) in release::toolchains(workspace_root)?.values() {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn read_stamp(path: &Path) -> Result<Option<String>, Box<dyn Error>> {
    match fs::read_to_string(path) {
        Ok(stamp) => Ok(Some(stamp.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)?;
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
