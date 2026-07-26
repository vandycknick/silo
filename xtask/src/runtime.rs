use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::components::BuildContext;
use crate::initramfs::{write_initramfs, InitramfsOptions};
use crate::kernel::KernelArtifact;

const HELPERS: [(&str, u32); 3] = [("vmmon", 0o755), ("netd", 0o755), ("krun", 0o755)];
const ASSETS: [(&str, u32); 3] = [
    ("kernel-default", 0o644),
    ("initramfs", 0o644),
    ("agent", 0o755),
];

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Initramfs(#[from] crate::initramfs::InitramfsError),
    #[error("failed to create directory {path}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read metadata for {path}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to copy {from} to {to}")]
    Copy {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set mode on {path}")]
    SetMode {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to rename {from} to {to}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove temporary directory {path}")]
    RemoveTemporaryDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid runtime layout: {0}")]
    Invalid(String),
}

pub fn assemble_development(
    context: &BuildContext<'_>,
    kernel: &KernelArtifact,
) -> Result<(), RuntimeError> {
    let profile_dir = context.target_dir.join(context.profile.directory());
    validate_directory(&profile_dir)?;
    let assets = profile_dir.join("assets");
    let temporary = create_sibling_directory(&assets, "assets")?;
    let result = (|| {
        copy_regular_file(&kernel.path, &temporary.join("kernel-default"), 0o644)?;
        let init = guest_binary(context, "init");
        write_initramfs(&InitramfsOptions::new(init, temporary.join("initramfs")))?;
        set_mode(&temporary.join("initramfs"), 0o644)?;
        copy_regular_file(
            &guest_binary(context, "agent"),
            &temporary.join("agent"),
            0o755,
        )?;
        validate_assets(&temporary)?;
        replace_directory(&temporary, &assets)?;
        validate_adjacent(context)
    })();
    if result.is_err() && temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|source| {
            RuntimeError::RemoveTemporaryDirectory {
                path: temporary,
                source,
            }
        })?;
    }
    result
}

pub fn stage(context: &BuildContext<'_>) -> Result<(), RuntimeError> {
    validate_adjacent(context)?;
    let profile_dir = context.target_dir.join(context.profile.directory());
    let stage = context
        .target_dir
        .join("silo-runtime")
        .join(context.host.runtime_target())
        .join(context.profile.directory());
    let parent = stage.parent().ok_or_else(|| {
        RuntimeError::Invalid(format!("stage path has no parent: {}", stage.display()))
    })?;
    create_directory(parent)?;
    let temporary = create_sibling_directory(&stage, "stage")?;
    let result = (|| {
        let bin = temporary.join("bin");
        let assets = temporary.join("assets");
        create_directory(&bin)?;
        create_directory(&assets)?;
        for (name, mode) in HELPERS {
            copy_regular_file(&profile_dir.join(name), &bin.join(name), mode)?;
        }
        for (name, mode) in ASSETS {
            copy_regular_file(
                &profile_dir.join("assets").join(name),
                &assets.join(name),
                mode,
            )?;
        }
        validate_stage(&temporary)?;
        replace_directory(&temporary, &stage)?;
        validate_stage(&stage)
    })();
    if result.is_err() && temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|source| {
            RuntimeError::RemoveTemporaryDirectory {
                path: temporary,
                source,
            }
        })?;
    }
    result
}

fn guest_binary(context: &BuildContext<'_>, name: &str) -> PathBuf {
    let binary = match name {
        "agent" => "silo-agent",
        name => name,
    };
    context
        .target_dir
        .join(context.host.guest_target().triple())
        .join(context.profile.directory())
        .join(binary)
}

fn validate_adjacent(context: &BuildContext<'_>) -> Result<(), RuntimeError> {
    let profile_dir = context.target_dir.join(context.profile.directory());
    for (name, _) in HELPERS {
        validate_regular_file(&profile_dir.join(name), true, None)?;
    }
    validate_assets(&profile_dir.join("assets"))
}

fn validate_assets(assets: &Path) -> Result<(), RuntimeError> {
    validate_directory(assets)?;
    for (name, mode) in ASSETS {
        validate_regular_file(&assets.join(name), name == "agent", Some(mode))?;
    }
    Ok(())
}

fn validate_stage(stage: &Path) -> Result<(), RuntimeError> {
    validate_directory(stage)?;
    let expected_root = BTreeSet::from(["assets", "bin"]);
    validate_directory_entries(stage, &expected_root)?;
    let bin = stage.join("bin");
    let assets = stage.join("assets");
    validate_directory_entries(&bin, &BTreeSet::from(["krun", "netd", "vmmon"]))?;
    validate_directory_entries(
        &assets,
        &BTreeSet::from(["agent", "initramfs", "kernel-default"]),
    )?;
    for (name, mode) in HELPERS {
        validate_regular_file(&bin.join(name), true, Some(mode))?;
    }
    validate_assets(&assets)
}

fn validate_directory_entries(
    directory: &Path,
    expected: &BTreeSet<&str>,
) -> Result<(), RuntimeError> {
    validate_directory(directory)?;
    let entries = fs::read_dir(directory).map_err(|source| RuntimeError::Metadata {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| RuntimeError::Metadata {
            path: directory.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        actual.insert(name.into_owned());
    }
    let expected = expected.iter().map(|name| (*name).to_string()).collect();
    if actual != expected {
        return Err(RuntimeError::Invalid(format!(
            "{} contains {:?}, expected {:?}",
            directory.display(),
            actual,
            expected
        )));
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<(), RuntimeError> {
    validate_regular_file(source, mode & 0o111 != 0, None)?;
    fs::copy(source, destination).map_err(|error| RuntimeError::Copy {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: error,
    })?;
    set_mode(destination, mode)?;
    validate_regular_file(destination, mode & 0o111 != 0, Some(mode))
}

fn create_sibling_directory(path: &Path, purpose: &str) -> Result<PathBuf, RuntimeError> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::Invalid(format!("path has no parent: {}", path.display())))?;
    create_directory(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RuntimeError::Invalid(format!("invalid path name: {}", path.display())))?;
    for attempt in 0..128 {
        let temporary = parent.join(format!(
            ".{name}.{purpose}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&temporary) {
            Ok(()) => return Ok(temporary),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(RuntimeError::CreateDirectory {
                    path: temporary,
                    source,
                });
            }
        }
    }
    Err(RuntimeError::Invalid(format!(
        "could not create a temporary sibling for {}",
        path.display()
    )))
}

fn replace_directory(temporary: &Path, final_path: &Path) -> Result<(), RuntimeError> {
    validate_directory(temporary)?;
    let parent = final_path.parent().ok_or_else(|| {
        RuntimeError::Invalid(format!("path has no parent: {}", final_path.display()))
    })?;
    validate_directory(parent)?;
    let final_exists = match fs::symlink_metadata(final_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RuntimeError::Invalid(format!(
                    "{} is not a real directory",
                    final_path.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(RuntimeError::Metadata {
                path: final_path.to_path_buf(),
                source,
            });
        }
    };
    if !final_exists {
        return fs::rename(temporary, final_path).map_err(|source| RuntimeError::Rename {
            from: temporary.to_path_buf(),
            to: final_path.to_path_buf(),
            source,
        });
    }
    let backup = unused_sibling_path(final_path, "previous")?;
    fs::rename(final_path, &backup).map_err(|source| RuntimeError::Rename {
        from: final_path.to_path_buf(),
        to: backup.clone(),
        source,
    })?;
    if let Err(source) = fs::rename(temporary, final_path) {
        let _ = fs::rename(&backup, final_path);
        return Err(RuntimeError::Rename {
            from: temporary.to_path_buf(),
            to: final_path.to_path_buf(),
            source,
        });
    }
    fs::remove_dir_all(&backup).map_err(|source| RuntimeError::RemoveTemporaryDirectory {
        path: backup,
        source,
    })
}

fn unused_sibling_path(path: &Path, purpose: &str) -> Result<PathBuf, RuntimeError> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::Invalid(format!("path has no parent: {}", path.display())))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RuntimeError::Invalid(format!("invalid path name: {}", path.display())))?;
    for attempt in 0..128 {
        let candidate = parent.join(format!(
            ".{name}.{purpose}-{}-{attempt}",
            std::process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(RuntimeError::Invalid(format!(
        "could not reserve a backup sibling for {}",
        path.display()
    )))
}

fn create_directory(path: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(path).map_err(|source| RuntimeError::CreateDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    validate_directory(path)
}

fn validate_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::Invalid(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    executable: bool,
    expected_mode: Option<u32>,
) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RuntimeError::Invalid(format!(
            "{} is not a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode() & 0o777;
        if executable && mode & 0o111 == 0 {
            return Err(RuntimeError::Invalid(format!(
                "{} is not executable",
                path.display()
            )));
        }
        if let Some(expected_mode) = expected_mode {
            if mode != expected_mode {
                return Err(RuntimeError::Invalid(format!(
                    "{} has mode {mode:o}, expected {expected_mode:o}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        RuntimeError::SetMode {
            path: path.to_path_buf(),
            source,
        }
    })
}
