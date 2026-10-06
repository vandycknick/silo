use crate::{parse_global_config, GlobalConfig};
use eyre::Context as _;
use nix::fcntl::{Flock, FlockArg, OFlag};
use serde_yaml_ng::{Mapping, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) fn config_path(host: &libvm::HostPaths) -> PathBuf {
    let primary = host.config_dir().join("config.yaml");
    let fallback = host.home().join("config.yaml");
    if std::fs::symlink_metadata(&primary).is_ok() {
        primary
    } else if std::fs::symlink_metadata(&fallback).is_ok() {
        fallback
    } else {
        primary
    }
}

fn check_file(file: &File, path: &Path) -> eyre::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        eyre::bail!(
            "config leaf {} must be an owned regular file not writable by group or others",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn read_config(path: &Path) -> eyre::Result<Option<String>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Dangling symlinks must not masquerade as missing config.
            if std::fs::symlink_metadata(path).is_ok() {
                eyre::bail!("unsafe config leaf {}", path.display());
            }
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("open global config {}", path.display())),
    };
    check_file(&file, path)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("read global config {}", path.display()))?;
    Ok(Some(raw))
}

/// Prepare an owned root, rejecting symlinks at the selected root while allowing
/// canonical parent aliases (for example macOS /var). Existing ancestors are not modified.
pub(super) fn prepare_root(path: &Path) -> eyre::Result<PathBuf> {
    if !path.is_absolute() {
        eyre::bail!("host root must be absolute: {}", path.display());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
            {
                eyre::bail!(
                    "host root {} must be an owned directory not writable by group or others",
                    path.display()
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| eyre::eyre!("root has no parent"))?;
            // Only missing ancestors are created. Canonicalize existing parents,
            // so a selected /var/... root resolves to /private/var/... on macOS.
            let canonical_parent = if parent.exists() {
                std::fs::canonicalize(parent)?
            } else {
                prepare_root(parent)?
            };
            let leaf = path
                .file_name()
                .ok_or_else(|| eyre::eyre!("root has no name"))?;
            let target = canonical_parent.join(leaf);
            match std::fs::DirBuilder::new().mode(0o700).create(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("create host root {}", target.display()))
                }
            }
            return prepare_root(&target);
        }
        Err(e) => return Err(e).with_context(|| format!("inspect host root {}", path.display())),
    }
    Ok(std::fs::canonicalize(path)?)
}

pub(super) fn mapping_entry<'a>(
    mapping: &'a mut Mapping,
    name: &str,
) -> eyre::Result<&'a mut Mapping> {
    let entry = mapping
        .entry(Value::String(name.into()))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    entry
        .as_mapping_mut()
        .ok_or_else(|| eyre::eyre!("{name} must be a YAML mapping"))
}

pub(super) fn update<T>(
    host: &libvm::HostPaths,
    edit: impl FnOnce(&mut Mapping, &GlobalConfig) -> eyre::Result<T>,
) -> eyre::Result<T> {
    // Always lock the primary config root, independent of legacy fallback selection.
    // Re-resolve the selected config file after acquiring the lock.
    let root = prepare_root(host.config_dir())?;
    let lock_path = root.join("config.yaml.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
        .open(&lock_path)
        .context("open global config transaction lock")?;
    check_file(&lock, &lock_path)?;
    let _lock = Flock::lock(lock, FlockArg::LockExclusive)
        .map_err(|(_, error)| eyre::eyre!("lock global config transaction: {error}"))?;
    let selected = config_path(host);
    let parent = prepare_root(
        selected
            .parent()
            .ok_or_else(|| eyre::eyre!("config has no parent"))?,
    )?;
    let path = parent.join("config.yaml");
    let raw = read_config(&path)?.unwrap_or_else(|| "{}\n".into());
    let config = parse_global_config(&raw)?;
    let mut document: Value = serde_yaml_ng::from_str(&raw)?;
    let mapping = document
        .as_mapping_mut()
        .ok_or_else(|| eyre::eyre!("global config must be a YAML mapping"))?;
    let result = edit(mapping, &config)?;
    let rendered = serde_yaml_ng::to_string(&document)?;
    parse_global_config(&rendered).context("validate prospective global config")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(&parent).context("create atomic config temporary")?;
    temporary.write_all(rendered.as_bytes())?;
    temporary
        .as_file()
        .sync_all()
        .context("fsync global config temporary")?;
    temporary
        .persist(&path)
        .map_err(|e| e.error)
        .context("rename global config")?;
    File::open(&parent)?
        .sync_all()
        .context("fsync global config directory")?;
    Ok(result)
}
