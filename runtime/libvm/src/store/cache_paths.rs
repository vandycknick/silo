use std::path::{Component, Path, PathBuf};

use crate::store::models::MachineConfig;
use crate::store::row::DbMachineConfig;
use crate::LibVmError;

pub(crate) fn storage_pool_dependencies(
    storage: &crate::MachineStorageRecord,
) -> (
    std::collections::BTreeSet<crate::storage::identity::StreamId>,
    std::collections::BTreeSet<crate::storage::identity::ObjectDigest>,
) {
    let mut streams = std::collections::BTreeSet::new();
    let mut objects = std::collections::BTreeSet::new();
    if let crate::MachineRoot::LinuxOverlay {
        lower: crate::OverlayLower::FlatExt4 { stream, .. },
        ..
    } = &storage.root
    {
        streams.insert(*stream);
    }
    for disk in &storage.disks {
        if let crate::DiskStorage::ManagedReadOnly { stream, .. } = &disk.storage {
            streams.insert(*stream);
        }
    }
    if let crate::BootProfile::LinuxDirect {
        binding:
            crate::BootBinding::Pinned {
                kernel,
                base_initramfs,
                agent,
                ..
            },
        ..
    } = &storage.boot
    {
        objects.insert(*kernel);
        objects.insert(*base_initramfs);
        objects.extend(agent.iter().copied());
    }
    (streams, objects)
}

pub(crate) async fn retained_machine_objects(
    connection: &mut sqlx::SqliteConnection,
) -> Result<std::collections::BTreeSet<crate::storage::identity::ObjectDigest>, LibVmError> {
    let records = sqlx::query_scalar::<_,String>("SELECT CASE WHEN json_valid(record_json,8) THEN json(record_json) ELSE '{}' END FROM machine_storage").fetch_all(connection).await?;
    let mut objects = std::collections::BTreeSet::new();
    for json in records {
        objects.extend(storage_pool_dependencies(&crate::MachineStorageRecord::decode(&json)?).1);
    }
    Ok(objects)
}

pub(crate) async fn retained_machine_streams(
    connection: &mut sqlx::SqliteConnection,
) -> Result<std::collections::HashSet<crate::storage::identity::StreamId>, LibVmError> {
    let records = sqlx::query_scalar::<_, String>(
        "SELECT CASE WHEN json_valid(record_json, 8) THEN json(record_json) ELSE '{}' END FROM machine_storage",
    ).fetch_all(connection).await?;
    let mut streams = std::collections::HashSet::new();
    for json in records {
        let record = crate::MachineStorageRecord::decode(&json)?;
        streams.extend(storage_pool_dependencies(&record).0);
    }
    Ok(streams)
}
/// Call inside the same write transaction that removes catalog roots, after
/// acquiring roots coordination. Provenance strings are not dependencies.
pub(crate) async fn ensure_cache_paths_unreferenced(
    connection: &mut sqlx::SqliteConnection,
    candidates: &[PathBuf],
    home: &Path,
) -> Result<(), LibVmError> {
    ensure_paths_unreferenced(connection, candidates, home, false).await
}

/// Capture staging is below a retained machine's intrinsic directory, but every
/// explicitly configured resource (including shares of that directory) still pins it.
pub(crate) async fn ensure_capture_paths_unreferenced(
    connection: &mut sqlx::SqliteConnection,
    candidates: &[PathBuf],
    home: &Path,
) -> Result<(), LibVmError> {
    ensure_paths_unreferenced(connection, candidates, home, true).await
}

async fn ensure_paths_unreferenced(
    connection: &mut sqlx::SqliteConnection,
    candidates: &[PathBuf],
    home: &Path,
    capture_staging: bool,
) -> Result<(), LibVmError> {
    if candidates.is_empty() {
        return Ok(());
    }
    let candidates = candidates
        .iter()
        .map(|path| resolve(path))
        .collect::<Result<Vec<_>, _>>()?;
    let machines =
        sqlx::query("SELECT id, name, json(config_json) AS config_json FROM machine_config")
            .fetch_all(&mut *connection)
            .await?;
    for row in machines {
        let DbMachineConfig(config) = DbMachineConfig::from_row_in(&row, home)?;
        for (path, directory) in dependencies(&config)
            .into_iter()
            .skip(usize::from(capture_staging))
        {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                config.machine_dir.join(path)
            };
            let dependency = resolve(&absolute)?;
            if candidates.iter().any(|candidate| {
                dependency.starts_with(candidate)
                    || (directory && candidate.starts_with(&dependency))
            }) {
                return Err(LibVmError::CacheDependency {
                    machine: config.id.to_string(),
                    path: absolute,
                });
            }
        }
    }
    // Operation constraints survive machine removal. External resources never
    // become owned pool bytes merely because their original config disappeared.
    let operations = sqlx::query_scalar::<_, String>(
        "SELECT json(record_json) FROM storage_operation WHERE kind='launch'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for json in operations {
        let operation: crate::store::operation_store::RetainedStorageOperation =
            serde_json::from_str(&json).map_err(|error| LibVmError::InvalidStorageRecord {
                record: "storage-operation",
                message: error.to_string(),
            })?;
        for resource in operation.external_resources {
            let (path, directory) = match resource {
                crate::ExternalResource::Disk { path, .. } => (path, false),
                crate::ExternalResource::Share { source, .. } => (source, true),
            };
            if !path.is_absolute() {
                return Err(LibVmError::InvalidStorageRecord {
                    record: "storage-operation",
                    message: "retained external resource is not absolute".into(),
                });
            }
            let dependency = resolve(&path)?;
            if candidates.iter().any(|candidate| {
                dependency.starts_with(candidate)
                    || (directory && candidate.starts_with(&dependency))
            }) {
                return Err(LibVmError::CacheDependency {
                    machine: operation.machine_id.to_string(),
                    path,
                });
            }
        }
    }
    Ok(())
}

/// Resolve proposed dependencies before entering catalog coordination. The SQL
/// admission check below consumes only these plain path facts.
pub(crate) struct ConfigurationPaths {
    pub(crate) machines: PathBuf,
    pub(crate) resources: Vec<(PathBuf, bool)>,
}

impl ConfigurationPaths {
    pub(crate) fn new(config: &MachineConfig, home: &Path) -> Result<Self, LibVmError> {
        let absolute_home = if home.is_absolute() {
            home.to_path_buf()
        } else {
            std::env::current_dir()?.join(home)
        };
        let lexical_machines = normalize(&absolute_home.join("machines"));
        let machines = resolve(&absolute_home.join("machines"))?;
        let machine_dir = crate::paths::machine_data_dir_in(&absolute_home, config.id);
        let mut resources = Vec::new();
        let dependencies = std::iter::once((machine_dir.as_path(), true))
            .chain(dependencies(config).into_iter().skip(1));
        for (path, directory) in dependencies {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                machine_dir.join(path)
            };
            let lexical = normalize(&absolute);
            // The namespace is reserved by spelling, even when its entry is a
            // symlink pointing outside the catalog. Never resolve it first.
            reject_quarantine_reference(&lexical, &lexical_machines)?;
            reject_quarantine_reference(&lexical, &machines)?;
            // A symlinked parent may provide another spelling of machines/.
            // Resolve only that parent before considering a reserved child.
            for ancestor in absolute.ancestors() {
                if let (Some(parent), Some(name)) = (ancestor.parent(), ancestor.file_name()) {
                    if name.as_encoded_bytes().starts_with(b".retiring-") {
                        let parent = resolve(parent)?;
                        reject_quarantine_reference(&parent.join(name), &machines)?;
                    }
                }
            }
            let resolved = resolve(&absolute)?;
            reject_quarantine_reference(&resolved, &machines)?;
            resources.push((resolved, directory));
        }
        Ok(Self {
            machines,
            resources,
        })
    }
}

fn reject_quarantine_reference(path: &Path, machines: &Path) -> Result<(), LibVmError> {
    if path.strip_prefix(machines).ok().and_then(|relative| relative.components().next()).is_some_and(|component| {
        matches!(component, Component::Normal(name) if name.as_encoded_bytes().starts_with(b".retiring-"))
    }) {
        return Err(LibVmError::InvalidStorageRecord {
            record: "machine-config",
            message: "operation cleanup quarantine is not a configurable resource".into(),
        });
    }
    Ok(())
}

fn dependencies(config: &MachineConfig) -> Vec<(&Path, bool)> {
    let mut paths = vec![(config.machine_dir.as_path(), true)];
    if let Some(kernel) = config
        .spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
    {
        paths.extend(kernel.path.as_deref().map(|path| (path, false)));
        paths.extend(kernel.initramfs.as_deref().map(|path| (path, false)));
    }
    if let Some(storage) = &config.spec.storage {
        paths.extend(
            storage
                .disks
                .iter()
                .map(|disk| (disk.path.as_path(), false)),
        );
    }
    paths.extend(
        config
            .spec
            .mounts
            .iter()
            .map(|mount| (mount.source.as_path(), true)),
    );
    for agent in std::iter::once(&config.guest.agent).chain(config.agent_mode.iter()) {
        if let crate::MachineAgent::Custom { path } = agent {
            paths.push((path.as_path(), false));
        }
    }
    paths
}

fn resolve(path: &Path) -> Result<PathBuf, LibVmError> {
    resolve_with_symlinks(path, 0)
}

fn resolve_with_symlinks(path: &Path, followed: u32) -> Result<PathBuf, LibVmError> {
    if followed >= 40 {
        return Err(std::io::Error::from(nix::errno::Errno::ELOOP).into());
    }
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A dangling link can already name a future quarantine entry.
            // Resolve its intended target, not merely its existing ancestor.
            let mut ancestor = path;
            let mut suffix = Vec::new();
            loop {
                match std::fs::symlink_metadata(ancestor) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        let target = std::fs::read_link(ancestor)?;
                        let mut target = if target.is_absolute() {
                            target
                        } else {
                            ancestor
                                .parent()
                                .ok_or_else(|| std::io::Error::other("symlink has no parent"))?
                                .join(target)
                        };
                        for component in suffix.into_iter().rev() {
                            target.push(component);
                        }
                        return resolve_with_symlinks(&target, followed + 1);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let Some(parent) = ancestor.parent() else {
                    break;
                };
                let name = match ancestor.components().next_back() {
                    Some(Component::Normal(name)) => name,
                    Some(Component::ParentDir) => std::ffi::OsStr::new(".."),
                    Some(Component::CurDir) => std::ffi::OsStr::new("."),
                    _ => break,
                };
                suffix.push(name);
                ancestor = parent;
                match std::fs::canonicalize(ancestor) {
                    Ok(mut canonical) => {
                        for component in suffix.into_iter().rev() {
                            canonical.push(component);
                        }
                        return Ok(normalize(&canonical));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(normalize(path))
        }
        Err(error) => Err(error.into()),
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}
