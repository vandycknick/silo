use std::path::{Component, Path, PathBuf};

use crate::store::models::MachineConfig;
use crate::store::row::DbMachineConfig;
use crate::LibVmError;

/// Typed retained-storage edges of one machine. Its layered lower is rooted
/// by identity; the composition row roots that lower's complete closure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PoolDependencies {
    pub(crate) streams: std::collections::BTreeSet<crate::storage::identity::StreamId>,
    pub(crate) objects: std::collections::BTreeSet<crate::storage::identity::ObjectDigest>,
    pub(crate) lowers: std::collections::BTreeSet<crate::storage::identity::LowerResultId>,
}

pub(crate) fn storage_pool_dependencies(
    storage: &crate::MachineStorageRecord,
) -> Result<PoolDependencies, LibVmError> {
    let mut dependencies = PoolDependencies::default();
    // A prior-owner record is a replay/collision guard, not a bulk retention
    // request. Unresolved reservations/fences still retain the complete closure.
    if matches!(storage.ownership, crate::MachineOwnership::Relocated { .. }) {
        return Ok(dependencies);
    }
    if let crate::MachineRoot::LinuxOverlay { lower, .. } = &storage.root {
        dependencies.lowers.insert(lower.record());
    }
    for disk in &storage.disks {
        if let crate::DiskStorage::ManagedReadOnly { stream, .. } = &disk.storage {
            dependencies.streams.insert(*stream);
        }
    }
    if let crate::BootProfile::LinuxDirect {
        binding:
            binding @ crate::BootBinding::Pinned {
                kernel,
                base_initramfs,
                agent,
                ..
            },
        ..
    } = &storage.boot
    {
        dependencies.objects.insert(*kernel);
        dependencies.objects.insert(*base_initramfs);
        dependencies.objects.extend(agent.iter().copied());
        dependencies.objects.insert(binding.digest()?);
    }
    Ok(dependencies)
}

pub(crate) async fn machine_retains_object(
    connection: &mut sqlx::SqliteConnection,
    object: crate::storage::identity::ObjectDigest,
) -> Result<bool, LibVmError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM machine_object_dependency WHERE object_digest=?1)",
    )
    .bind(object.to_string())
    .fetch_one(connection)
    .await?)
}

pub(crate) async fn machine_retains_stream(
    connection: &mut sqlx::SqliteConnection,
    stream: crate::storage::identity::StreamId,
) -> Result<bool, LibVmError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM machine_stream_dependency WHERE stream_id=?1)",
    )
    .bind(stream.to_string())
    .fetch_one(connection)
    .await?)
}

/// Derive typed edges one bounded record at a time, outside root coordination.
/// A writer swaps record and indexed generation in one transaction. The read
/// transaction compares a coherent generation, rejecting missing AND extra edges.
pub(crate) async fn check_machine_dependencies(
    store: &crate::store::Store,
) -> Result<(), LibVmError> {
    use sqlx::Row;
    let mut cursor = String::new();
    loop {
        let mut tx = store.pool.begin().await?;
        let row=sqlx::query("SELECT machine_id,CASE WHEN json_valid(record_json,8) AND length(json(record_json))<=?2 THEN json(record_json) END AS bytes FROM machine_storage WHERE machine_id>?1 ORDER BY machine_id LIMIT 1")
            .bind(&cursor).bind(crate::storage::limits::Resource::MetadataPageBytes.maximum() as i64).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            break;
        };
        cursor = row.try_get("machine_id")?;
        let bytes = row.try_get::<Option<String>, _>("bytes")?.ok_or_else(|| {
            crate::store::models::snapshot::invalid("invalid or oversized machine storage catalog")
        })?;
        let record = crate::MachineStorageRecord::decode(&bytes)?;
        let PoolDependencies {
            streams,
            objects,
            lowers,
        } = storage_pool_dependencies(&record)?;
        let generation = i64::try_from(record.storage_generation)
            .map_err(crate::store::models::snapshot::invalid)?;
        let actual_streams = sqlx::query_as::<_, (i64, String)>(
            "SELECT generation,stream_id FROM machine_stream_dependency WHERE machine_id=?1",
        )
        .bind(&cursor)
        .fetch_all(&mut *tx)
        .await?;
        let actual_objects = sqlx::query_as::<_, (i64, String)>(
            "SELECT generation,object_digest FROM machine_object_dependency WHERE machine_id=?1",
        )
        .bind(&cursor)
        .fetch_all(&mut *tx)
        .await?;
        let actual_lowers = sqlx::query_as::<_, (i64, String)>(
            "SELECT generation,lower_id FROM machine_lower_dependency WHERE machine_id=?1",
        )
        .bind(&cursor)
        .fetch_all(&mut *tx)
        .await?;
        if actual_streams.iter().any(|(g, _)| *g != generation)
            || actual_objects.iter().any(|(g, _)| *g != generation)
            || actual_lowers.iter().any(|(g, _)| *g != generation)
            || streams
                != actual_streams
                    .into_iter()
                    .map(|(_, v)| v.parse().map_err(crate::store::models::snapshot::invalid))
                    .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            || objects
                != actual_objects
                    .into_iter()
                    .map(|(_, v)| v.parse().map_err(crate::store::models::snapshot::invalid))
                    .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            || lowers
                != actual_lowers
                    .into_iter()
                    .map(|(_, v)| v.parse().map_err(crate::store::models::snapshot::invalid))
                    .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        {
            return Err(crate::store::models::snapshot::invalid(
                "machine dependency index contradicts its semantic generation",
            ));
        }
        tx.commit().await?;
    }
    Ok(())
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
