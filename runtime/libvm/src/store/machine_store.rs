use async_trait::async_trait;
use sqlx::Row;

use crate::store::models::MachineId;
use crate::store::models::{MachineConfig, MachineRootfsRecord, MachineState};
use crate::store::row::{DbMachineConfig, DbMachineState};
use crate::store::{MachineStore, Store};
use crate::LibVmError;

fn has_pool_roots(storage: &crate::MachineStorageRecord) -> bool {
    matches!(&storage.root, crate::MachineRoot::LinuxOverlay { .. })
        || storage
            .disks
            .iter()
            .any(|disk| matches!(&disk.storage, crate::DiskStorage::ManagedReadOnly { .. }))
        || matches!(
            &storage.boot,
            crate::BootProfile::LinuxDirect {
                binding: crate::BootBinding::Pinned { .. },
                ..
            }
        )
}

pub(crate) struct InventoryRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) config: Result<MachineConfig, LibVmError>,
}

#[async_trait]
impl MachineStore for Store {
    fn native_store(&self) -> Option<Store> {
        Some(self.clone())
    }
    async fn register_launch_storage(
        &self,
        machine_id: MachineId,
        run_id: uuid::Uuid,
        storage: &crate::MachineStorageRecord,
        spec: &vm_spec::VmSpec,
    ) -> Result<crate::store::operation_store::LaunchStorageLease, LibVmError> {
        let store = self.clone();
        let storage = storage.clone();
        let spec = spec.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(
                store.register_launch_storage_inner(machine_id, run_id, &storage, &spec, None),
            )
        })
        .await?
    }
    async fn mark_launch_storage_admitted(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<(), LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.mark_launch_storage_admitted_inner(operation_id))
        })
        .await?
    }
    async fn launch_storage_operations(
        &self,
        machine_id: MachineId,
    ) -> Result<Vec<crate::store::operation_store::RetainedStorageOperation>, LibVmError> {
        self.launch_storage_operations_inner(machine_id).await
    }
    async fn try_retire_launch_storage(
        &self,
        operation_id: uuid::Uuid,
        run_id: uuid::Uuid,
        generation: u64,
        next_state: &MachineState,
        outcome: crate::StorageStopOutcome,
    ) -> Result<bool, LibVmError> {
        let store = self.clone();
        let next_state = next_state.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.try_retire_launch_storage_inner(
                operation_id,
                run_id,
                generation,
                &next_state,
                outcome,
            ))
        })
        .await?
    }
    async fn machine_inventory(&self) -> Result<Vec<InventoryRecord>, LibVmError> {
        // Guard JSON conversion per row: malformed JSONB must not abort the
        // entire SELECT before we can retain its indexed identity.
        let rows = sqlx::query("SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config ORDER BY name")
            .fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(InventoryRecord {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    config: DbMachineConfig::from_row_in(&row, &self.home)
                        .map(|DbMachineConfig(config)| config)
                        .map_err(Into::into),
                })
            })
            .collect()
    }

    #[cfg(test)]
    async fn add_machine(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
    ) -> Result<(), LibVmError> {
        if initial_state.machine_id != config.id {
            return Err(LibVmError::InvalidCreateRequest {
                name: config.name.clone(),
                reason: "initial machine state id does not match machine config id".to_string(),
            });
        }

        let paths = crate::store::cache_paths::ConfigurationPaths::new(config, &self.home)?;
        let mut tx = self.pool.begin().await?;
        self.check_cleaning_dependencies(&mut tx, &paths).await?;
        Self::insert_machine_config_and_state(&mut tx, config, initial_state).await?;
        let platform = oci::Platform::host().map_err(|error| LibVmError::InvalidStorageRecord {
            record: "machine-storage",
            message: error.to_string(),
        })?;
        let storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new(crate::paths::root_disk_relative_path())?,
            512,
            &platform,
        )?;
        Self::write_machine_storage(&mut tx, config.id, &storage).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn add_machine_with_rootfs(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
        rootfs: &MachineRootfsRecord,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        let store = self.clone();
        let config = config.clone();
        let initial_state = initial_state.clone();
        let rootfs = rootfs.clone();
        let storage = storage.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.add_machine_with_rootfs_inner(
                &config,
                &initial_state,
                &rootfs,
                &storage,
            ))
        })
        .await?
    }

    async fn machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError> {
        let state = sqlx::query_as::<_, DbMachineState>(
            "SELECT machine_id, status, CASE WHEN json_valid(state_json, 8) THEN json(state_json) ELSE '{}' END AS state_json FROM machine_state WHERE machine_id = ?1",
        )
        .bind(machine_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(state.map(|DbMachineState(state)| state))
    }

    async fn machine_rootfs(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineRootfsRecord>, LibVmError> {
        let row = sqlx::query(
            "SELECT r.machine_id, r.source_kind, r.requested_reference, r.selected_reference,
                    r.manifest_digest, r.config_digest, r.image_id, r.created_at,
                    CASE WHEN json_valid(s.record_json, 8) THEN json(s.record_json) ELSE '{}' END AS storage_json
             FROM machine_rootfs r JOIN machine_storage s ON s.machine_id = r.machine_id
             WHERE r.machine_id = ?1",
        )
        .bind(machine_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| machine_rootfs_from_row(row, &self.home))
            .transpose()
    }

    async fn machine_storage(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<crate::MachineStorageRecord>, LibVmError> {
        let json = sqlx::query_scalar::<_, Option<String>>(
            "SELECT CASE WHEN s.machine_id IS NULL THEN NULL WHEN json_valid(s.record_json, 8) THEN json(s.record_json) ELSE '{}' END FROM machine_config c LEFT JOIN machine_storage s ON s.machine_id = c.id WHERE c.id = ?1",
        )
        .bind(machine_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        match json {
            None => Ok(None),
            Some(None) => Err(LibVmError::InvalidStorageRecord {
                record: "machine-storage",
                message: "machine has no storage record".to_string(),
            }),
            Some(Some(json)) => {
                let storage = crate::MachineStorageRecord::decode(&json)?;
                storage.validate_for_machine(machine_id.into())?;
                Ok(Some(storage))
            }
        }
    }

    async fn save_machine_state(&self, state: &MachineState) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_state (machine_id, status, state_json)
             VALUES (?1, ?2, jsonb(?3))
             ON CONFLICT(machine_id) DO UPDATE SET
                 status = excluded.status,
                 state_json = excluded.state_json",
        )
        .bind(state.machine_id.to_string())
        .bind(state.status.as_str())
        .bind(Self::serialize("machine_state.state_json", state)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn save_machine_config_with_storage(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        let store = self.clone();
        let config = config.clone();
        let storage = storage.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.save_machine_config_with_storage_inner(&config, &storage))
        })
        .await?
    }

    async fn save_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        let paths = crate::store::cache_paths::ConfigurationPaths::new(config, &self.home)?;
        let mut tx = self.pool.begin().await?;
        self.check_cleaning_dependencies(&mut tx, &paths).await?;
        let result = sqlx::query(
            "UPDATE machine_config
             SET name = ?1, config_json = jsonb(?2)
             WHERE id = ?3",
        )
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .bind(config.id.to_string())
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LibVmError::MachineNotFound {
                reference: config.id.to_string(),
            });
        }
        if let Some(length) = config.root_disk_size {
            let json = sqlx::query_scalar::<_, String>(
                "SELECT CASE WHEN json_valid(record_json, 8) THEN json(record_json) ELSE '{}' END FROM machine_storage WHERE machine_id = ?1",
            ).bind(config.id.to_string()).fetch_optional(&mut *tx).await?
                .ok_or_else(|| LibVmError::InvalidStorageRecord { record: "machine-storage", message: "machine has no storage record".to_string() })?;
            let mut storage = crate::MachineStorageRecord::decode(&json)?;
            match &mut storage.root {
                crate::MachineRoot::OpaqueRaw { geometry, .. } => geometry.length = length,
                crate::MachineRoot::LinuxOverlay {
                    capacity, upper, ..
                } => {
                    let disk = config
                        .spec
                        .storage
                        .as_ref()
                        .and_then(|storage| {
                            storage
                                .disks
                                .iter()
                                .find(|disk| disk.role == vm_spec::DiskRole::RootUpper)
                        })
                        .ok_or_else(|| LibVmError::InvalidStorageRecord {
                            record: "machine-storage",
                            message: "overlay update has no upper attachment".into(),
                        })?;
                    if *capacity != length || upper.as_path() != disk.path {
                        *upper = crate::PrivatePath::new(disk.path.clone())?;
                        *capacity = length;
                        storage.storage_generation = storage
                            .storage_generation
                            .checked_add(1)
                            .ok_or_else(|| LibVmError::InvalidStorageRecord {
                                record: "machine-storage",
                                message: "storage generation overflow".into(),
                            })?;
                    }
                }
            }
            Self::write_machine_storage(&mut tx, config.id, &storage).await?;
        }
        tx.commit().await?;

        Ok(())
    }

    async fn machine_config(&self, id: MachineId) -> Result<Option<MachineConfig>, LibVmError> {
        let machine = sqlx::query(
            "SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        machine
            .map(|row| {
                DbMachineConfig::from_row_in(&row, &self.home).map(|DbMachineConfig(config)| config)
            })
            .transpose()
            .map_err(Into::into)
    }

    async fn machine_config_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        let machine = sqlx::query(
            "SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        machine
            .map(|row| {
                DbMachineConfig::from_row_in(&row, &self.home).map(|DbMachineConfig(config)| config)
            })
            .transpose()
            .map_err(Into::into)
    }

    async fn machine_configs_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError> {
        Self::validate_machine_id_prefix(prefix)?;
        let pattern = format!("{prefix}%");
        let rows = sqlx::query(
            "SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE id LIKE ?1",
        )
        .bind(pattern)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                DbMachineConfig::from_row_in(row, &self.home).map(|DbMachineConfig(config)| config)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        let rows = sqlx::query(
            "SELECT id, name, json(config_json) AS config_json FROM machine_config ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                DbMachineConfig::from_row_in(row, &self.home).map(|DbMachineConfig(config)| config)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn remove_machine(&self, machine: &MachineConfig) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM machine_state WHERE machine_id = ?1")
            .bind(machine.id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM machine_config WHERE id = ?1")
            .bind(machine.id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

impl Store {
    async fn add_machine_with_rootfs_inner(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
        rootfs: &MachineRootfsRecord,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        if initial_state.machine_id != config.id {
            return Err(LibVmError::InvalidCreateRequest {
                name: config.name.clone(),
                reason: "initial machine state id does not match machine config id".to_string(),
            });
        }
        if rootfs.machine_id != config.id {
            return Err(LibVmError::InvalidCreateRequest {
                name: config.name.clone(),
                reason: "machine rootfs id does not match machine config id".to_string(),
            });
        }
        storage.validate()?;
        let machine_dir = crate::paths::machine_data_dir_in(&self.home, config.id);
        let matches_root = match &storage.root {
            crate::MachineRoot::OpaqueRaw { path, geometry, .. } => {
                machine_dir.join(path.as_path()) == rootfs.root_disk_path
                    && geometry.length == rootfs.root_disk_size_bytes
            }
            crate::MachineRoot::LinuxOverlay {
                upper, capacity, ..
            } => {
                machine_dir.join(upper.as_path()) == rootfs.root_disk_path
                    && *capacity == rootfs.root_disk_size_bytes
            }
        };
        if !matches_root {
            return Err(LibVmError::InvalidStorageRecord {
                record: "machine-storage",
                message: "root provenance path or length differs from the selected root"
                    .to_string(),
            });
        }

        let paths = crate::store::cache_paths::ConfigurationPaths::new(config, &self.home)?;
        let pool = if has_pool_roots(storage) {
            Some(
                crate::storage::pool::StoragePool::open_existing(&self.images_dir)?.ok_or_else(
                    || {
                        crate::machine::root_storage::invalid(
                            "retained lower pool disappeared before machine publication",
                        )
                    },
                )?,
            )
        } else {
            None
        };
        let _roots = pool
            .as_ref()
            .map(|pool| pool.lock_roots_shared())
            .transpose()?;
        let mut tx = self.pool.begin().await?;
        self.check_cleaning_dependencies(&mut tx, &paths).await?;
        Self::insert_machine_config_and_state(&mut tx, config, initial_state).await?;
        Self::insert_machine_rootfs(&mut tx, rootfs).await?;
        Self::write_machine_storage(&mut tx, config.id, storage).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn save_machine_config_with_storage_inner(
        &self,
        config: &MachineConfig,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        storage.validate()?;
        let paths = crate::store::cache_paths::ConfigurationPaths::new(config, &self.home)?;
        let pool = if has_pool_roots(storage) {
            Some(
                crate::storage::pool::StoragePool::open_existing(&self.images_dir)?.ok_or_else(
                    || {
                        crate::machine::root_storage::invalid(
                            "retained lower pool disappeared before semantic update",
                        )
                    },
                )?,
            )
        } else {
            None
        };
        let _roots = pool
            .as_ref()
            .map(|pool| pool.lock_roots_shared())
            .transpose()?;
        let mut tx = self.pool.begin().await?;
        self.check_cleaning_dependencies(&mut tx, &paths).await?;
        let result =
            sqlx::query("UPDATE machine_config SET name=?1, config_json=jsonb(?2) WHERE id=?3")
                .bind(&config.name)
                .bind(Self::serialize("machine_config.config_json", config)?)
                .bind(config.id.to_string())
                .execute(&mut *tx)
                .await?;
        if result.rows_affected() != 1 {
            return Err(LibVmError::MachineNotFound {
                reference: config.id.to_string(),
            });
        }
        Self::write_machine_storage(&mut tx, config.id, storage).await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn write_machine_storage(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        machine_id: MachineId,
        storage: &crate::MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        storage.validate_for_machine(machine_id.into())?;
        let json = Self::serialize("machine_storage.record_json", storage)?;
        crate::storage::limits::Resource::MetadataPageBytes
            .check(json.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        sqlx::query("INSERT INTO machine_storage (machine_id, record_json) VALUES (?1, jsonb(?2)) ON CONFLICT(machine_id) DO UPDATE SET record_json = excluded.record_json")
            .bind(machine_id.to_string())
            .bind(json)
            .execute(&mut **tx).await?;
        Ok(())
    }
    async fn insert_machine_config_and_state(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        config: &MachineConfig,
        initial_state: &MachineState,
    ) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_config (id, name, config_json)
             VALUES (?1, ?2, jsonb(?3))",
        )
        .bind(config.id.to_string())
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .execute(&mut **tx)
        .await
        .map_err(|err| Self::map_add_machine_error(err, &config.name))?;

        sqlx::query(
            "INSERT INTO machine_state (machine_id, status, state_json)
             VALUES (?1, ?2, jsonb(?3))",
        )
        .bind(initial_state.machine_id.to_string())
        .bind(initial_state.status.as_str())
        .bind(Self::serialize("machine_state.state_json", initial_state)?)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn insert_machine_rootfs(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        rootfs: &MachineRootfsRecord,
    ) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_rootfs
                (machine_id, source_kind, requested_reference, selected_reference,
                 manifest_digest, config_digest, image_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(rootfs.machine_id.to_string())
        .bind(rootfs.source_kind.as_str())
        .bind(&rootfs.requested_reference)
        .bind(&rootfs.selected_reference)
        .bind(&rootfs.manifest_digest)
        .bind(&rootfs.config_digest)
        .bind(&rootfs.image_id)
        .bind(rootfs.created_at)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    fn validate_machine_id_prefix(prefix: &str) -> Result<(), LibVmError> {
        let valid_length = prefix.len() >= 3 && prefix.len() <= 32;
        let normalized_hex = prefix
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'));
        if valid_length && normalized_hex {
            return Ok(());
        }

        let reason = if prefix.len() < 3 {
            "prefix must be at least 3 characters".to_string()
        } else if prefix.len() > 32 {
            "prefix must be at most 32 characters".to_string()
        } else {
            "prefix must be normalized lowercase hex".to_string()
        };
        Err(LibVmError::InvalidMachineIdPrefix {
            prefix: prefix.to_string(),
            reason,
        })
    }

    fn map_add_machine_error(err: sqlx::Error, name: &str) -> LibVmError {
        match err {
            sqlx::Error::Database(db_err) => {
                if Self::is_machine_name_unique_violation(db_err.as_ref()) {
                    return LibVmError::MachineAlreadyExists {
                        name: name.to_string(),
                    };
                }

                sqlx::Error::Database(db_err).into()
            }
            other => other.into(),
        }
    }

    fn is_machine_name_unique_violation(err: &(dyn sqlx::error::DatabaseError + 'static)) -> bool {
        err.constraint() == Some("machine_config.name")
            || err
                .message()
                .contains("UNIQUE constraint failed: machine_config.name")
    }

    pub(crate) fn serialize<T>(field: &'static str, value: &T) -> Result<String, LibVmError>
    where
        T: serde::Serialize,
    {
        serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
            name: field.to_string(),
            reason: format!("serialize {field}: {err}"),
        })
    }
}

fn machine_rootfs_from_row(
    row: sqlx::sqlite::SqliteRow,
    home: &std::path::Path,
) -> Result<MachineRootfsRecord, LibVmError> {
    let source_kind: String = row.try_get("source_kind")?;
    let source_kind = match source_kind.as_str() {
        "oci" => crate::ImageSourceKind::Oci,
        "disk" => crate::ImageSourceKind::Disk,
        _ => {
            return Err(LibVmError::StateDecode {
                field: "machine_rootfs.source_kind",
                message: format!("unknown image source kind {source_kind:?}"),
            });
        }
    };
    let storage = crate::MachineStorageRecord::decode(&row.try_get::<String, _>("storage_json")?)?;
    let (path, length) = match storage.root {
        crate::MachineRoot::OpaqueRaw { path, geometry, .. } => (path, geometry.length),
        crate::MachineRoot::LinuxOverlay {
            upper, capacity, ..
        } => (upper, capacity),
    };
    let machine_id = row
        .try_get::<String, _>("machine_id")?
        .parse::<MachineId>()
        .map_err(|error| LibVmError::StateDecode {
            field: "machine_rootfs.machine_id",
            message: error.to_string(),
        })?;
    let machine_dir = crate::paths::machine_data_dir_in(home, machine_id);
    Ok(MachineRootfsRecord {
        machine_id,
        source_kind,
        requested_reference: row.try_get("requested_reference")?,
        selected_reference: row.try_get("selected_reference")?,
        manifest_digest: row.try_get("manifest_digest")?,
        config_digest: row.try_get("config_digest")?,
        image_id: row.try_get("image_id")?,
        root_disk_path: machine_dir.join(path.as_path()),
        root_disk_size_bytes: length,
        created_at: row.try_get("created_at")?,
    })
}
