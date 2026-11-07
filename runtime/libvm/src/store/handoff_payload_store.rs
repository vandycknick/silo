//! Bulk roots and machine publication for stopped handoff transfer.
//!
//! One `storage_operation` row of kind `relocate` per handoff, keyed by the
//! ledger's operation UUID, pins every immutable object, stream, received
//! chunk and document the operation needs. The ownership ledger, not the
//! process lease, decides when those pins may be retired.

use sqlx::{Row, Sqlite, Transaction};

use crate::handoff::types::OperationId;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::store::models::{MachineConfig, MachineRootfsRecord, MachineState};
use crate::store::Store;
use crate::{LibVmError, MachineId, MachineStorageRecord};

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "handoff-storage",
        message: message.to_string(),
    }
}

/// Whether the destination machine record is created or replaces the fenced
/// prior-owner record of a direct return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandoffPublication {
    Create,
    ReplacePriorOwner,
}

impl Store {
    /// Register, or rejoin after a restart, the handoff's bulk root. The
    /// returned shared OFD must stay open while this process uses the pins.
    pub(crate) async fn begin_handoff_storage(
        &self,
        operation: OperationId,
    ) -> Result<StorageLock, LibVmError> {
        let id = operation.as_uuid();
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let row = sqlx::query(
            "SELECT kind,state,file_device,file_inode FROM storage_operation WHERE operation_id=?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            let kind: String = row.try_get("kind")?;
            let state: String = row.try_get("state")?;
            if kind != "relocate" || state != "staging" {
                return Err(invalid(
                    "handoff bulk root is not an active relocate operation",
                ));
            }
            let lease = pool.existing_lease(id)?;
            let (device, inode) = lease.file_identity()?;
            if row.try_get::<String, _>("file_device")? != device.to_string()
                || row.try_get::<String, _>("file_inode")? != inode.to_string()
            {
                return Err(invalid("handoff operation lease was replaced"));
            }
            return Ok(lease);
        }
        let lease = match pool.lease(id) {
            Ok(lease) => lease,
            // A retired row may leave its stable lease file; rejoin it.
            Err(_) => pool.existing_lease(id)?,
        };
        let (device, inode) = lease.file_identity()?;
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'relocate','staging',?2,?3,jsonb('{}'))")
            .bind(id.to_string())
            .bind(device.to_string())
            .bind(inode.to_string())
            .execute(&self.pool)
            .await?;
        Ok(lease)
    }

    /// Pin already published pool members. The caller keeps the publication
    /// roots guard of any member it just published through this commit.
    pub(crate) async fn pin_handoff_dependencies(
        &self,
        operation: OperationId,
        streams: &[StreamId],
        objects: &[ObjectDigest],
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='relocate' AND state='staging')")
            .bind(operation.to_string())
            .fetch_one(&mut *tx)
            .await?;
        if !active {
            return Err(invalid("handoff dependency has no active bulk root"));
        }
        for stream in streams {
            crate::store::operation_store::insert_stream(&mut tx, operation.as_uuid(), stream)
                .await?;
        }
        for object in objects {
            sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) VALUES(?1,?2)")
                .bind(operation.to_string())
                .bind(object.to_string())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Terminal decisions release bulk pins to ordinary collection. The ledger
    /// row keeps the replay guard; this only marks the bulk root finished.
    pub(crate) async fn finish_handoff_storage(
        &self,
        operation: OperationId,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        sqlx::query("UPDATE storage_operation SET state='committed',record_json=jsonb('{}') WHERE operation_id=?1 AND kind='relocate' AND state IN ('staging','committed')")
            .bind(operation.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Run `discard` while one write transaction proves `machine` has no
    /// catalog record and no other unresolved destination handoff targets it.
    /// Publishing that machine or receiving another operation for it needs
    /// the same write lock, so neither can interleave with `discard`.
    /// Returns whether `discard` ran.
    pub(crate) async fn discard_unpublished_handoff_machine(
        &self,
        operation: OperationId,
        machine: MachineId,
        discard: impl FnOnce() -> Result<(), LibVmError>,
    ) -> Result<bool, LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let published: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_config WHERE id=?1)")
                .bind(machine.to_string())
                .fetch_one(&mut *tx)
                .await?;
        let contended: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM handoff_operation WHERE destination_machine=?1 AND role='destination' AND terminal=0 AND operation_id<>?2)")
            .bind(machine.to_string())
            .bind(operation.to_string())
            .fetch_one(&mut *tx)
            .await?;
        if published || contended {
            tx.rollback().await?;
            return Ok(false);
        }
        discard()?;
        tx.rollback().await?;
        Ok(true)
    }

    /// Whether this operation's bulk root pins `object`.
    #[cfg(test)]
    pub(crate) async fn handoff_pins_object(
        &self,
        operation: OperationId,
        object: &ObjectDigest,
    ) -> Result<bool, LibVmError> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_object WHERE operation_id=?1 AND object_digest=?2)")
            .bind(operation.to_string())
            .bind(object.to_string())
            .fetch_one(&self.pool)
            .await?)
    }

    /// Write a complete stopped destination machine inside the ledger's
    /// destination-commit transaction. Never commits by itself.
    pub(crate) async fn publish_handoff_machine(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        publication: HandoffPublication,
        config: &MachineConfig,
        state: &MachineState,
        rootfs: &MachineRootfsRecord,
        storage: &MachineStorageRecord,
    ) -> Result<(), LibVmError> {
        if state.machine_id != config.id || rootfs.machine_id != config.id {
            return Err(invalid(
                "handoff publication records name different machines",
            ));
        }
        storage.validate()?;
        let machine_dir = crate::paths::machine_data_dir_in(&self.home, config.id);
        let (root, length) = crate::machine::stopped::root_private(storage);
        if machine_dir.join(root.as_path()) != rootfs.root_disk_path
            || length != rootfs.root_disk_size_bytes
        {
            return Err(invalid("root provenance differs from the published root"));
        }
        let paths = crate::store::cache_paths::ConfigurationPaths::new(config, &self.home)?;
        self.check_cleaning_dependencies(tx, &paths).await?;
        let config_json = Self::serialize("machine_config.config_json", config)?;
        let state_json = Self::serialize("machine_state.state_json", state)?;
        match publication {
            HandoffPublication::Create => {
                sqlx::query(
                    "INSERT INTO machine_config (id, name, config_json) VALUES (?1, ?2, jsonb(?3))",
                )
                .bind(config.id.to_string())
                .bind(&config.name)
                .bind(config_json)
                .execute(&mut **tx)
                .await
                .map_err(|error| match error {
                    sqlx::Error::Database(database)
                        if database.message().contains("machine_config.name") =>
                    {
                        LibVmError::MachineAlreadyExists {
                            name: config.name.clone(),
                        }
                    }
                    other => other.into(),
                })?;
                sqlx::query("INSERT INTO machine_state (machine_id, status, state_json) VALUES (?1, ?2, jsonb(?3))")
                    .bind(config.id.to_string())
                    .bind(state.status.as_str())
                    .bind(state_json)
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("INSERT INTO machine_rootfs (machine_id, source_kind, requested_reference, selected_reference, manifest_digest, config_digest, image_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
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
            }
            HandoffPublication::ReplacePriorOwner => {
                let changed = sqlx::query(
                    "UPDATE machine_config SET name=?1, config_json=jsonb(?2) WHERE id=?3",
                )
                .bind(&config.name)
                .bind(config_json)
                .bind(config.id.to_string())
                .execute(&mut **tx)
                .await?;
                let state_changed = sqlx::query(
                    "UPDATE machine_state SET status=?1, state_json=jsonb(?2) WHERE machine_id=?3",
                )
                .bind(state.status.as_str())
                .bind(state_json)
                .bind(config.id.to_string())
                .execute(&mut **tx)
                .await?;
                let rootfs_changed = sqlx::query("UPDATE machine_rootfs SET source_kind=?1, requested_reference=?2, selected_reference=?3, manifest_digest=?4, config_digest=?5, image_id=?6 WHERE machine_id=?7")
                    .bind(rootfs.source_kind.as_str())
                    .bind(&rootfs.requested_reference)
                    .bind(&rootfs.selected_reference)
                    .bind(&rootfs.manifest_digest)
                    .bind(&rootfs.config_digest)
                    .bind(&rootfs.image_id)
                    .bind(rootfs.machine_id.to_string())
                    .execute(&mut **tx)
                    .await?;
                if changed.rows_affected() != 1
                    || state_changed.rows_affected() != 1
                    || rootfs_changed.rows_affected() != 1
                {
                    return Err(invalid("prior-owner record is incomplete"));
                }
            }
        }
        Self::write_machine_storage(tx, config.id, storage).await
    }
}
