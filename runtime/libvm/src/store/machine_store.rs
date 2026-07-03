use async_trait::async_trait;

use crate::store::models::MachineId;
use crate::store::models::{MachineConfig, MachineRootfsRecord, MachineState};
use crate::store::row::{DbMachineConfig, DbMachineState};
use crate::store::{MachineStore, Store};
use crate::LibVmError;

const MACHINE_CONFIG_COLUMNS: &str = "id, name, json(config_json) AS config_json";
const MACHINE_STATE_COLUMNS: &str = "machine_id, status, json(state_json) AS state_json";

#[async_trait]
impl MachineStore for Store {
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

        let mut tx = self.pool.begin().await?;
        Self::insert_machine_config_and_state(&mut tx, config, initial_state).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn add_machine_with_rootfs(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
        rootfs: &MachineRootfsRecord,
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

        let mut tx = self.pool.begin().await?;
        Self::insert_machine_config_and_state(&mut tx, config, initial_state).await?;
        Self::insert_machine_rootfs(&mut tx, rootfs).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError> {
        let query =
            format!("SELECT {MACHINE_STATE_COLUMNS} FROM machine_state WHERE machine_id = ?1");
        let state = sqlx::query_as::<_, DbMachineState>(&query)
            .bind(machine_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(state.map(|DbMachineState(state)| state))
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

    async fn save_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        let result = sqlx::query(
            "UPDATE machine_config
             SET name = ?1, config_json = jsonb(?2)
             WHERE id = ?3",
        )
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .bind(config.id.to_string())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LibVmError::MachineNotFound {
                reference: config.id.to_string(),
            });
        }

        Ok(())
    }

    async fn machine_config(&self, id: MachineId) -> Result<Option<MachineConfig>, LibVmError> {
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE id = ?1");
        let machine = sqlx::query_as::<_, DbMachineConfig>(&query)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(machine.map(|DbMachineConfig(machine)| machine))
    }

    async fn machine_config_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE name = ?1");
        let machine = sqlx::query_as::<_, DbMachineConfig>(&query)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(machine.map(|DbMachineConfig(machine)| machine))
    }

    async fn machine_configs_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError> {
        Self::validate_machine_id_prefix(prefix)?;
        let pattern = format!("{prefix}%");
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE id LIKE ?1");
        let rows = sqlx::query_as::<_, DbMachineConfig>(&query)
            .bind(pattern)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|DbMachineConfig(machine)| machine)
            .collect())
    }

    async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config ORDER BY name");
        let rows = sqlx::query_as::<_, DbMachineConfig>(&query)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|DbMachineConfig(machine)| machine)
            .collect())
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
                (machine_id, source_kind, source_reference, manifest_digest, image_id,
                 root_disk_path, root_disk_size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(rootfs.machine_id.to_string())
        .bind(rootfs.source_kind.as_str())
        .bind(&rootfs.source_reference)
        .bind(&rootfs.manifest_digest)
        .bind(&rootfs.image_id)
        .bind(rootfs.root_disk_path.to_string_lossy().as_ref())
        .bind(Self::i64_from_u64(
            "machine_rootfs.root_disk_size_bytes",
            rootfs.root_disk_size_bytes,
        )?)
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

    fn serialize<T>(field: &'static str, value: &T) -> Result<String, LibVmError>
    where
        T: serde::Serialize,
    {
        serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
            name: field.to_string(),
            reason: format!("serialize {field}: {err}"),
        })
    }

    fn i64_from_u64(field: &'static str, value: u64) -> Result<i64, LibVmError> {
        i64::try_from(value).map_err(|_| LibVmError::StateDecode {
            field,
            message: format!("value {value} does not fit in i64"),
        })
    }
}
