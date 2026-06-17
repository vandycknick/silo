use crate::store::models::MachineId;
use crate::store::models::{MachineConfig, MachineState};
use crate::store::row::{DbMachineConfig, DbMachineState};
use crate::store::Store;
use crate::LibVmError;

const MACHINE_CONFIG_COLUMNS: &str = "id, name, json(config_json) AS config_json";
const MACHINE_STATE_COLUMNS: &str = "machine_id, status, json(state_json) AS state_json";

impl Store {
    pub(crate) async fn add_machine(
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
        sqlx::query(
            "INSERT INTO machine_config (id, name, config_json)
             VALUES (?1, ?2, jsonb(?3))",
        )
        .bind(config.id.to_string())
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO machine_state (machine_id, status, state_json)
             VALUES (?1, ?2, jsonb(?3))",
        )
        .bind(initial_state.machine_id.to_string())
        .bind(initial_state.status.as_str())
        .bind(Self::serialize("machine_state.state_json", initial_state)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn insert_machine_config(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_config (id, name, config_json)
             VALUES (?1, ?2, jsonb(?3))",
        )
        .bind(config.id.to_string())
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn machine_state(
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

    pub(crate) async fn save_machine_state(&self, state: &MachineState) -> Result<(), LibVmError> {
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

    #[cfg(test)]
    pub(crate) async fn remove_machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM machine_state WHERE machine_id = ?1")
            .bind(machine_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn save_machine_config(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        sqlx::query(
            "UPDATE machine_config
             SET name = ?1, config_json = jsonb(?2)
             WHERE id = ?3",
        )
        .bind(&config.name)
        .bind(Self::serialize("machine_config.config_json", config)?)
        .bind(config.id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn machine_config(
        &self,
        id: MachineId,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE id = ?1");
        let machine = sqlx::query_as::<_, DbMachineConfig>(&query)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(machine.map(|DbMachineConfig(machine)| machine))
    }

    pub(crate) async fn machine_config_by_name(
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

    pub(crate) async fn machine_configs_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError> {
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

    pub(crate) async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config ORDER BY name");
        let rows = sqlx::query_as::<_, DbMachineConfig>(&query)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|DbMachineConfig(machine)| machine)
            .collect())
    }

    pub(crate) async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        for index in 1..10_000u32 {
            let candidate = format!("{prefix}-{index}");
            if self.machine_config_by_name(&candidate).await?.is_none() {
                return Ok(candidate);
            }
        }

        Err(LibVmError::InvalidMachineName {
            name: prefix.to_string(),
            reason: "failed to allocate ephemeral VM name".to_string(),
        })
    }

    pub(crate) async fn remove_machine(&self, machine: &MachineConfig) -> Result<(), LibVmError> {
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

    fn serialize<T>(field: &'static str, value: &T) -> Result<String, LibVmError>
    where
        T: serde::Serialize,
    {
        serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
            name: field.to_string(),
            reason: format!("serialize {field}: {err}"),
        })
    }
}
