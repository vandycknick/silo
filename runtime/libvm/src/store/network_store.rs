use async_trait::async_trait;

use crate::store::models::MachineId;
use crate::store::models::{NetworkAttachment, NetworkDefinition, NetworkInstance};
use crate::store::row::{DbNetworkAttachment, DbNetworkDefinition, DbNetworkInstance};
use crate::store::{NetworkStore, Store};
use crate::utils::now_unix;
use crate::LibVmError;

#[async_trait]
impl NetworkStore for Store {
    async fn network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<NetworkAttachment>, LibVmError> {
        let attachment = sqlx::query_as::<_, DbNetworkAttachment>(
            "SELECT machine_id, network_instance_id, guest_mac, created_at, modified_at
             FROM network_attachments WHERE machine_id = ?1",
        )
        .bind(machine_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(attachment.map(|DbNetworkAttachment(attachment)| attachment))
    }

    async fn network_instance(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        let instance = sqlx::query_as::<_, DbNetworkInstance>(
            "SELECT id, driver, definition_name, runtime_dir, json(attachment_json) AS attachment_json,
                    json(driver_state_json) AS driver_state_json, state, created_at, modified_at
             FROM network_instances WHERE id = ?1",
        )
        .bind(network_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(instance.map(|DbNetworkInstance(instance)| instance))
    }

    async fn save_network_instance(&self, instance: &NetworkInstance) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO network_instances
                (id, driver, definition_name, runtime_dir, attachment_json, driver_state_json,
                 state, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, jsonb(?5), jsonb(?6), ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                driver = excluded.driver,
                definition_name = excluded.definition_name,
                runtime_dir = excluded.runtime_dir,
                attachment_json = excluded.attachment_json,
                driver_state_json = excluded.driver_state_json,
                state = excluded.state,
                modified_at = excluded.modified_at",
        )
        .bind(&instance.id)
        .bind(&instance.driver)
        .bind(&instance.definition_name)
        .bind(&instance.runtime_dir)
        .bind(&instance.attachment_json)
        .bind(&instance.driver_state_json)
        .bind(instance.state.as_str())
        .bind(instance.created_at)
        .bind(instance.modified_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn attach_network(&self, attachment: &NetworkAttachment) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO network_attachments
                (machine_id, network_instance_id, guest_mac, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(machine_id) DO UPDATE SET
                network_instance_id = excluded.network_instance_id,
                guest_mac = excluded.guest_mac,
                modified_at = excluded.modified_at",
        )
        .bind(attachment.machine_id.to_string())
        .bind(&attachment.network_instance_id)
        .bind(&attachment.guest_mac)
        .bind(attachment.created_at)
        .bind(attachment.modified_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn detach_network(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM network_attachments WHERE machine_id = ?1")
            .bind(machine_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM network_instances WHERE id = ?1")
            .bind(network_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn network_instance_by_definition(
        &self,
        definition_name: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        let instance = sqlx::query_as::<_, DbNetworkInstance>(
            "SELECT id, driver, definition_name, runtime_dir, json(attachment_json) AS attachment_json,
                    json(driver_state_json) AS driver_state_json, state, created_at, modified_at
             FROM network_instances WHERE definition_name = ?1",
        )
        .bind(definition_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(instance.map(|DbNetworkInstance(instance)| instance))
    }

    async fn network_attachment_count(&self, network_id: &str) -> Result<u32, LibVmError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM network_attachments WHERE network_instance_id = ?1",
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;
        u32::try_from(count).map_err(|err| LibVmError::StateDecode {
            field: "network_attachments.count",
            message: err.to_string(),
        })
    }

    async fn define_network(&self, definition: &NetworkDefinition) -> Result<(), LibVmError> {
        let now = now_unix();
        sqlx::query(
            "INSERT INTO network_definitions (name, mode, driver_preference, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                mode = excluded.mode,
                driver_preference = excluded.driver_preference,
                modified_at = excluded.modified_at",
        )
        .bind(&definition.name)
        .bind(Self::serialize_definition_field(
            definition,
            "network topology",
            &definition.topology,
        )?)
        .bind(Self::serialize_definition_field(
            definition,
            "network driver preference",
            &definition.driver_preference,
        )?)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError> {
        let rows = sqlx::query_as::<_, DbNetworkDefinition>(
            "SELECT name, mode, driver_preference, created_at, modified_at
             FROM network_definitions ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|DbNetworkDefinition(definition)| definition)
            .collect())
    }

    async fn network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinition>, LibVmError> {
        let definition = sqlx::query_as::<_, DbNetworkDefinition>(
            "SELECT name, mode, driver_preference, created_at, modified_at
             FROM network_definitions WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(definition.map(|DbNetworkDefinition(definition)| definition))
    }

    async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM network_definitions WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl Store {
    fn serialize_definition_field<T>(
        definition: &NetworkDefinition,
        field: &str,
        value: &T,
    ) -> Result<String, LibVmError>
    where
        T: serde::Serialize,
    {
        serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
            name: definition.name.clone(),
            reason: format!("serialize {field}: {err}"),
        })
    }
}
