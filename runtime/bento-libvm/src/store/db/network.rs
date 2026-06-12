use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{NetworkAttachment, NetworkDefinition, NetworkInstance};
use crate::store::db::Sqlite;
use crate::store::wrappers::{DbNetworkAttachment, DbNetworkDefinition, DbNetworkInstance};
use crate::{LibVmError, MachineId};

pub(super) async fn get_attachment(
    db: &Sqlite,
    machine_id: MachineId,
) -> Result<Option<NetworkAttachment>, LibVmError> {
    let attachment = sqlx::query_as::<_, DbNetworkAttachment>(
        "SELECT machine_id, network_instance_id, guest_mac, created_at, modified_at
         FROM network_attachments WHERE machine_id = ?1",
    )
    .bind(machine_id.to_string())
    .fetch_optional(&db.pool)
    .await?;
    Ok(attachment.map(|DbNetworkAttachment(attachment)| attachment))
}

pub(super) async fn get_instance(
    db: &Sqlite,
    network_id: &str,
) -> Result<Option<NetworkInstance>, LibVmError> {
    let instance = sqlx::query_as::<_, DbNetworkInstance>(
        "SELECT id, driver, definition_name, runtime_dir, json(attachment_json) AS attachment_json,
                json(driver_state_json) AS driver_state_json, state, created_at, modified_at
         FROM network_instances WHERE id = ?1",
    )
    .bind(network_id)
    .fetch_optional(&db.pool)
    .await?;
    Ok(instance.map(|DbNetworkInstance(instance)| instance))
}

pub(super) async fn upsert_instance(
    db: &Sqlite,
    instance: &NetworkInstance,
) -> Result<(), LibVmError> {
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
    .bind(&instance.state)
    .bind(instance.created_at)
    .bind(instance.modified_at)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn upsert_attachment(
    db: &Sqlite,
    attachment: &NetworkAttachment,
) -> Result<(), LibVmError> {
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
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn remove_attachment(
    db: &Sqlite,
    machine_id: MachineId,
) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM network_attachments WHERE machine_id = ?1")
        .bind(machine_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(super) async fn remove_instance(db: &Sqlite, network_id: &str) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM network_instances WHERE id = ?1")
        .bind(network_id)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(super) async fn get_instance_by_definition(
    db: &Sqlite,
    definition_name: &str,
) -> Result<Option<NetworkInstance>, LibVmError> {
    let instance = sqlx::query_as::<_, DbNetworkInstance>(
        "SELECT id, driver, definition_name, runtime_dir, json(attachment_json) AS attachment_json,
                json(driver_state_json) AS driver_state_json, state, created_at, modified_at
         FROM network_instances WHERE definition_name = ?1",
    )
    .bind(definition_name)
    .fetch_optional(&db.pool)
    .await?;
    Ok(instance.map(|DbNetworkInstance(instance)| instance))
}

pub(super) async fn count_attachments(db: &Sqlite, network_id: &str) -> Result<u32, LibVmError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_attachments WHERE network_instance_id = ?1",
    )
    .bind(network_id)
    .fetch_one(&db.pool)
    .await?;
    u32::try_from(count).map_err(|err| LibVmError::StateDecode {
        field: "network_attachments.count",
        message: err.to_string(),
    })
}

pub(super) async fn upsert_definition(
    db: &Sqlite,
    definition: &NetworkDefinition,
) -> Result<(), LibVmError> {
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
    .bind(serialize_definition_field(
        definition,
        "network mode",
        &definition.mode,
    )?)
    .bind(serialize_definition_field(
        definition,
        "network driver preference",
        &definition.driver_preference,
    )?)
    .bind(now)
    .bind(now)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn list_definitions(db: &Sqlite) -> Result<Vec<NetworkDefinition>, LibVmError> {
    let rows = sqlx::query_as::<_, DbNetworkDefinition>(
        "SELECT name, mode, driver_preference, created_at, modified_at
         FROM network_definitions ORDER BY name",
    )
    .fetch_all(&db.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|DbNetworkDefinition(definition)| definition)
        .collect())
}

pub(super) async fn get_definition(
    db: &Sqlite,
    name: &str,
) -> Result<Option<NetworkDefinition>, LibVmError> {
    let definition = sqlx::query_as::<_, DbNetworkDefinition>(
        "SELECT name, mode, driver_preference, created_at, modified_at
         FROM network_definitions WHERE name = ?1",
    )
    .bind(name)
    .fetch_optional(&db.pool)
    .await?;
    Ok(definition.map(|DbNetworkDefinition(definition)| definition))
}

pub(super) async fn remove_definition(db: &Sqlite, name: &str) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM network_definitions WHERE name = ?1")
        .bind(name)
        .execute(&db.pool)
        .await?;
    Ok(())
}

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

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
