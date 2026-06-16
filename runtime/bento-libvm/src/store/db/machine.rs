use crate::store::db::json;
use crate::store::db::Sqlite;
use crate::store::models::MachineId;
use crate::store::models::{MachineConfig, MachineState};
use crate::store::wrappers::{DbMachineConfig, DbMachineState};
use crate::LibVmError;

const MACHINE_CONFIG_COLUMNS: &str = "id, name, json(config_json) AS config_json";
const MACHINE_STATE_COLUMNS: &str = "machine_id, status, json(state_json) AS state_json";

pub(super) async fn insert_config(db: &Sqlite, config: &MachineConfig) -> Result<(), LibVmError> {
    sqlx::query(
        "INSERT INTO machine_config (id, name, config_json)
         VALUES (?1, ?2, jsonb(?3))",
    )
    .bind(config.id.to_string())
    .bind(&config.name)
    .bind(json::serialize("machine_config.config_json", config)?)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn update_config(db: &Sqlite, config: &MachineConfig) -> Result<(), LibVmError> {
    sqlx::query(
        "UPDATE machine_config
         SET name = ?1, config_json = jsonb(?2)
         WHERE id = ?3",
    )
    .bind(&config.name)
    .bind(json::serialize("machine_config.config_json", config)?)
    .bind(config.id.to_string())
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn get_config_by_id(
    db: &Sqlite,
    id: MachineId,
) -> Result<Option<MachineConfig>, LibVmError> {
    let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE id = ?1");
    let machine = sqlx::query_as::<_, DbMachineConfig>(&query)
        .bind(id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    Ok(machine.map(|DbMachineConfig(machine)| machine))
}

pub(super) async fn get_config_by_name(
    db: &Sqlite,
    name: &str,
) -> Result<Option<MachineConfig>, LibVmError> {
    let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE name = ?1");
    let machine = sqlx::query_as::<_, DbMachineConfig>(&query)
        .bind(name)
        .fetch_optional(&db.pool)
        .await?;
    Ok(machine.map(|DbMachineConfig(machine)| machine))
}

pub(super) async fn get_config_by_id_prefix(
    db: &Sqlite,
    prefix: &str,
) -> Result<Vec<MachineConfig>, LibVmError> {
    let pattern = format!("{prefix}%");
    let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config WHERE id LIKE ?1");
    let rows = sqlx::query_as::<_, DbMachineConfig>(&query)
        .bind(pattern)
        .fetch_all(&db.pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|DbMachineConfig(machine)| machine)
        .collect())
}

pub(super) async fn list_configs(db: &Sqlite) -> Result<Vec<MachineConfig>, LibVmError> {
    let query = format!("SELECT {MACHINE_CONFIG_COLUMNS} FROM machine_config ORDER BY name");
    let rows = sqlx::query_as::<_, DbMachineConfig>(&query)
        .fetch_all(&db.pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|DbMachineConfig(machine)| machine)
        .collect())
}

pub(super) async fn allocate_ephemeral_name(
    db: &Sqlite,
    prefix: &str,
) -> Result<String, LibVmError> {
    for index in 1..10_000u32 {
        let candidate = format!("{prefix}-{index}");
        if get_config_by_name(db, &candidate).await?.is_none() {
            return Ok(candidate);
        }
    }

    Err(LibVmError::InvalidMachineName {
        name: prefix.to_string(),
        reason: "failed to allocate ephemeral VM name".to_string(),
    })
}

pub(super) async fn remove_config(db: &Sqlite, machine: &MachineConfig) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM machine_config WHERE id = ?1")
        .bind(machine.id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(super) async fn get_state(
    db: &Sqlite,
    machine_id: MachineId,
) -> Result<Option<MachineState>, LibVmError> {
    let query = format!("SELECT {MACHINE_STATE_COLUMNS} FROM machine_state WHERE machine_id = ?1");
    let state = sqlx::query_as::<_, DbMachineState>(&query)
        .bind(machine_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    Ok(state.map(|DbMachineState(state)| state))
}

pub(super) async fn upsert_state(db: &Sqlite, state: &MachineState) -> Result<(), LibVmError> {
    sqlx::query(
        "INSERT INTO machine_state (machine_id, status, state_json)
         VALUES (?1, ?2, jsonb(?3))
         ON CONFLICT(machine_id) DO UPDATE SET
             status = excluded.status,
             state_json = excluded.state_json",
    )
    .bind(state.machine_id.to_string())
    .bind(state.status.as_str())
    .bind(json::serialize("machine_state.state_json", state)?)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub(super) async fn remove_state(db: &Sqlite, machine_id: MachineId) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM machine_state WHERE machine_id = ?1")
        .bind(machine_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}
