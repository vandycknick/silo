use std::error::Error;
use std::str::FromStr;

use sqlx::sqlite::SqliteRow;
use sqlx::{FromRow, Row};

use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineRuntimeState, MachineState, NetworkAttachment, NetworkDefinition,
    NetworkDriverPreference, NetworkInstance, NetworkInstanceState,
};

pub(crate) struct DbMachineConfig(pub(crate) MachineConfig);
pub(crate) struct DbMachineState(pub(crate) MachineState);
pub(crate) struct DbNetworkAttachment(pub(crate) NetworkAttachment);
pub(crate) struct DbNetworkInstance(pub(crate) NetworkInstance);
pub(crate) struct DbNetworkDefinition(pub(crate) NetworkDefinition);

impl<'row> FromRow<'row, SqliteRow> for DbMachineConfig {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        let id_str: String = row.try_get("id")?;
        let id = parse_machine_id(&id_str, "machine_config.id")?;
        let name: String = row.try_get("name")?;
        let config: MachineConfig =
            deserialize_json(row.try_get("config_json")?, "machine_config.config_json")?;
        if config.id != id {
            return Err(column_decode_error(
                "machine_config.config_json.id",
                std::io::Error::other(format!(
                    "config id {} does not match indexed id {}",
                    config.id, id
                )),
            ));
        }
        if config.name != name {
            return Err(column_decode_error(
                "machine_config.config_json.name",
                std::io::Error::other(format!(
                    "config name {:?} does not match indexed name {:?}",
                    config.name, name
                )),
            ));
        }
        Ok(Self(config))
    }
}

impl<'row> FromRow<'row, SqliteRow> for DbMachineState {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        let id_str: String = row.try_get("machine_id")?;
        let machine_id = parse_machine_id(&id_str, "machine_state.machine_id")?;
        let status_str: String = row.try_get("status")?;
        let status = MachineRuntimeState::parse(&status_str).map_err(|err| {
            column_decode_error("machine_state.status", std::io::Error::other(err))
        })?;
        let state: MachineState =
            deserialize_json(row.try_get("state_json")?, "machine_state.state_json")?;
        if state.machine_id != machine_id {
            return Err(column_decode_error(
                "machine_state.state_json.machineId",
                std::io::Error::other(format!(
                    "state machine_id {} does not match indexed machine_id {}",
                    state.machine_id, machine_id
                )),
            ));
        }
        if state.status != status {
            return Err(column_decode_error(
                "machine_state.state_json.status",
                std::io::Error::other(format!(
                    "state status {:?} does not match indexed status {:?}",
                    state.status, status
                )),
            ));
        }
        Ok(Self(state))
    }
}

impl<'row> FromRow<'row, SqliteRow> for DbNetworkAttachment {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        let id_str: String = row.try_get("machine_id")?;
        let machine_id = parse_machine_id(&id_str, "network_attachments.machine_id")?;
        Ok(Self(NetworkAttachment {
            machine_id,
            network_instance_id: row.try_get("network_instance_id")?,
            guest_mac: row.try_get("guest_mac")?,
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        }))
    }
}

impl<'row> FromRow<'row, SqliteRow> for DbNetworkInstance {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        Ok(Self(NetworkInstance {
            id: row.try_get("id")?,
            driver: row.try_get("driver")?,
            definition_name: row.try_get("definition_name")?,
            runtime_dir: row.try_get("runtime_dir")?,
            attachment_json: row.try_get("attachment_json")?,
            driver_state_json: row.try_get("driver_state_json")?,
            state: parse_network_instance_state(row.try_get("state")?)?,
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        }))
    }
}

impl<'row> FromRow<'row, SqliteRow> for DbNetworkDefinition {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        let name: String = row.try_get("name")?;
        let topology = deserialize_json(row.try_get("mode")?, "network_definitions.mode")?;
        let driver_preference: NetworkDriverPreference = deserialize_json(
            row.try_get("driver_preference")?,
            "network_definitions.driver_preference",
        )?;
        Ok(Self(NetworkDefinition {
            name,
            topology,
            driver_preference,
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        }))
    }
}

fn parse_machine_id(value: &str, field: &'static str) -> sqlx::Result<MachineId> {
    MachineId::from_str(value).map_err(|err| column_decode_error(field, err))
}

fn parse_network_instance_state(value: String) -> sqlx::Result<NetworkInstanceState> {
    NetworkInstanceState::parse(&value)
        .map_err(|err| column_decode_error("network_instances.state", std::io::Error::other(err)))
}

fn deserialize_json<T>(value: String, field: &'static str) -> sqlx::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(&value).map_err(|err| column_decode_error(field, err))
}

fn column_decode_error(
    field: &'static str,
    source: impl Error + Send + Sync + 'static,
) -> sqlx::Error {
    sqlx::Error::ColumnDecode {
        index: field.to_string(),
        source: Box::new(source),
    }
}
