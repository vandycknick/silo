use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use bento_core::MachineId;
use rusqlite::{params, Connection, OptionalExtension};

use crate::network::config::{NetworkDefinitionSpec, RequestedNetwork};
use crate::state::migrations::run_migrations;
use crate::state::models::{
    MachineState, NetworkAttachmentState, NetworkDefinitionState, NetworkInstanceState,
};
use crate::{Layout, LibVmError};

const MACHINE_COLUMNS: &str =
    "id, name, instance_dir, created_at, modified_at, image_ref, json(labels), json(metadata), json(network)";

pub(crate) struct StateStore {
    conn: Connection,
}

impl StateStore {
    pub(crate) fn open(layout: &Layout) -> Result<Self, LibVmError> {
        std::fs::create_dir_all(layout.data_dir())?;
        let conn = open_connection(&layout.state_db_path())?;
        run_migrations(&conn)?;
        Ok(Self { conn })
    }

    pub(crate) fn insert_machine(&self, machine: &MachineState) -> Result<(), LibVmError> {
        self.conn.execute(
            "INSERT INTO machines (id, name, instance_dir, created_at, modified_at, image_ref, labels, metadata, network)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, jsonb(?7), jsonb(?8), jsonb(?9))",
            params![
                machine.id.to_string(),
                machine.name,
                machine.instance_dir,
                machine.created_at,
                machine.modified_at,
                machine.image_ref,
                serialize_map("labels", &machine.labels)?,
                serialize_map("metadata", &machine.metadata)?,
                serialize_network(&machine.network)?,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn update_machine_network(
        &self,
        machine_id: MachineId,
        network: &RequestedNetwork,
    ) -> Result<(), LibVmError> {
        self.conn.execute(
            "UPDATE machines SET network = jsonb(?1), modified_at = ?2 WHERE id = ?3",
            params![
                serialize_network(network)?,
                now_unix(),
                machine_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub(crate) fn get_machine_by_id(
        &self,
        id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError> {
        self.conn
            .query_row(
                &format!("SELECT {MACHINE_COLUMNS} FROM machines WHERE id = ?1"),
                params![id.to_string()],
                row_to_machine_state,
            )
            .optional()
            .map_err(LibVmError::from)
    }

    pub(crate) fn get_machine_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineState>, LibVmError> {
        self.conn
            .query_row(
                &format!("SELECT {MACHINE_COLUMNS} FROM machines WHERE name = ?1"),
                params![name],
                row_to_machine_state,
            )
            .optional()
            .map_err(LibVmError::from)
    }

    pub(crate) fn get_machine_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineState>, LibVmError> {
        let pattern = format!("{prefix}%");
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines WHERE id LIKE ?1"
        ))?;
        let rows = stmt.query_map(params![pattern], row_to_machine_state)?;
        let mut machines = Vec::new();
        for row in rows {
            machines.push(row?);
        }
        Ok(machines)
    }

    pub(crate) fn list_machines(&self) -> Result<Vec<MachineState>, LibVmError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines ORDER BY name"
        ))?;
        let rows = stmt.query_map([], row_to_machine_state)?;
        let mut machines = Vec::new();
        for row in rows {
            machines.push(row?);
        }
        Ok(machines)
    }

    pub(crate) fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        for index in 1..10_000u32 {
            let candidate = format!("{prefix}-{index}");
            if self.get_machine_by_name(&candidate)?.is_none() {
                return Ok(candidate);
            }
        }

        Err(LibVmError::InvalidMachineName {
            name: prefix.to_string(),
            reason: "failed to allocate ephemeral VM name".to_string(),
        })
    }

    pub(crate) fn remove_machine(&self, machine: &MachineState) -> Result<(), LibVmError> {
        self.conn.execute(
            "DELETE FROM machines WHERE id = ?1",
            params![machine.id.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn get_network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<NetworkAttachmentState>, LibVmError> {
        self.conn
            .query_row(
                "SELECT machine_id, network_instance_id, guest_mac, created_at, modified_at
                 FROM network_attachments WHERE machine_id = ?1",
                params![machine_id.to_string()],
                row_to_network_attachment,
            )
            .optional()
            .map_err(LibVmError::from)
    }

    pub(crate) fn get_network_instance(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkInstanceState>, LibVmError> {
        self.conn
            .query_row(
                "SELECT id, driver, definition_name, runtime_dir, json(attachment_json),
                        json(driver_state_json), state, created_at, modified_at
                 FROM network_instances WHERE id = ?1",
                params![network_id],
                row_to_network_instance,
            )
            .optional()
            .map_err(LibVmError::from)
    }

    pub(crate) fn upsert_network_instance(
        &self,
        instance: &NetworkInstanceState,
    ) -> Result<(), LibVmError> {
        self.conn.execute(
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
            params![
                instance.id,
                instance.driver,
                instance.definition_name,
                instance.runtime_dir,
                instance.attachment_json,
                instance.driver_state_json,
                instance.state,
                instance.created_at,
                instance.modified_at,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn upsert_network_attachment(
        &self,
        attachment: &NetworkAttachmentState,
    ) -> Result<(), LibVmError> {
        self.conn.execute(
            "INSERT INTO network_attachments
                (machine_id, network_instance_id, guest_mac, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(machine_id) DO UPDATE SET
                network_instance_id = excluded.network_instance_id,
                guest_mac = excluded.guest_mac,
                modified_at = excluded.modified_at",
            params![
                attachment.machine_id.to_string(),
                attachment.network_instance_id,
                attachment.guest_mac,
                attachment.created_at,
                attachment.modified_at,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn remove_network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<(), LibVmError> {
        self.conn.execute(
            "DELETE FROM network_attachments WHERE machine_id = ?1",
            params![machine_id.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError> {
        self.conn.execute(
            "DELETE FROM network_instances WHERE id = ?1",
            params![network_id],
        )?;
        Ok(())
    }

    pub(crate) fn get_network_instance_by_definition(
        &self,
        definition_name: &str,
    ) -> Result<Option<NetworkInstanceState>, LibVmError> {
        self.conn
            .query_row(
                "SELECT id, driver, definition_name, runtime_dir, json(attachment_json),
                        json(driver_state_json), state, created_at, modified_at
                 FROM network_instances WHERE definition_name = ?1",
                params![definition_name],
                row_to_network_instance,
            )
            .optional()
            .map_err(LibVmError::from)
    }

    pub(crate) fn count_network_attachments(&self, network_id: &str) -> Result<u32, LibVmError> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM network_attachments WHERE network_instance_id = ?1",
            params![network_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub(crate) fn upsert_network_definition(
        &self,
        definition: &NetworkDefinitionSpec,
    ) -> Result<(), LibVmError> {
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO network_definitions (name, mode, driver_preference, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                mode = excluded.mode,
                driver_preference = excluded.driver_preference,
                modified_at = excluded.modified_at",
            params![
                definition.name,
                serde_json::to_string(&definition.mode).map_err(|err| {
                    LibVmError::InvalidCreateRequest {
                        name: definition.name.clone(),
                        reason: format!("serialize network mode: {err}"),
                    }
                })?,
                serde_json::to_string(&definition.driver_preference).map_err(|err| {
                    LibVmError::InvalidCreateRequest {
                        name: definition.name.clone(),
                        reason: format!("serialize network driver preference: {err}"),
                    }
                })?,
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn list_network_definitions(
        &self,
    ) -> Result<Vec<NetworkDefinitionSpec>, LibVmError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, mode, driver_preference, created_at, modified_at
             FROM network_definitions ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_network_definition)?;
        let mut definitions = Vec::new();
        for row in rows {
            definitions.push(network_definition_spec_from_state(&row?)?);
        }
        Ok(definitions)
    }

    pub(crate) fn get_network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinitionSpec>, LibVmError> {
        self.conn
            .query_row(
                "SELECT name, mode, driver_preference, created_at, modified_at
                 FROM network_definitions WHERE name = ?1",
                params![name],
                row_to_network_definition,
            )
            .optional()
            .map_err(LibVmError::from)?
            .map(|state| network_definition_spec_from_state(&state))
            .transpose()
    }

    pub(crate) fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        self.conn.execute(
            "DELETE FROM network_definitions WHERE name = ?1",
            params![name],
        )?;
        Ok(())
    }
}

fn open_connection(path: &Path) -> Result<Connection, LibVmError> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn row_to_machine_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<MachineState> {
    let id_str: String = row.get(0)?;
    let id: MachineId = id_str.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let labels = deserialize_map(row, 6)?;
    let metadata = deserialize_map(row, 7)?;
    let network = deserialize_network(row, 8)?;
    Ok(MachineState {
        id,
        name: row.get(1)?,
        instance_dir: row.get(2)?,
        created_at: row.get(3)?,
        modified_at: row.get(4)?,
        image_ref: row.get(5)?,
        labels,
        metadata,
        network,
    })
}

fn serialize_map(
    field: &'static str,
    values: &BTreeMap<String, String>,
) -> Result<String, LibVmError> {
    serde_json::to_string(values).map_err(|err| LibVmError::InvalidCreateRequest {
        name: field.to_string(),
        reason: format!("serialize {field}: {err}"),
    })
}

fn serialize_network(network: &RequestedNetwork) -> Result<String, LibVmError> {
    serde_json::to_string(network).map_err(|err| LibVmError::InvalidCreateRequest {
        name: "network".to_string(),
        reason: format!("serialize network: {err}"),
    })
}

fn row_to_network_definition(row: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkDefinitionState> {
    Ok(NetworkDefinitionState {
        name: row.get(0)?,
        mode: row.get(1)?,
        driver_preference: row.get(2)?,
        created_at: row.get(3)?,
        modified_at: row.get(4)?,
    })
}

fn network_definition_spec_from_state(
    state: &NetworkDefinitionState,
) -> Result<NetworkDefinitionSpec, LibVmError> {
    let mode =
        serde_json::from_str(&state.mode).map_err(|err| LibVmError::InvalidCreateRequest {
            name: state.name.clone(),
            reason: format!("parse network definition mode: {err}"),
        })?;
    let driver_preference = serde_json::from_str(&state.driver_preference).map_err(|err| {
        LibVmError::InvalidCreateRequest {
            name: state.name.clone(),
            reason: format!("parse network driver preference: {err}"),
        }
    })?;
    Ok(NetworkDefinitionSpec {
        name: state.name.clone(),
        mode,
        driver_preference,
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn deserialize_map(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<BTreeMap<String, String>> {
    let value: String = row.get(index)?;
    serde_json::from_str(&value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn deserialize_network(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<RequestedNetwork> {
    let value: String = row.get(index)?;
    serde_json::from_str(&value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn row_to_network_instance(row: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkInstanceState> {
    Ok(NetworkInstanceState {
        id: row.get(0)?,
        driver: row.get(1)?,
        definition_name: row.get(2)?,
        runtime_dir: row.get(3)?,
        attachment_json: row.get(4)?,
        driver_state_json: row.get(5)?,
        state: row.get(6)?,
        created_at: row.get(7)?,
        modified_at: row.get(8)?,
    })
}

fn row_to_network_attachment(row: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkAttachmentState> {
    let id_str: String = row.get(0)?;
    let machine_id: MachineId = id_str.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })?;
    Ok(NetworkAttachmentState {
        machine_id,
        network_instance_id: row.get(1)?,
        guest_mac: row.get(2)?,
        created_at: row.get(3)?,
        modified_at: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bento_core::MachineId;

    use crate::network::config::RequestedNetwork;
    use crate::state::{machine_state_from_path, NetworkAttachmentState, NetworkInstanceState};
    use crate::Layout;

    use super::StateStore;

    fn temp_layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let layout = Layout::new(dir.path());
        (dir, layout)
    }

    #[test]
    fn insert_and_lookup_by_name() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata = machine_state_from_path(id, "devbox".to_string(), &layout.instance_dir(id));

        store.insert_machine(&metadata).expect("insert");
        let found = store
            .get_machine_by_name("devbox")
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[test]
    fn insert_and_lookup_by_id() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata = machine_state_from_path(id, "testvm".to_string(), &layout.instance_dir(id));

        store.insert_machine(&metadata).expect("insert");
        let found = store
            .get_machine_by_id(id)
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[test]
    fn lookup_by_id_prefix() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata =
            machine_state_from_path(id, "prefix-test".to_string(), &layout.instance_dir(id));

        store.insert_machine(&metadata).expect("insert");

        let id_str = id.to_string();
        let prefix = &id_str[..8];
        let found = store.get_machine_by_id_prefix(prefix).expect("lookup");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0], metadata);
    }

    #[test]
    fn labels_metadata_and_network_round_trip_as_jsonb_blobs() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let mut labels = BTreeMap::new();
        labels.insert("owner".to_string(), "test".to_string());
        let mut metadata = BTreeMap::new();
        metadata.insert("bento.profile".to_string(), "rust-dev".to_string());

        let machine = crate::state::machine_state_from_path_with_details(
            id,
            "jsonb-test".to_string(),
            &layout.instance_dir(id),
            "test-image:latest".to_string(),
            labels,
            metadata,
            RequestedNetwork::default(),
        );

        store.insert_machine(&machine).expect("insert machine");
        let found = store
            .get_machine_by_id(id)
            .expect("lookup")
            .expect("machine exists");

        assert_eq!(found.labels.get("owner").map(String::as_str), Some("test"));
        assert_eq!(
            found.metadata.get("bento.profile").map(String::as_str),
            Some("rust-dev")
        );
        assert_eq!(found.network, RequestedNetwork::default());
        let storage_type: String = store
            .conn
            .query_row(
                "SELECT typeof(labels) FROM machines WHERE id = ?1",
                rusqlite::params![id.to_string()],
                |row| row.get(0),
            )
            .expect("query storage type");
        assert_eq!(storage_type, "blob");
    }

    #[test]
    fn list_machines_sorted_by_name() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");

        let id_b = MachineId::new();
        let id_a = MachineId::new();
        store
            .insert_machine(&machine_state_from_path(
                id_b,
                "bravo".to_string(),
                &layout.instance_dir(id_b),
            ))
            .expect("insert b");
        store
            .insert_machine(&machine_state_from_path(
                id_a,
                "alpha".to_string(),
                &layout.instance_dir(id_a),
            ))
            .expect("insert a");

        let list = store.list_machines().expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "bravo");
    }

    #[test]
    fn remove_machine() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata = machine_state_from_path(id, "gonner".to_string(), &layout.instance_dir(id));

        store.insert_machine(&metadata).expect("insert");
        store.remove_machine(&metadata).expect("remove");

        let found = store.get_machine_by_id(id).expect("lookup");
        assert!(found.is_none());
    }

    #[test]
    fn network_instance_and_attachment_round_trip_and_remove() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata = machine_state_from_path(id, "netbox".to_string(), &layout.instance_dir(id));
        store.insert_machine(&metadata).expect("insert machine");

        let network_id = "netbox-runtime".to_string();
        let instance = NetworkInstanceState {
            id: network_id.clone(),
            driver: "netd".to_string(),
            definition_name: None,
            runtime_dir: "/tmp/netbox-runtime".to_string(),
            attachment_json: r#"{"kind":"none"}"#.to_string(),
            driver_state_json: r#"{"helper_pid":1234}"#.to_string(),
            state: "running".to_string(),
            created_at: 41,
            modified_at: 42,
        };
        let attachment = NetworkAttachmentState {
            machine_id: id,
            network_instance_id: network_id.clone(),
            guest_mac: "02:11:22:33:44:55".to_string(),
            created_at: 43,
            modified_at: 44,
        };

        store
            .upsert_network_instance(&instance)
            .expect("upsert network instance");
        store
            .upsert_network_attachment(&attachment)
            .expect("upsert network attachment");
        assert_eq!(
            store
                .get_network_instance(&network_id)
                .expect("get network instance")
                .expect("network instance exists"),
            instance
        );
        assert_eq!(
            store
                .get_network_attachment(id)
                .expect("get network attachment")
                .expect("network attachment exists"),
            attachment
        );

        store
            .remove_network_attachment(id)
            .expect("remove network attachment");
        assert!(store
            .get_network_attachment(id)
            .expect("get network attachment")
            .is_none());
        store
            .remove_network_instance(&network_id)
            .expect("remove network instance");
        assert!(store
            .get_network_instance(&network_id)
            .expect("get network instance")
            .is_none());
    }

    #[test]
    fn created_at_columns_are_immutable() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");
        let id = MachineId::new();
        let metadata =
            machine_state_from_path(id, "immutable".to_string(), &layout.instance_dir(id));
        store.insert_machine(&metadata).expect("insert machine");

        let network_id = "immutable-runtime".to_string();
        store
            .upsert_network_instance(&NetworkInstanceState {
                id: network_id.clone(),
                driver: "netd".to_string(),
                definition_name: None,
                runtime_dir: "/tmp/immutable-runtime".to_string(),
                attachment_json: r#"{"kind":"none"}"#.to_string(),
                driver_state_json: r#"{"helper_pid":1234}"#.to_string(),
                state: "running".to_string(),
                created_at: 41,
                modified_at: 42,
            })
            .expect("insert network instance");
        store
            .upsert_network_attachment(&NetworkAttachmentState {
                machine_id: id,
                network_instance_id: network_id.clone(),
                guest_mac: "02:11:22:33:44:55".to_string(),
                created_at: 43,
                modified_at: 44,
            })
            .expect("insert network attachment");

        let result = store.conn.execute(
            "UPDATE machines SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![metadata.created_at + 1, id.to_string()],
        );
        assert!(result.is_err(), "created_at update should be rejected");
        let result = store.conn.execute(
            "UPDATE network_instances SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![42, network_id],
        );
        assert!(result.is_err(), "created_at update should be rejected");
        let result = store.conn.execute(
            "UPDATE network_attachments SET created_at = ?1 WHERE machine_id = ?2",
            rusqlite::params![44, id.to_string()],
        );
        assert!(result.is_err(), "created_at update should be rejected");
    }

    #[test]
    fn duplicate_name_fails() {
        let (_dir, layout) = temp_layout();
        let store = StateStore::open(&layout).expect("open store");

        let id1 = MachineId::new();
        let id2 = MachineId::new();
        store
            .insert_machine(&machine_state_from_path(
                id1,
                "dupe".to_string(),
                &layout.instance_dir(id1),
            ))
            .expect("insert first");

        let result = store.insert_machine(&machine_state_from_path(
            id2,
            "dupe".to_string(),
            &layout.instance_dir(id2),
        ));
        assert!(result.is_err(), "duplicate name should fail");
    }

    #[test]
    fn concurrent_connections_work() {
        let (_dir, layout) = temp_layout();
        let store1 = StateStore::open(&layout).expect("open store 1");
        let store2 = StateStore::open(&layout).expect("open store 2");

        let id = MachineId::new();
        store1
            .insert_machine(&machine_state_from_path(
                id,
                "shared".to_string(),
                &layout.instance_dir(id),
            ))
            .expect("insert via store1");

        let found = store2
            .get_machine_by_name("shared")
            .expect("lookup via store2")
            .expect("should find machine from other connection");

        assert_eq!(found.id, id);
    }
}
