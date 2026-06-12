use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

use crate::models::{
    MachineConfig, MachineState, NetworkAttachment, NetworkDefinition, NetworkInstance,
};
use crate::store::wrappers::{
    DbMachineConfig, DbMachineState, DbNetworkAttachment, DbNetworkDefinition, DbNetworkInstance,
};
use crate::store::Database;
use crate::{Layout, LibVmError, MachineId};

const STATE_SCHEMA_VERSION: i64 = 1;
const MACHINE_CONFIG_COLUMNS: &str = "id, name, json(config_json) AS config_json";
const MACHINE_STATE_COLUMNS: &str =
    "machine_id, status, json(state_json) AS state_json, updated_at";

#[derive(Debug, Clone)]
pub(crate) struct Sqlite {
    pool: SqlitePool,
}

impl Sqlite {
    async fn setup_db(pool: &SqlitePool, layout: &Layout) -> Result<(), LibVmError> {
        sqlx::migrate!("./migrations").run(pool).await?;
        validate_db_config(pool, layout).await?;
        Ok(())
    }
}

impl Database for Sqlite {
    type Settings = Layout;

    async fn new(layout: &Self::Settings) -> Result<Self, LibVmError> {
        std::fs::create_dir_all(layout.data_dir())?;
        let options = sqlite_options(&layout.state_db_path());
        let pool = SqlitePoolOptions::new()
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await?;
        Self::setup_db(&pool, layout).await?;
        Ok(Self { pool })
    }

    async fn insert_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_config (id, name, config_json, created_at, modified_at)
             VALUES (?1, ?2, jsonb(?3), ?4, ?5)",
        )
        .bind(config.id.to_string())
        .bind(&config.name)
        .bind(serialize_json("machine_config.config_json", config)?)
        .bind(config.created_at)
        .bind(config.modified_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_machine_state(
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

    async fn upsert_machine_state(&self, state: &MachineState) -> Result<(), LibVmError> {
        sqlx::query(
            "INSERT INTO machine_state (machine_id, status, state_json, updated_at)
             VALUES (?1, ?2, jsonb(?3), ?4)
             ON CONFLICT(machine_id) DO UPDATE SET
                status = excluded.status,
                state_json = excluded.state_json,
                updated_at = excluded.updated_at",
        )
        .bind(state.machine_id.to_string())
        .bind(state.status.as_str())
        .bind(serialize_json("machine_state.state_json", state)?)
        .bind(state.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_machine_state(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM machine_state WHERE machine_id = ?1")
            .bind(machine_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        sqlx::query(
            "UPDATE machine_config
             SET name = ?1, config_json = jsonb(?2), modified_at = ?3
             WHERE id = ?4",
        )
        .bind(&config.name)
        .bind(serialize_json("machine_config.config_json", config)?)
        .bind(config.modified_at)
        .bind(config.id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_machine_config_by_id(
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

    async fn get_machine_config_by_name(
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

    async fn get_machine_config_by_id_prefix(
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

    async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        for index in 1..10_000u32 {
            let candidate = format!("{prefix}-{index}");
            if self.get_machine_config_by_name(&candidate).await?.is_none() {
                return Ok(candidate);
            }
        }

        Err(LibVmError::InvalidMachineName {
            name: prefix.to_string(),
            reason: "failed to allocate ephemeral VM name".to_string(),
        })
    }

    async fn remove_machine_config(&self, machine: &MachineConfig) -> Result<(), LibVmError> {
        sqlx::query("DELETE FROM machine_config WHERE id = ?1")
            .bind(machine.id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_network_attachment(
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

    async fn get_network_instance(
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

    async fn upsert_network_instance(&self, instance: &NetworkInstance) -> Result<(), LibVmError> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_network_attachment(
        &self,
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_network_attachment(&self, machine_id: MachineId) -> Result<(), LibVmError> {
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

    async fn get_network_instance_by_definition(
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

    async fn count_network_attachments(&self, network_id: &str) -> Result<u32, LibVmError> {
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

    async fn upsert_network_definition(
        &self,
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
        .bind(serde_json::to_string(&definition.mode).map_err(|err| {
            LibVmError::InvalidCreateRequest {
                name: definition.name.clone(),
                reason: format!("serialize network mode: {err}"),
            }
        })?)
        .bind(serde_json::to_string(&definition.driver_preference).map_err(|err| {
            LibVmError::InvalidCreateRequest {
                name: definition.name.clone(),
                reason: format!("serialize network driver preference: {err}"),
            }
        })?)
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

    async fn get_network_definition(
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

fn sqlite_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
}

async fn validate_db_config(pool: &SqlitePool, layout: &Layout) -> Result<(), LibVmError> {
    let expected = ExpectedDbConfig::from_layout(layout);
    let now = now_unix();
    sqlx::query(
        "INSERT OR IGNORE INTO db_config
            (id, schema_version, data_dir, state_db_path, instances_dir, images_dir, net_dir, created_at, modified_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
    )
    .bind(expected.schema_version)
    .bind(&expected.data_dir)
    .bind(&expected.state_db_path)
    .bind(&expected.instances_dir)
    .bind(&expected.images_dir)
    .bind(&expected.net_dir)
    .bind(now)
    .execute(pool)
    .await?;

    let row = sqlx::query(
        "SELECT schema_version, data_dir, state_db_path, instances_dir, images_dir, net_dir
         FROM db_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await?;

    compare_db_config_i64(
        "schema_version",
        expected.schema_version,
        row.try_get("schema_version")?,
    )?;
    compare_db_config_str("data_dir", &expected.data_dir, row.try_get("data_dir")?)?;
    compare_db_config_str(
        "state_db_path",
        &expected.state_db_path,
        row.try_get("state_db_path")?,
    )?;
    compare_db_config_str(
        "instances_dir",
        &expected.instances_dir,
        row.try_get("instances_dir")?,
    )?;
    compare_db_config_str(
        "images_dir",
        &expected.images_dir,
        row.try_get("images_dir")?,
    )?;
    compare_db_config_str("net_dir", &expected.net_dir, row.try_get("net_dir")?)?;
    Ok(())
}

struct ExpectedDbConfig {
    schema_version: i64,
    data_dir: String,
    state_db_path: String,
    instances_dir: String,
    images_dir: String,
    net_dir: String,
}

impl ExpectedDbConfig {
    fn from_layout(layout: &Layout) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            data_dir: path_to_db_string(layout.data_dir()),
            state_db_path: path_to_db_string(&layout.state_db_path()),
            instances_dir: path_to_db_string(&layout.instances_dir()),
            images_dir: path_to_db_string(&layout.images_dir()),
            net_dir: path_to_db_string(&layout.net_dir()),
        }
    }
}

fn path_to_db_string(path: &Path) -> String {
    path.display().to_string()
}

fn compare_db_config_i64(
    field: &'static str,
    expected: i64,
    actual: i64,
) -> Result<(), LibVmError> {
    if expected == actual {
        return Ok(());
    }
    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn compare_db_config_str(
    field: &'static str,
    expected: &str,
    actual: String,
) -> Result<(), LibVmError> {
    if expected == actual {
        return Ok(());
    }
    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: expected.to_string(),
        actual,
    })
}

fn serialize_json<T>(field: &'static str, value: &T) -> Result<String, LibVmError>
where
    T: serde::Serialize,
{
    serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
        name: field.to_string(),
        reason: format!("serialize {field}: {err}"),
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use bento_vm_spec::{Hardware, VmSpec};

    use crate::models::{
        MachineConfig, MachineRuntimeState, MachineState, NetworkAttachment, NetworkInstance,
        RequestedNetwork,
    };
    use crate::store::{Database, Sqlite};
    use crate::{Layout, MachineId};

    fn temp_layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let layout = Layout::new(dir.path());
        (dir, layout)
    }

    fn machine_from_path(id: MachineId, name: String, instance_dir: &Path) -> MachineConfig {
        MachineConfig {
            id,
            name,
            spec: sample_vm_spec(),
            instance_dir: instance_dir.to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: RequestedNetwork::default(),
        }
    }

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            hardware: Some(Hardware {
                cpus: Some(2),
                memory: Some(1024),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            ..VmSpec::current()
        }
    }

    #[tokio::test]
    async fn insert_and_lookup_by_name() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "devbox".to_string(), &layout.instance_dir(id));

        db.insert_machine_config(&metadata).await.expect("insert");
        let found = db
            .get_machine_config_by_name("devbox")
            .await
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[tokio::test]
    async fn insert_and_lookup_by_id() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "testvm".to_string(), &layout.instance_dir(id));

        db.insert_machine_config(&metadata).await.expect("insert");
        let found = db
            .get_machine_config_by_id(id)
            .await
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[tokio::test]
    async fn lookup_by_id_prefix() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "prefix-test".to_string(), &layout.instance_dir(id));

        db.insert_machine_config(&metadata).await.expect("insert");

        let id_str = id.to_string();
        let prefix = &id_str[..8];
        let found = db
            .get_machine_config_by_id_prefix(prefix)
            .await
            .expect("lookup");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0], metadata);
    }

    #[tokio::test]
    async fn static_machine_config_round_trips_as_jsonb_blob() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let mut labels = BTreeMap::new();
        labels.insert("owner".to_string(), "test".to_string());
        let mut metadata = BTreeMap::new();
        metadata.insert("bento.profile".to_string(), "rust-dev".to_string());

        let machine = MachineConfig {
            id,
            name: "jsonb-test".to_string(),
            spec: sample_vm_spec(),
            instance_dir: layout.instance_dir(id),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            labels,
            metadata,
            network: RequestedNetwork::default(),
        };

        db.insert_machine_config(&machine)
            .await
            .expect("insert machine");
        let found = db
            .get_machine_config_by_id(id)
            .await
            .expect("lookup")
            .expect("machine exists");

        assert_eq!(found.labels.get("owner").map(String::as_str), Some("test"));
        assert_eq!(
            found.metadata.get("bento.profile").map(String::as_str),
            Some("rust-dev")
        );
        assert_eq!(found.network, RequestedNetwork::default());
        let storage_type: String =
            sqlx::query_scalar("SELECT typeof(config_json) FROM machine_config WHERE id = ?1")
                .bind(id.to_string())
                .fetch_one(&db.pool)
                .await
                .expect("query storage type");
        assert_eq!(storage_type, "blob");
    }

    #[tokio::test]
    async fn list_machines_sorted_by_name() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");

        let id_b = MachineId::new();
        let id_a = MachineId::new();
        db.insert_machine_config(&machine_from_path(
            id_b,
            "bravo".to_string(),
            &layout.instance_dir(id_b),
        ))
        .await
        .expect("insert b");
        db.insert_machine_config(&machine_from_path(
            id_a,
            "alpha".to_string(),
            &layout.instance_dir(id_a),
        ))
        .await
        .expect("insert a");

        let list = db.list_machine_configs().await.expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "bravo");
    }

    #[tokio::test]
    async fn remove_machine() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "gonner".to_string(), &layout.instance_dir(id));

        db.insert_machine_config(&metadata).await.expect("insert");
        db.remove_machine_config(&metadata).await.expect("remove");

        let found = db.get_machine_config_by_id(id).await.expect("lookup");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn machine_state_round_trips() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "runtime".to_string(), &layout.instance_dir(id));
        db.insert_machine_config(&metadata).await.expect("insert");

        let state = MachineState {
            machine_id: id,
            status: MachineRuntimeState::Running,
            vmmon_pid: Some(1234),
            started_at: Some(42),
            last_error: None,
            updated_at: 43,
        };
        db.upsert_machine_state(&state).await.expect("upsert state");

        assert_eq!(
            db.get_machine_state(id)
                .await
                .expect("get state")
                .expect("state exists"),
            state
        );

        db.remove_machine_state(id).await.expect("remove state");
        assert!(db.get_machine_state(id).await.expect("get state").is_none());
    }

    #[tokio::test]
    async fn update_machine_config_persists_config_json() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let mut metadata = machine_from_path(id, "config".to_string(), &layout.instance_dir(id));
        db.insert_machine_config(&metadata).await.expect("insert");

        metadata
            .spec
            .hardware
            .as_mut()
            .expect("sample config should include hardware")
            .cpus = Some(8);
        metadata.modified_at = 2;
        db.update_machine_config(&metadata)
            .await
            .expect("update config");

        let found = db
            .get_machine_config_by_id(id)
            .await
            .expect("lookup")
            .expect("machine exists");
        assert_eq!(
            found
                .spec
                .hardware
                .as_ref()
                .expect("stored config should include hardware")
                .cpus,
            Some(8)
        );
    }

    #[tokio::test]
    async fn network_instance_and_attachment_round_trip_and_remove() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "netbox".to_string(), &layout.instance_dir(id));
        db.insert_machine_config(&metadata)
            .await
            .expect("insert machine");

        let network_id = "netbox-runtime".to_string();
        let instance = NetworkInstance {
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
        let attachment = NetworkAttachment {
            machine_id: id,
            network_instance_id: network_id.clone(),
            guest_mac: "02:11:22:33:44:55".to_string(),
            created_at: 43,
            modified_at: 44,
        };

        db.upsert_network_instance(&instance)
            .await
            .expect("upsert network instance");
        db.upsert_network_attachment(&attachment)
            .await
            .expect("upsert network attachment");
        assert_eq!(
            db.get_network_instance(&network_id)
                .await
                .expect("get network instance")
                .expect("network instance exists"),
            instance
        );
        assert_eq!(
            db.get_network_attachment(id)
                .await
                .expect("get network attachment")
                .expect("network attachment exists"),
            attachment
        );

        db.remove_network_attachment(id)
            .await
            .expect("remove network attachment");
        assert!(db
            .get_network_attachment(id)
            .await
            .expect("get network attachment")
            .is_none());
        db.remove_network_instance(&network_id)
            .await
            .expect("remove network instance");
        assert!(db
            .get_network_instance(&network_id)
            .await
            .expect("get network instance")
            .is_none());
    }

    #[tokio::test]
    async fn created_at_columns_are_immutable() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "immutable".to_string(), &layout.instance_dir(id));
        db.insert_machine_config(&metadata)
            .await
            .expect("insert machine");

        let result = sqlx::query("UPDATE machine_config SET created_at = ?1 WHERE id = ?2")
            .bind(metadata.created_at + 1)
            .bind(id.to_string())
            .execute(&db.pool)
            .await;
        assert!(result.is_err(), "created_at update should be rejected");
    }

    #[tokio::test]
    async fn duplicate_name_fails() {
        let (_dir, layout) = temp_layout();
        let db = Sqlite::new(&layout).await.expect("open db");

        let id1 = MachineId::new();
        let id2 = MachineId::new();
        db.insert_machine_config(&machine_from_path(
            id1,
            "dupe".to_string(),
            &layout.instance_dir(id1),
        ))
        .await
        .expect("insert first");

        let result = db
            .insert_machine_config(&machine_from_path(
                id2,
                "dupe".to_string(),
                &layout.instance_dir(id2),
            ))
            .await;
        assert!(result.is_err(), "duplicate name should fail");
    }

    #[tokio::test]
    async fn concurrent_connections_work() {
        let (_dir, layout) = temp_layout();
        let db1 = Sqlite::new(&layout).await.expect("open db 1");
        let db2 = Sqlite::new(&layout).await.expect("open db 2");

        let id = MachineId::new();
        db1.insert_machine_config(&machine_from_path(
            id,
            "shared".to_string(),
            &layout.instance_dir(id),
        ))
        .await
        .expect("insert via db1");

        let found = db2
            .get_machine_config_by_name("shared")
            .await
            .expect("lookup via db2")
            .expect("should find machine from other connection");

        assert_eq!(found.id, id);
    }
}
