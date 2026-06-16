mod connection;
mod db_config;
mod json;
mod machine;
mod network;

use std::time::Duration;

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

use crate::paths::{LocalPaths, LocalRoots};
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineState, NetworkAttachment, NetworkDefinition, NetworkInstance,
};
use crate::store::Database;
use crate::LibVmError;

#[derive(Debug, Clone)]
pub(crate) struct Sqlite {
    pub(super) pool: SqlitePool,
    roots: LocalRoots,
}

impl Sqlite {
    pub(crate) fn roots(&self) -> &LocalRoots {
        &self.roots
    }

    async fn setup_db(pool: &SqlitePool, paths: &LocalPaths) -> Result<LocalRoots, LibVmError> {
        sqlx::migrate!("./migrations").run(pool).await?;
        db_config::validate(pool, paths.roots()).await
    }
}

impl Database for Sqlite {
    type Settings = LocalPaths;

    async fn new(paths: &Self::Settings) -> Result<Self, LibVmError> {
        std::fs::create_dir_all(paths.data_dir())?;
        let options = connection::options(paths.state_db_path());
        let pool = SqlitePoolOptions::new()
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await?;
        let roots = Self::setup_db(&pool, paths).await?;
        Ok(Self { pool, roots })
    }

    async fn insert_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        machine::insert_config(self, config).await
    }

    async fn get_machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError> {
        machine::get_state(self, machine_id).await
    }

    async fn upsert_machine_state(&self, state: &MachineState) -> Result<(), LibVmError> {
        machine::upsert_state(self, state).await
    }

    async fn remove_machine_state(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        machine::remove_state(self, machine_id).await
    }

    async fn update_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError> {
        machine::update_config(self, config).await
    }

    async fn get_machine_config_by_id(
        &self,
        id: MachineId,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        machine::get_config_by_id(self, id).await
    }

    async fn get_machine_config_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        machine::get_config_by_name(self, name).await
    }

    async fn get_machine_config_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError> {
        machine::get_config_by_id_prefix(self, prefix).await
    }

    async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        machine::list_configs(self).await
    }

    async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        machine::allocate_ephemeral_name(self, prefix).await
    }

    async fn remove_machine_config(&self, machine: &MachineConfig) -> Result<(), LibVmError> {
        machine::remove_config(self, machine).await
    }

    async fn get_network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<NetworkAttachment>, LibVmError> {
        network::get_attachment(self, machine_id).await
    }

    async fn get_network_instance(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        network::get_instance(self, network_id).await
    }

    async fn upsert_network_instance(&self, instance: &NetworkInstance) -> Result<(), LibVmError> {
        network::upsert_instance(self, instance).await
    }

    async fn upsert_network_attachment(
        &self,
        attachment: &NetworkAttachment,
    ) -> Result<(), LibVmError> {
        network::upsert_attachment(self, attachment).await
    }

    async fn remove_network_attachment(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        network::remove_attachment(self, machine_id).await
    }

    async fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError> {
        network::remove_instance(self, network_id).await
    }

    async fn get_network_instance_by_definition(
        &self,
        definition_name: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        network::get_instance_by_definition(self, definition_name).await
    }

    async fn count_network_attachments(&self, network_id: &str) -> Result<u32, LibVmError> {
        network::count_attachments(self, network_id).await
    }

    async fn upsert_network_definition(
        &self,
        definition: &NetworkDefinition,
    ) -> Result<(), LibVmError> {
        network::upsert_definition(self, definition).await
    }

    async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError> {
        network::list_definitions(self).await
    }

    async fn get_network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinition>, LibVmError> {
        network::get_definition(self, name).await
    }

    async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        network::remove_definition(self, name).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use bento_vm_spec::{Hardware, VmSpec};

    use crate::lock_manager::LockId;
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig, MachineRuntimeState, MachineState, NetworkAttachment,
        NetworkInstance, NetworkInstanceState,
    };
    use crate::store::{Database, Sqlite};

    fn temp_paths() -> (tempfile::TempDir, LocalPaths) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(dir.path());
        (dir, paths)
    }

    fn machine_from_path(id: MachineId, name: String, instance_dir: &Path) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name,
            spec: sample_vm_spec(),
            instance_dir: instance_dir.to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::default(),
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
    async fn db_config_allows_exactly_one_row() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");

        assert_eq!(db.roots(), paths.roots());

        let result = sqlx::query(
            "INSERT INTO db_config
                (id, schema_version, data_dir, state_db_path, created_at, modified_at)
             VALUES (2, 1, '/tmp/other', '/tmp/other/state.db', 1, 1)",
        )
        .execute(&db.pool)
        .await;
        assert!(result.is_err(), "second db_config row should fail");

        let row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM db_config")
            .fetch_one(&db.pool)
            .await
            .expect("count db_config rows");
        assert_eq!(row_count, 1);
    }

    #[tokio::test]
    async fn insert_and_lookup_by_name() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "devbox".to_string(), paths.machine(id).dir());

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
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "testvm".to_string(), paths.machine(id).dir());

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
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "prefix-test".to_string(), paths.machine(id).dir());

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
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut labels = BTreeMap::new();
        labels.insert("owner".to_string(), "test".to_string());
        let mut metadata = BTreeMap::new();
        metadata.insert("bento.profile".to_string(), "rust-dev".to_string());

        let machine = MachineConfig {
            id,
            lock_id: LockId::from(42),
            name: "jsonb-test".to_string(),
            spec: sample_vm_spec(),
            instance_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: Some(64_000_000_000),
            labels,
            metadata,
            network: MachineNetworkConfig::default(),
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
        assert_eq!(found.name, "jsonb-test");
        assert_eq!(
            found.metadata.get("bento.profile").map(String::as_str),
            Some("rust-dev")
        );
        assert_eq!(found.network, MachineNetworkConfig::default());
        let storage_type: String =
            sqlx::query_scalar("SELECT typeof(config_json) FROM machine_config WHERE id = ?1")
                .bind(id.to_string())
                .fetch_one(&db.pool)
                .await
                .expect("query storage type");
        assert_eq!(storage_type, "blob");
        let config_id: Option<String> = sqlx::query_scalar(
            "SELECT json_extract(json(config_json), '$.id') FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query config id");
        assert_eq!(config_id, Some(id.to_string()));
        let config_name: Option<String> = sqlx::query_scalar(
            "SELECT json_extract(json(config_json), '$.name') FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query config name");
        assert_eq!(config_name.as_deref(), Some("jsonb-test"));
        let lock_id: i64 = sqlx::query_scalar(
            "SELECT json_extract(json(config_json), '$.lockId') FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query lock id");
        assert_eq!(lock_id, 42);
        let created_at: Option<i64> = sqlx::query_scalar(
            "SELECT json_extract(json(config_json), '$.createdAt') FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query created_at");
        assert_eq!(created_at, Some(1));
        let modified_at: Option<i64> = sqlx::query_scalar(
            "SELECT json_extract(json(config_json), '$.modifiedAt') FROM machine_config WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query modified_at");
        assert_eq!(modified_at, Some(1));
    }

    #[tokio::test]
    async fn list_machines_sorted_by_name() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");

        let id_b = MachineId::new();
        let id_a = MachineId::new();
        db.insert_machine_config(&machine_from_path(
            id_b,
            "bravo".to_string(),
            paths.machine(id_b).dir(),
        ))
        .await
        .expect("insert b");
        db.insert_machine_config(&machine_from_path(
            id_a,
            "alpha".to_string(),
            paths.machine(id_a).dir(),
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
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "gonner".to_string(), paths.machine(id).dir());

        db.insert_machine_config(&metadata).await.expect("insert");
        db.remove_machine_config(&metadata).await.expect("remove");

        let found = db.get_machine_config_by_id(id).await.expect("lookup");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn machine_state_round_trips() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "runtime".to_string(), paths.machine(id).dir());
        db.insert_machine_config(&metadata).await.expect("insert");

        let state = MachineState {
            machine_id: id,
            status: MachineRuntimeState::Running,
            vmmon_pid: Some(1234),
            started_at: Some(42),
            run_id: Some("run-1".to_string()),
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
        let updated_at: Option<i64> = sqlx::query_scalar(
            "SELECT json_extract(json(state_json), '$.updatedAt') FROM machine_state WHERE machine_id = ?1",
        )
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("query state updated_at");
        assert_eq!(updated_at, Some(43));

        db.remove_machine_state(id).await.expect("remove state");
        assert!(db.get_machine_state(id).await.expect("get state").is_none());
    }

    #[tokio::test]
    async fn update_machine_config_persists_config_json() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut metadata = machine_from_path(id, "config".to_string(), paths.machine(id).dir());
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
        assert_eq!(found.modified_at, 2);
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
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "netbox".to_string(), paths.machine(id).dir());
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
            state: NetworkInstanceState::Running,
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
    async fn machine_timestamps_live_in_json_not_columns() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");

        let machine_config_timestamp_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('machine_config') WHERE name IN ('created_at', 'modified_at')",
        )
        .fetch_one(&db.pool)
        .await
        .expect("query machine_config columns");
        assert_eq!(machine_config_timestamp_columns, 0);

        let machine_state_timestamp_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('machine_state') WHERE name = 'updated_at'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("query machine_state columns");
        assert_eq!(machine_state_timestamp_columns, 0);
    }

    #[tokio::test]
    async fn duplicate_name_fails() {
        let (_dir, paths) = temp_paths();
        let db = Sqlite::new(&paths).await.expect("open db");

        let id1 = MachineId::new();
        let id2 = MachineId::new();
        db.insert_machine_config(&machine_from_path(
            id1,
            "dupe".to_string(),
            paths.machine(id1).dir(),
        ))
        .await
        .expect("insert first");

        let result = db
            .insert_machine_config(&machine_from_path(
                id2,
                "dupe".to_string(),
                paths.machine(id2).dir(),
            ))
            .await;
        assert!(result.is_err(), "duplicate name should fail");
    }

    #[tokio::test]
    async fn concurrent_connections_work() {
        let (_dir, paths) = temp_paths();
        let db1 = Sqlite::new(&paths).await.expect("open db 1");
        let db2 = Sqlite::new(&paths).await.expect("open db 2");

        let id = MachineId::new();
        db1.insert_machine_config(&machine_from_path(
            id,
            "shared".to_string(),
            paths.machine(id).dir(),
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
