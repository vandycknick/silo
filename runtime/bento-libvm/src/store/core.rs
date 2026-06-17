use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

use crate::paths::{LocalPaths, LocalRoots};
use crate::store::models::MachineId;
use crate::store::models::{
    MachineConfig, MachineState, NetworkAttachment, NetworkDefinition, NetworkInstance,
};
use crate::{LibVmError, RuntimeConfig};

#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub(super) pool: SqlitePool,
    roots: LocalRoots,
}

impl Store {
    pub(crate) fn roots(&self) -> &LocalRoots {
        &self.roots
    }

    #[cfg(test)]
    async fn setup_db(pool: &SqlitePool, paths: &LocalPaths) -> Result<LocalRoots, LibVmError> {
        sqlx::migrate!("./migrations").run(pool).await?;
        crate::store::config::validate(pool, paths.state_db_path(), paths.roots()).await
    }

    #[cfg(test)]
    pub(crate) async fn new(paths: &LocalPaths) -> Result<Self, LibVmError> {
        crate::store::config::validate_roots_absolute(paths.roots())?;
        std::fs::create_dir_all(paths.data_dir())?;
        let pool = connect(paths.state_db_path()).await?;
        let roots = Self::setup_db(&pool, paths).await?;
        Ok(Self { pool, roots })
    }

    pub(crate) async fn from_config(config: &RuntimeConfig) -> Result<Self, LibVmError> {
        let data_root = config.bootstrap_data_root()?;
        let bootstrap_paths = LocalPaths::from_roots(LocalRoots::with_roots(
            data_root.clone(),
            data_root.join("run"),
            data_root.join("images"),
        ));
        crate::store::config::validate_roots_absolute(bootstrap_paths.roots())?;
        std::fs::create_dir_all(bootstrap_paths.data_dir())?;
        let pool = connect(bootstrap_paths.state_db_path()).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let roots =
            crate::store::config::open(&pool, bootstrap_paths.state_db_path(), config).await?;
        Ok(Self { pool, roots })
    }

    pub(crate) async fn add_machine(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
    ) -> Result<(), LibVmError> {
        crate::store::machine::add(self, config, initial_state).await
    }

    #[cfg(test)]
    pub(crate) async fn insert_machine_config(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        crate::store::machine::insert_config(self, config).await
    }

    pub(crate) async fn machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError> {
        crate::store::machine::get_state(self, machine_id).await
    }

    pub(crate) async fn save_machine_state(&self, state: &MachineState) -> Result<(), LibVmError> {
        crate::store::machine::upsert_state(self, state).await
    }

    #[cfg(test)]
    pub(crate) async fn remove_machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<(), LibVmError> {
        crate::store::machine::remove_state(self, machine_id).await
    }

    pub(crate) async fn save_machine_config(
        &self,
        config: &MachineConfig,
    ) -> Result<(), LibVmError> {
        crate::store::machine::update_config(self, config).await
    }

    pub(crate) async fn machine_config(
        &self,
        id: MachineId,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        crate::store::machine::get_config_by_id(self, id).await
    }

    pub(crate) async fn machine_config_by_name(
        &self,
        name: &str,
    ) -> Result<Option<MachineConfig>, LibVmError> {
        crate::store::machine::get_config_by_name(self, name).await
    }

    pub(crate) async fn machine_configs_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError> {
        crate::store::machine::get_config_by_id_prefix(self, prefix).await
    }

    pub(crate) async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        crate::store::machine::list_configs(self).await
    }

    pub(crate) async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        crate::store::machine::allocate_ephemeral_name(self, prefix).await
    }

    pub(crate) async fn remove_machine(&self, machine: &MachineConfig) -> Result<(), LibVmError> {
        crate::store::machine::remove_machine(self, machine).await
    }

    pub(crate) async fn network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<NetworkAttachment>, LibVmError> {
        crate::store::network::get_attachment(self, machine_id).await
    }

    pub(crate) async fn network_instance(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        crate::store::network::get_instance(self, network_id).await
    }

    pub(crate) async fn save_network_instance(
        &self,
        instance: &NetworkInstance,
    ) -> Result<(), LibVmError> {
        crate::store::network::upsert_instance(self, instance).await
    }

    pub(crate) async fn attach_network(
        &self,
        attachment: &NetworkAttachment,
    ) -> Result<(), LibVmError> {
        crate::store::network::upsert_attachment(self, attachment).await
    }

    pub(crate) async fn detach_network(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        crate::store::network::remove_attachment(self, machine_id).await
    }

    pub(crate) async fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError> {
        crate::store::network::remove_instance(self, network_id).await
    }

    pub(crate) async fn network_instance_by_definition(
        &self,
        definition_name: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError> {
        crate::store::network::get_instance_by_definition(self, definition_name).await
    }

    pub(crate) async fn network_attachment_count(
        &self,
        network_id: &str,
    ) -> Result<u32, LibVmError> {
        crate::store::network::count_attachments(self, network_id).await
    }

    pub(crate) async fn define_network(
        &self,
        definition: &NetworkDefinition,
    ) -> Result<(), LibVmError> {
        crate::store::network::upsert_definition(self, definition).await
    }

    pub(crate) async fn list_network_definitions(
        &self,
    ) -> Result<Vec<NetworkDefinition>, LibVmError> {
        crate::store::network::list_definitions(self).await
    }

    pub(crate) async fn network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinition>, LibVmError> {
        crate::store::network::get_definition(self, name).await
    }

    pub(crate) async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        crate::store::network::remove_definition(self, name).await
    }
}

async fn connect(path: &Path) -> Result<SqlitePool, LibVmError> {
    let options = sqlite_options(path);
    Ok(SqlitePoolOptions::new()
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(options)
        .await?)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use bento_vm_spec::{Hardware, VmSpec};

    use crate::lock_manager::LockId;
    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig, MachineRuntimeState, MachineState, NetworkAttachment,
        NetworkInstance, NetworkInstanceState,
    };
    use crate::store::Store;
    use crate::{LibVmError, RuntimeConfig};

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

    fn machine_state(id: MachineId, status: MachineRuntimeState) -> MachineState {
        MachineState {
            machine_id: id,
            status,
            vmmon_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn db_config_allows_exactly_one_row() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        assert_eq!(db.roots(), paths.roots());

        let result = sqlx::query(
            "INSERT INTO db_config
                (id, os, data_root, run_root, image_root, created_at, modified_at)
             VALUES (2, 'linux', '/tmp/other', '/tmp/other/run', '/tmp/other/images', 1, 1)",
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
    async fn db_config_seeds_root_contract() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        let row: (String, String, String) =
            sqlx::query_as("SELECT data_root, run_root, image_root FROM db_config WHERE id = 1")
                .fetch_one(&db.pool)
                .await
                .expect("read db_config");

        assert_eq!(row.0, paths.data_dir().display().to_string());
        assert_eq!(row.1, paths.roots().run_root().display().to_string());
        assert_eq!(row.2, paths.images_dir().display().to_string());
    }

    #[tokio::test]
    async fn db_config_merges_default_roots_from_existing_contract() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("bento");
        let run_root = temp.path().join("runtime-root");
        let image_root = temp.path().join("image-root");
        let expected_roots = LocalRoots::with_roots(&data_root, &run_root, &image_root);

        let initial = RuntimeConfig::local(&data_root)
            .with_run_root(&run_root)
            .with_image_root(&image_root);
        let db = Store::from_config(&initial).await.expect("seed db_config");
        assert_eq!(db.roots(), &expected_roots);
        drop(db);

        let reopened = Store::from_config(&RuntimeConfig::local(&data_root))
            .await
            .expect("reopen with default run/image roots");

        assert_eq!(reopened.roots(), &expected_roots);
    }

    #[tokio::test]
    async fn db_config_rejects_explicit_root_mismatch() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("bento");
        let run_root = temp.path().join("runtime-root");
        let image_root = temp.path().join("image-root");
        let initial = RuntimeConfig::local(&data_root)
            .with_run_root(&run_root)
            .with_image_root(&image_root);
        let db = Store::from_config(&initial).await.expect("seed db_config");
        drop(db);

        let err = Store::from_config(
            &RuntimeConfig::local(&data_root)
                .with_run_root(temp.path().join("other-runtime-root"))
                .with_image_root(&image_root),
        )
        .await
        .expect_err("explicit run root mismatch should fail");

        assert!(matches!(
            err,
            LibVmError::StateDatabaseConfigMismatch {
                field: "run_root",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn db_config_rejects_relative_roots() {
        let err = Store::from_config(&RuntimeConfig::local("relative-bento"))
            .await
            .expect_err("relative data root should fail");

        assert!(matches!(
            err,
            LibVmError::StateDatabaseConfigMismatch {
                field: "data_root",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn add_machine_inserts_config_and_initial_state() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "created".to_string(), paths.machine(id).dir());
        let state = machine_state(id, MachineRuntimeState::Stopped);

        db.add_machine(&metadata, &state)
            .await
            .expect("add machine");

        assert_eq!(
            db.machine_config(id).await.expect("lookup config"),
            Some(metadata)
        );
        assert_eq!(
            db.machine_state(id).await.expect("lookup state"),
            Some(state)
        );
    }

    #[tokio::test]
    async fn add_machine_rolls_back_config_when_state_insert_fails() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        sqlx::query(
            "CREATE TRIGGER fail_machine_state_insert
             BEFORE INSERT ON machine_state
             BEGIN
                 SELECT RAISE(ABORT, 'machine_state insert failed');
             END",
        )
        .execute(&db.pool)
        .await
        .expect("create failing trigger");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "rollback".to_string(), paths.machine(id).dir());
        let state = machine_state(id, MachineRuntimeState::Stopped);

        db.add_machine(&metadata, &state)
            .await
            .expect_err("state insert should fail");

        assert!(db
            .machine_config(id)
            .await
            .expect("lookup config")
            .is_none());
    }

    #[tokio::test]
    async fn insert_and_lookup_by_name() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "devbox".to_string(), paths.machine(id).dir());

        db.insert_machine_config(&metadata).await.expect("insert");
        let found = db
            .machine_config_by_name("devbox")
            .await
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[tokio::test]
    async fn insert_and_lookup_by_id() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "testvm".to_string(), paths.machine(id).dir());

        db.insert_machine_config(&metadata).await.expect("insert");
        let found = db
            .machine_config(id)
            .await
            .expect("lookup")
            .expect("should find machine");

        assert_eq!(found, metadata);
    }

    #[tokio::test]
    async fn lookup_by_id_prefix() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "prefix-test".to_string(), paths.machine(id).dir());

        db.insert_machine_config(&metadata).await.expect("insert");

        let id_str = id.to_string();
        let prefix = &id_str[..8];
        let found = db
            .machine_configs_by_id_prefix(prefix)
            .await
            .expect("lookup");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0], metadata);
    }

    #[tokio::test]
    async fn static_machine_config_round_trips_as_jsonb_blob() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
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
            .machine_config(id)
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
        let db = Store::new(&paths).await.expect("open db");

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
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "gonner".to_string(), paths.machine(id).dir());
        let state = machine_state(id, MachineRuntimeState::Stopped);

        db.add_machine(&metadata, &state).await.expect("insert");
        db.remove_machine(&metadata).await.expect("remove");

        let found = db.machine_config(id).await.expect("lookup");
        assert!(found.is_none());
        assert!(db.machine_state(id).await.expect("lookup").is_none());
    }

    #[tokio::test]
    async fn machine_state_round_trips() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "runtime".to_string(), paths.machine(id).dir());
        db.insert_machine_config(&metadata).await.expect("insert");

        let state = MachineState {
            vmmon_pid: Some(1234),
            started_at: Some(42),
            run_id: Some("run-1".to_string()),
            updated_at: 43,
            ..machine_state(id, MachineRuntimeState::Running)
        };
        db.save_machine_state(&state).await.expect("upsert state");

        assert_eq!(
            db.machine_state(id)
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
        assert!(db.machine_state(id).await.expect("get state").is_none());
    }

    #[tokio::test]
    async fn save_machine_config_persists_config_json() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
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
        db.save_machine_config(&metadata)
            .await
            .expect("update config");

        let found = db
            .machine_config(id)
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
        let db = Store::new(&paths).await.expect("open db");
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

        db.save_network_instance(&instance)
            .await
            .expect("upsert network instance");
        db.attach_network(&attachment)
            .await
            .expect("upsert network attachment");
        assert_eq!(
            db.network_instance(&network_id)
                .await
                .expect("get network instance")
                .expect("network instance exists"),
            instance
        );
        assert_eq!(
            db.network_attachment(id)
                .await
                .expect("get network attachment")
                .expect("network attachment exists"),
            attachment
        );

        db.detach_network(id)
            .await
            .expect("remove network attachment");
        assert!(db
            .network_attachment(id)
            .await
            .expect("get network attachment")
            .is_none());
        db.remove_network_instance(&network_id)
            .await
            .expect("remove network instance");
        assert!(db
            .network_instance(&network_id)
            .await
            .expect("get network instance")
            .is_none());
    }

    #[tokio::test]
    async fn machine_timestamps_live_in_json_not_columns() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

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
        let db = Store::new(&paths).await.expect("open db");

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
        let db1 = Store::new(&paths).await.expect("open db 1");
        let db2 = Store::new(&paths).await.expect("open db 2");

        let id = MachineId::new();
        db1.insert_machine_config(&machine_from_path(
            id,
            "shared".to_string(),
            paths.machine(id).dir(),
        ))
        .await
        .expect("insert via db1");

        let found = db2
            .machine_config_by_name("shared")
            .await
            .expect("lookup via db2")
            .expect("should find machine from other connection");

        assert_eq!(found.id, id);
    }
}
