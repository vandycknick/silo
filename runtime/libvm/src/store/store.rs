use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

#[cfg(test)]
use crate::paths::LocalPaths;
#[cfg(test)]
use crate::store::models::DbConfig;
#[cfg(test)]
use crate::store::ConfigStore;
use crate::LibVmError;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub(super) pool: SqlitePool,
}

impl Store {
    #[cfg(test)]
    pub(crate) async fn new(paths: &LocalPaths) -> Result<Self, LibVmError> {
        let store = Self::open(paths.state_db_path()).await?;
        store
            .read_or_seed_db_config(&DbConfig::from_roots(paths.roots()))
            .await?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) async fn execute_test_sql(&self, statement: &'static str) -> Result<(), LibVmError> {
        sqlx::raw_sql(statement).execute(&self.pool).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn close(self) {
        self.pool.close().await;
    }

    pub(crate) async fn open(state_db_path: &Path) -> Result<Self, LibVmError> {
        if let Some(parent) = state_db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pool = Self::connect(state_db_path).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    async fn connect(path: &Path) -> Result<SqlitePool, LibVmError> {
        let options = Self::sqlite_options(path);
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
}

#[derive(Debug, Clone)]
pub(crate) struct ReadOnlyStore {
    pool: SqlitePool,
}

impl ReadOnlyStore {
    pub(crate) async fn open_if_exists(state_db_path: &Path) -> Result<Option<Self>, LibVmError> {
        match std::fs::metadata(state_db_path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(std::io::Error::other("state database is not a regular file").into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let mut wal_name = state_db_path.as_os_str().to_os_string();
        wal_name.push("-wal");
        if std::fs::exists(std::path::Path::new(&wal_name))? {
            return Err(std::io::Error::other(format!(
                "state database {} has an active WAL and cannot be planned without local writes",
                state_db_path.display()
            ))
            .into());
        }

        let options = SqliteConnectOptions::new()
            .filename(state_db_path)
            .read_only(true)
            .immutable(true)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await?;
        validate_embedded_migration_history(&pool).await?;
        Ok(Some(Self { pool }))
    }

    pub(crate) async fn db_config(
        &self,
    ) -> Result<Option<crate::store::models::DbConfig>, LibVmError> {
        let row =
            sqlx::query("SELECT os, data_root, state_root, image_root FROM db_config WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|row| crate::store::models::DbConfig {
            os: row.get("os"),
            data_root: row.get("data_root"),
            state_root: row.get("state_root"),
            image_root: row.get("image_root"),
        }))
    }

    pub(crate) async fn machine_name_exists(&self, name: &str) -> Result<bool, LibVmError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM machine_config WHERE name = ?1)",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }
}

async fn validate_embedded_migration_history(pool: &SqlitePool) -> Result<(), LibVmError> {
    let rows = sqlx::query(
        "SELECT version, description, success, checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await?;
    let expected = MIGRATOR.iter().collect::<Vec<_>>();
    if rows.len() != expected.len() {
        return Err(LibVmError::StateDecode {
            field: "state_db.migrations",
            message: format!(
                "applied migration count {} does not match embedded migration count {}",
                rows.len(),
                expected.len()
            ),
        });
    }
    for (row, migration) in rows.iter().zip(expected) {
        let version: i64 = row.get("version");
        let description: String = row.get("description");
        let success: bool = row.get("success");
        let checksum: Vec<u8> = row.get("checksum");
        if version != migration.version
            || description != migration.description
            || !success
            || migration.checksum != checksum
        {
            return Err(LibVmError::StateDecode {
                field: "state_db.migrations",
                message: format!("migration {version} does not match the embedded schema"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use vm_spec::{Hardware, VmSpec};

    use crate::lock_manager::LockId;
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig, MachineRootfsRecord, MachineRuntimeState,
        MachineState, NetworkAttachment, NetworkDefinition, NetworkDriverPreference,
        NetworkInstance, NetworkInstanceState, NetworkTopology,
    };
    use crate::store::{ConfigStore, MachineStore, NetworkStore, Store};
    use crate::LibVmError;

    fn temp_paths() -> (tempfile::TempDir, LocalPaths) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(dir.path());
        (dir, paths)
    }

    fn machine_from_path(id: MachineId, name: String, machine_dir: &Path) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: LockId::from(0),
            name,
            spec: sample_vm_spec(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: machine_dir.to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::default(),
            guest: crate::machine::MachineGuestConfig::default(),
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

    async fn seed_machine(db: &Store, config: &MachineConfig) {
        let state = machine_state(config.id, MachineRuntimeState::Stopped);
        db.add_machine(config, &state)
            .await
            .expect("insert machine");
    }

    fn network_instance(id: &str, definition_name: Option<&str>) -> NetworkInstance {
        NetworkInstance {
            id: id.to_string(),
            driver: "netd".to_string(),
            definition_name: definition_name.map(str::to_string),
            attachment_json: r#"{"kind":"none"}"#.to_string(),
            driver_state_json: r#"{"helper_pid":1234}"#.to_string(),
            state: NetworkInstanceState::Running,
            created_at: 41,
            modified_at: 42,
        }
    }

    fn network_attachment(machine_id: MachineId, network_id: &str) -> NetworkAttachment {
        NetworkAttachment {
            machine_id,
            network_instance_id: network_id.to_string(),
            guest_mac: "02:11:22:33:44:55".to_string(),
            created_at: 43,
            modified_at: 44,
        }
    }

    fn network_definition(
        name: &str,
        topology: NetworkTopology,
        driver_preference: NetworkDriverPreference,
    ) -> NetworkDefinition {
        NetworkDefinition {
            name: name.to_string(),
            topology,
            driver_preference,
            created_at: 0,
            modified_at: 0,
        }
    }

    #[tokio::test]
    async fn db_config_allows_exactly_one_row() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        let result = sqlx::query(
            "INSERT INTO db_config
                (id, os, data_root, state_root, image_root, created_at, modified_at)
             VALUES (2, 'linux', '/tmp/other', '/tmp/other/state', '/tmp/other/images', 1, 1)",
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

        let config = db
            .db_config()
            .await
            .expect("read db_config")
            .expect("db_config row");

        assert_eq!(config.data_root, paths.data_dir().display().to_string());
        assert_eq!(
            config.state_root,
            paths.roots().state_root().display().to_string()
        );
        assert_eq!(config.image_root, paths.images_dir().display().to_string());
    }

    #[tokio::test]
    async fn fresh_database_has_complete_schema_without_runtime_paths() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open fresh database");

        let tables = sqlx::query_scalar::<_, String>(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        )
        .fetch_all(&db.pool)
        .await
        .expect("list tables")
        .into_iter()
        .collect::<BTreeSet<_>>();
        let required_tables = BTreeSet::from([
            "db_config".to_string(),
            "machine_config".to_string(),
            "machine_state".to_string(),
            "network_instances".to_string(),
            "network_attachments".to_string(),
            "network_definitions".to_string(),
            "image_manifest".to_string(),
            "image_ref".to_string(),
            "image_config".to_string(),
            "image_layer".to_string(),
            "image_manifest_layer".to_string(),
            "image_rootfs_artifact".to_string(),
            "machine_rootfs".to_string(),
        ]);
        assert!(required_tables.is_subset(&tables));

        let db_config_columns = sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('db_config') ORDER BY cid",
        )
        .fetch_all(&db.pool)
        .await
        .expect("list db_config columns");
        assert_eq!(
            db_config_columns,
            [
                "id",
                "os",
                "data_root",
                "state_root",
                "image_root",
                "created_at",
                "modified_at",
            ]
        );

        let network_columns = sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('network_instances') ORDER BY cid",
        )
        .fetch_all(&db.pool)
        .await
        .expect("list network instance columns");
        assert!(!network_columns.iter().any(|column| column == "runtime_dir"));

        let schema_objects = sqlx::query_scalar::<_, String>(
            "SELECT name FROM sqlite_master WHERE type IN ('index', 'trigger')",
        )
        .fetch_all(&db.pool)
        .await
        .expect("list indexes and triggers")
        .into_iter()
        .collect::<BTreeSet<_>>();
        for object in [
            "network_instances_definition_name_unique",
            "image_ref_manifest_digest_idx",
            "image_manifest_layer_layer_diff_id_idx",
            "image_rootfs_artifact_manifest_digest_idx",
            "machine_rootfs_manifest_digest_idx",
            "db_config_created_at_immutable",
            "network_instances_created_at_immutable",
            "network_attachments_created_at_immutable",
            "network_definitions_created_at_immutable",
            "image_manifest_created_at_immutable",
            "image_ref_created_at_immutable",
            "image_config_created_at_immutable",
            "image_layer_created_at_immutable",
            "image_rootfs_artifact_created_at_immutable",
            "machine_rootfs_created_at_immutable",
        ] {
            assert!(
                schema_objects.contains(object),
                "missing schema object {object}"
            );
        }
    }

    #[tokio::test]
    async fn old_migration_history_is_rejected() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let state_db = dir.path().join("state.db");
        std::fs::File::create(&state_db).expect("create old state database");
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", state_db.display()))
            .await
            .expect("open old state database");
        sqlx::query(
            "CREATE TABLE _sqlx_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL,
                checksum BLOB NOT NULL,
                execution_time BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("create migration history");
        sqlx::query(
            "INSERT INTO _sqlx_migrations
                (version, description, success, checksum, execution_time)
             VALUES (1, 'initial', TRUE, x'00', 1)",
        )
        .execute(&pool)
        .await
        .expect("record old migration");
        pool.close().await;

        let error = Store::open(&state_db)
            .await
            .expect_err("old state database must not be adopted");
        assert!(
            error.to_string().contains("migration") || error.to_string().contains("checksum"),
            "unexpected migration rejection: {error}"
        );
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
    async fn machine_rootfs_round_trips_oci_identity_and_local_disk_pin() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let machine = machine_from_path(id, "rootfs-pin".to_string(), paths.machine(id).dir());
        sqlx::query(
            "INSERT INTO image_manifest
                (digest, media_type, image_id, platform_os, platform_architecture,
                 config_digest, layer_count, total_size_bytes, created_at)
             VALUES ('sha256:manifest', 'application/vnd.oci.image.manifest.v1+json',
                     'sha256:image-id', 'linux', 'amd64', 'sha256:config', 0, 0, 1)",
        )
        .execute(&db.pool)
        .await
        .expect("insert manifest pin target");
        let rootfs = MachineRootfsRecord {
            machine_id: id,
            source_kind: crate::ImageSourceKind::Oci,
            requested_reference: "example.test/demo:latest".to_string(),
            selected_reference: Some("example.test/demo@sha256:manifest".to_string()),
            manifest_digest: Some("sha256:manifest".to_string()),
            config_digest: Some("sha256:config".to_string()),
            image_id: Some("sha256:image-id".to_string()),
            root_disk_path: paths.machine(id).dir().join("rootfs.img"),
            root_disk_size_bytes: 64 * 1024 * 1024,
            created_at: 7,
        };

        db.add_machine_with_rootfs(
            &machine,
            &machine_state(id, MachineRuntimeState::Stopped),
            &rootfs,
        )
        .await
        .expect("insert machine rootfs pin");

        assert_eq!(
            db.machine_rootfs(id).await.expect("read rootfs pin"),
            Some(rootfs)
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
    async fn add_machine_rejects_mismatched_initial_state_id() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let other_id = MachineId::new();
        let metadata = machine_from_path(id, "mismatched".to_string(), paths.machine(id).dir());
        let state = machine_state(other_id, MachineRuntimeState::Stopped);

        let err = db
            .add_machine(&metadata, &state)
            .await
            .expect_err("mismatched state id should fail");

        assert!(matches!(err, LibVmError::InvalidCreateRequest { .. }));
        assert!(db
            .machine_config(id)
            .await
            .expect("lookup config")
            .is_none());
        assert!(db
            .machine_state(other_id)
            .await
            .expect("lookup state")
            .is_none());
    }

    #[tokio::test]
    async fn insert_and_lookup_by_name() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "devbox".to_string(), paths.machine(id).dir());

        seed_machine(&db, &metadata).await;
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

        seed_machine(&db, &metadata).await;
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

        seed_machine(&db, &metadata).await;

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
    async fn lookup_by_id_prefix_rejects_non_normalized_prefixes() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let too_long = "a".repeat(33);
        let invalid_prefixes = ["", "ab", "ABC", "abc%", "abc_", "abcg", too_long.as_str()];

        for prefix in invalid_prefixes {
            let err = db
                .machine_configs_by_id_prefix(prefix)
                .await
                .expect_err("invalid prefix should fail");
            assert!(
                matches!(err, LibVmError::InvalidMachineIdPrefix { .. }),
                "expected InvalidMachineIdPrefix for {prefix:?}, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn static_machine_config_round_trips_as_jsonb_blob() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut labels = BTreeMap::new();
        labels.insert("owner".to_string(), "test".to_string());
        let mut metadata = BTreeMap::new();
        metadata.insert("silo.note".to_string(), "test value".to_string());

        let machine = MachineConfig {
            id,
            lock_id: LockId::from(42),
            name: "jsonb-test".to_string(),
            spec: sample_vm_spec(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: Some(64_000_000_000),
            labels,
            metadata,
            network: MachineNetworkConfig::default(),
            guest: crate::machine::MachineGuestConfig::default(),
        };

        seed_machine(&db, &machine).await;
        let found = db
            .machine_config(id)
            .await
            .expect("lookup")
            .expect("machine exists");

        assert_eq!(found.labels.get("owner").map(String::as_str), Some("test"));
        assert_eq!(found.name, "jsonb-test");
        assert_eq!(
            found.metadata.get("silo.note").map(String::as_str),
            Some("test value")
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
    async fn process_and_retention_survive_sqlite_reopen() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut environment = BTreeMap::new();
        environment.insert("ZED".to_string(), "last".to_string());
        environment.insert("ALPHA".to_string(), "first".to_string());
        let machine = MachineConfig {
            id,
            lock_id: LockId::from(42),
            name: "reopen-stage-two".to_string(),
            spec: sample_vm_spec(),
            retention: crate::MachineRetention::Ephemeral,
            process: crate::ProcessConfig {
                entrypoint: Some(Vec::new()),
                command: Some(vec!["/bin/echo".to_string(), "hello".to_string()]),
                environment,
                working_directory: "/workspace".to_string(),
                user: Some("1000:1000".to_string()),
            },
            template_name: Some("rust-worker".to_string()),
            agent_mode: Some(crate::MachineAgent::Disabled),
            machine_dir: paths.machine(id).dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image:latest".to_string(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::default(),
            guest: crate::machine::MachineGuestConfig::default(),
        };
        seed_machine(&db, &machine).await;
        db.pool.close().await;

        let reopened = Store::open(paths.state_db_path()).await.expect("reopen db");
        assert_eq!(
            reopened.machine_config(id).await.expect("read config"),
            Some(machine)
        );
    }

    #[tokio::test]
    async fn list_machines_sorted_by_name() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        let id_b = MachineId::new();
        let id_a = MachineId::new();
        let machine_b = machine_from_path(id_b, "bravo".to_string(), paths.machine(id_b).dir());
        let machine_a = machine_from_path(id_a, "alpha".to_string(), paths.machine(id_a).dir());
        seed_machine(&db, &machine_b).await;
        seed_machine(&db, &machine_a).await;

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
    async fn remove_machine_cascades_network_attachment() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "networked".to_string(), paths.machine(id).dir());
        seed_machine(&db, &metadata).await;
        let instance = network_instance("networked-runtime", None);
        let attachment = network_attachment(id, &instance.id);

        db.save_network_instance(&instance)
            .await
            .expect("save network instance");
        db.attach_network(&attachment)
            .await
            .expect("attach network");

        db.remove_machine(&metadata).await.expect("remove machine");

        assert!(db
            .network_attachment(id)
            .await
            .expect("lookup attachment")
            .is_none());
        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            0
        );
    }

    #[tokio::test]
    async fn machine_state_round_trips() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "runtime".to_string(), paths.machine(id).dir());
        seed_machine(&db, &metadata).await;

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
    }

    #[tokio::test]
    async fn save_machine_state_requires_existing_machine() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let state = machine_state(id, MachineRuntimeState::Stopped);

        db.save_machine_state(&state)
            .await
            .expect_err("state for missing machine should fail");
    }

    #[tokio::test]
    async fn save_machine_config_persists_config_json() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut metadata = machine_from_path(id, "config".to_string(), paths.machine(id).dir());
        seed_machine(&db, &metadata).await;

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
    async fn save_machine_config_requires_existing_machine() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "missing".to_string(), paths.machine(id).dir());

        let err = db
            .save_machine_config(&metadata)
            .await
            .expect_err("saving missing machine should fail");

        assert!(matches!(
            err,
            LibVmError::MachineNotFound { reference } if reference == id.to_string()
        ));
    }

    #[tokio::test]
    async fn save_machine_config_duplicate_rename_fails_without_changing_rows() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id_a = MachineId::new();
        let id_b = MachineId::new();
        let machine_a = machine_from_path(id_a, "alpha".to_string(), paths.machine(id_a).dir());
        let mut machine_b = machine_from_path(id_b, "bravo".to_string(), paths.machine(id_b).dir());
        seed_machine(&db, &machine_a).await;
        seed_machine(&db, &machine_b).await;

        machine_b.name = "alpha".to_string();
        db.save_machine_config(&machine_b)
            .await
            .expect_err("duplicate rename should fail");

        assert_eq!(
            db.machine_config(id_a)
                .await
                .expect("lookup alpha")
                .expect("alpha exists"),
            machine_a
        );
        assert_eq!(
            db.machine_config(id_b)
                .await
                .expect("lookup bravo")
                .expect("bravo exists")
                .name,
            "bravo"
        );
    }

    #[tokio::test]
    async fn network_instance_and_attachment_round_trip_and_remove() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "netbox".to_string(), paths.machine(id).dir());
        seed_machine(&db, &metadata).await;

        let network_id = "netbox-runtime".to_string();
        let instance = network_instance(&network_id, None);
        let attachment = network_attachment(id, &network_id);

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
    async fn named_network_instance_definition_is_unique_but_private_instances_are_not() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        db.save_network_instance(&network_instance("named-a", Some("devnet")))
            .await
            .expect("save first named instance");
        db.save_network_instance(&network_instance("private-a", None))
            .await
            .expect("save first private instance");
        db.save_network_instance(&network_instance("private-b", None))
            .await
            .expect("save second private instance");

        db.save_network_instance(&network_instance("named-b", Some("devnet")))
            .await
            .expect_err("duplicate named instance definition should fail");
    }

    #[tokio::test]
    async fn remove_network_instance_cascades_network_attachment() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let metadata = machine_from_path(id, "attached".to_string(), paths.machine(id).dir());
        seed_machine(&db, &metadata).await;
        let instance = network_instance("attached-runtime", None);
        let attachment = network_attachment(id, &instance.id);

        db.save_network_instance(&instance)
            .await
            .expect("save network instance");
        db.attach_network(&attachment)
            .await
            .expect("attach network");

        db.remove_network_instance(&instance.id)
            .await
            .expect("remove network instance");

        assert!(db
            .network_attachment(id)
            .await
            .expect("lookup attachment")
            .is_none());
    }

    #[tokio::test]
    async fn network_attachment_count_tracks_attachment_lifecycle() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id_a = MachineId::new();
        let id_b = MachineId::new();
        let machine_a = machine_from_path(id_a, "net-a".to_string(), paths.machine(id_a).dir());
        let machine_b = machine_from_path(id_b, "net-b".to_string(), paths.machine(id_b).dir());
        seed_machine(&db, &machine_a).await;
        seed_machine(&db, &machine_b).await;
        let instance = network_instance("shared-runtime", None);
        db.save_network_instance(&instance)
            .await
            .expect("save network instance");

        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            0
        );
        db.attach_network(&network_attachment(id_a, &instance.id))
            .await
            .expect("attach first machine");
        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            1
        );
        db.attach_network(&network_attachment(id_b, &instance.id))
            .await
            .expect("attach second machine");
        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            2
        );
        db.detach_network(id_a).await.expect("detach first machine");
        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            1
        );
        db.remove_network_instance(&instance.id)
            .await
            .expect("remove network instance");
        assert_eq!(
            db.network_attachment_count(&instance.id)
                .await
                .expect("count attachments"),
            0
        );
    }

    #[tokio::test]
    async fn network_definitions_round_trip_list_update_and_remove() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let alpha = network_definition(
            "alpha-net",
            NetworkTopology::Bridge,
            NetworkDriverPreference::Netd,
        );
        let beta = network_definition(
            "beta-net",
            NetworkTopology::Nat,
            NetworkDriverPreference::Auto,
        );

        db.define_network(&beta).await.expect("define beta network");
        db.define_network(&alpha)
            .await
            .expect("define alpha network");

        let list = db.list_network_definitions().await.expect("list networks");
        assert_eq!(
            list.iter()
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha-net", "beta-net"]
        );
        let stored_alpha = db
            .network_definition("alpha-net")
            .await
            .expect("lookup alpha")
            .expect("alpha exists");
        assert_eq!(stored_alpha.topology, NetworkTopology::Bridge);
        assert_eq!(
            stored_alpha.driver_preference,
            NetworkDriverPreference::Netd
        );
        assert!(stored_alpha.created_at > 0);
        assert!(stored_alpha.modified_at > 0);

        let updated_alpha = network_definition(
            "alpha-net",
            NetworkTopology::Isolated,
            NetworkDriverPreference::Auto,
        );
        db.define_network(&updated_alpha)
            .await
            .expect("update alpha network");
        let stored_updated_alpha = db
            .network_definition("alpha-net")
            .await
            .expect("lookup updated alpha")
            .expect("updated alpha exists");
        assert_eq!(stored_updated_alpha.topology, NetworkTopology::Isolated);
        assert_eq!(
            stored_updated_alpha.driver_preference,
            NetworkDriverPreference::Auto
        );
        assert_eq!(stored_updated_alpha.created_at, stored_alpha.created_at);
        assert!(stored_updated_alpha.modified_at >= stored_alpha.modified_at);

        db.remove_network_definition("alpha-net")
            .await
            .expect("remove alpha network");
        assert!(db
            .network_definition("alpha-net")
            .await
            .expect("lookup removed alpha")
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
    async fn machine_config_decode_rejects_json_id_mismatch() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut machine = machine_from_path(id, "corrupt-id".to_string(), paths.machine(id).dir());
        seed_machine(&db, &machine).await;
        machine.id = MachineId::new();

        sqlx::query("UPDATE machine_config SET config_json = jsonb(?1) WHERE id = ?2")
            .bind(serde_json::to_string(&machine).expect("serialize corrupt config"))
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .expect("corrupt stored config");

        let err = db
            .machine_config(id)
            .await
            .expect_err("corrupt config should fail decode");
        assert!(err.to_string().contains("machine_config.config_json.id"));
    }

    #[tokio::test]
    async fn machine_config_decode_rejects_json_name_mismatch() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let mut machine =
            machine_from_path(id, "indexed-name".to_string(), paths.machine(id).dir());
        seed_machine(&db, &machine).await;
        machine.name = "json-name".to_string();

        sqlx::query("UPDATE machine_config SET config_json = jsonb(?1) WHERE id = ?2")
            .bind(serde_json::to_string(&machine).expect("serialize corrupt config"))
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .expect("corrupt stored config");

        let err = db
            .machine_config(id)
            .await
            .expect_err("corrupt config should fail decode");
        assert!(err.to_string().contains("machine_config.config_json.name"));
    }

    #[tokio::test]
    async fn machine_state_decode_rejects_json_machine_id_mismatch() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let machine = machine_from_path(id, "corrupt-state".to_string(), paths.machine(id).dir());
        seed_machine(&db, &machine).await;
        let corrupt_state = machine_state(MachineId::new(), MachineRuntimeState::Stopped);

        sqlx::query("UPDATE machine_state SET state_json = jsonb(?1) WHERE machine_id = ?2")
            .bind(serde_json::to_string(&corrupt_state).expect("serialize corrupt state"))
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .expect("corrupt stored state");

        let err = db
            .machine_state(id)
            .await
            .expect_err("corrupt state should fail decode");
        assert!(err
            .to_string()
            .contains("machine_state.state_json.machineId"));
    }

    #[tokio::test]
    async fn machine_state_decode_rejects_json_status_mismatch() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let id = MachineId::new();
        let machine = machine_from_path(id, "corrupt-status".to_string(), paths.machine(id).dir());
        seed_machine(&db, &machine).await;

        sqlx::query("UPDATE machine_state SET status = 'running' WHERE machine_id = ?1")
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .expect("corrupt stored state status");

        let err = db
            .machine_state(id)
            .await
            .expect_err("corrupt state should fail decode");
        assert!(err.to_string().contains("machine_state.state_json.status"));
    }

    #[tokio::test]
    async fn network_instance_decode_rejects_unknown_state() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let instance = network_instance("corrupt-network", None);
        db.save_network_instance(&instance)
            .await
            .expect("save network instance");

        sqlx::query("UPDATE network_instances SET state = 'stuck' WHERE id = ?1")
            .bind(&instance.id)
            .execute(&db.pool)
            .await
            .expect("corrupt network instance state");

        let err = db
            .network_instance(&instance.id)
            .await
            .expect_err("corrupt network instance should fail decode");
        assert!(err.to_string().contains("network_instances.state"));
    }

    #[tokio::test]
    async fn network_definition_decode_rejects_invalid_json() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");
        let definition = network_definition(
            "corrupt-definition",
            NetworkTopology::Nat,
            NetworkDriverPreference::Auto,
        );
        db.define_network(&definition)
            .await
            .expect("define network");

        sqlx::query("UPDATE network_definitions SET mode = 'not-json' WHERE name = ?1")
            .bind(&definition.name)
            .execute(&db.pool)
            .await
            .expect("corrupt network definition mode");

        let err = db
            .network_definition(&definition.name)
            .await
            .expect_err("corrupt network definition should fail decode");
        assert!(err.to_string().contains("network_definitions.mode"));
    }

    #[tokio::test]
    async fn duplicate_name_fails() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.expect("open db");

        let id1 = MachineId::new();
        let id2 = MachineId::new();
        let first = machine_from_path(id1, "dupe".to_string(), paths.machine(id1).dir());
        seed_machine(&db, &first).await;

        let second = machine_from_path(id2, "dupe".to_string(), paths.machine(id2).dir());
        let second_state = machine_state(id2, MachineRuntimeState::Stopped);
        let result = db.add_machine(&second, &second_state).await;
        assert!(matches!(
            result,
            Err(LibVmError::MachineAlreadyExists { name }) if name == "dupe"
        ));
    }

    #[tokio::test]
    async fn concurrent_connections_work() {
        let (_dir, paths) = temp_paths();
        let db1 = Store::new(&paths).await.expect("open db 1");
        let db2 = Store::new(&paths).await.expect("open db 2");

        let id = MachineId::new();
        let machine = machine_from_path(id, "shared".to_string(), paths.machine(id).dir());
        seed_machine(&db1, &machine).await;

        let found = db2
            .machine_config_by_name("shared")
            .await
            .expect("lookup via db2")
            .expect("should find machine from other connection");

        assert_eq!(found.id, id);
    }
}
