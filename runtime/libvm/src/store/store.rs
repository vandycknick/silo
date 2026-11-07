use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

#[cfg(test)]
use crate::paths::LocalPaths;
use crate::store::catalog_guard::CatalogGuard;
#[cfg(test)]
use crate::store::models::DbConfig;
#[cfg(test)]
use crate::store::ConfigStore;
use crate::LibVmError;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub(super) pool: SqlitePool,
    pub(super) home: PathBuf,
    /// `<home>/images`, the immutable pool; `state.db` is `<home>/state.db`.
    pub(super) images_dir: PathBuf,
    /// Explicit capability for detached filesystem workers, independent of
    /// SqlitePool::close; native connections retain their own clone as well.
    pub(super) catalog: std::sync::Arc<CatalogGuard>,
    #[cfg(test)]
    pub(super) layer_hook: Option<std::sync::Arc<crate::store::layer_store::tests::WorkerHook>>,
    #[cfg(test)]
    pub(super) resource_budget_directory: Option<PathBuf>,
}

impl Store {
    pub(crate) fn home_path(&self) -> &Path {
        &self.home
    }
    pub(crate) fn images_path(&self) -> &Path {
        &self.images_dir
    }
    #[cfg(test)]
    pub(crate) async fn new(paths: &LocalPaths) -> Result<Self, LibVmError> {
        let store = Self::open(&paths.state_db_path()).await?;
        store.read_or_seed_db_config(&DbConfig::current()).await?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) async fn execute_test_sql(&self, statement: &'static str) -> Result<(), LibVmError> {
        sqlx::raw_sql(statement).execute(&self.pool).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_pool(&self) -> &SqlitePool {
        &self.pool
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn storage_operation_count(&self) -> Result<i64, LibVmError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&self.pool)
            .await?)
    }

    #[cfg(test)]
    pub(crate) async fn close(self) {
        self.pool.close().await;
    }

    pub(crate) async fn open(state_db_path: &Path) -> Result<Self, LibVmError> {
        let home = state_db_path.parent().ok_or_else(|| {
            std::io::Error::other(format!(
                "state database {} has no parent directory",
                state_db_path.display()
            ))
        })?;
        std::fs::create_dir_all(home)?;
        let guard = CatalogGuard::writable(home).await?;
        let pool = Self::connect_guarded(state_db_path, guard.clone()).await?;
        if let Err(error) = MIGRATOR.run(&pool).await {
            pool.close().await;
            return Err(match error {
                sqlx::migrate::MigrateError::VersionMismatch(_)
                | sqlx::migrate::MigrateError::VersionMissing(_) => {
                    LibVmError::StateDatabaseIncompatible { source: error }
                }
                other => other.into(),
            });
        }
        let store = Self {
            pool,
            home: home.to_path_buf(),
            images_dir: home.join("images"),
            catalog: guard,
            #[cfg(test)]
            layer_hook: None,
            #[cfg(test)]
            resource_budget_directory: Some(home.join("resource-budget")),
        };
        match store.recover_image_cache().await {
            Ok(report) => {
                for deferred in report.deferred {
                    tracing::warn!(
                        ?deferred,
                        "image cache cleanup deferred; bytes and pending jobs retained"
                    );
                }
            }
            Err(error) => {
                store.pool.close().await;
                return Err(error);
            }
        }
        Ok(store)
    }

    #[cfg(test)]
    async fn connect(path: &Path) -> Result<SqlitePool, LibVmError> {
        let home = path
            .parent()
            .ok_or_else(|| std::io::Error::other("state database has no parent"))?;
        let guard = CatalogGuard::writable(home).await?;
        Self::connect_guarded(path, guard).await
    }

    async fn connect_guarded(
        path: &Path,
        guard: std::sync::Arc<CatalogGuard>,
    ) -> Result<SqlitePool, LibVmError> {
        let expected = match crate::storage::identity_file::FileIdentity::from_path(path) {
            Ok(identity) => Some(identity),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let options = CatalogGuard::attach_sqlite(guard, Self::sqlite_options(path));
        let pool = SqlitePoolOptions::new()
            .acquire_timeout(Duration::from_secs(30))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // Native SQLite ownership of catalog.lock is installed
                    // before these database-touching PRAGMAs can run.
                    sqlx::raw_sql("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA fullfsync = ON; PRAGMA checkpoint_fullfsync = ON;")
                        .execute(connection).await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        if let Some(expected) = expected {
            if expected != crate::storage::identity_file::FileIdentity::from_path(path)? {
                pool.close().await;
                return Err(
                    std::io::Error::other("state database changed identity while opening").into(),
                );
            }
        }
        Ok(pool)
    }

    fn sqlite_options(path: &Path) -> SqliteConnectOptions {
        SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReadOnlyStore {
    pub(crate) pool: SqlitePool,
}

impl ReadOnlyStore {
    pub(crate) async fn open_if_exists(state_db_path: &Path) -> Result<Option<Self>, LibVmError> {
        let metadata = match std::fs::symlink_metadata(state_db_path) {
            Ok(metadata) if metadata.is_file() && metadata.len() >= 100 => metadata,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "state database is not a regular initialized SQLite file",
                )
                .into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let identity = crate::storage::identity_file::FileIdentity::from_metadata(&metadata);
        let home = state_db_path
            .parent()
            .ok_or_else(|| std::io::Error::other("state database has no parent"))?;
        let guard = CatalogGuard::readonly(home)?;
        let options = CatalogGuard::attach_sqlite(
            guard,
            SqliteConnectOptions::new()
                .filename(state_db_path)
                .read_only(true)
                .create_if_missing(false)
                .shared_cache(false)
                .busy_timeout(Duration::from_secs(5)),
        );
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("PRAGMA query_only = ON")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        if identity != crate::storage::identity_file::FileIdentity::from_path(state_db_path)? {
            pool.close().await;
            return Err(
                std::io::Error::other("state database changed identity while opening").into(),
            );
        }
        if let Err(error) = validate_embedded_migration_history(&pool).await {
            pool.close().await;
            return Err(error);
        }
        Ok(Some(Self { pool }))
    }

    pub(crate) async fn db_config(
        &self,
    ) -> Result<Option<crate::store::models::DbConfig>, LibVmError> {
        let os = sqlx::query_scalar::<_, String>("SELECT os FROM db_config WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(os.map(|os| crate::store::models::DbConfig { os }))
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

pub(crate) async fn validate_embedded_migration_history(
    pool: &SqlitePool,
) -> Result<(), LibVmError> {
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
                "incompatible state: applied migration count {} does not match embedded migration count {}; reinstall Silo and explicitly wipe state",
                rows.len(),
                expected.len()
            ),
        });
    }
    for (row, migration) in rows.iter().zip(expected) {
        let version: i64 = row.try_get("version")?;
        let description: String = row.try_get("description")?;
        let success: bool = row.try_get("success")?;
        let checksum: Vec<u8> = row.try_get("checksum")?;
        if version != migration.version
            || description != migration.description
            || !success
            || migration.checksum != checksum
        {
            return Err(LibVmError::StateDatabaseIncompatible {
                source: sqlx::migrate::MigrateError::VersionMismatch(version),
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
    use crate::store::models::DbConfig;
    use crate::store::models::MachineId;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig, MachineRootfsRecord, MachineRuntimeState,
        MachineState, NetworkAttachment, NetworkDefinition, NetworkDriverPreference,
        NetworkInstance, NetworkInstanceState, NetworkTopology,
    };
    use crate::store::{MachineStore, NetworkStore, Store};
    use crate::LibVmError;

    mod logical_catalog {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/live_catalog.rs"
        ));
    }

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
            vmm_pid: None,
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

        assert_eq!(config, DbConfig::current());
        assert_eq!(db.images_dir, paths.images_dir());
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
        assert_eq!(db_config_columns, ["id", "os", "created_at", "modified_at"]);

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
    async fn incompatible_schema_refusal_preserves_existing_state() {
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
        sqlx::query("CREATE TABLE owner_data (value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO owner_data VALUES ('must survive refusal')")
            .execute(&pool)
            .await
            .unwrap();
        let retained_file = dir.path().join("owner-root.raw");
        std::fs::write(&retained_file, b"owner bytes").unwrap();
        pool.close().await;

        let error = Store::open(&state_db)
            .await
            .expect_err("old state database must not be adopted");
        assert!(matches!(
            error,
            LibVmError::StateDatabaseIncompatible { .. }
        ));
        assert!(error.to_string().contains("reinstall"));
        assert!(error.to_string().contains("wipe"));
        let retained = sqlx::SqlitePool::connect(&format!("sqlite://{}", state_db.display()))
            .await
            .unwrap();
        let value: String = sqlx::query_scalar("SELECT value FROM owner_data")
            .fetch_one(&retained)
            .await
            .unwrap();
        assert_eq!(value, "must survive refusal");
        retained.close().await;
        assert_eq!(std::fs::read(retained_file).unwrap(), b"owner bytes");
        assert!(state_db.is_file());
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
    async fn persistent_direct_boot_refuses_transient_selection_without_replacing_old_bundle() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let config = machine_from_path(id, "pinned-only".into(), paths.machine(id).dir());
        db.add_machine(&config, &machine_state(id, MachineRuntimeState::Stopped))
            .await
            .unwrap();
        let original = db.machine_storage(id).await.unwrap().unwrap();
        let mut transient = original.clone();
        if let crate::BootProfile::LinuxDirect { binding, .. } = &mut transient.boot {
            *binding = crate::BootBinding::RuntimeSelected;
        }
        assert!(db
            .save_machine_config_with_storage(&config, &transient)
            .await
            .is_err());
        assert_eq!(db.machine_storage(id).await.unwrap().unwrap(), original);
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
            root_disk_path: paths.machine(id).dir().join("root.raw"),
            root_disk_size_bytes: 64 * 1024 * 1024,
            created_at: 7,
        };

        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            rootfs.root_disk_size_bytes,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let _boot = db.pin_test_boot(&mut storage).await.unwrap();
        db.add_machine_with_rootfs(
            &machine,
            &machine_state(id, MachineRuntimeState::Stopped),
            &rootfs,
            &storage,
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
            vmm_pid: Some(1234),
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

    #[tokio::test]
    async fn acknowledged_connections_use_wal_full_and_fullfsync() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let mut first = db.pool.acquire().await.unwrap();
        let mut second = db.pool.acquire().await.unwrap();
        for connection in [&mut first, &mut second] {
            let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            let fullfsync: i64 = sqlx::query_scalar("PRAGMA fullfsync")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            assert_eq!(journal, "wal");
            assert_eq!(sync, 2);
            assert_eq!(fullfsync, 1);
        }
    }

    #[tokio::test]
    async fn readonly_planning_excludes_writers_and_outliving_pool_clones() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = db.pool.clone();
        drop(db);
        assert!(
            crate::store::ReadOnlyStore::open_if_exists(&paths.state_db_path())
                .await
                .is_err()
        );
        pool.close().await;
        drop(pool);
        let readonly = crate::store::ReadOnlyStore::open_if_exists(&paths.state_db_path())
            .await
            .unwrap()
            .unwrap();
        assert!(readonly.db_config().await.unwrap().is_some());
        // Writers cannot acquire even their first connection during read-only planning.
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            Store::open(&paths.state_db_path())
        )
        .await
        .is_err());
        let readonly_pool = readonly.pool.clone();
        drop(readonly);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            Store::open(&paths.state_db_path())
        )
        .await
        .is_err());
        readonly_pool.close().await;
        drop(readonly_pool);
        Store::open(&paths.state_db_path())
            .await
            .unwrap()
            .close()
            .await;
    }

    #[tokio::test]
    async fn unknown_history_dry_run_preserves_logical_catalog_and_noncatalog_state() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        sqlx::query("UPDATE _sqlx_migrations SET version = 999")
            .execute(&db.pool)
            .await
            .unwrap();
        db.close().await;
        let identity =
            crate::storage::identity_file::FileIdentity::from_path(&paths.state_db_path()).unwrap();
        let entries = || {
            std::fs::read_dir(paths.home())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| !matches!(name.to_str(), Some("state.db-wal" | "state.db-shm")))
                .collect::<BTreeSet<_>>()
        };
        let before = entries();
        let logical_before = logical_catalog::snapshot(paths.home()).await;
        let error = crate::store::ReadOnlyStore::open_if_exists(&paths.state_db_path())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            LibVmError::StateDatabaseIncompatible { .. }
        ));
        assert_eq!(entries(), before);
        assert_eq!(
            logical_catalog::snapshot(paths.home()).await,
            logical_before
        );
        assert_eq!(
            crate::storage::identity_file::FileIdentity::from_path(&paths.state_db_path()).unwrap(),
            identity
        );
        let pool = Store::connect(&paths.state_db_path()).await.unwrap();
        let version: i64 = sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 999);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM db_config")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn storage_insert_failure_rolls_back_machine_state_and_provenance() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        db.execute_test_sql("CREATE TRIGGER reject_storage BEFORE INSERT ON machine_storage BEGIN SELECT RAISE(ABORT, 'reject storage'); END;").await.unwrap();
        let id = MachineId::new();
        let config = machine_from_path(id, "atomic".to_string(), paths.machine(id).dir());
        let rootfs = MachineRootfsRecord {
            machine_id: id,
            source_kind: crate::ImageSourceKind::Disk,
            requested_reference: "/input.raw".to_string(),
            selected_reference: None,
            manifest_digest: None,
            config_digest: None,
            image_id: None,
            root_disk_path: config.machine_dir.join("root.raw"),
            root_disk_size_bytes: 512,
            created_at: 1,
        };
        let storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        assert!(db
            .add_machine_with_rootfs(
                &config,
                &machine_state(id, MachineRuntimeState::Stopped),
                &rootfs,
                &storage
            )
            .await
            .is_err());
        for (table, query) in [
            ("machine_config", "SELECT count(*) FROM machine_config"),
            ("machine_state", "SELECT count(*) FROM machine_state"),
            ("machine_rootfs", "SELECT count(*) FROM machine_rootfs"),
            ("machine_storage", "SELECT count(*) FROM machine_storage"),
        ] {
            let count: i64 = sqlx::query_scalar(query).fetch_one(&db.pool).await.unwrap();
            assert_eq!(count, 0, "partial row in {table}");
        }
    }

    #[tokio::test]
    async fn embedded_operation_fence_round_trip_and_invalid_update_are_atomic() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        seed_machine(
            &db,
            &machine_from_path(id, "fenced".to_string(), paths.machine(id).dir()),
        )
        .await;
        let mut storage = db.machine_storage(id).await.unwrap().unwrap();
        let operation = uuid::Uuid::new_v4();
        storage.operation = Some(crate::StorageOperationRecord {
            id: operation,
            kind: crate::StorageOperationKind::Relocate,
            state: crate::StorageOperationState::Prepared,
            machine_id: Some(id.into()),
            ownership_epoch: 0,
        });
        storage.relocation_operation = Some(operation);
        storage.fence = Some(crate::FenceRecord {
            operation,
            ownership_epoch: 0,
            state: crate::FenceState::Prepared,
        });
        let mut tx = db.pool.begin().await.unwrap();
        Store::write_machine_storage(&mut tx, id, &storage)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(db.machine_storage(id).await.unwrap(), Some(storage.clone()));
        let mut invalid = storage.clone();
        invalid.fence.as_mut().unwrap().ownership_epoch = 1;
        let mut tx = db.pool.begin().await.unwrap();
        assert!(matches!(
            Store::write_machine_storage(&mut tx, id, &invalid).await,
            Err(LibVmError::InvalidStorageRecord { .. })
        ));
        tx.rollback().await.unwrap();
        assert_eq!(db.machine_storage(id).await.unwrap(), Some(storage));
    }

    #[tokio::test]
    async fn cache_dependency_preflight_covers_relative_disks_boot_symlinks_and_shares() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let mut config = machine_from_path(id, "dependencies".to_string(), paths.machine(id).dir());
        std::fs::create_dir_all(&config.machine_dir).unwrap();
        let _pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let candidate = paths.images_dir().join("streams/sha256/retained");
        std::fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        std::fs::write(&candidate, [0x64; 512]).unwrap();
        // A source string is provenance only and cannot retain evictable bytes.
        config.image_ref = candidate.display().to_string();
        seed_machine(&db, &config).await;
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        crate::store::ensure_cache_paths_unreferenced(
            &mut tx,
            std::slice::from_ref(&candidate),
            &db.home,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        config.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                crate::machine::root_storage::disk(
                    "root.raw",
                    vm_spec::DiskRole::Root,
                    512,
                    "silo-root".into(),
                )
                .unwrap(),
                vm_spec::Disk {
                    path: "../../images/streams/sha256/retained".into(),
                    role: vm_spec::DiskRole::Data,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 512,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-data-0").unwrap(),
                    read_only: false,
                },
            ],
        });
        db.save_machine_config(&config).await.unwrap();
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert!(matches!(
            crate::store::ensure_cache_paths_unreferenced(
                &mut tx,
                std::slice::from_ref(&candidate),
                &db.home,
            )
            .await,
            Err(LibVmError::CacheDependency { .. })
        ));
        tx.rollback().await.unwrap();
        config.spec.storage = None;
        let alias = paths.home().join("kernel-alias");
        std::os::unix::fs::symlink(&candidate, &alias).unwrap();
        config.spec.boot = Some(vm_spec::Boot {
            kernel: Some(vm_spec::Kernel {
                path: Some(alias),
                initramfs: None,
                cmdline: Vec::new(),
            }),
            userdata: None,
        });
        db.save_machine_config(&config).await.unwrap();
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert!(crate::store::ensure_cache_paths_unreferenced(
            &mut tx,
            std::slice::from_ref(&candidate),
            &db.home,
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        config.spec.boot = None;
        config.spec.mounts.push(vm_spec::Mount {
            source: paths.images_dir().to_path_buf(),
            tag: "/images".into(),
            read_only: true,
        });
        db.save_machine_config(&config).await.unwrap();
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert!(crate::store::ensure_cache_paths_unreferenced(
            &mut tx,
            std::slice::from_ref(&candidate),
            &db.home,
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        assert_eq!(std::fs::metadata(candidate).unwrap().len(), 512);
    }

    #[tokio::test]
    async fn path_identity_preserves_sqlite_writer_locks_across_processes() {
        const PROBE: &str = "SILO_STORE_IDENTITY_LOCK_PROBE";
        if let Some(path) = std::env::var_os(PROBE) {
            let pool = Store::connect(Path::new(&path)).await.unwrap();
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("PRAGMA busy_timeout = 50")
                .execute(&mut *connection)
                .await
                .unwrap();
            let result = sqlx::query("UPDATE lock_probe SET value = value + 1")
                .execute(&mut *connection)
                .await;
            let blocked = std::env::var_os("SILO_STORE_EXPECT_BLOCKED").is_some();
            if blocked {
                let error = result.unwrap_err();
                assert!(
                    matches!(&error, sqlx::Error::Database(error) if error.code().is_some_and(|code| code == "5" || code == "SQLITE_BUSY"))
                );
            } else {
                result.unwrap();
            }
            drop(connection);
            pool.close().await;
            return;
        }
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        db.execute_test_sql(
            "CREATE TABLE lock_probe(value INTEGER NOT NULL); INSERT INTO lock_probe VALUES (0);",
        )
        .await
        .unwrap();
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        sqlx::query("UPDATE lock_probe SET value = 10")
            .execute(&mut *tx)
            .await
            .unwrap();
        for _ in 0..64 {
            crate::storage::identity_file::FileIdentity::from_path(&paths.state_db_path()).unwrap();
        }
        let test = concat!(
            module_path!(),
            "::path_identity_preserves_sqlite_writer_locks_across_processes"
        )
        .split_once("::")
        .unwrap()
        .1;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture"])
            .env(PROBE, paths.state_db_path())
            .env("SILO_STORE_EXPECT_BLOCKED", "1");
        let child = command.output().unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stdout)
        );
        tx.commit().await.unwrap();
        let child = command
            .env_remove("SILO_STORE_EXPECT_BLOCKED")
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stdout)
        );
        let value: i64 = sqlx::query_scalar("SELECT value FROM lock_probe")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(value, 11);
    }

    #[tokio::test]
    async fn selected_geometry_and_config_update_commit_or_rollback_together() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let mut config = machine_from_path(id, "resized".to_string(), paths.machine(id).dir());
        seed_machine(&db, &config).await;
        config.root_disk_size = Some(1024);
        db.save_machine_config(&config).await.unwrap();
        let selected = db.machine_storage(id).await.unwrap().unwrap();
        assert!(matches!(
            selected.root,
            crate::MachineRoot::OpaqueRaw {
                geometry: vm_spec::DiskGeometry { length: 1024, .. },
                ..
            }
        ));
        let mut invalid = config.clone();
        invalid.name = "must-not-commit".to_string();
        invalid.root_disk_size = Some(513);
        assert!(matches!(
            db.save_machine_config(&invalid).await,
            Err(LibVmError::Storage(crate::storage::StorageError::Bound(_)))
        ));
        assert_eq!(db.machine_config(id).await.unwrap(), Some(config));
        assert_eq!(db.machine_storage(id).await.unwrap(), Some(selected));
    }

    #[tokio::test]
    async fn malformed_or_missing_new_format_storage_is_a_typed_observation_error() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        seed_machine(
            &db,
            &machine_from_path(id, "corrupt-storage".to_string(), paths.machine(id).dir()),
        )
        .await;
        sqlx::query("UPDATE machine_storage SET record_json = x'ff' WHERE machine_id = ?1")
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        let error = db.machine_storage(id).await.unwrap_err();
        assert!(matches!(error, LibVmError::InvalidStorageRecord { .. }));
        assert!(error.is_machine_observation_error());
        sqlx::query("DELETE FROM machine_storage WHERE machine_id = ?1")
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        let error = db.machine_storage(id).await.unwrap_err();
        assert!(matches!(error, LibVmError::InvalidStorageRecord { .. }));
        assert!(error.is_machine_observation_error());
        assert!(db
            .machine_storage(MachineId::new())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn deferred_cache_recovery_does_not_strand_private_roots() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        std::fs::write(&source, [0x64; 512]).unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        // Deliberately leave this stream unrooted so recovery must discover the
        // configured external dependency, not an active publication guard.
        let stream = pool.publish_stream(&source).unwrap();
        let id = MachineId::new();
        let mut config =
            machine_from_path(id, "independent-root".to_string(), paths.machine(id).dir());
        std::fs::create_dir_all(&config.machine_dir).unwrap();
        let private_root = config.machine_dir.join("root.raw");
        std::fs::write(&private_root, [0x65; 512]).unwrap();
        std::fs::set_permissions(&private_root, std::fs::Permissions::from_mode(0o600)).unwrap();
        config.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                vm_spec::Disk {
                    path: "root.raw".into(),
                    role: vm_spec::DiskRole::Root,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 512,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-root").unwrap(),
                    read_only: false,
                },
                vm_spec::Disk {
                    path: stream.path.clone(),
                    role: vm_spec::DiskRole::Data,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 512,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-data-0").unwrap(),
                    read_only: true,
                },
            ],
        });
        seed_machine(&db, &config).await;
        sqlx::query("INSERT INTO image_stream_gc (stream_id, size_bytes) VALUES (?1, 512)")
            .bind(stream.id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        db.close().await;
        let reopened = Store::open(&paths.state_db_path()).await.unwrap();
        assert_eq!(reopened.machine_config(id).await.unwrap(), Some(config));
        assert!(reopened.machine_storage(id).await.unwrap().is_some());
        assert_eq!(std::fs::read(private_root).unwrap(), [0x65; 512]);
        assert!(stream.path.is_file());
        let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM image_stream_gc")
            .fetch_one(&reopened.pool)
            .await
            .unwrap();
        assert_eq!(jobs, 1);
        assert!(matches!(
            crate::store::ImageStore::prune_images(&reopened).await,
            Err(LibVmError::CacheDependency { .. })
        ));
    }

    #[tokio::test]
    async fn corrupt_recovery_metadata_remains_a_fatal_startup_error() {
        let (_dir, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let id = MachineId::new();
        let config =
            machine_from_path(id, "retained-on-error".to_string(), paths.machine(id).dir());
        std::fs::create_dir_all(&config.machine_dir).unwrap();
        let private = config.machine_dir.join("root.raw");
        std::fs::write(&private, [0x65; 512]).unwrap();
        seed_machine(&db, &config).await;
        sqlx::query("INSERT INTO image_stream_gc (stream_id, size_bytes) VALUES ('invalid-stream-identity', 512)")
            .execute(&db.pool).await.unwrap();
        db.close().await;
        Store::open(&paths.state_db_path())
            .await
            .expect_err("corrupt recovery metadata must not be downgraded to a deferral");
        let inspected = Store::connect(&paths.state_db_path()).await.unwrap();
        let job: String = sqlx::query_scalar("SELECT stream_id FROM image_stream_gc")
            .fetch_one(&inspected)
            .await
            .unwrap();
        assert_eq!(job, "invalid-stream-identity");
        let machines: i64 = sqlx::query_scalar("SELECT count(*) FROM machine_config")
            .fetch_one(&inspected)
            .await
            .unwrap();
        assert_eq!(machines, 1);
        assert_eq!(std::fs::read(private).unwrap(), [0x65; 512]);
        inspected.close().await;
        drop(pool);
    }

    #[tokio::test]
    async fn object_recovery_defers_persisted_disk_kernel_and_directory_mount_dependencies() {
        for dependency in ["disk", "kernel", "mount"] {
            let (_dir, paths) = temp_paths();
            let db = Store::new(&paths).await.unwrap();
            let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
            let source = paths.home().join("object-source");
            std::fs::write(&source, [0x21; 512]).unwrap();
            let protected = pool.publish_object(&source).unwrap();
            std::fs::write(&source, [0x22; 512]).unwrap();
            let orphan = pool.publish_object(&source).unwrap();
            let unrelated_stream = pool.publish_stream(&source).unwrap();
            let id = MachineId::new();
            let mut config =
                machine_from_path(id, format!("object-{dependency}"), paths.machine(id).dir());
            std::fs::create_dir_all(&config.machine_dir).unwrap();
            let private = config.machine_dir.join("root.raw");
            std::fs::write(&private, [0x23; 512]).unwrap();
            config.spec.storage = Some(vm_spec::Storage {
                disks: vec![vm_spec::Disk {
                    path: private.clone(),
                    role: vm_spec::DiskRole::Root,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 512,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new("silo-root").unwrap(),
                    read_only: false,
                }],
            });
            match dependency {
                "disk" => config
                    .spec
                    .storage
                    .as_mut()
                    .unwrap()
                    .disks
                    .push(vm_spec::Disk {
                        path: protected.path.clone(),
                        role: vm_spec::DiskRole::Data,
                        format: vm_spec::DiskFormat::Raw,
                        geometry: vm_spec::DiskGeometry {
                            length: 512,
                            logical_sector_size: 512,
                        },
                        block_id: vm_spec::BlockId::new("silo-data-0").unwrap(),
                        read_only: true,
                    }),
                "kernel" => {
                    config.spec.boot = Some(vm_spec::Boot {
                        kernel: Some(vm_spec::Kernel {
                            path: Some(protected.path.clone()),
                            initramfs: None,
                            cmdline: vec![],
                        }),
                        userdata: None,
                    })
                }
                _ => config.spec.mounts.push(vm_spec::Mount {
                    source: protected.path.parent().unwrap().to_path_buf(),
                    tag: "/retained-objects".into(),
                    read_only: true,
                }),
            }
            seed_machine(&db, &config).await;
            let report = db.recover_image_cache().await.unwrap();
            assert!(
                matches!(report.deferred.as_slice(),[crate::store::models::CacheCleanupDeferral::ExternalDependency{machine,..}] if machine==&id.to_string())
            );
            assert_eq!(std::fs::read(&protected.path).unwrap(), [0x21; 512]);
            // Recovery preflights a complete bounded batch before deleting any
            // member; a protected member conservatively defers its batch peers.
            assert!(orphan.path.exists());
            db.close().await;
            let reopened = Store::open(&paths.state_db_path()).await.unwrap();
            assert_eq!(reopened.machine_config(id).await.unwrap(), Some(config));
            assert!(reopened.machine_storage(id).await.unwrap().is_some());
            assert_eq!(std::fs::read(private).unwrap(), [0x23; 512]);
            assert_eq!(std::fs::read(protected.path).unwrap(), [0x21; 512]);
            assert!(orphan.path.exists());
            assert!(unrelated_stream.path.exists());
        }
    }

    #[tokio::test]
    async fn vmdk_semantic_machine_roots_survive_prune_recovery_and_release_last_reference() {
        use crate::store::ImageStore;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("source");
        std::fs::write(&source, [0x42; 512]).unwrap();
        let lower = pool.publish_stream(&source).unwrap();
        let mut configs = Vec::new();
        sqlx::query("INSERT INTO image_manifest(digest,media_type,image_id,platform_os,platform_architecture,config_digest,layer_count,total_size_bytes,created_at) VALUES('sha256:flat-manifest','application/vnd.oci.image.manifest.v1+json','sha256:flat-image','linux','amd64','sha256:flat-config',0,512,1)")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO image_ref(requested_reference,selected_reference,manifest_digest,created_at,updated_at) VALUES('example.test/flat:latest','example.test/flat@sha256:flat-manifest','sha256:flat-manifest',1,1)")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO image_rootfs_artifact(image_id,manifest_digest,config_digest,platform_os,platform_architecture,filesystem,rootfs_path,size_bytes,created_at,stream_id,conversion_abi) VALUES('sha256:flat-image','sha256:flat-manifest','sha256:flat-config','linux','amd64','ext4',?1,512,1,?2,?3)")
            .bind(lower.path.to_str().unwrap()).bind(lower.id.to_string()).bind(crate::image::oci::CONVERSION_ABI)
            .execute(&db.pool).await.unwrap();
        let mut uuids = std::collections::HashSet::new();
        let lower_uuid = uuid::Uuid::new_v4();
        for index in 0..2 {
            let id = MachineId::new();
            let mut config =
                machine_from_path(id, format!("overlay-{index}"), paths.machine(id).dir());
            std::fs::create_dir_all(&config.machine_dir).unwrap();
            let capacity = 64 * 1024 * 1024;
            let upper = disk_image::ext4::upper::format_upper(
                &config.machine_dir.join("upper.raw"),
                rootfs_spec::upper_geometry::UpperCapacity::new(capacity).unwrap(),
            )
            .unwrap();
            assert!(uuids.insert(upper.uuid));
            config.root_disk_size = Some(capacity);
            config.spec.storage = Some(vm_spec::Storage {
                disks: vec![
                    crate::machine::root_storage::disk(
                        "lower.vmdk",
                        vm_spec::DiskRole::RootLower,
                        512,
                        "silo-root-lower".into(),
                    )
                    .unwrap(),
                    crate::machine::root_storage::disk(
                        "upper.raw",
                        vm_spec::DiskRole::RootUpper,
                        capacity,
                        "silo-root-upper".into(),
                    )
                    .unwrap(),
                ],
            });
            seed_machine(&db, &config).await;
            let mut storage = db.machine_storage(id).await.unwrap().unwrap();
            storage.root = crate::MachineRoot::LinuxOverlay {
                lower: crate::OverlayLower::FlatExt4 {
                    stream: lower.id,
                    geometry: vm_spec::DiskGeometry {
                        length: 512,
                        logical_sector_size: 512,
                    },
                    filesystem_uuid: lower_uuid,
                },
                upper: crate::PrivatePath::new("upper.raw").unwrap(),
                upper_uuid: upper.uuid,
                capacity,
                ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
                overlay_profile: crate::OverlayProfile::SiloOverlayV1,
                temporary_directory: crate::TemporaryDirectoryPolicy::DiskBacked,
            };
            storage.profile = crate::StorageProfile::LinuxOverlayV1;
            storage.backend = crate::BackendRequirement::KrunOverlay;
            if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot {
                *root_selector = crate::RootSelector::ManagedOverlay;
            }
            db.save_machine_config_with_storage(&config, &storage)
                .await
                .unwrap();
            configs.push(config);
        }
        db.remove_image(
            "example.test/flat:latest",
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        // No image alias, descriptor or operation lease retains this stream.
        // Even an already queued collection must obey the semantic machine roots.
        sqlx::query("INSERT INTO image_stream_gc(stream_id,size_bytes) VALUES(?1,512)")
            .bind(lower.id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        db.prune_images().await.unwrap();
        assert_eq!(std::fs::read(&lower.path).unwrap(), [0x42; 512]);
        db.close().await;
        let db = Store::open(&paths.state_db_path()).await.unwrap();
        assert!(lower.path.exists());
        db.remove_machine(&configs[0]).await.unwrap();
        db.prune_images().await.unwrap();
        assert!(lower.path.exists());
        db.remove_machine(&configs[1]).await.unwrap();
        db.prune_images().await.unwrap();
        assert!(!lower.path.exists());
    }

    #[tokio::test]
    async fn launch_operation_survives_cancellation_and_retires_exact_generation_atomically() {
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let config = machine_from_path(id, "retained-launch".into(), paths.machine(id).dir());
        seed_machine(&db, &config).await;
        let storage = db.machine_storage(id).await.unwrap().unwrap();
        let run = uuid::Uuid::new_v4();
        let owner = db
            .register_launch_storage(id, run, &storage, &config.spec)
            .await
            .unwrap();
        let operation = owner.operation_id();
        let duplicate = owner.lock().duplicate_inheritable().unwrap();
        let identity = owner.file_identity().unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        assert!(pool.try_exclusive_lease(operation).unwrap().is_none());
        drop(owner);
        assert!(pool.try_exclusive_lease(operation).unwrap().is_none());
        drop(duplicate);
        let operations = db.launch_storage_operations(id).await.unwrap();
        assert_eq!(operations.len(), 1);
        assert!(!operations[0].admitted);
        db.mark_launch_storage_admitted(operation).await.unwrap();
        assert!(db.launch_storage_operations(id).await.unwrap()[0].admitted);
        let mut next = machine_state(id, MachineRuntimeState::Stopped);
        next.updated_at = 7;
        assert!(db
            .try_retire_launch_storage(
                operation,
                uuid::Uuid::new_v4(),
                storage.storage_generation,
                &next,
                crate::StorageStopOutcome::Forced
            )
            .await
            .is_err());
        assert_eq!(db.launch_storage_operations(id).await.unwrap().len(), 1);
        sqlx::query("CREATE TRIGGER reject_retirement BEFORE UPDATE ON machine_state BEGIN SELECT RAISE(ABORT,'retirement interrupted'); END")
            .execute(&db.pool).await.unwrap();
        assert!(db
            .try_retire_launch_storage(
                operation,
                run,
                storage.storage_generation,
                &next,
                crate::StorageStopOutcome::Forced
            )
            .await
            .is_err());
        assert_eq!(
            db.machine_storage(id).await.unwrap().unwrap().stop_outcome,
            storage.stop_outcome
        );
        assert_eq!(db.launch_storage_operations(id).await.unwrap().len(), 1);
        sqlx::query("DROP TRIGGER reject_retirement")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(db
            .try_retire_launch_storage(
                operation,
                run,
                storage.storage_generation,
                &next,
                crate::StorageStopOutcome::Forced
            )
            .await
            .unwrap());
        assert!(db.launch_storage_operations(id).await.unwrap().is_empty());
        assert_eq!(db.machine_state(id).await.unwrap().unwrap(), next);
        assert_eq!(
            db.machine_storage(id).await.unwrap().unwrap().stop_outcome,
            crate::StorageStopOutcome::Forced
        );
        assert_eq!(
            pool.try_exclusive_lease(operation)
                .unwrap()
                .unwrap()
                .file_identity()
                .unwrap(),
            identity
        );
    }

    #[tokio::test]
    async fn launch_pins_and_external_constraints_survive_machine_row_deletion() {
        use crate::store::ImageStore;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("stream-source");
        std::fs::write(&source, [9; 512]).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let id = MachineId::new();
        let mut config = machine_from_path(id, "operation-only".into(), paths.machine(id).dir());
        config.spec.mounts.push(vm_spec::Mount {
            source: paths.images_dir().join("streams"),
            tag: "foreign-share".into(),
            read_only: true,
        });
        seed_machine(&db, &config).await;
        let storage = db.machine_storage(id).await.unwrap().unwrap();
        let owner = db
            .register_launch_storage(id, uuid::Uuid::new_v4(), &storage, &config.spec)
            .await
            .unwrap();
        let operation = owner.operation_id();
        sqlx::query("DELETE FROM machine_config WHERE id=?1")
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(db.launch_storage_operations(id).await.unwrap().len(), 1);
        assert!(matches!(
            db.prune_images().await,
            Err(LibVmError::CacheDependency { .. })
        ));
        assert_eq!(std::fs::read(&stream.path).unwrap(), [9; 512]);
        drop(owner);
        // Free lease is not permission to forget a launch's durable resources.
        assert!(db.prune_images().await.is_err());
        assert_eq!(db.launch_storage_operations(id).await.unwrap().len(), 1);
        let _exclusive = pool.try_exclusive_lease(operation).unwrap().unwrap();
        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
            .bind(operation.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        drop(_exclusive);
        db.prune_images().await.unwrap();
        assert!(!stream.path.exists());
    }

    #[tokio::test]
    async fn unknown_busy_or_missing_operation_lease_fails_recovery_closed() {
        use crate::store::ImageStore;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("source");
        std::fs::write(&source, [3; 512]).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let operation = uuid::Uuid::new_v4();
        let lease = pool.lease(operation).unwrap();
        assert!(db.prune_images().await.is_err());
        assert!(stream.path.exists());
        assert!(db
            .retain_storage_stream(&stream.id, operation)
            .await
            .is_err());
        drop(lease);
        let operation = uuid::Uuid::new_v4();
        let lease = db.begin_storage_operation(operation).await.unwrap();
        db.retain_storage_stream(&stream.id, operation)
            .await
            .unwrap();
        drop(lease);
        let path = paths
            .images_dir()
            .join("locks/leases")
            .join(format!("{operation}.lease"));
        std::fs::remove_file(&path).unwrap();
        assert!(db.prune_images().await.is_err());
        assert!(!path.exists());
        assert!(stream.path.exists());
    }

    #[tokio::test]
    async fn launch_snapshot_pins_managed_data_and_boot_objects_without_machine_roots() {
        use crate::store::ImageStore;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("source");
        std::fs::write(&source, [7; 512]).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let object = pool.publish_object(&source).unwrap();
        let id = MachineId::new();
        let config = machine_from_path(id, "closure-pins".into(), paths.machine(id).dir());
        seed_machine(&db, &config).await;
        let mut storage = db.machine_storage(id).await.unwrap().unwrap();
        storage.disks.push(crate::IncludedDisk {
            id: uuid::Uuid::new_v4(),
            role: vm_spec::DiskRole::Data,
            order: 1,
            storage: crate::DiskStorage::ManagedReadOnly {
                stream: stream.id,
                geometry: vm_spec::DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
            },
        });
        if let crate::BootProfile::LinuxDirect {
            binding,
            kernel_architecture,
            ..
        } = &mut storage.boot
        {
            *binding = crate::BootBinding::Pinned {
                kernel: object.digest,
                base_initramfs: object.digest,
                agent: Some(object.digest),
                architecture: *kernel_architecture,
                abi: crate::runtime::boot_assets::DIRECT_BOOT_ABI.into(),
            };
        } else {
            panic!("fixture must use LinuxDirect");
        }
        let crate::BootProfile::LinuxDirect { binding, .. } = &storage.boot else {
            panic!("direct fixture")
        };
        let bundle_input = paths.home().join("bundle");
        std::fs::write(&bundle_input, binding.canonical_bytes().unwrap()).unwrap();
        let (bundle, roots) = pool.publish_object_for_catalog(&bundle_input).unwrap();
        db.save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        drop(roots);
        // Committed semantic roots protect the same projection before launch.
        db.prune_images().await.unwrap();
        assert!(object.path.exists());
        assert!(stream.path.exists());
        assert!(bundle.path.exists());
        let owner = db
            .register_launch_storage(id, uuid::Uuid::new_v4(), &storage, &config.spec)
            .await
            .unwrap();
        let op = owner.operation_id();
        let duplicate = owner.lock().duplicate_inheritable().unwrap();
        sqlx::query("DELETE FROM machine_config WHERE id=?1")
            .bind(id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        drop(owner);
        db.prune_images().await.unwrap();
        assert_eq!(std::fs::read(&stream.path).unwrap(), [7; 512]);
        assert_eq!(std::fs::read(&object.path).unwrap(), [7; 512]);
        assert!(bundle.path.exists());
        let links: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM storage_operation_object WHERE operation_id=?1",
        )
        .bind(op.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(links, 2);
        drop(duplicate);
        // Launch roots remain until explicit terminal reconciliation, not EX alone.
        db.prune_images().await.unwrap();
        assert!(stream.path.exists());
        assert!(object.path.exists());
        let _terminal = pool.try_exclusive_lease(op).unwrap().unwrap();
        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
            .bind(op.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        drop(_terminal);
        db.prune_images().await.unwrap();
        assert!(!stream.path.exists());
        assert!(!object.path.exists());
    }

    #[tokio::test]
    async fn replaced_lease_inode_and_malformed_launch_closure_never_authorize_gc() {
        use crate::store::ImageStore;
        use std::os::unix::fs::OpenOptionsExt;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("source");
        std::fs::write(&source, [4; 512]).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let operation = uuid::Uuid::new_v4();
        let lease = db.begin_storage_operation(operation).await.unwrap();
        db.retain_storage_stream(&stream.id, operation)
            .await
            .unwrap();
        let path = paths
            .images_dir()
            .join("locks/leases")
            .join(format!("{operation}.lease"));
        let displaced = paths.home().join("displaced-lease");
        std::fs::rename(&path, &displaced).unwrap();
        let replacement = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert!(db.prune_images().await.is_err());
        assert!(stream.path.exists());
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
        drop(lease);
        let id = MachineId::new();
        let config = machine_from_path(id, "malformed-closure".into(), paths.machine(id).dir());
        seed_machine(&db, &config).await;
        let storage = db.machine_storage(id).await.unwrap().unwrap();
        let owner = db
            .register_launch_storage(id, uuid::Uuid::new_v4(), &storage, &config.spec)
            .await
            .unwrap();
        let json: String = sqlx::query_scalar(
            "SELECT json(record_json) FROM storage_operation WHERE operation_id=?1",
        )
        .bind(owner.operation_id().to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let mut malformed: serde_json::Value = serde_json::from_str(&json).unwrap();
        malformed["storageGeneration"] = serde_json::json!(storage.storage_generation + 1);
        sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(owner.operation_id().to_string())
            .bind(malformed.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(db.prune_images().await.is_err());
        assert!(stream.path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn roots_waiters_keep_current_thread_executor_available_for_sql_owners() {
        use crate::store::ImageStore;
        use std::time::Duration;
        let (_temp, paths) = temp_paths();
        let db = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let config = machine_from_path(id, "concurrent-roots".into(), paths.machine(id).dir());
        seed_machine(&db, &config).await;
        let storage = db.machine_storage(id).await.unwrap().unwrap();
        let run = uuid::Uuid::new_v4();
        let owner = db
            .register_launch_storage(id, run, &storage, &config.spec)
            .await
            .unwrap();
        let operation = owner.operation_id();
        drop(owner);
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("concurrent-source");
        std::fs::write(&source, [8; 512]).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let stream_operation = uuid::Uuid::new_v4();
        let _stream_lease = db.begin_storage_operation(stream_operation).await.unwrap();
        for phase in ["register", "admit", "retain", "retire"] {
            let images = paths.images_dir().to_path_buf();
            let (entered, ready) = tokio::sync::oneshot::channel();
            let (release, resume) = std::sync::mpsc::channel();
            // A real OS deadline releases roots even in the regressed code,
            // where synchronous flock would prevent Tokio timers from firing.
            let holder = std::thread::spawn(move || {
                let pool = crate::storage::pool::StoragePool::open(&images).unwrap();
                let roots = pool.lock_roots().unwrap();
                entered.send(()).unwrap();
                let executor_responsive = resume.recv_timeout(Duration::from_secs(3)).is_ok();
                drop(roots);
                executor_responsive
            });
            ready.await.unwrap();
            let worker = db.clone();
            let storage = storage.clone();
            let spec = config.spec.clone();
            let stream_id = stream.id;
            let task = tokio::spawn(async move {
                match phase {
                    "register" => worker
                        .register_launch_storage(id, uuid::Uuid::new_v4(), &storage, &spec)
                        .await
                        .map(drop),
                    "admit" => worker.mark_launch_storage_admitted(operation).await,
                    "retain" => {
                        worker
                            .retain_storage_stream(&stream_id, stream_operation)
                            .await
                    }
                    "retire" => worker
                        .try_retire_launch_storage(
                            operation,
                            run,
                            storage.storage_generation,
                            &machine_state(id, MachineRuntimeState::Stopped),
                            crate::StorageStopOutcome::Unknown,
                        )
                        .await
                        .map(|retired| assert!(retired)),
                    _ => unreachable!("closed test phase"),
                }
            });
            tokio::time::sleep(Duration::from_millis(30)).await;
            let sent_while_coordinated = release.send(()).is_ok();
            let result = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
            assert!(
                holder.join().unwrap(),
                "{phase} blocked the SQL executor on flock"
            );
            assert!(sent_while_coordinated);
            result.unwrap();
        }
    }

    async fn add_catalog_relative_raw_fixture(
        store: &Store,
        paths: &LocalPaths,
        name: &str,
    ) -> MachineConfig {
        use std::os::unix::fs::PermissionsExt;
        let id = MachineId::new();
        let config = machine_from_path(id, name.into(), paths.machine(id).dir());
        std::fs::create_dir_all(&config.machine_dir).unwrap();
        let disk = config.machine_dir.join("root.raw");
        std::fs::write(&disk, [0x51; 512]).unwrap();
        std::fs::set_permissions(&disk, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let _boot = store.pin_test_boot(&mut storage).await.unwrap();
        let rootfs = MachineRootfsRecord {
            machine_id: id,
            source_kind: crate::ImageSourceKind::Disk,
            requested_reference: "source-provenance.raw".into(),
            selected_reference: None,
            manifest_digest: None,
            config_digest: None,
            image_id: None,
            root_disk_path: disk,
            root_disk_size_bytes: 512,
            created_at: 1,
        };
        store
            .add_machine_with_rootfs(
                &config,
                &machine_state(id, MachineRuntimeState::Stopped),
                &rootfs,
                &storage,
            )
            .await
            .unwrap();
        drop(_boot);
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        config
    }

    #[tokio::test]
    async fn machine_publication_waits_for_existing_catalog_writer_before_dependency_reads() {
        use std::time::Duration;
        let (_temporary, paths) = temp_paths();
        let store = Store::new(&paths).await.unwrap();
        let writer = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let worker = store.clone();
        let mut publication = tokio::spawn(async move {
            add_catalog_relative_raw_fixture(&worker, &paths, "concurrent-publication").await
        });
        let early = tokio::time::timeout(Duration::from_millis(150), &mut publication).await;
        writer.commit().await.unwrap();
        assert!(early.is_err(), "publication must wait for write admission, not fail upgrading a read transaction: {early:?}");
        let config = tokio::time::timeout(Duration::from_secs(5), publication)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.machine_config(config.id).await.unwrap(),
            Some(config.clone())
        );
        let rootfs = store.machine_rootfs(config.id).await.unwrap().unwrap();
        assert_eq!(rootfs.root_disk_path, config.machine_dir.join("root.raw"));
        assert_eq!(rootfs.root_disk_size_bytes, 512);
        assert_eq!(
            store
                .machine_state(config.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MachineRuntimeState::Stopped
        );
        store.close().await;
    }

    #[tokio::test]
    async fn whole_home_rename_derives_all_machine_read_paths_from_current_catalog() {
        use crate::store::observation::ObservationStore;
        let temporary = tempfile::tempdir().unwrap();
        let old_home = temporary.path().join("old catalog home");
        let new_home = temporary.path().join("moved catalog home");
        let original_paths = LocalPaths::new(&old_home);
        let store = Store::new(&original_paths).await.unwrap();
        let original =
            add_catalog_relative_raw_fixture(&store, &original_paths, "relocated-machine").await;
        let id = original.id;
        let before = logical_catalog::snapshot(&old_home).await;
        store.close().await;
        std::fs::rename(&old_home, &new_home).unwrap();
        // A different real inode at the former spelling must never become
        // private-machine authority after opening the relocated catalog.
        std::fs::create_dir_all(&original.machine_dir).unwrap();
        std::fs::write(original.machine_dir.join("root.raw"), [0x72; 512]).unwrap();
        let expected = crate::paths::machine_data_dir_in(&new_home, id);
        let references = [
            id.to_string(),
            original.name.clone(),
            id.to_string()[..8].to_string(),
        ];
        let observer = ObservationStore::open(&new_home.join("state.db"))
            .await
            .unwrap();
        for reference in &references {
            let (config, state) = observer
                .lookup(&crate::machine::MachineRef::parse(reference.clone()).unwrap())
                .await
                .unwrap();
            assert_eq!(config.machine_dir, expected);
            assert_eq!(state.machine_id, id);
            assert_eq!(
                std::fs::read(config.machine_dir.join("root.raw")).unwrap(),
                [0x51; 512]
            );
        }
        observer.close().await.unwrap();
        assert_eq!(logical_catalog::snapshot(&new_home).await, before);
        let store = Store::open(&new_home.join("state.db")).await.unwrap();
        let mut decoded = vec![
            store.machine_config(id).await.unwrap().unwrap(),
            store
                .machine_config_by_name(&original.name)
                .await
                .unwrap()
                .unwrap(),
        ];
        decoded.extend(
            store
                .machine_configs_by_id_prefix(&id.to_string()[..8])
                .await
                .unwrap(),
        );
        decoded.extend(store.list_machine_configs().await.unwrap());
        decoded.extend(
            store
                .machine_inventory()
                .await
                .unwrap()
                .into_iter()
                .map(|entry| entry.config.unwrap()),
        );
        for config in decoded {
            assert_eq!(config.machine_dir, expected);
        }
        let rootfs = store.machine_rootfs(id).await.unwrap().unwrap();
        assert_eq!(rootfs.root_disk_path, expected.join("root.raw"));
        assert_eq!(std::fs::read(&rootfs.root_disk_path).unwrap(), [0x51; 512]);
        assert_eq!(
            std::fs::read(original.machine_dir.join("root.raw")).unwrap(),
            [0x72; 512]
        );
        let observer = ObservationStore::existing(&store);
        assert_eq!(
            observer
                .lookup(&crate::machine::MachineRef::parse(original.name.clone()).unwrap())
                .await
                .unwrap()
                .0
                .machine_dir,
            expected
        );
        observer.close().await.unwrap();
        assert_eq!(logical_catalog::snapshot(&new_home).await, before);
        let config = store.machine_config(id).await.unwrap().unwrap();
        let storage = store.machine_storage(id).await.unwrap().unwrap();
        let owner = store
            .register_launch_storage(id, uuid::Uuid::new_v4(), &storage, &config.spec)
            .await
            .unwrap();
        drop(owner);
    }

    #[tokio::test]
    async fn foreign_machine_directory_is_never_persisted_or_accepted_as_json_authority() {
        use crate::store::observation::ObservationStore;
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("catalog home"));
        let store = Store::new(&paths).await.unwrap();
        let mut config = add_catalog_relative_raw_fixture(&store, &paths, "foreign-dir").await;
        let expected = config.machine_dir.clone();
        let foreign = temporary.path().join("foreign machine dir");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("root.raw"), [0x73; 512]).unwrap();
        config.machine_dir = foreign.clone();
        store.save_machine_config(&config).await.unwrap();
        let json: String =
            sqlx::query_scalar("SELECT json(config_json) FROM machine_config WHERE id=?1")
                .bind(config.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("machineDir").is_none());
        assert_eq!(
            store
                .machine_config(config.id)
                .await
                .unwrap()
                .unwrap()
                .machine_dir,
            expected
        );
        assert_eq!(
            store
                .machine_rootfs(config.id)
                .await
                .unwrap()
                .unwrap()
                .root_disk_path,
            expected.join("root.raw")
        );
        // A persisted absolute spelling is not an old-shape reader or a
        // relocation hint: it is invalid in the current closed schema.
        value["machineDir"] = serde_json::json!(foreign);
        sqlx::query("UPDATE machine_config SET config_json=jsonb(?2) WHERE id=?1")
            .bind(config.id.to_string())
            .bind(value.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.machine_config(config.id).await.is_err());
        assert!(store.machine_config_by_name(&config.name).await.is_err());
        assert!(store
            .machine_configs_by_id_prefix(&config.id.to_string()[..8])
            .await
            .is_err());
        assert!(store.list_machine_configs().await.is_err());
        assert!(store
            .machine_inventory()
            .await
            .unwrap()
            .remove(0)
            .config
            .is_err());
        let before = logical_catalog::snapshot(paths.home()).await;
        let observer = ObservationStore::open(&paths.state_db_path())
            .await
            .unwrap();
        for reference in [
            config.id.to_string(),
            config.name.clone(),
            config.id.to_string()[..8].to_string(),
        ] {
            assert!(observer
                .lookup(&crate::machine::MachineRef::parse(reference).unwrap())
                .await
                .is_err());
        }
        observer.close().await.unwrap();
        assert_eq!(logical_catalog::snapshot(paths.home()).await, before);
        assert_eq!(
            std::fs::read(foreign.join("root.raw")).unwrap(),
            [0x73; 512]
        );
        assert_eq!(
            std::fs::read(expected.join("root.raw")).unwrap(),
            [0x51; 512]
        );
    }
}
