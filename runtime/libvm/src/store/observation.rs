//! Existing-catalog SELECTs only. This is deliberately separate from the
//! exclusive immutable planning reader and from writable initialization.
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};

use crate::machine::{MachineRef, MachineRefKind};
use crate::storage::identity_file::FileIdentity;
use crate::store::catalog_guard::CatalogGuard;
use crate::store::models::{MachineConfig, MachineState};
use crate::store::row::{DbMachineConfig, DbMachineState};
use crate::store::Store;
use crate::LibVmError;

#[derive(Debug)]
pub(crate) struct ObservationStore {
    pool: SqlitePool,
    home: PathBuf,
    closed: Option<tokio::sync::oneshot::Receiver<()>>,
}

pub(crate) struct ObservationConnection {
    pub(crate) options: SqliteConnectOptions,
    pub(crate) closed: tokio::sync::oneshot::Receiver<()>,
    identity: FileIdentity,
}

impl ObservationStore {
    pub(crate) fn existing(store: &Store) -> Self {
        Self {
            pool: store.pool.clone(),
            home: store.home.clone(),
            closed: None,
        }
    }

    pub(crate) async fn open(path: &Path) -> Result<Self, LibVmError> {
        Self::open_inner(path).await.map_err(observation_error)
    }

    async fn open_inner(path: &Path) -> Result<Self, LibVmError> {
        let ObservationConnection {
            options,
            closed,
            identity,
        } = connection_options(path)?;
        let pool = match SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("PRAGMA query_only = ON")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                await_catalog_close(closed).await?;
                return Err(error.into());
            }
        };
        let validation = async {
            if identity != FileIdentity::from_path(path)? {
                return Err(std::io::Error::other("catalog changed identity while opening").into());
            }
            validate_existing_sidecars(path)?;
            crate::store::storage::validate_embedded_migration_history(&pool).await?;
            let os: String = sqlx::query_scalar("SELECT os FROM db_config WHERE id = 1")
                .fetch_one(&pool)
                .await?;
            crate::runtime::validate_db_config(&crate::store::models::DbConfig { os })?;
            Ok::<(), LibVmError>(())
        }
        .await;
        if let Err(error) = validation {
            close_owned(pool, closed).await?;
            return Err(error);
        }
        Ok(Self {
            pool,
            home: path
                .parent()
                .ok_or_else(|| std::io::Error::other("catalog has no parent"))?
                .to_path_buf(),
            closed: Some(closed),
        })
    }

    /// One deferred SQLite snapshot. No connection/transaction survives the
    /// return into the monitor network await.
    pub(crate) async fn lookup(
        &self,
        reference: &MachineRef,
    ) -> Result<(MachineConfig, MachineState), LibVmError> {
        self.lookup_inner(reference)
            .await
            .map_err(|error| match error {
                LibVmError::MachineNotFound { .. } | LibVmError::AmbiguousIdPrefix { .. } => error,
                other => observation_error(other),
            })
    }

    async fn lookup_inner(
        &self,
        reference: &MachineRef,
    ) -> Result<(MachineConfig, MachineState), LibVmError> {
        let mut transaction = self.pool.begin().await?;
        let (statement, value) = match reference.kind() {
            MachineRefKind::Id(id) => ("SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE id = ?1 LIMIT 2", id.to_string()),
            MachineRefKind::Name(name) => ("SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE name = ?1 LIMIT 2", name.clone()),
            MachineRefKind::IdPrefix(prefix) => ("SELECT id, name, CASE WHEN json_valid(config_json, 8) THEN json(config_json) ELSE '{}' END AS config_json FROM machine_config WHERE id LIKE ?1 LIMIT 2", format!("{prefix}%")),
        };
        let rows = sqlx::query(statement)
            .bind(&value)
            .fetch_all(&mut *transaction)
            .await?;
        let config = match rows.as_slice() {
            [] => return Err(LibVmError::MachineNotFound { reference: value }),
            [row] => DbMachineConfig::from_row_in(row, &self.home)?.0,
            _ => {
                return Err(LibVmError::AmbiguousIdPrefix {
                    prefix: value.trim_end_matches('%').to_string(),
                    count: rows.len(),
                })
            }
        };
        let row = sqlx::query("SELECT machine_id, status, CASE WHEN json_valid(state_json, 8) THEN json(state_json) ELSE '{}' END AS state_json FROM machine_state WHERE machine_id = ?1")
            .bind(config.id.to_string()).fetch_one(&mut *transaction).await?;
        let state = DbMachineState::from_row(&row)?.0;
        transaction.commit().await?;
        Ok((config, state))
    }
    pub(crate) async fn pending_pause(
        &self,
        machine_id: crate::store::models::MachineId,
        run_id: Option<&str>,
    ) -> Result<Option<crate::store::live_store::LiveCommandIntent>, LibVmError> {
        let Some(run_id) = run_id else {
            return Ok(None);
        };
        let json: Option<String> = sqlx::query_scalar("SELECT json(input_json) FROM live_command WHERE machine_id=?1 AND run_id=?2 AND result_json IS NULL AND json_extract(input_json,'$.command.command')='pause' ORDER BY rowid LIMIT 1")
            .bind(machine_id.to_string()).bind(run_id).fetch_optional(&self.pool).await?;
        json.map(|json| {
            serde_json::from_str(&json).map_err(|error| LibVmError::LiveProtocol {
                message: error.to_string(),
            })
        })
        .transpose()
    }

    pub(crate) async fn machine_storage(
        &self,
        id: crate::store::models::MachineId,
    ) -> Result<crate::MachineStorageRecord, LibVmError> {
        let json: String =
            sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
                .bind(id.to_string())
                .fetch_one(&self.pool)
                .await?;
        crate::MachineStorageRecord::decode(&json)
    }

    pub(crate) async fn snapshot_record(
        &self,
        reference: &crate::store::snapshot_store::SnapshotRef,
    ) -> Result<crate::store::models::snapshot::StoppedSnapshotRecord, LibVmError> {
        let mut transaction = self.pool.begin().await?;
        let facts =
            crate::store::snapshot_store::fetch_catalog(&mut transaction, reference).await?;
        transaction.commit().await?;
        crate::store::snapshot_store::authenticate_catalog(facts).map(|(record, _)| record)
    }

    pub(crate) async fn close(self) -> Result<(), LibVmError> {
        if let Some(closed) = self.closed {
            close_owned(self.pool, closed).await?;
        }
        Ok(())
    }
}

/// Normal SQLite read coordination may create/update/remove WAL and SHM.
/// Readonly protects logical catalog contents, not physical sidecar bytes.
pub(crate) fn connection_options(path: &Path) -> Result<ObservationConnection, LibVmError> {
    let home = path
        .parent()
        .ok_or_else(|| std::io::Error::other("catalog has no parent"))?;
    let (guard, closed) = CatalogGuard::observation(home)?;
    let metadata = validate_file(path)?;
    // Empty-main WAL deletion is based on actual file size, not the header.
    // Stat alone rejects it without closing an unrelated POSIX-locking fd.
    if metadata.len() < 100 {
        return Err(
            std::io::Error::other("catalog is empty or has a truncated SQLite header").into(),
        );
    }
    validate_existing_sidecars(path)?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .shared_cache(false)
        .busy_timeout(Duration::from_secs(2));
    Ok(ObservationConnection {
        options: CatalogGuard::attach_sqlite(guard, options),
        closed,
        identity: FileIdentity::from_metadata(&metadata),
    })
}

fn validate_existing_sidecars(path: &Path) -> Result<(), LibVmError> {
    for suffix in ["-wal", "-shm"] {
        match validate_file(&sidecar(path, suffix)) {
            Ok(_) => {}
            Err(LibVmError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn close_owned(
    pool: SqlitePool,
    closed: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), LibVmError> {
    // SQLx awaits native worker shutdown, but its pool/options maintenance
    // owners may outlive close(). Drop our pool owner as well, then await this
    // observer's exact guard release rather than any unrelated catalog writer.
    pool.close().await;
    drop(pool);
    await_catalog_close(closed).await
}

async fn await_catalog_close(closed: tokio::sync::oneshot::Receiver<()>) -> Result<(), LibVmError> {
    closed.await.map_err(|error| LibVmError::LiveObservation {
        reference: "state.db".to_string(),
        message: format!("catalog native-close notification failed: {error}"),
    })
}

fn validate_file(path: &Path) -> Result<std::fs::Metadata, LibVmError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::other(format!(
            "catalog file {} is not an owner-controlled regular file",
            path.display()
        ))
        .into());
    }
    Ok(metadata)
}

fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

fn observation_error(error: LibVmError) -> LibVmError {
    LibVmError::LiveObservation {
        reference: "state.db".to_string(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection};

    use crate::store::catalog_guard::CatalogGuard;
    use crate::store::models::DbConfig;
    use crate::store::observation::ObservationStore;
    use crate::store::{ConfigStore, ReadOnlyStore, Store};

    mod logical_catalog {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/live_catalog.rs"
        ));
    }

    #[test]
    fn live_capabilities_observer_lock_contender() {
        let Some(path) = std::env::var_os("SILO_OBSERVER_LOCK_TEST_DB") else {
            return;
        };
        // Only this subprocess opens an ordinary fd. There are no SQLite
        // connections in it, so close cannot disturb the parent writer's
        // process-wide locks. Probe SQLite's standard main-file SHARED range
        // directly; WAL write-lock contention alone would miss that bug.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let request = nix::libc::flock {
            l_type: nix::libc::F_WRLCK as i16,
            l_whence: nix::libc::SEEK_SET as i16,
            l_start: 0x4000_0002,
            l_len: 510,
            l_pid: 0,
        };
        let error = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLK(&request)).unwrap_err();
        assert!(
            matches!(error, nix::errno::Errno::EACCES | nix::errno::Errno::EAGAIN),
            "{error}"
        );
    }

    fn assert_writer_still_excludes(path: &std::path::Path) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::observation::tests::live_capabilities_observer_lock_contender",
                "--nocapture",
            ])
            .env("SILO_OBSERVER_LOCK_TEST_DB", path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[tokio::test]
    async fn live_capabilities_stat_preflight_preserves_other_connection_posix_locks() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.db");
        let store = Store::open(&path).await.unwrap();
        store
            .read_or_seed_db_config(&DbConfig::current())
            .await
            .unwrap();
        let mut writer = SqliteConnectOptions::new()
            .filename(&path)
            .connect()
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut writer)
            .await
            .unwrap();
        sqlx::query("UPDATE db_config SET os = os")
            .execute(&mut writer)
            .await
            .unwrap();
        assert_writer_still_excludes(&path);
        let observer = ObservationStore::open(&path).await.unwrap();
        assert_writer_still_excludes(&path);
        observer.close().await.unwrap();
        assert_writer_still_excludes(&path);
        sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
        writer.close().await.unwrap();
        store.close().await;
    }

    #[tokio::test]
    async fn live_capabilities_observer_and_planning_exclude_until_native_close() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.db");
        let store = Store::open(&path).await.unwrap();
        store
            .read_or_seed_db_config(&DbConfig::current())
            .await
            .unwrap();
        store.close().await;
        // Finish fixture pool/options teardown before introducing the writer
        // whose native close this test controls explicitly.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let quiescent = loop {
            if let Ok(guard) = CatalogGuard::readonly(home.path()) {
                break guard;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "fixture writer did not close"
            );
            tokio::task::yield_now().await;
        };
        drop(quiescent);
        let options = CatalogGuard::attach_sqlite(
            CatalogGuard::writable(home.path()).await.unwrap(),
            SqliteConnectOptions::new().filename(&path),
        );
        let mut writer = options.connect().await.unwrap();
        drop(options);
        sqlx::query("UPDATE db_config SET os = os")
            .execute(&mut writer)
            .await
            .unwrap();
        let observer = ObservationStore::open(&path).await.unwrap();
        // Direct SqliteConnection::close awaits its native worker's shutdown
        // acknowledgment, with no writer pool/options maintenance owner.
        writer.close().await.unwrap();
        assert!(CatalogGuard::readonly(home.path()).is_err());
        // Closing the last writer may remove its WAL/SHM; an already attached
        // readonly native connection remains a valid committed snapshot reader.
        let os: String = sqlx::query_scalar("SELECT os FROM db_config WHERE id = 1")
            .fetch_one(&observer.pool)
            .await
            .unwrap();
        assert_eq!(os, std::env::consts::OS);
        tokio::time::timeout(Duration::from_secs(2), observer.close())
            .await
            .unwrap()
            .unwrap();
        // The awaited close above fences our native worker and guard file.
        // Unrelated parallel forks can briefly retain CLOEXEC duplicates.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let planning = loop {
            if let Ok(guard) = CatalogGuard::readonly(home.path()) {
                break guard;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "inherited catalog descriptor did not close"
            );
            tokio::task::yield_now().await;
        };
        assert!(ObservationStore::open(&path).await.is_err());
        drop(planning);
    }

    #[tokio::test]
    async fn live_capabilities_observation_then_planning_preserves_logical_catalog() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.db");
        let store = Store::open(&path).await.unwrap();
        store
            .read_or_seed_db_config(&DbConfig::current())
            .await
            .unwrap();
        let before = logical_catalog::snapshot(home.path()).await;
        store.close().await;
        // Only establish that the initializer's native catalog lifetime has
        // ended; do not checkpoint, delete or otherwise normalize sidecars.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(guard) = CatalogGuard::readonly(home.path()) {
                drop(guard);
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "initializer did not close"
            );
            tokio::task::yield_now().await;
        }

        let observer = ObservationStore::open(&path)
            .await
            .expect("ordinary read-only observation");
        let observed_os: String = sqlx::query_scalar("SELECT os FROM db_config WHERE id = 1")
            .fetch_one(&observer.pool)
            .await
            .expect("read existing logical catalog");
        assert_eq!(observed_os, std::env::consts::OS);
        observer
            .close()
            .await
            .expect("await observer's native close");

        let planning = ReadOnlyStore::open_if_exists(&path)
            .await
            .expect("permitted observation coordination must not prevent planning")
            .expect("existing catalog");
        assert_eq!(planning.db_config().await.unwrap().unwrap().os, observed_os);
        assert!(!planning.machine_name_exists("not-created").await.unwrap());
        planning.pool.close().await;
        drop(planning);
        assert_eq!(logical_catalog::snapshot(home.path()).await, before);
    }

    #[tokio::test]
    async fn live_capabilities_empty_catalog_refuses_without_initializing_main() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.db");
        let store = Store::open(&path).await.unwrap();
        store.close().await;
        std::fs::write(&path, []).unwrap();
        let wal = home.path().join("state.db-wal");
        std::fs::write(&wal, b"preserve malformed-state evidence").unwrap();
        std::fs::write(home.path().join("state.db-shm"), vec![0u8; 32768]).unwrap();
        assert!(matches!(
            ObservationStore::open(&path).await,
            Err(crate::LibVmError::LiveObservation { .. })
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }
}
