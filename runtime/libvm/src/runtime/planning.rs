use std::path::{Path, PathBuf};

use nix::unistd::{access, AccessFlags};
use oci::{MaterializeOptions, OciMaterializer};

use crate::image::{
    local_disk::resolve_local_disk,
    oci::{
        cached_resolved_oci_image, image_error, resolve_oci_image_from_registry,
        verify_cached_image,
    },
    ImagePullPolicy, ResolvedOciImage,
};
use crate::runtime::RuntimeConfig;
use crate::store::ReadOnlyStore;
use crate::LibVmError;
use crate::RegistryPolicy;

/// Read-only runtime facilities used to build a creation plan.
///
/// This type never initializes runtime directories, locks, migrations, or cache
/// entries. Registry resolution may use the network for policies that allow it.
#[derive(Debug, Clone)]
pub struct ReadOnlyRuntime {
    home: PathBuf,
    store: Option<ReadOnlyStore>,
    registry_policy: RegistryPolicy,
}

impl ReadOnlyRuntime {
    /// Opens existing planning state without initializing runtime or logical
    /// catalog state. SQLite may manage its ordinary WAL/SHM coordination files.
    pub async fn open(config: RuntimeConfig) -> Result<Self, LibVmError> {
        let home = config.resolve_home()?;
        let store = ReadOnlyStore::open_if_exists(&home.join("state.db")).await?;
        if let Some(store) = &store {
            if let Some(stored) = store.db_config().await? {
                crate::runtime::config::validate_db_config(&stored)?;
            }
        }
        Ok(Self {
            home,
            store,
            registry_policy: config.registry_policy,
        })
    }

    /// Checks whether a machine name is free without reserving it.
    pub async fn machine_name_available(&self, name: &str) -> Result<bool, LibVmError> {
        match &self.store {
            Some(store) => Ok(!store.machine_name_exists(name).await?),
            None => Ok(true),
        }
    }

    /// Generates a proposed name without reserving it.
    pub fn propose_machine_name(&self) -> Result<String, LibVmError> {
        crate::planning::propose_machine_name()
    }

    /// Resolves OCI metadata without writing cache or durable state.
    pub async fn resolve_oci_image(
        &self,
        reference: String,
        policy: ImagePullPolicy,
    ) -> Result<ResolvedOciImage, LibVmError> {
        let producer =
            OciMaterializer::open(self.home.join("images"), self.registry_policy.clone())
                .map_err(|error| image_error(&reference, error))?;
        let options =
            MaterializeOptions::for_host().map_err(|error| image_error(&reference, error))?;
        if policy != ImagePullPolicy::Always {
            if let Some(image) = self.cached_oci_image(&reference, &options.platform).await? {
                return Ok(image);
            }
            if policy == ImagePullPolicy::Never {
                return Err(LibVmError::ImageNotFound { reference });
            }
        }
        let mut image =
            resolve_oci_image_from_registry(&producer, reference, options, None).await?;
        if self
            .cached_oci_image(&image.selected_reference, &image.platform)
            .await?
            .is_some()
        {
            image.cache_state = crate::ImageCacheState::Complete;
        }
        Ok(image)
    }

    async fn cached_oci_image(
        &self,
        reference: &str,
        platform: &oci::Platform,
    ) -> Result<Option<ResolvedOciImage>, LibVmError> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        for candidate in self
            .registry_policy
            .candidates(reference)
            .map_err(|error| image_error(reference, error))?
        {
            if let Some(mut image) = store
                .cached_oci_image(&candidate.to_string(), platform)
                .await?
            {
                let images = self.home.join("images");
                return tokio::task::spawn_blocking(move || {
                    verify_cached_image(&mut image, &images)?;
                    Ok(Some(cached_resolved_oci_image(
                        &image,
                        candidate.to_string(),
                    )))
                })
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
        }
        Ok(None)
    }

    /// Validates that a disk can be read and that its future machine parent can be created.
    pub fn validate_disk_source(&self, path: &Path) -> Result<PathBuf, LibVmError> {
        validate_create_parent(&self.home.join("machines"))?;
        Ok(resolve_local_disk(path)?.canonical_path)
    }
}

fn validate_create_parent(path: &Path) -> Result<(), LibVmError> {
    let mut ancestor = path;
    loop {
        match std::fs::metadata(ancestor) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(std::io::Error::other(format!(
                        "future machine parent {} is not a directory",
                        ancestor.display()
                    ))
                    .into());
                }
                access(ancestor, AccessFlags::W_OK | AccessFlags::X_OK)
                    .map_err(std::io::Error::from)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or_else(|| {
                    std::io::Error::other(format!(
                        "future machine parent {} has no existing ancestor",
                        path.display()
                    ))
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use crate::store::models::DbConfig;
    use crate::store::{ConfigStore, Store};
    use crate::{ImagePullPolicy, ReadOnlyRuntime, RuntimeConfig};

    mod logical_catalog {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/live_catalog.rs"
        ));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FileSnapshot {
        contents: Vec<u8>,
        mode: u32,
        modified: i64,
    }

    fn snapshot(root: &Path, catalog_home: &Path) -> BTreeMap<PathBuf, FileSnapshot> {
        let mut files = BTreeMap::new();
        snapshot_directory(root, root, catalog_home, &mut files);
        files
    }

    fn snapshot_directory(
        root: &Path,
        directory: &Path,
        catalog_home: &Path,
        files: &mut BTreeMap<PathBuf, FileSnapshot>,
    ) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read snapshot entry");
            let path = entry.path();
            // SQLx snapshots below compare logical catalog contents. These
            // files are native SQLite read coordination, not runtime artifacts.
            if directory == catalog_home
                && matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("state.db" | "state.db-wal" | "state.db-shm")
                )
            {
                continue;
            }
            if path.is_dir() {
                snapshot_directory(root, &path, catalog_home, files);
            } else {
                let metadata = entry.metadata().expect("read snapshot metadata");
                files.insert(
                    path.strip_prefix(root)
                        .expect("relative snapshot path")
                        .to_path_buf(),
                    FileSnapshot {
                        contents: std::fs::read(&path).expect("read snapshot file"),
                        mode: metadata.mode(),
                        modified: metadata.mtime(),
                    },
                );
            }
        }
    }

    #[tokio::test]
    async fn absent_roots_disk_validation_creates_no_runtime_paths() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let disk = temp.path().join("disk.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        let disk = runtime.validate_disk_source(&disk).expect("validate disk");

        assert!(disk.is_file());
        assert!(!data_root.exists());
        assert!(!temp.path().join("data/images").exists());
        assert!(runtime
            .machine_name_available("new-machine")
            .await
            .expect("check name"));
    }

    #[tokio::test]
    async fn logical_catalog_is_unchanged_while_checking_name_collisions() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("create state database");
        store
            .read_or_seed_db_config(&DbConfig::current())
            .await
            .expect("seed host contract");
        store
            .execute_test_sql(
                "INSERT INTO machine_config (id, name, config_json)
                 VALUES ('00000000-0000-0000-0000-000000000001', 'taken', '{}')",
            )
            .await
            .expect("insert machine name");
        store.close().await;
        let logical_before = logical_catalog::snapshot(&data_root).await;
        let before = snapshot(temp.path(), &data_root);

        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        assert!(!runtime
            .machine_name_available("taken")
            .await
            .expect("check taken name"));
        assert_eq!(logical_catalog::snapshot(&data_root).await, logical_before);
        let after = snapshot(temp.path(), &data_root);
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>()
        );
        for (path, before) in before {
            let after = after.get(&path).expect("snapshot path remains");
            assert_eq!(
                before.contents,
                after.contents,
                "contents changed: {}",
                path.display()
            );
            assert_eq!(before.mode, after.mode, "mode changed: {}", path.display());
            assert_eq!(
                before.modified,
                after.modified,
                "mtime changed: {}",
                path.display()
            );
        }
    }

    #[tokio::test]
    async fn dry_run_rejects_incompatible_schema_without_logical_changes() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        std::fs::create_dir_all(&data_root).expect("create data root");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(data_root.join("catalog.lock"))
            .unwrap();
        let state_db = data_root.join("state.db");
        std::fs::File::create(&state_db).expect("create state database");
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
        .expect("create old migration history");
        sqlx::query(
            "INSERT INTO _sqlx_migrations
                (version, description, success, checksum, execution_time)
             VALUES (1, 'initial', TRUE, x'00', 1)",
        )
        .execute(&pool)
        .await
        .expect("record old migration");
        pool.close().await;
        let logical_before = logical_catalog::snapshot(&data_root).await;
        let before = snapshot(temp.path(), &data_root);

        let error = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect_err("dry run must reject an old state database");

        assert!(error.to_string().contains("reinstall"));
        assert_eq!(logical_catalog::snapshot(&data_root).await, logical_before);
        assert_eq!(before, snapshot(temp.path(), &data_root));
    }

    #[tokio::test]
    async fn cached_oci_resolution_preserves_logical_catalog_and_cache_metadata() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = format!("example.test/demo@{digest}");
        let paths = crate::paths::LocalPaths::new(&data_root);
        let store = Store::new(&paths).await.unwrap();
        let runtime = crate::Runtime::from_store(
            paths.clone(),
            std::sync::Arc::new(store.clone()),
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
            crate::runtime::components::test_components(paths.home()),
            None,
        )
        .await
        .unwrap();
        crate::runtime::core::tests::write_cached_oci_rootfs(
            &runtime,
            &paths,
            &reference,
            &digest,
            &format!("sha256:{}", "b".repeat(64)),
        )
        .await;
        drop(runtime);
        store.close().await;
        let logical_before = logical_catalog::snapshot(&data_root).await;
        let before = snapshot(temp.path(), &data_root);
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        let image = runtime
            .resolve_oci_image(reference.clone(), ImagePullPolicy::Never)
            .await
            .expect("resolve cached image");

        assert_eq!(image.selected_reference, reference);
        assert_eq!(logical_catalog::snapshot(&data_root).await, logical_before);
        assert_eq!(before, snapshot(temp.path(), &data_root));
        assert!(data_root.join("state.db").exists());
    }

    #[tokio::test]
    async fn uncached_never_resolution_creates_no_local_state() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        assert!(runtime
            .resolve_oci_image(
                "example.test/missing:latest".to_string(),
                ImagePullPolicy::Never,
            )
            .await
            .is_err());
        assert!(snapshot(temp.path(), &data_root).is_empty());
    }
}
