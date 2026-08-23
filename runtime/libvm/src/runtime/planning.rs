use std::path::{Path, PathBuf};

use nix::unistd::{access, AccessFlags};
use oci::{ImageStore as RootfsImageStore, MaterializeOptions};

use crate::image::{
    local_disk::resolve_local_disk,
    oci::{cached_resolved_oci_image, image_error, resolve_oci_image_from_registry},
    ImagePullPolicy, ResolvedOciImage,
};
use crate::machine::generate_machine_name;
use crate::runtime::RuntimeConfig;
use crate::store::ReadOnlyStore;
use crate::LibVmError;

/// Read-only runtime facilities used to build a creation plan.
///
/// This type never initializes runtime directories, locks, migrations, or cache
/// entries. Registry resolution may use the network for policies that allow it.
#[derive(Debug, Clone)]
pub struct ReadOnlyRuntime {
    data_root: PathBuf,
    image_root: PathBuf,
    store: Option<ReadOnlyStore>,
}

impl ReadOnlyRuntime {
    /// Opens existing planning state without creating any local state.
    pub async fn open(config: RuntimeConfig) -> Result<Self, LibVmError> {
        let data_root = config.bootstrap_data_root()?;
        let state_db_path = data_root.join("state.db");
        let store = ReadOnlyStore::open_if_exists(&state_db_path).await?;
        let stored = match &store {
            Some(store) => store.db_config().await?,
            None => None,
        };
        let (data_root, _state_root, image_root) =
            config.resolve_durable_roots_read_only(stored.as_ref(), &state_db_path)?;
        Ok(Self {
            data_root,
            image_root,
            store,
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
        generate_machine_name()
    }

    /// Resolves OCI metadata without writing cache or durable state.
    pub async fn resolve_oci_image(
        &self,
        reference: String,
        policy: ImagePullPolicy,
    ) -> Result<ResolvedOciImage, LibVmError> {
        let store = RootfsImageStore::open(&self.image_root)
            .map_err(|error| image_error(&reference, error))?;
        let options =
            MaterializeOptions::for_host().map_err(|error| image_error(&reference, error))?;
        match policy {
            ImagePullPolicy::IfMissing => {
                if let Some(image) = cached_resolved_oci_image(&store, &reference, options.clone())?
                {
                    Ok(image)
                } else {
                    resolve_oci_image_from_registry(&store, reference, options, None).await
                }
            }
            ImagePullPolicy::Always => {
                resolve_oci_image_from_registry(&store, reference, options, None).await
            }
            ImagePullPolicy::Never => cached_resolved_oci_image(&store, &reference, options)?
                .ok_or(LibVmError::ImageNotFound { reference }),
        }
    }

    /// Validates that a disk can be read and that its future machine parent can be created.
    pub fn validate_disk_source(&self, path: &Path) -> Result<PathBuf, LibVmError> {
        validate_create_parent(&self.data_root.join("machines"))?;
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
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use crate::{OciImageConfigMetadata, Platform};
    use oci::{RootfsLayerMetadata, RootfsMetadata};

    use crate::paths::LocalRoots;
    use crate::store::models::DbConfig;
    use crate::store::{ConfigStore, Store};
    use crate::{ImagePullPolicy, ReadOnlyRuntime, RuntimeConfig};

    #[derive(Debug, PartialEq, Eq)]
    struct FileSnapshot {
        contents: Vec<u8>,
        mode: u32,
        modified: i64,
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, FileSnapshot> {
        let mut files = BTreeMap::new();
        snapshot_directory(root, root, &mut files);
        files
    }

    fn snapshot_directory(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<PathBuf, FileSnapshot>,
    ) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read snapshot entry");
            let path = entry.path();
            if path.is_dir() {
                snapshot_directory(root, &path, files);
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
    async fn existing_database_is_unchanged_while_checking_name_collisions() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let state_root = temp.path().join("state");
        let image_root = temp.path().join("images");
        let roots = LocalRoots::with_roots(
            &data_root,
            &state_root,
            temp.path().join("run"),
            &image_root,
        );
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("create state database");
        store
            .read_or_seed_db_config(&DbConfig::from_roots(&roots))
            .await
            .expect("seed roots");
        store
            .execute_test_sql(
                "INSERT INTO machine_config (id, name, config_json)
                 VALUES ('00000000-0000-0000-0000-000000000001', 'taken', '{}')",
            )
            .await
            .expect("insert machine name");
        store.close().await;
        let before = snapshot(temp.path());

        let runtime = ReadOnlyRuntime::open(
            RuntimeConfig::local(&data_root)
                .with_state_root(&state_root)
                .with_image_root(&image_root),
        )
        .await
        .expect("open read-only runtime");

        assert!(!runtime
            .machine_name_available("taken")
            .await
            .expect("check taken name"));
        let after = snapshot(temp.path());
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
    async fn dry_run_rejects_old_migration_history_without_writing() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        std::fs::create_dir_all(&data_root).expect("create data root");
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
        let before = snapshot(temp.path());

        let error = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect_err("dry run must reject an old state database");

        assert!(error.to_string().contains("embedded schema"));
        assert_eq!(before, snapshot(temp.path()));
    }

    #[tokio::test]
    async fn cached_oci_resolution_preserves_all_local_metadata() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let image_root = temp.path().join("images");
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = format!("example.test/demo@{digest}");
        let platform = Platform::host().expect("host platform");
        let image_dir = image_root
            .join(format!("sha256-{}", "a".repeat(64)))
            .join(format!("{}-{}", platform.os, platform.architecture));
        std::fs::create_dir_all(&image_dir).expect("create cached image directory");
        std::fs::write(image_dir.join("rootfs.img"), b"rootfs").expect("write cached rootfs");
        let metadata = RootfsMetadata {
            version: 2,
            image_ref: reference.clone(),
            image_id: digest.clone(),
            requested_reference: reference.clone(),
            selected_reference: reference.clone(),
            manifest_digest: digest.clone(),
            config_digest: format!("sha256:{}", "b".repeat(64)),
            config: OciImageConfigMetadata::default(),
            layers: Vec::<RootfsLayerMetadata>::new(),
            platform,
            filesystem: "ext4".to_string(),
            rootfs_file: "rootfs.img".to_string(),
            created_at_unix: 1,
        };
        let mut stored_metadata =
            serde_json::to_value(&metadata).expect("serialize cached metadata");
        stored_metadata
            .as_object_mut()
            .expect("metadata object")
            .insert(
                "source".to_string(),
                serde_json::Value::String("oci-registry".to_string()),
            );
        std::fs::write(
            image_dir.join("metadata.json"),
            serde_json::to_vec_pretty(&stored_metadata).expect("serialize stored metadata"),
        )
        .expect("write cached metadata");
        let before = snapshot(temp.path());
        let runtime =
            ReadOnlyRuntime::open(RuntimeConfig::local(&data_root).with_image_root(&image_root))
                .await
                .expect("open read-only runtime");

        let image = runtime
            .resolve_oci_image(reference.clone(), ImagePullPolicy::Never)
            .await
            .expect("resolve cached image");

        assert_eq!(image.selected_reference, reference);
        assert_eq!(before, snapshot(temp.path()));
        assert!(!data_root.exists());
    }

    #[tokio::test]
    async fn uncached_never_resolution_creates_no_local_state() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let image_root = temp.path().join("images");
        let runtime =
            ReadOnlyRuntime::open(RuntimeConfig::local(&data_root).with_image_root(&image_root))
                .await
                .expect("open read-only runtime");

        assert!(runtime
            .resolve_oci_image(
                "example.test/missing:latest".to_string(),
                ImagePullPolicy::Never,
            )
            .await
            .is_err());
        assert!(snapshot(temp.path()).is_empty());
    }
}
