use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sqlx::Row;

use crate::image::{
    ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport, ImageRemoveOptions,
    OciImageConfigMetadata,
};
use crate::store::models::{ImageRootfsArtifactRecord, OciImageRecord};
use crate::store::{ImageStore, Store};
use crate::LibVmError;

#[async_trait]
impl ImageStore for Store {
    async fn save_oci_image(&self, image: &OciImageRecord) -> Result<(), LibVmError> {
        if image.reference.manifest_digest != image.manifest.digest {
            return Err(LibVmError::InvalidCreateRequest {
                name: image.reference.requested_reference.clone(),
                reason: "image reference manifest digest does not match manifest record"
                    .to_string(),
            });
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO image_manifest
                (digest, media_type, image_id, platform_os, platform_architecture,
                 platform_variant, config_digest, layer_count, total_size_bytes,
                 created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(digest) DO UPDATE SET
                media_type = excluded.media_type,
                image_id = excluded.image_id,
                platform_os = excluded.platform_os,
                platform_architecture = excluded.platform_architecture,
                platform_variant = excluded.platform_variant,
                config_digest = excluded.config_digest,
                layer_count = excluded.layer_count,
                total_size_bytes = excluded.total_size_bytes,
                last_used_at = excluded.last_used_at",
        )
        .bind(&image.manifest.digest)
        .bind(&image.manifest.media_type)
        .bind(&image.manifest.image_id)
        .bind(&image.manifest.platform_os)
        .bind(&image.manifest.platform_architecture)
        .bind(&image.manifest.platform_variant)
        .bind(&image.manifest.config_digest)
        .bind(image.manifest.layer_count)
        .bind(image.manifest.total_size_bytes)
        .bind(image.manifest.created_at)
        .bind(image.manifest.last_used_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO image_ref
                (requested_reference, selected_reference, manifest_digest, created_at, updated_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(requested_reference) DO UPDATE SET
                 selected_reference = excluded.selected_reference,
                 manifest_digest = excluded.manifest_digest,
                updated_at = excluded.updated_at,
                last_used_at = excluded.last_used_at",
        )
        .bind(&image.reference.requested_reference)
        .bind(&image.reference.selected_reference)
        .bind(&image.reference.manifest_digest)
        .bind(image.reference.created_at)
        .bind(image.reference.updated_at)
        .bind(image.reference.last_used_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO image_config
                (manifest_digest, digest, env_json, cmd_json, entrypoint_json,
                 working_dir, user, labels_json, stop_signal, created_at)
             VALUES (?1, ?2, jsonb(?3), jsonb(?4), jsonb(?5), ?6, ?7, jsonb(?8), ?9, ?10)
             ON CONFLICT(manifest_digest) DO UPDATE SET
                digest = excluded.digest,
                env_json = excluded.env_json,
                cmd_json = excluded.cmd_json,
                entrypoint_json = excluded.entrypoint_json,
                 working_dir = excluded.working_dir,
                 user = excluded.user,
                 labels_json = excluded.labels_json,
                 stop_signal = excluded.stop_signal",
        )
        .bind(&image.config.manifest_digest)
        .bind(&image.config.digest)
        .bind(json_string(&image.config.metadata.env)?)
        .bind(json_string(&image.config.metadata.cmd)?)
        .bind(json_string(&image.config.metadata.entrypoint)?)
        .bind(&image.config.metadata.working_dir)
        .bind(&image.config.metadata.user)
        .bind(json_string(&image.config.metadata.labels)?)
        .bind(&image.config.metadata.stop_signal)
        .bind(image.config.created_at)
        .execute(&mut *tx)
        .await?;

        for layer in &image.layers {
            sqlx::query(
                "INSERT INTO image_layer
                    (diff_id, blob_digest, media_type, compressed_size_bytes,
                     uncompressed_size_bytes, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(diff_id) DO UPDATE SET
                    blob_digest = excluded.blob_digest,
                    media_type = excluded.media_type,
                    compressed_size_bytes = excluded.compressed_size_bytes,
                    uncompressed_size_bytes = excluded.uncompressed_size_bytes,
                    last_used_at = excluded.last_used_at",
            )
            .bind(&layer.diff_id)
            .bind(&layer.blob_digest)
            .bind(&layer.media_type)
            .bind(layer.compressed_size_bytes.map(i64_from_u64).transpose()?)
            .bind(
                layer
                    .uncompressed_size_bytes
                    .map(i64_from_u64)
                    .transpose()?,
            )
            .bind(layer.created_at)
            .bind(layer.last_used_at)
            .execute(&mut *tx)
            .await?;
        }

        for layer in &image.manifest_layers {
            sqlx::query(
                "INSERT INTO image_manifest_layer
                    (manifest_digest, layer_diff_id, position)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(manifest_digest, layer_diff_id) DO UPDATE SET
                    position = excluded.position",
            )
            .bind(&layer.manifest_digest)
            .bind(&layer.layer_diff_id)
            .bind(layer.position)
            .execute(&mut *tx)
            .await?;
        }

        upsert_artifact(&mut tx, &image.artifact).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn image_handle(&self, reference: &str) -> Result<Option<ImageHandle>, LibVmError> {
        let row = sqlx::query(IMAGE_HANDLE_BY_REFERENCE_QUERY)
            .bind(reference)
            .fetch_optional(&self.pool)
            .await?;
        row.map(image_handle_from_row).transpose()
    }

    async fn list_image_handles(&self) -> Result<Vec<ImageHandle>, LibVmError> {
        let rows = sqlx::query(IMAGE_HANDLE_LIST_QUERY)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(image_handle_from_row).collect()
    }

    async fn image_detail(&self, reference: &str) -> Result<Option<ImageDetail>, LibVmError> {
        let Some(handle) = self.image_handle(reference).await? else {
            return Ok(None);
        };
        let config = image_config(&self.pool, &handle.selected_manifest_digest).await?;

        let rows = sqlx::query(
            "SELECT l.blob_digest, l.diff_id, l.media_type,
                    l.compressed_size_bytes, l.uncompressed_size_bytes, ml.position
             FROM image_manifest_layer ml
             JOIN image_layer l ON l.diff_id = ml.layer_diff_id
             WHERE ml.manifest_digest = ?1
             ORDER BY ml.position",
        )
        .bind(&handle.selected_manifest_digest)
        .fetch_all(&self.pool)
        .await?;
        let layers = rows
            .into_iter()
            .map(image_layer_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Some(ImageDetail {
            handle,
            config,
            layers,
        }))
    }

    async fn ensure_image_removable(
        &self,
        reference: &str,
        options: ImageRemoveOptions,
    ) -> Result<ImageHandle, LibVmError> {
        let Some(handle) = self.image_handle(reference).await? else {
            return Err(LibVmError::ImageNotFound {
                reference: reference.to_string(),
            });
        };
        if !options.force {
            let count = machine_pin_count(&self.pool, &handle.selected_manifest_digest).await?;
            if count > 0 {
                return Err(LibVmError::ImageInUse {
                    reference: reference.to_string(),
                    machine_count: count,
                });
            }
        }

        Ok(handle)
    }

    async fn remove_image(
        &self,
        reference: &str,
        options: ImageRemoveOptions,
    ) -> Result<(), LibVmError> {
        self.ensure_image_removable(reference, options).await?;

        sqlx::query("DELETE FROM image_ref WHERE requested_reference = ?1")
            .bind(reference)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_images(&self) -> Result<ImagePruneReport, LibVmError> {
        let image_root = PathBuf::from(
            sqlx::query_scalar::<_, String>("SELECT image_root FROM db_config WHERE id = 1")
                .fetch_one(&self.pool)
                .await?,
        );
        let artifact_rows = sqlx::query(
            "SELECT image_id, rootfs_path, size_bytes
             FROM image_rootfs_artifact a
             WHERE NOT EXISTS (
                SELECT 1 FROM image_ref r WHERE r.manifest_digest = a.manifest_digest
             )
             AND NOT EXISTS (
                SELECT 1 FROM machine_rootfs mr
                WHERE mr.image_id = a.image_id
                   OR (a.manifest_digest IS NOT NULL AND mr.manifest_digest = a.manifest_digest)
             )",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut artifacts_removed = 0_u64;
        let mut bytes_removed = 0_u64;
        for row in artifact_rows {
            let image_id: String = row.try_get("image_id")?;
            let rootfs_path: String = row.try_get("rootfs_path")?;
            let size_bytes = u64_from_i64(row.try_get("size_bytes")?)?;
            let removed_from_disk = remove_cached_rootfs(Path::new(&rootfs_path), &image_root)?;
            sqlx::query("DELETE FROM image_rootfs_artifact WHERE image_id = ?1")
                .bind(image_id)
                .execute(&self.pool)
                .await?;
            artifacts_removed = artifacts_removed.saturating_add(1);
            if removed_from_disk {
                bytes_removed = bytes_removed.saturating_add(size_bytes);
            }
        }

        sqlx::query(
            "DELETE FROM image_manifest
             WHERE NOT EXISTS (
                SELECT 1 FROM image_ref r WHERE r.manifest_digest = image_manifest.digest
             )
             AND NOT EXISTS (
                SELECT 1 FROM machine_rootfs mr WHERE mr.manifest_digest = image_manifest.digest
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "DELETE FROM image_layer
             WHERE NOT EXISTS (
                SELECT 1 FROM image_manifest_layer ml WHERE ml.layer_diff_id = image_layer.diff_id
             )",
        )
        .execute(&self.pool)
        .await?;

        Ok(ImagePruneReport {
            references_removed: 0,
            artifacts_removed,
            bytes_removed,
        })
    }
}

fn remove_cached_rootfs(rootfs_path: &Path, image_root: &Path) -> Result<bool, LibVmError> {
    let rootfs_exists = match fs::metadata(rootfs_path) {
        Ok(metadata) => metadata.is_file(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };

    let Some(parent) = rootfs_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    else {
        return Ok(false);
    };

    let canonical_parent = match fs::canonicalize(parent) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let canonical_image_root = match fs::canonicalize(image_root) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !canonical_parent.starts_with(&canonical_image_root) {
        return Err(LibVmError::StateDecode {
            field: "image_rootfs_artifact.rootfs_path",
            message: format!(
                "refusing to prune image artifact outside image root: {}",
                rootfs_path.display()
            ),
        });
    }

    match fs::remove_dir_all(parent) {
        Ok(()) => Ok(rootfs_exists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

const IMAGE_HANDLE_BY_REFERENCE_QUERY: &str =
    "SELECT r.requested_reference, r.selected_reference, r.manifest_digest,
            m.config_digest, m.image_id, m.platform_os,
            m.platform_architecture, m.platform_variant, a.size_bytes,
            r.created_at, r.updated_at, r.last_used_at
     FROM image_ref r
     JOIN image_manifest m ON m.digest = r.manifest_digest
     LEFT JOIN image_rootfs_artifact a ON a.manifest_digest = r.manifest_digest
      WHERE r.requested_reference = ?1";

const IMAGE_HANDLE_LIST_QUERY: &str =
    "SELECT r.requested_reference, r.selected_reference, r.manifest_digest,
            m.config_digest, m.image_id, m.platform_os,
            m.platform_architecture, m.platform_variant, a.size_bytes,
            r.created_at, r.updated_at, r.last_used_at
     FROM image_ref r
     JOIN image_manifest m ON m.digest = r.manifest_digest
     LEFT JOIN image_rootfs_artifact a ON a.manifest_digest = r.manifest_digest
      ORDER BY r.requested_reference";

async fn upsert_artifact(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    artifact: &ImageRootfsArtifactRecord,
) -> Result<(), LibVmError> {
    sqlx::query(
        "INSERT INTO image_rootfs_artifact
            (image_id, manifest_digest, config_digest, platform_os, platform_architecture,
             platform_variant, filesystem, rootfs_path, size_bytes, created_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(image_id) DO UPDATE SET
             manifest_digest = excluded.manifest_digest,
             config_digest = excluded.config_digest,
            platform_os = excluded.platform_os,
            platform_architecture = excluded.platform_architecture,
            platform_variant = excluded.platform_variant,
            filesystem = excluded.filesystem,
            rootfs_path = excluded.rootfs_path,
            size_bytes = excluded.size_bytes,
            last_used_at = excluded.last_used_at",
    )
    .bind(&artifact.image_id)
    .bind(&artifact.manifest_digest)
    .bind(&artifact.config_digest)
    .bind(&artifact.platform_os)
    .bind(&artifact.platform_architecture)
    .bind(&artifact.platform_variant)
    .bind(&artifact.filesystem)
    .bind(artifact.rootfs_path.to_string_lossy().as_ref())
    .bind(i64_from_u64(artifact.size_bytes)?)
    .bind(artifact.created_at)
    .bind(artifact.last_used_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn image_handle_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ImageHandle, LibVmError> {
    Ok(ImageHandle {
        requested_reference: row.try_get("requested_reference")?,
        selected_reference: row.try_get("selected_reference")?,
        selected_manifest_digest: row.try_get("manifest_digest")?,
        config_digest: row.try_get("config_digest")?,
        image_id: row.try_get("image_id")?,
        platform_os: row.try_get("platform_os")?,
        platform_architecture: row.try_get("platform_architecture")?,
        platform_variant: row.try_get("platform_variant")?,
        size_bytes: row
            .try_get::<Option<i64>, _>("size_bytes")?
            .map(u64_from_i64)
            .transpose()?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}

async fn image_config(
    pool: &sqlx::SqlitePool,
    manifest_digest: &str,
) -> Result<OciImageConfigMetadata, LibVmError> {
    let row = sqlx::query(
        "SELECT json(entrypoint_json) AS entrypoint_json, json(cmd_json) AS cmd_json,
                json(env_json) AS env_json, working_dir, user,
                json(labels_json) AS labels_json, stop_signal
         FROM image_config WHERE manifest_digest = ?1",
    )
    .bind(manifest_digest)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| LibVmError::StateDecode {
        field: "image_config.manifest_digest",
        message: format!("missing OCI configuration for manifest {manifest_digest}"),
    })?;
    Ok(OciImageConfigMetadata {
        entrypoint: json_value(&row, "image_config.entrypoint_json", "entrypoint_json")?,
        cmd: json_value(&row, "image_config.cmd_json", "cmd_json")?,
        env: json_value(&row, "image_config.env_json", "env_json")?,
        working_dir: row.try_get("working_dir")?,
        user: row.try_get("user")?,
        labels: json_value(&row, "image_config.labels_json", "labels_json")?,
        stop_signal: row.try_get("stop_signal")?,
    })
}

fn json_string<T: serde::Serialize>(value: &Option<T>) -> Result<Option<String>, LibVmError> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| LibVmError::StateDecode {
            field: "image_config",
            message: format!("serialize OCI configuration: {error}"),
        })
}

fn json_value<T: serde::de::DeserializeOwned>(
    row: &sqlx::sqlite::SqliteRow,
    field: &'static str,
    column: &str,
) -> Result<Option<T>, LibVmError> {
    let value: Option<String> = row.try_get(column)?;
    value
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(|error| LibVmError::StateDecode {
            field,
            message: error.to_string(),
        })
}

fn image_layer_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ImageLayerDetail, LibVmError> {
    Ok(ImageLayerDetail {
        blob_digest: row.try_get("blob_digest")?,
        diff_id: row.try_get("diff_id")?,
        media_type: row.try_get("media_type")?,
        compressed_size_bytes: row
            .try_get::<Option<i64>, _>("compressed_size_bytes")?
            .map(u64_from_i64)
            .transpose()?,
        uncompressed_size_bytes: row
            .try_get::<Option<i64>, _>("uncompressed_size_bytes")?
            .map(u64_from_i64)
            .transpose()?,
        position: row.try_get("position")?,
    })
}

async fn machine_pin_count(
    pool: &sqlx::SqlitePool,
    manifest_digest: &str,
) -> Result<u64, LibVmError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM machine_rootfs WHERE manifest_digest = ?1",
    )
    .bind(manifest_digest)
    .fetch_one(pool)
    .await?;
    u64_from_i64(count)
}

fn i64_from_u64(value: u64) -> Result<i64, LibVmError> {
    i64::try_from(value).map_err(|_| LibVmError::StateDecode {
        field: "image.size_bytes",
        message: format!("value {value} does not fit in i64"),
    })
}

fn u64_from_i64(value: i64) -> Result<u64, LibVmError> {
    u64::try_from(value).map_err(|_| LibVmError::StateDecode {
        field: "image.size_bytes",
        message: format!("value {value} is negative"),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::image::OciImageConfigMetadata;
    use crate::paths::LocalPaths;
    use crate::store::models::{
        ImageConfigRecord, ImageManifestRecord, ImageRefRecord, ImageRootfsArtifactRecord,
        OciImageRecord,
    };
    use crate::store::{ImageStore, Store};

    fn oci_image_record(rootfs_path: std::path::PathBuf) -> OciImageRecord {
        OciImageRecord {
            manifest: ImageManifestRecord {
                digest: "sha256:manifest".to_string(),
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                image_id: "sha256:image-id".to_string(),
                platform_os: "linux".to_string(),
                platform_architecture: "amd64".to_string(),
                platform_variant: None,
                config_digest: Some("sha256:config".to_string()),
                layer_count: 0,
                total_size_bytes: 6,
                created_at: 1,
                last_used_at: Some(2),
            },
            reference: ImageRefRecord {
                requested_reference: "example.test/demo:latest".to_string(),
                selected_reference: "example.test/demo@sha256:manifest".to_string(),
                manifest_digest: "sha256:manifest".to_string(),
                image_id: "sha256:image-id".to_string(),
                platform_os: "linux".to_string(),
                platform_architecture: "amd64".to_string(),
                platform_variant: None,
                size_bytes: Some(6),
                created_at: 1,
                updated_at: 2,
                last_used_at: Some(2),
            },
            config: ImageConfigRecord {
                manifest_digest: "sha256:manifest".to_string(),
                digest: "sha256:config".to_string(),
                metadata: OciImageConfigMetadata {
                    entrypoint: Some(Vec::new()),
                    cmd: None,
                    env: Some(vec!["A=B".to_string()]),
                    working_dir: Some("".to_string()),
                    user: Some("1000".to_string()),
                    labels: Some(Default::default()),
                    stop_signal: Some("SIGQUIT".to_string()),
                },
                created_at: 1,
            },
            layers: Vec::new(),
            manifest_layers: Vec::new(),
            artifact: ImageRootfsArtifactRecord {
                image_id: "sha256:image-id".to_string(),
                manifest_digest: "sha256:manifest".to_string(),
                config_digest: "sha256:config".to_string(),
                platform_os: "linux".to_string(),
                platform_architecture: "amd64".to_string(),
                platform_variant: None,
                filesystem: "ext4".to_string(),
                rootfs_path,
                size_bytes: 6,
                created_at: 1,
                last_used_at: Some(2),
            },
        }
    }

    #[tokio::test]
    async fn image_detail_round_trips_oci_identity_and_config_nullability() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("state"));
        let db = Store::new(&paths).await.expect("open db");
        let rootfs_path = paths
            .images_dir()
            .join("sha256-image-id/linux-amd64/rootfs.img");
        fs::create_dir_all(rootfs_path.parent().expect("rootfs parent")).expect("create rootfs");
        fs::write(&rootfs_path, b"rootfs").expect("write rootfs");
        db.save_oci_image(&oci_image_record(rootfs_path))
            .await
            .expect("save OCI image");

        let detail = db
            .image_detail("example.test/demo:latest")
            .await
            .expect("inspect image")
            .expect("image exists");

        assert_eq!(
            detail.handle.requested_reference,
            "example.test/demo:latest"
        );
        assert_eq!(
            detail.handle.selected_reference,
            "example.test/demo@sha256:manifest"
        );
        assert_eq!(detail.handle.selected_manifest_digest, "sha256:manifest");
        assert_eq!(detail.handle.config_digest, "sha256:config");
        assert_eq!(detail.handle.image_id, "sha256:image-id");
        assert_eq!(detail.config.entrypoint, Some(Vec::new()));
        assert_eq!(detail.config.cmd, None);
        assert_eq!(detail.config.env, Some(vec!["A=B".to_string()]));
        assert_eq!(detail.config.working_dir.as_deref(), Some(""));
        assert_eq!(detail.config.labels, Some(Default::default()));
        assert_eq!(detail.config.stop_signal.as_deref(), Some("SIGQUIT"));
    }

    #[tokio::test]
    async fn prune_images_removes_cached_rootfs_and_reports_bytes() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let paths = LocalPaths::new(temp.path().join("state"));
        let db = Store::new(&paths).await.expect("open db");
        let artifact_dir = paths.images_dir().join("sha256-image-id/linux-amd64");
        let rootfs_path = artifact_dir.join("rootfs.img");
        fs::create_dir_all(&artifact_dir).expect("create artifact dir");
        fs::write(&rootfs_path, b"rootfs").expect("write rootfs");
        fs::write(artifact_dir.join("metadata.json"), b"{}").expect("write metadata");

        db.save_oci_image(&oci_image_record(rootfs_path.clone()))
            .await
            .expect("save OCI image");
        sqlx::query("DELETE FROM image_ref WHERE requested_reference = ?1")
            .bind("example.test/demo:latest")
            .execute(&db.pool)
            .await
            .expect("remove image reference");

        let report = db.prune_images().await.expect("prune images");

        assert_eq!(report.artifacts_removed, 1);
        assert_eq!(report.bytes_removed, 6);
        assert!(!artifact_dir.exists());
        let artifact_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_rootfs_artifact")
                .fetch_one(&db.pool)
                .await
                .expect("count artifacts");
        assert_eq!(artifact_count, 0);
    }
}
