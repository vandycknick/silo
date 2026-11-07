use std::fs;
use std::path::Path;

use async_trait::async_trait;
use sqlx::Row;

use crate::image::oci::{storage_error, CONVERSION_ABI};
use crate::image::{
    ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport, ImageRemoveOptions,
    OciImageConfigMetadata,
};
use crate::store::models::{
    CacheCleanupDeferral, CacheRecoveryReport, ImageConfigRecord, ImageLayerRecord,
    ImageManifestLayerRecord, ImageManifestRecord, ImageRefRecord, ImageRootfsArtifactRecord,
    OciImageRecord,
};
use crate::store::{ImageStore, ReadOnlyStore, Store};
use crate::LibVmError;

#[async_trait]
impl ImageStore for Store {
    async fn begin_storage_operation(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<crate::storage::locks::StorageLock, LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.begin_storage_operation_inner(operation_id))
        })
        .await?
    }
    async fn retain_storage_stream(
        &self,
        stream_id: &crate::storage::identity::StreamId,
        operation_id: uuid::Uuid,
    ) -> Result<(), LibVmError> {
        let store = self.clone();
        let stream = *stream_id;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.retain_storage_stream_inner(&stream, operation_id))
        })
        .await?
    }
    async fn cached_oci_image(
        &self,
        reference: &str,
        platform: &oci::Platform,
    ) -> Result<Option<OciImageRecord>, LibVmError> {
        cached_oci_image(&self.pool, reference, platform).await
    }
    async fn save_oci_image(&self, image: &OciImageRecord) -> Result<(), LibVmError> {
        let coherent_layers = image.layers.len() <= 1024
            && image.layers.len() == image.manifest_layers.len()
            && image.manifest.layer_count == image.layers.len() as i64
            && image
                .layers
                .iter()
                .zip(&image.manifest_layers)
                .enumerate()
                .all(|(position, (layer, occurrence))| {
                    occurrence.position == position as i64
                        && occurrence.manifest_digest == image.manifest.digest
                        && occurrence.layer_diff_id == layer.diff_id
                        && occurrence.layer_blob_digest == layer.blob_digest
                });
        if image.reference.manifest_digest != image.manifest.digest
            || image.config.manifest_digest != image.manifest.digest
            || image.artifact.manifest_digest != image.manifest.digest
            || image.manifest.config_digest.as_deref() != Some(image.config.digest.as_str())
            || image.artifact.config_digest != image.config.digest
            || image.artifact.image_id != image.manifest.image_id
            || image.reference.image_id != image.manifest.image_id
            || !coherent_layers
        {
            return Err(LibVmError::InvalidCreateRequest {
                name: image.reference.requested_reference.clone(),
                reason: "OCI catalog metadata does not match its manifest and ordered descriptors"
                    .to_string(),
            });
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        verify_immutable_image(&mut tx, image).await?;
        sqlx::query(
            "INSERT INTO image_manifest
                (digest, media_type, image_id, platform_os, platform_architecture,
                 platform_variant, config_digest, layer_count, total_size_bytes,
                 created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(digest) DO UPDATE SET
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
             ON CONFLICT(manifest_digest) DO NOTHING",
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
                    (diff_id, blob_digest, compressed_size_bytes,
                     uncompressed_size_bytes, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(diff_id, blob_digest) DO UPDATE SET
                    last_used_at = excluded.last_used_at",
            )
            .bind(&layer.diff_id)
            .bind(&layer.blob_digest)
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
                    (manifest_digest, layer_diff_id, position, layer_blob_digest, media_type)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(manifest_digest, position) DO NOTHING",
            )
            .bind(&layer.manifest_digest)
            .bind(&layer.layer_diff_id)
            .bind(layer.position)
            .bind(&layer.layer_blob_digest)
            .bind(&layer.media_type)
            .execute(&mut *tx)
            .await?;
        }

        upsert_artifact(&mut tx, &image.artifact).await?;
        sqlx::query("DELETE FROM image_stream_gc WHERE stream_id = ?1")
            .bind(image.artifact.stream_id.to_string())
            .execute(&mut *tx)
            .await?;
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
            "SELECT l.blob_digest, l.diff_id, ml.media_type,
                    l.compressed_size_bytes, l.uncompressed_size_bytes, ml.position
             FROM image_manifest_layer ml
             JOIN image_layer l ON l.diff_id = ml.layer_diff_id AND l.blob_digest = ml.layer_blob_digest
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
        _options: ImageRemoveOptions,
    ) -> Result<ImageHandle, LibVmError> {
        let Some(handle) = self.image_handle(reference).await? else {
            return Err(LibVmError::ImageNotFound {
                reference: reference.to_string(),
            });
        };

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
        self.recover_layer_objects().await?;
        self.prune_image_cache(true).await.map(|(pruned, _)| pruned)
    }
}

impl Store {
    async fn retain_storage_stream_inner(
        &self,
        stream_id: &crate::storage::identity::StreamId,
        operation_id: uuid::Uuid,
    ) -> Result<(), LibVmError> {
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots_shared()?;
        // The staging owner already holds this operation's one shared OFD.
        // A missing stable inode must never be recreated for an existing owner.
        if pool.try_exclusive_lease(operation_id)?.is_some() {
            return Err(LibVmError::InvalidStorageRecord {
                record: "storage-operation",
                message: "stream retention requires a live staging lease".into(),
            });
        }
        let (device, inode) = pool.operation_lease_identity(operation_id)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='convert' AND state='staging' AND file_device=?2 AND file_inode=?3)")
            .bind(operation_id.to_string()).bind(device.to_string()).bind(inode.to_string()).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(LibVmError::InvalidStorageRecord {
                record: "storage-operation",
                message: "cannot append to a frozen or replaced operation".into(),
            });
        }
        crate::store::operation_store::insert_stream(&mut tx, operation_id, stream_id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub(crate) async fn recover_image_cache(&self) -> Result<CacheRecoveryReport, LibVmError> {
        match fs::symlink_metadata(&self.images_dir) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CacheRecoveryReport::default())
            }
            Err(error) => return Err(error.into()),
        }
        let recovered = async {
            self.recover_layer_objects().await?;
            self.prune_image_cache(false).await
        }
        .await;
        match recovered {
            Ok((_, recovery)) => Ok(recovery),
            Err(LibVmError::CacheDependency { machine, path }) => Ok(CacheRecoveryReport {
                deferred: vec![CacheCleanupDeferral::ExternalDependency { machine, path }],
            }),
            Err(error) => Err(error),
        }
    }

    async fn prune_image_cache(
        &self,
        prune_unreferenced: bool,
    ) -> Result<(ImagePruneReport, CacheRecoveryReport), LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        // The worker owns both catalog access and every deletion/root guard.
        // Cancellation of an awaiting caller cannot strand filesystem cleanup
        // on an executor or outlive its writable catalog capability.
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.prune_image_cache_inner(prune_unreferenced))
        })
        .await?
    }

    async fn prune_image_cache_inner(
        &self,
        prune_unreferenced: bool,
    ) -> Result<(ImagePruneReport, CacheRecoveryReport), LibVmError> {
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let recovery = self.retire_abandoned_storage_operations(&pool).await?;
        // Keep only one temporary directory/lease open, and never discover
        // directory entries while holding roots.
        for candidate in pool.abandoned_temporary()? {
            let candidate = candidate?;
            let _roots = pool.lock_roots()?;
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let name = candidate
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| LibVmError::InvalidStorageRecord {
                    record: "capture-workspace",
                    message: "workspace name is not UTF-8".into(),
                })?;
            let retained_capture: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind IN ('capture','live-fork'))")
                .bind(name).fetch_one(&mut *tx).await?;
            if retained_capture {
                tx.commit().await?;
                continue;
            }
            crate::store::ensure_cache_paths_unreferenced(
                &mut tx,
                &[candidate.path().to_path_buf()],
                &self.home,
            )
            .await?;
            candidate.remove()?;
            tx.commit().await?;
        }
        let mut report = ImagePruneReport {
            references_removed: 0,
            artifacts_removed: 0,
            bytes_removed: 0,
        };
        let mut scan = pool.scan_streams()?;
        let mut pending_cursor = String::new();
        loop {
            self.check_operation_recovery(&pool).await?;
            crate::store::snapshot_store::check_snapshot_catalog(self).await?;
            crate::store::managed_image_store::check_image_catalog(self).await?;
            let discovered = scan.by_ref().take(256).collect::<Result<Vec<_>, _>>()?;
            let scan_finished = discovered.is_empty();
            let _roots = pool.lock_roots()?;
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let machine_streams =
                crate::store::cache_paths::retained_machine_streams(&mut tx).await?;
            for (id, length) in discovered {
                if machine_streams.contains(&id) {
                    continue;
                }
                sqlx::query("INSERT INTO image_stream_gc(stream_id,size_bytes) SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM image_rootfs_artifact WHERE stream_id=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation_stream WHERE stream_id=?1) AND NOT EXISTS(SELECT 1 FROM snapshot_stream_dependency WHERE stream_id=?1) AND NOT EXISTS(SELECT 1 FROM image_stream_dependency WHERE stream_id=?1) AND NOT EXISTS(SELECT 1 FROM layer_result WHERE pack_stream=?1) ON CONFLICT(stream_id) DO NOTHING")
                    .bind(id.to_string()).bind(i64_from_u64(length)?).execute(&mut *tx).await?;
            }
            let artifacts = sqlx::query("SELECT image_id,rootfs_path,size_bytes,stream_id FROM image_rootfs_artifact a WHERE ?1 AND NOT EXISTS(SELECT 1 FROM image_ref r WHERE r.manifest_digest=a.manifest_digest) AND NOT EXISTS(SELECT 1 FROM storage_operation_stream p WHERE p.stream_id=a.stream_id) LIMIT 256")
                .bind(prune_unreferenced).fetch_all(&mut *tx).await?;
            let artifact_count = artifacts.len();
            for row in artifacts {
                let id: String = row.try_get("image_id")?;
                let stream: String = row.try_get("stream_id")?;
                let size: i64 = row.try_get("size_bytes")?;
                let parsed = stream
                    .parse::<crate::storage::identity::StreamId>()
                    .map_err(|error| storage_error(error.into()))?;
                let path: String = row.try_get("rootfs_path")?;
                if !Path::new(&path).is_absolute()
                    || !Path::new(&path)
                        .ends_with(Path::new("images/streams/sha256").join(parsed.hex()))
                {
                    return Err(LibVmError::StateDecode {
                        field: "image_rootfs_artifact.rootfs_path",
                        message: "cached stream spelling does not name its content-identity slot"
                            .into(),
                    });
                }
                sqlx::query("INSERT INTO image_stream_gc(stream_id,size_bytes) VALUES(?1,?2) ON CONFLICT(stream_id) DO NOTHING").bind(&stream).bind(size).execute(&mut *tx).await?;
                sqlx::query("DELETE FROM image_rootfs_artifact WHERE image_id=?1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                report.artifacts_removed = report.artifacts_removed.saturating_add(1);
            }
            sqlx::query("DELETE FROM image_manifest WHERE NOT EXISTS(SELECT 1 FROM image_ref r WHERE r.manifest_digest=image_manifest.digest) AND NOT EXISTS(SELECT 1 FROM image_rootfs_artifact a WHERE a.manifest_digest=image_manifest.digest)").execute(&mut *tx).await?;
            sqlx::query("DELETE FROM image_layer WHERE NOT EXISTS(SELECT 1 FROM image_manifest_layer ml WHERE ml.layer_diff_id=image_layer.diff_id AND ml.layer_blob_digest=image_layer.blob_digest)").execute(&mut *tx).await?;
            if !scan_finished || artifact_count > 0 {
                pending_cursor.clear();
            }
            let pending = sqlx::query("SELECT stream_id,size_bytes FROM image_stream_gc g WHERE stream_id>?1 AND NOT EXISTS(SELECT 1 FROM image_rootfs_artifact a WHERE a.stream_id=g.stream_id) AND NOT EXISTS(SELECT 1 FROM layer_result l WHERE l.pack_stream=g.stream_id) AND NOT EXISTS(SELECT 1 FROM storage_operation_stream p WHERE p.stream_id=g.stream_id) AND NOT EXISTS(SELECT 1 FROM snapshot_stream_dependency s WHERE s.stream_id=g.stream_id) AND NOT EXISTS(SELECT 1 FROM image_stream_dependency i WHERE i.stream_id=g.stream_id) ORDER BY stream_id LIMIT 256").bind(&pending_cursor).fetch_all(&mut *tx).await?;
            let pending_count = pending.len();
            let mut deletions = Vec::new();
            for row in pending {
                let stream: String = row.try_get("stream_id")?;
                pending_cursor.clone_from(&stream);
                let id = stream
                    .parse::<crate::storage::identity::StreamId>()
                    .map_err(|error| storage_error(error.into()))?;
                if machine_streams.contains(&id) {
                    continue;
                }
                let path = pool.stream_path(&id);
                validate_cached_rootfs(&path, &self.images_dir, &stream)?;
                deletions.push((stream, path, u64_from_i64(row.try_get("size_bytes")?)?));
            }
            crate::store::ensure_cache_paths_unreferenced(
                &mut tx,
                &deletions
                    .iter()
                    .map(|(_, path, _)| path.clone())
                    .collect::<Vec<_>>(),
                &self.home,
            )
            .await?;
            // Publish retryable deletion intent before touching bytes. A crash
            // must not resurrect an artifact row naming an already unlinked file.
            tx.commit().await?;
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            crate::store::ensure_cache_paths_unreferenced(
                &mut tx,
                &deletions
                    .iter()
                    .map(|(_, path, _)| path.clone())
                    .collect::<Vec<_>>(),
                &self.home,
            )
            .await?;
            #[cfg(test)]
            if let Some(hook) = &self.layer_hook {
                hook.hit(crate::store::layer_store::tests::WorkerPoint::RecoveryDelete)?;
            }
            // The blocking owner keeps Store, transaction, roots and directory
            // capabilities through actual unlink, directory sync and commit.
            for (stream, _path, size) in deletions {
                let id = stream
                    .parse::<crate::storage::identity::StreamId>()
                    .map_err(|error| storage_error(error.into()))?;
                if pool.remove_stream(&id)? {
                    report.bytes_removed = report.bytes_removed.saturating_add(size);
                }
                sqlx::query("DELETE FROM image_stream_gc WHERE stream_id=?1")
                    .bind(stream)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            if scan_finished && artifact_count < 256 && pending_count < 256 {
                break;
            }
        }
        Ok((report, recovery))
    }
}

fn validate_cached_rootfs(
    rootfs_path: &Path,
    image_root: &Path,
    stream_id: &str,
) -> Result<bool, LibVmError> {
    let id = stream_id
        .parse::<crate::storage::identity::StreamId>()
        .map_err(|error| storage_error(error.into()))?;
    let expected = image_root.join("streams/sha256").join(id.hex());
    if rootfs_path != expected {
        return Err(LibVmError::StateDecode {
            field: "image_rootfs_artifact.rootfs_path",
            message: "refusing to prune a path outside its owned stream slot".into(),
        });
    }
    let metadata = match fs::symlink_metadata(rootfs_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(LibVmError::StateDecode {
            field: "image_rootfs_artifact.rootfs_path",
            message: "refusing to prune a non-regular stream".into(),
        });
    }
    Ok(true)
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
             platform_variant, filesystem, rootfs_path, size_bytes, created_at, last_used_at,
             stream_id, conversion_abi)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(image_id) DO UPDATE SET
             manifest_digest = excluded.manifest_digest,
             config_digest = excluded.config_digest,
            platform_os = excluded.platform_os,
            platform_architecture = excluded.platform_architecture,
            platform_variant = excluded.platform_variant,
            filesystem = excluded.filesystem,
            rootfs_path = excluded.rootfs_path,
            size_bytes = excluded.size_bytes,
            last_used_at = excluded.last_used_at,
            stream_id = excluded.stream_id,
            conversion_abi = excluded.conversion_abi",
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
    .bind(artifact.stream_id.to_string())
    .bind(&artifact.conversion_abi)
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
    image_config_from_row(row)
}

fn image_config_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<OciImageConfigMetadata, LibVmError> {
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

fn immutable_image_error(field: &'static str) -> LibVmError {
    LibVmError::StateDecode {
        field,
        message: "OCI digest-bound metadata contradicts the stored immutable record".into(),
    }
}

async fn verify_immutable_image(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    image: &OciImageRecord,
) -> Result<(), LibVmError> {
    let existing = sqlx::query("SELECT * FROM image_manifest WHERE digest = ?1")
        .bind(&image.manifest.digest)
        .fetch_optional(&mut **tx)
        .await?;
    if let Some(row) = existing {
        let manifest = &image.manifest;
        if row.try_get::<&str, _>("media_type")? != manifest.media_type
            || row.try_get::<&str, _>("image_id")? != manifest.image_id
            || row.try_get::<&str, _>("platform_os")? != manifest.platform_os
            || row.try_get::<&str, _>("platform_architecture")? != manifest.platform_architecture
            || row.try_get::<Option<&str>, _>("platform_variant")?
                != manifest.platform_variant.as_deref()
            || row.try_get::<Option<&str>, _>("config_digest")? != manifest.config_digest.as_deref()
            || row.try_get::<i64, _>("layer_count")? != manifest.layer_count
            || row.try_get::<i64, _>("total_size_bytes")? != manifest.total_size_bytes
        {
            return Err(immutable_image_error("image_manifest"));
        }
        let config = sqlx::query(
            "SELECT digest, json(entrypoint_json) AS entrypoint_json, json(cmd_json) AS cmd_json,
                    json(env_json) AS env_json, working_dir, user, json(labels_json) AS labels_json, stop_signal
             FROM image_config WHERE manifest_digest = ?1",
        ).bind(&manifest.digest).fetch_optional(&mut **tx).await?
            .ok_or_else(|| immutable_image_error("image_config"))?;
        if config.try_get::<&str, _>("digest")? != image.config.digest
            || image_config_from_row(config)? != image.config.metadata
        {
            return Err(immutable_image_error("image_config"));
        }
        let occurrences = sqlx::query(
            "SELECT position, layer_diff_id, layer_blob_digest, media_type FROM image_manifest_layer WHERE manifest_digest = ?1 ORDER BY position LIMIT 1025",
        ).bind(&manifest.digest).fetch_all(&mut **tx).await?;
        if occurrences.len() != image.manifest_layers.len() {
            return Err(immutable_image_error("image_manifest_layer"));
        }
        for (stored, expected) in occurrences.iter().zip(&image.manifest_layers) {
            if stored.try_get::<i64, _>("position")? != expected.position
                || stored.try_get::<&str, _>("layer_diff_id")? != expected.layer_diff_id
                || stored.try_get::<&str, _>("layer_blob_digest")? != expected.layer_blob_digest
                || stored.try_get::<&str, _>("media_type")? != expected.media_type
            {
                return Err(immutable_image_error("image_manifest_layer"));
            }
        }
    }
    for layer in &image.layers {
        if let Some(stored) =
            sqlx::query("SELECT * FROM image_layer WHERE diff_id = ?1 AND blob_digest = ?2")
                .bind(&layer.diff_id)
                .bind(&layer.blob_digest)
                .fetch_optional(&mut **tx)
                .await?
        {
            if stored.try_get::<Option<i64>, _>("compressed_size_bytes")?
                != layer.compressed_size_bytes.map(i64_from_u64).transpose()?
                || stored.try_get::<Option<i64>, _>("uncompressed_size_bytes")?
                    != layer
                        .uncompressed_size_bytes
                        .map(i64_from_u64)
                        .transpose()?
            {
                return Err(immutable_image_error("image_layer"));
            }
        }
    }
    Ok(())
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

impl ReadOnlyStore {
    pub(crate) async fn cached_oci_image(
        &self,
        reference: &str,
        platform: &oci::Platform,
    ) -> Result<Option<OciImageRecord>, LibVmError> {
        cached_oci_image(&self.pool, reference, platform).await
    }
}

async fn cached_oci_image(
    pool: &sqlx::SqlitePool,
    reference: &str,
    platform: &oci::Platform,
) -> Result<Option<OciImageRecord>, LibVmError> {
    let selected_digest = reference.rsplit_once('@').map(|(_, digest)| digest);
    if let Some(digest) = selected_digest {
        digest
            .parse::<crate::storage::identity::ObjectDigest>()
            .map_err(|error| storage_error(error.into()))?;
    }
    let row = sqlx::query(
        "SELECT CASE WHEN ?6 IS NULL THEN r.requested_reference ELSE ?1 END AS requested_reference,
                CASE WHEN ?6 IS NULL THEN r.selected_reference ELSE ?1 END AS selected_reference,
                COALESCE(r.created_at, m.created_at) AS ref_created_at,
                COALESCE(r.updated_at, m.created_at) AS updated_at, r.last_used_at AS ref_last_used_at,
                m.*, a.rootfs_path, a.size_bytes, a.stream_id, a.conversion_abi, a.filesystem,
                a.created_at AS artifact_created_at, a.last_used_at AS artifact_last_used_at
         FROM image_manifest m JOIN image_rootfs_artifact a ON a.manifest_digest = m.digest
         LEFT JOIN image_ref r ON r.manifest_digest = m.digest
         WHERE (r.requested_reference = ?1 OR r.selected_reference = ?1 OR m.digest = ?6)
           AND m.platform_os = ?2 AND m.platform_architecture = ?3
           AND m.platform_variant IS ?4 AND a.conversion_abi = ?5
         ORDER BY r.requested_reference LIMIT 1",
    ).bind(reference).bind(&platform.os).bind(&platform.architecture).bind(&platform.variant)
        .bind(CONVERSION_ABI).bind(selected_digest).fetch_optional(pool).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let digest: String = row.try_get("digest")?;
    let config_digest: String = row.try_get("config_digest")?;
    let image_id: String = row.try_get("image_id")?;
    let created_at: i64 = row.try_get("created_at")?;
    let size_bytes = u64_from_i64(row.try_get("size_bytes")?)?;
    let config = image_config(pool, &digest).await?;
    let layer_rows = sqlx::query(
        "SELECT l.*, ml.position, ml.media_type FROM image_manifest_layer ml JOIN image_layer l ON l.diff_id = ml.layer_diff_id AND l.blob_digest = ml.layer_blob_digest WHERE ml.manifest_digest = ?1 ORDER BY ml.position LIMIT 1025",
    ).bind(&digest).fetch_all(pool).await?;
    if layer_rows.len() > 1024 || row.try_get::<i64, _>("layer_count")? != layer_rows.len() as i64 {
        return Err(LibVmError::StateDecode {
            field: "image.layers",
            message: "catalog layer count does not match its bounded descriptor sequence".into(),
        });
    }
    let mut layers = Vec::with_capacity(layer_rows.len());
    let mut manifest_layers = Vec::with_capacity(layer_rows.len());
    for row in layer_rows {
        let layer = image_layer_from_row(row)?;
        manifest_layers.push(ImageManifestLayerRecord {
            manifest_digest: digest.clone(),
            layer_diff_id: layer.diff_id.clone(),
            layer_blob_digest: layer.blob_digest.clone(),
            media_type: layer.media_type,
            position: layer.position,
        });
        layers.push(ImageLayerRecord {
            diff_id: layer.diff_id,
            blob_digest: layer.blob_digest,
            compressed_size_bytes: layer.compressed_size_bytes,
            uncompressed_size_bytes: layer.uncompressed_size_bytes,
            created_at,
            last_used_at: None,
        });
    }
    Ok(Some(OciImageRecord {
        manifest: ImageManifestRecord {
            digest: digest.clone(),
            media_type: row.try_get("media_type")?,
            image_id: image_id.clone(),
            platform_os: platform.os.clone(),
            platform_architecture: platform.architecture.clone(),
            platform_variant: platform.variant.clone(),
            config_digest: Some(config_digest.clone()),
            layer_count: row.try_get("layer_count")?,
            total_size_bytes: row.try_get("total_size_bytes")?,
            created_at,
            last_used_at: row.try_get("last_used_at")?,
        },
        reference: ImageRefRecord {
            requested_reference: row.try_get("requested_reference")?,
            selected_reference: row.try_get("selected_reference")?,
            manifest_digest: digest.clone(),
            image_id: image_id.clone(),
            platform_os: platform.os.clone(),
            platform_architecture: platform.architecture.clone(),
            platform_variant: platform.variant.clone(),
            size_bytes: Some(size_bytes),
            created_at: row.try_get("ref_created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_used_at: row.try_get("ref_last_used_at")?,
        },
        config: ImageConfigRecord {
            manifest_digest: digest.clone(),
            digest: config_digest.clone(),
            metadata: config,
            created_at,
        },
        layers,
        manifest_layers,
        artifact: ImageRootfsArtifactRecord {
            image_id,
            manifest_digest: digest,
            config_digest,
            platform_os: platform.os.clone(),
            platform_architecture: platform.architecture.clone(),
            platform_variant: platform.variant.clone(),
            filesystem: row.try_get("filesystem")?,
            rootfs_path: std::path::PathBuf::from(row.try_get::<String, _>("rootfs_path")?),
            stream_id: row
                .try_get::<String, _>("stream_id")?
                .parse::<crate::storage::identity::StreamId>()
                .map_err(|error| storage_error(error.into()))?,
            conversion_abi: row.try_get("conversion_abi")?,
            size_bytes,
            created_at: row.try_get("artifact_created_at")?,
            last_used_at: row.try_get("artifact_last_used_at")?,
        },
    }))
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
                stream_id: crate::storage::stream::StreamHasher::new()
                    .hash_reader(b"rootfs".as_slice())
                    .unwrap()
                    .id(),
                conversion_abi: crate::image::oci::CONVERSION_ABI.into(),
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
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let rootfs_path = pool.publish_stream(&source).unwrap().path;
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
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let rootfs_path = pool.publish_stream(&source).unwrap().path;

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
        assert!(!rootfs_path.exists());
        let artifact_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_rootfs_artifact")
                .fetch_one(&db.pool)
                .await
                .expect("count artifacts");
        assert_eq!(artifact_count, 0);
    }
    #[tokio::test]
    async fn active_copy_lease_blocks_prune_until_released() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let image = oci_image_record(stream.path.clone());
        db.save_oci_image(&image).await.unwrap();
        let operation = uuid::Uuid::new_v4();
        let lease = db.begin_storage_operation(operation).await.unwrap();
        db.retain_storage_stream(&stream.id, operation)
            .await
            .unwrap();
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        let recovery = db.recover_image_cache().await.unwrap();
        assert!(matches!(
            recovery.deferred.as_slice(),
            [crate::store::models::CacheCleanupDeferral::ActiveLease { operation_id }] if *operation_id == operation
        ));
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 0);
        assert_eq!(fs::read(&stream.path).unwrap(), b"rootfs");
        drop(lease);
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 1);
        assert!(!stream.path.exists());
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 0);
    }

    #[tokio::test]
    async fn duplicate_layer_occurrences_round_trip_in_manifest_order() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let mut image = oci_image_record(paths.images_dir().join("unused"));
        let layer = crate::store::models::ImageLayerRecord {
            diff_id: format!("sha256:{}", "a".repeat(64)),
            blob_digest: format!("sha256:{}", "b".repeat(64)),
            compressed_size_bytes: Some(1024),
            uncompressed_size_bytes: Some(1024),
            created_at: 1,
            last_used_at: None,
        };
        image.layers = vec![layer.clone(), layer.clone()];
        image.manifest.layer_count = 2;
        image.manifest_layers = (0..2)
            .map(|position| crate::store::models::ImageManifestLayerRecord {
                manifest_digest: image.manifest.digest.clone(),
                layer_diff_id: layer.diff_id.clone(),
                layer_blob_digest: layer.blob_digest.clone(),
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                position,
            })
            .collect();
        db.save_oci_image(&image).await.unwrap();
        let detail = db
            .image_detail(&image.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(detail.layers.len(), 2);
        assert_eq!(detail.layers[0].diff_id, detail.layers[1].diff_id);
        assert_eq!(
            (detail.layers[0].position, detail.layers[1].position),
            (0, 1)
        );
        let original_blob = detail.layers[0].blob_digest.clone();
        let mut second = image.clone();
        second.manifest.digest = format!("sha256:{}", "c".repeat(64));
        second.manifest.image_id = second.manifest.digest.clone();
        second.reference.requested_reference = "example.test/other:latest".into();
        second.reference.manifest_digest = second.manifest.digest.clone();
        second.reference.image_id = second.manifest.image_id.clone();
        second.config.manifest_digest = second.manifest.digest.clone();
        second.artifact.manifest_digest = second.manifest.digest.clone();
        second.artifact.image_id = second.manifest.image_id.clone();
        for layer in &mut second.layers {
            layer.blob_digest = format!("sha256:{}", "d".repeat(64));
        }
        for layer in &mut second.manifest_layers {
            layer.manifest_digest = second.manifest.digest.clone();
            layer.layer_blob_digest = second.layers[0].blob_digest.clone();
        }
        db.save_oci_image(&second).await.unwrap();
        let original = db
            .image_detail(&image.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        let changed = db
            .image_detail(&second.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.layers[0].blob_digest, original_blob);
        assert_ne!(
            original.layers[0].blob_digest,
            changed.layers[0].blob_digest
        );
        let mut equivalent = image.clone();
        equivalent.manifest.digest = format!("sha256:{}", "f".repeat(64));
        equivalent.manifest.image_id = equivalent.manifest.digest.clone();
        equivalent.reference.requested_reference = "example.test/equivalent:latest".into();
        equivalent.reference.manifest_digest = equivalent.manifest.digest.clone();
        equivalent.reference.image_id = equivalent.manifest.image_id.clone();
        equivalent.config.manifest_digest = equivalent.manifest.digest.clone();
        equivalent.artifact.manifest_digest = equivalent.manifest.digest.clone();
        equivalent.artifact.image_id = equivalent.manifest.image_id.clone();
        for occurrence in &mut equivalent.manifest_layers {
            occurrence.manifest_digest = equivalent.manifest.digest.clone();
            occurrence.media_type = "application/vnd.docker.image.rootfs.diff.tar".into();
        }
        db.save_oci_image(&equivalent).await.unwrap();
        let preserved = db
            .image_detail(&image.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        let alternate = db
            .image_detail(&equivalent.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preserved.layers[0].media_type,
            "application/vnd.oci.image.layer.v1.tar"
        );
        assert_eq!(
            alternate.layers[0].media_type,
            "application/vnd.docker.image.rootfs.diff.tar"
        );
    }

    #[tokio::test]
    async fn failed_catalog_publication_rolls_back_reference_and_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        sqlx::query("CREATE TRIGGER reject_artifact BEFORE INSERT ON image_rootfs_artifact BEGIN SELECT RAISE(ABORT, 'reject artifact'); END")
            .execute(&db.pool).await.unwrap();
        let image = oci_image_record(paths.images_dir().join("unused"));
        assert!(db.save_oci_image(&image).await.is_err());
        assert!(db.list_image_handles().await.unwrap().is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_manifest")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn cache_profile_miss_and_invalid_stream_identity_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let image = oci_image_record(paths.images_dir().join("unused"));
        db.save_oci_image(&image).await.unwrap();
        let platform = oci::Platform::linux_amd64();
        assert!(db
            .cached_oci_image(&image.reference.requested_reference, &platform)
            .await
            .unwrap()
            .is_some());
        sqlx::query("UPDATE image_rootfs_artifact SET conversion_abi = 'another-formatter'")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(db
            .cached_oci_image(&image.reference.requested_reference, &platform)
            .await
            .unwrap()
            .is_none());
        sqlx::query(
            "UPDATE image_rootfs_artifact SET conversion_abi = ?1, stream_id = 'sha256:not-valid'",
        )
        .bind(crate::image::oci::CONVERSION_ABI)
        .execute(&db.pool)
        .await
        .unwrap();
        assert!(matches!(
            db.cached_oci_image(&image.reference.requested_reference, &platform)
                .await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::Identity(_)
            ))
        ));
    }

    #[tokio::test]
    async fn prune_transaction_abort_preserves_retained_bytes_and_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let image = oci_image_record(stream.path.clone());
        db.save_oci_image(&image).await.unwrap();
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER reject_prune BEFORE DELETE ON image_rootfs_artifact BEGIN SELECT RAISE(ABORT, 'reject prune'); END")
            .execute(&db.pool).await.unwrap();
        assert!(db.prune_images().await.is_err());
        assert_eq!(fs::read(&stream.path).unwrap(), b"rootfs");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_rootfs_artifact")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            1
        );
        sqlx::query("DROP TRIGGER reject_prune")
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 6);
    }

    #[tokio::test]
    async fn pending_prune_is_retry_safe_and_republication_cancels_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        sqlx::query("INSERT INTO image_stream_gc (stream_id, size_bytes) VALUES (?1, 6)")
            .bind(stream.id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        let recovered = db.prune_images().await.unwrap();
        assert_eq!(recovered.artifacts_removed, 0);
        assert_eq!(recovered.bytes_removed, 6);
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 0);
        let stream = pool.publish_stream(&source).unwrap();
        sqlx::query("INSERT INTO image_stream_gc (stream_id, size_bytes) VALUES (?1, 6)")
            .bind(stream.id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        db.save_oci_image(&oci_image_record(stream.path.clone()))
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_stream_gc")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 0);
        assert!(stream.path.is_file());
    }

    #[tokio::test]
    async fn corrupt_cache_path_cannot_prune_a_private_machine_root() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let private_root = paths.home().join("machines/private/root.raw");
        fs::create_dir_all(private_root.parent().unwrap()).unwrap();
        fs::write(&private_root, b"private bytes").unwrap();
        let image = oci_image_record(private_root.clone());
        db.save_oci_image(&image).await.unwrap();
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            db.prune_images().await,
            Err(crate::LibVmError::StateDecode { .. })
        ));
        assert_eq!(fs::read(private_root).unwrap(), b"private bytes");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_rootfs_artifact")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn digest_bound_facts_are_insert_or_verify_and_failed_aliases_roll_back() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let mut image = oci_image_record(paths.images_dir().join("unused"));
        let layer = crate::store::models::ImageLayerRecord {
            diff_id: format!("sha256:{}", "a".repeat(64)),
            blob_digest: format!("sha256:{}", "b".repeat(64)),
            compressed_size_bytes: Some(1024),
            uncompressed_size_bytes: None,
            created_at: 1,
            last_used_at: None,
        };
        image.layers = vec![layer.clone(), layer.clone()];
        image.manifest.layer_count = 2;
        image.manifest_layers = (0..2)
            .map(|position| crate::store::models::ImageManifestLayerRecord {
                manifest_digest: image.manifest.digest.clone(),
                layer_diff_id: layer.diff_id.clone(),
                layer_blob_digest: layer.blob_digest.clone(),
                position,
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            })
            .collect();
        db.save_oci_image(&image).await.unwrap();
        db.save_oci_image(&image).await.unwrap();
        let original = db
            .image_detail(&image.reference.requested_reference)
            .await
            .unwrap()
            .unwrap();
        let mut shorter = image.clone();
        shorter.layers.pop();
        shorter.manifest_layers.pop();
        shorter.manifest.layer_count = 1;
        let mut config = image.clone();
        config.config.metadata.cmd = Some(vec!["different".into()]);
        let mut descriptor = image.clone();
        for layer in &mut descriptor.layers {
            layer.compressed_size_bytes = Some(2048);
        }
        let mut order = image.clone();
        order.layers[1].blob_digest = format!("sha256:{}", "c".repeat(64));
        order.manifest_layers[1].layer_blob_digest = order.layers[1].blob_digest.clone();
        for mut conflicting in [shorter, config, descriptor, order] {
            conflicting.reference.requested_reference = "example.test/failed:latest".into();
            assert!(matches!(
                db.save_oci_image(&conflicting).await,
                Err(crate::LibVmError::StateDecode { .. })
            ));
            assert!(db
                .image_handle(&conflicting.reference.requested_reference)
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                db.image_detail(&image.reference.requested_reference)
                    .await
                    .unwrap()
                    .unwrap(),
                original
            );
        }
    }

    #[tokio::test]
    async fn prune_recovers_uncatalogued_publication_and_abandoned_but_not_live_staging() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"uncommitted").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let stream = pool.publish_stream(&source).unwrap();
        let live_id = uuid::Uuid::new_v4();
        let live_lease = db.begin_storage_operation(live_id).await.unwrap();
        let live = pool
            .create_operation_with_lease(live_id, live_lease)
            .unwrap();
        fs::write(live.temporary.join("in-flight"), b"live").unwrap();
        let abandoned_id = uuid::Uuid::new_v4();
        let abandoned_lease = db.begin_storage_operation(abandoned_id).await.unwrap();
        let abandoned = pool
            .create_operation_with_lease(abandoned_id, abandoned_lease)
            .unwrap();
        let abandoned_path = abandoned.temporary.clone();
        fs::write(abandoned_path.join("interrupted"), b"abandoned").unwrap();
        drop(abandoned);
        let report = db.prune_images().await.unwrap();
        assert_eq!(report.artifacts_removed, 0);
        assert_eq!(report.bytes_removed, 11);
        assert!(!stream.path.exists());
        assert!(!abandoned_path.exists());
        assert!(live.temporary.join("in-flight").exists());
        let live_path = live.temporary.clone();
        drop(live);
        db.prune_images().await.unwrap();
        assert!(!live_path.exists());
    }

    #[tokio::test]
    async fn reopening_recovers_orphans_without_pruning_catalogued_digest_cache() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        fs::write(&source, b"rootfs").unwrap();
        let retained = pool.publish_stream(&source).unwrap();
        let image = oci_image_record(retained.path.clone());
        db.save_oci_image(&image).await.unwrap();
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        fs::write(&source, b"interrupted-publication").unwrap();
        let orphan = pool.publish_stream(&source).unwrap();
        db.close().await;
        let reopened = Store::new(&paths).await.unwrap();
        assert!(retained.path.is_file());
        assert!(!orphan.path.exists());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM image_rootfs_artifact")
                .fetch_one(&reopened.pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(reopened.prune_images().await.unwrap().artifacts_removed, 1);
        assert!(!retained.path.exists());
    }

    #[tokio::test]
    async fn writable_startup_initializes_snapshot_coordination_without_private_state() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = temp.path().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let retained = pool.publish_stream(&source).unwrap();
        let image = oci_image_record(retained.path.clone());
        db.save_oci_image(&image).await.unwrap();
        drop(pool);
        db.close().await;
        fs::remove_file(&source).unwrap();

        // A fresh current-schema catalog/immutable-pool snapshot omits these
        // transient directories. Remove them only after closing the fixture;
        // this is not normal lock-file cleanup or a legacy-state migration.
        fs::remove_dir_all(paths.images_dir().join("tmp")).unwrap();
        fs::remove_dir_all(paths.images_dir().join("locks")).unwrap();
        assert!(crate::storage::pool::StoragePool::open_existing(paths.images_dir()).is_err());
        assert!(!paths.images_dir().join("tmp").exists());
        assert!(!paths.images_dir().join("locks").exists());

        let reopened = Store::new(&paths).await.unwrap();
        for directory in ["tmp", "locks/publication", "locks/leases"] {
            assert!(paths.images_dir().join(directory).is_dir());
        }
        assert_eq!(
            fs::read_dir(paths.images_dir().join("tmp"))
                .unwrap()
                .count(),
            0
        );
        assert!(!paths.home().join("operations").exists());
        assert!(!paths.home().join("machines").exists());
        let cached = reopened
            .cached_oci_image(
                &image.reference.requested_reference,
                &oci::Platform::linux_amd64(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached.artifact.stream_id, retained.id);
        assert_eq!(cached.artifact.rootfs_path, retained.path);
        assert_eq!(fs::read(&cached.artifact.rootfs_path).unwrap(), b"rootfs");
    }

    #[tokio::test]
    async fn one_operation_pins_overlapping_multistream_closures_until_last_ofd_closes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = temp.path().join("source");
        fs::write(&source, [1; 512]).unwrap();
        let first = pool.publish_stream(&source).unwrap();
        fs::write(&source, [2; 512]).unwrap();
        let second = pool.publish_stream(&source).unwrap();
        let op_a = uuid::Uuid::new_v4();
        let lease_a = db.begin_storage_operation(op_a).await.unwrap();
        let child_a = lease_a.duplicate_inheritable().unwrap();
        db.retain_storage_stream(&first.id, op_a).await.unwrap();
        db.retain_storage_stream(&second.id, op_a).await.unwrap();
        let op_b = uuid::Uuid::new_v4();
        let lease_b = db.begin_storage_operation(op_b).await.unwrap();
        db.retain_storage_stream(&second.id, op_b).await.unwrap();
        drop(lease_a);
        db.prune_images().await.unwrap();
        assert_eq!(fs::read(&first.path).unwrap(), [1; 512]);
        assert_eq!(fs::read(&second.path).unwrap(), [2; 512]);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM storage_operation_stream WHERE operation_id=?1",
        )
        .bind(op_a.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
        drop(child_a);
        db.prune_images().await.unwrap();
        assert!(!first.path.exists());
        assert!(second.path.exists());
        assert!(paths
            .images_dir()
            .join("locks/leases")
            .join(format!("{op_a}.lease"))
            .exists());
        drop(lease_b);
        db.prune_images().await.unwrap();
        assert!(!second.path.exists());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn stream_gc_collects_multiple_bounded_batches() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let source = temp.path().join("source");
        let mut paths_to_remove = Vec::new();
        for value in 0_u64..257 {
            fs::write(&source, value.to_le_bytes()).unwrap();
            paths_to_remove.push(pool.publish_stream(&source).unwrap().path);
        }
        let report = db.prune_images().await.unwrap();
        assert_eq!(report.bytes_removed, 257 * 8);
        assert!(paths_to_remove.iter().all(|path| !path.exists()));
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM image_stream_gc")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(pending, 0);
    }
}
