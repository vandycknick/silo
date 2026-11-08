use std::fs;
use std::path::Path;

use async_trait::async_trait;
use sqlx::Row;

use crate::image::oci::storage_error;
use crate::image::{
    ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport, ImageRemoveOptions,
    OciImageConfigMetadata,
};
use crate::store::models::{
    CacheCleanupDeferral, CacheRecoveryReport, ImageCompositionArtifactRecord, ImageConfigRecord,
    ImageLayerRecord, ImageManifestLayerRecord, ImageManifestRecord, ImageRefRecord,
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
    async fn pin_source_blobs(
        &self,
        operation_id: uuid::Uuid,
        digests: &[crate::storage::identity::ObjectDigest],
    ) -> Result<(), LibVmError> {
        let store = self.clone();
        let digests = digests.to_vec();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(store.pin_cache_inputs(
                operation_id,
                crate::store::stream_representation::CacheKind::SourceBlob,
                &digests,
            ))
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
            || image.artifact.platform_os != image.manifest.platform_os
            || image.artifact.platform_architecture != image.manifest.platform_architecture
            || image.artifact.platform_variant != image.manifest.platform_variant
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
        // Retire unreferenced selections first so one prune collects the
        // whole graph: artifact ─► composition ─► layers ─► objects ─► packs.
        let artifacts = self.retire_image_artifacts().await?;
        self.retire_layer_cache().await?;
        self.recover_layer_objects().await?;
        let (mut report, _) = self.prune_image_cache(true).await?;
        report.artifacts_removed = report.artifacts_removed.saturating_add(artifacts);
        Ok(report)
    }
}

impl Store {
    /// Delete composition rows of OCI selections no reference names. A lower
    /// still pinned by a live operation keeps its row until released; the
    /// composition graph itself is retired by the layer collector afterwards.
    async fn retire_image_artifacts(&self) -> Result<u64, LibVmError> {
        let store = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let pool = crate::storage::pool::StoragePool::open(&store.images_dir)?;
                store.retire_abandoned_storage_operations(&pool).await?;
                let mut removed = 0_u64;
                loop {
                    let _roots = pool.lock_roots()?;
                    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
                    let ids = sqlx::query_scalar::<_, String>("SELECT image_id FROM image_composition_artifact a WHERE NOT EXISTS(SELECT 1 FROM image_ref r WHERE r.manifest_digest=a.manifest_digest) AND NOT EXISTS(SELECT 1 FROM storage_operation_lower p WHERE p.lower_id=a.lower_id) ORDER BY image_id LIMIT 256")
                        .fetch_all(&mut *tx)
                        .await?;
                    for id in &ids {
                        sqlx::query("DELETE FROM image_composition_artifact WHERE image_id=?1")
                            .bind(id)
                            .execute(&mut *tx)
                            .await?;
                    }
                    tx.commit().await?;
                    removed = removed.saturating_add(ids.len() as u64);
                    if ids.len() < 256 {
                        return Ok::<u64, LibVmError>(removed);
                    }
                }
            })
        })
        .await?
    }

    /// Pin retained layer results (pack stream, records, index and map
    /// objects) to an active staging operation. `false` means a result was
    /// retired before the pin; nothing is pinned then.
    pub(crate) async fn pin_operation_layers(
        &self,
        operation: uuid::Uuid,
        results: &[oci::changeset::LayerResultId],
    ) -> Result<bool, LibVmError> {
        let store = self.clone();
        let results = results.to_vec();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let pool = crate::storage::pool::StoragePool::open(&store.images_dir)?;
                let _roots = pool.lock_roots_shared()?;
                let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
                let active: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state='staging')",
                )
                .bind(operation.to_string())
                .fetch_one(&mut *tx)
                .await?;
                if !active {
                    return Err(LibVmError::InvalidStorageRecord {
                        record: "storage-operation",
                        message: "layer pin has no active registered operation".into(),
                    });
                }
                for result in results {
                    let stream: Option<String> =
                        sqlx::query_scalar("SELECT pack_stream FROM layer_result WHERE id=?1")
                            .bind(result.to_string())
                            .fetch_optional(&mut *tx)
                            .await?;
                    let Some(stream) = stream else {
                        return Ok(false);
                    };
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_layer(operation_id,result_id) VALUES(?1,?2)")
                        .bind(operation.to_string()).bind(result.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_stream(operation_id,stream_id) VALUES(?1,?2)")
                        .bind(operation.to_string()).bind(stream).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM layer_object_dependency WHERE result_id=?2")
                        .bind(operation.to_string()).bind(result.to_string()).execute(&mut *tx).await?;
                }
                tx.commit().await?;
                Ok(true)
            })
        })
        .await?
    }

    /// The digest-pinned OCI selection a machine root was created from.
    pub(crate) async fn oci_machine_provenance(
        &self,
        machine: crate::store::models::MachineId,
    ) -> Result<Option<(String, String)>, LibVmError> {
        let row = sqlx::query(
            "SELECT selected_reference,manifest_digest FROM machine_rootfs WHERE machine_id=?1 AND source_kind='oci'",
        )
        .bind(machine.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let selected: Option<String> = row.try_get("selected_reference")?;
        let manifest: Option<String> = row.try_get("manifest_digest")?;
        Ok(selected.zip(manifest))
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
        crate::store::stream_representation::check_catalog(self).await?;
        if prune_unreferenced {
            report.bytes_removed = report
                .bytes_removed
                .saturating_add(self.evict_flat_materializations().await?);
        }
        report.bytes_removed = report.bytes_removed.saturating_add(
            self.prune_transport_caches(&pool, prune_unreferenced)
                .await?,
        );
        let mut scan = pool.scan_streams()?;
        let mut pending_cursor = String::new();
        loop {
            self.check_operation_recovery(&pool).await?;
            crate::store::snapshot_store::check_snapshot_catalog(self).await?;
            crate::store::managed_image_store::check_image_catalog(self).await?;
            crate::store::stream_representation::check_catalog(self).await?;
            crate::store::cache_paths::check_machine_dependencies(self).await?;
            let discovered = scan.by_ref().take(256).collect::<Result<Vec<_>, _>>()?;
            let scan_finished = discovered.is_empty();
            let _roots = pool.lock_roots()?;
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            for (id, length) in discovered {
                if crate::store::cache_paths::machine_retains_stream(&mut tx, id).await?
                    || crate::store::stream_representation::stream_reachable(&mut tx, id).await?
                {
                    continue;
                }
                sqlx::query("INSERT INTO image_stream_gc(stream_id,size_bytes) VALUES(?1,?2) ON CONFLICT(stream_id) DO NOTHING")
                    .bind(id.to_string()).bind(i64_from_u64(length)?).execute(&mut *tx).await?;
            }
            sqlx::query("DELETE FROM image_manifest WHERE NOT EXISTS(SELECT 1 FROM image_ref r WHERE r.manifest_digest=image_manifest.digest) AND NOT EXISTS(SELECT 1 FROM image_composition_artifact a WHERE a.manifest_digest=image_manifest.digest)").execute(&mut *tx).await?;
            sqlx::query("DELETE FROM image_layer WHERE NOT EXISTS(SELECT 1 FROM image_manifest_layer ml WHERE ml.layer_diff_id=image_layer.diff_id AND ml.layer_blob_digest=image_layer.blob_digest)").execute(&mut *tx).await?;
            if !scan_finished {
                pending_cursor.clear();
            }
            let pending = sqlx::query("SELECT stream_id,size_bytes FROM image_stream_gc g WHERE stream_id>?1 AND NOT EXISTS(SELECT 1 FROM layer_result l WHERE l.pack_stream=g.stream_id) AND NOT EXISTS(SELECT 1 FROM storage_operation_stream p WHERE p.stream_id=g.stream_id) AND NOT EXISTS(SELECT 1 FROM snapshot_stream_dependency s WHERE s.stream_id=g.stream_id) AND NOT EXISTS(SELECT 1 FROM image_stream_dependency i WHERE i.stream_id=g.stream_id) ORDER BY stream_id LIMIT 256").bind(&pending_cursor).fetch_all(&mut *tx).await?;
            let pending_count = pending.len();
            let mut deletions = Vec::new();
            for row in pending {
                let stream: String = row.try_get("stream_id")?;
                pending_cursor.clone_from(&stream);
                let id = stream
                    .parse::<crate::storage::identity::StreamId>()
                    .map_err(|error| storage_error(error.into()))?;
                if crate::store::cache_paths::machine_retains_stream(&mut tx, id).await?
                    || crate::store::stream_representation::stream_reachable(&mut tx, id).await?
                {
                    continue;
                }
                let path = pool.stream_path(&id);
                validate_collectable_stream(&path, &self.images_dir, &stream)?;
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
            // must not resurrect a catalog row naming an already unlinked file.
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
                sqlx::query("DELETE FROM storage_stream WHERE stream_id=?1")
                    .bind(&stream)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM image_stream_gc WHERE stream_id=?1")
                    .bind(stream)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            if scan_finished && pending_count < 256 {
                break;
            }
        }
        Ok((report, recovery))
    }
}

fn validate_collectable_stream(
    path: &Path,
    image_root: &Path,
    stream_id: &str,
) -> Result<bool, LibVmError> {
    let id = stream_id
        .parse::<crate::storage::identity::StreamId>()
        .map_err(|error| storage_error(error.into()))?;
    let expected = image_root.join("streams/sha256").join(id.hex());
    if path != expected {
        return Err(LibVmError::StateDecode {
            field: "image_stream_gc.stream_id",
            message: "refusing to prune a path outside its owned stream slot".into(),
        });
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(LibVmError::StateDecode {
            field: "image_stream_gc.stream_id",
            message: "refusing to prune a non-regular stream".into(),
        });
    }
    Ok(true)
}

const IMAGE_HANDLE_BY_REFERENCE_QUERY: &str =
    "SELECT r.requested_reference, r.selected_reference, r.manifest_digest,
            m.config_digest, m.image_id, m.platform_os,
            m.platform_architecture, m.platform_variant, a.lower_length AS size_bytes,
            r.created_at, r.updated_at, r.last_used_at
     FROM image_ref r
     JOIN image_manifest m ON m.digest = r.manifest_digest
     LEFT JOIN image_composition_artifact a ON a.manifest_digest = r.manifest_digest
      WHERE r.requested_reference = ?1";

const IMAGE_HANDLE_LIST_QUERY: &str =
    "SELECT r.requested_reference, r.selected_reference, r.manifest_digest,
            m.config_digest, m.image_id, m.platform_os,
            m.platform_architecture, m.platform_variant, a.lower_length AS size_bytes,
            r.created_at, r.updated_at, r.last_used_at
     FROM image_ref r
     JOIN image_manifest m ON m.digest = r.manifest_digest
     LEFT JOIN image_composition_artifact a ON a.manifest_digest = r.manifest_digest
      ORDER BY r.requested_reference";

/// Insert or verify the selection's immutable lower, refreshing only use time.
async fn upsert_artifact(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    artifact: &ImageCompositionArtifactRecord,
) -> Result<(), LibVmError> {
    sqlx::query(
        "INSERT INTO image_composition_artifact
            (image_id, manifest_digest, config_digest, platform_os, platform_architecture,
             platform_variant, lower_id, lower_length, created_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(image_id) DO UPDATE SET
            last_used_at = excluded.last_used_at",
    )
    .bind(&artifact.image_id)
    .bind(&artifact.manifest_digest)
    .bind(&artifact.config_digest)
    .bind(&artifact.platform_os)
    .bind(&artifact.platform_architecture)
    .bind(&artifact.platform_variant)
    .bind(artifact.lower.to_string())
    .bind(i64_from_u64(artifact.lower_length)?)
    .bind(artifact.created_at)
    .bind(artifact.last_used_at)
    .execute(&mut **tx)
    .await?;
    let stored = sqlx::query(
        "SELECT manifest_digest, config_digest, platform_os, platform_architecture,
                platform_variant, lower_id, lower_length
         FROM image_composition_artifact WHERE image_id = ?1",
    )
    .bind(&artifact.image_id)
    .fetch_one(&mut **tx)
    .await?;
    if stored.try_get::<&str, _>("manifest_digest")? != artifact.manifest_digest
        || stored.try_get::<&str, _>("config_digest")? != artifact.config_digest
        || stored.try_get::<&str, _>("platform_os")? != artifact.platform_os
        || stored.try_get::<&str, _>("platform_architecture")? != artifact.platform_architecture
        || stored.try_get::<Option<&str>, _>("platform_variant")?
            != artifact.platform_variant.as_deref()
        || stored.try_get::<String, _>("lower_id")? != artifact.lower.to_string()
        || stored.try_get::<i64, _>("lower_length")? != i64_from_u64(artifact.lower_length)?
    {
        return Err(immutable_image_error("image_composition_artifact"));
    }
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
        "SELECT CASE WHEN ?5 IS NULL THEN r.requested_reference ELSE ?1 END AS requested_reference,
                CASE WHEN ?5 IS NULL THEN r.selected_reference ELSE ?1 END AS selected_reference,
                COALESCE(r.created_at, m.created_at) AS ref_created_at,
                COALESCE(r.updated_at, m.created_at) AS updated_at, r.last_used_at AS ref_last_used_at,
                m.*, a.lower_id, a.lower_length,
                a.created_at AS artifact_created_at, a.last_used_at AS artifact_last_used_at
         FROM image_manifest m JOIN image_composition_artifact a ON a.manifest_digest = m.digest
         LEFT JOIN image_ref r ON r.manifest_digest = m.digest
         WHERE (r.requested_reference = ?1 OR r.selected_reference = ?1 OR m.digest = ?5)
           AND m.platform_os = ?2 AND m.platform_architecture = ?3
           AND m.platform_variant IS ?4
         ORDER BY r.requested_reference LIMIT 1",
    ).bind(reference).bind(&platform.os).bind(&platform.architecture).bind(&platform.variant)
        .bind(selected_digest).fetch_optional(pool).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let digest: String = row.try_get("digest")?;
    let config_digest: String = row.try_get("config_digest")?;
    let image_id: String = row.try_get("image_id")?;
    let created_at: i64 = row.try_get("created_at")?;
    let lower_length = u64_from_i64(row.try_get("lower_length")?)?;
    let lower = row
        .try_get::<String, _>("lower_id")?
        .parse::<crate::storage::identity::LowerResultId>()
        .map_err(|error| LibVmError::StateDecode {
            field: "image_composition_artifact.lower_id",
            message: error.to_string(),
        })?;
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
            size_bytes: Some(lower_length),
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
        artifact: ImageCompositionArtifactRecord {
            image_id,
            manifest_digest: digest,
            config_digest,
            platform_os: platform.os.clone(),
            platform_architecture: platform.architecture.clone(),
            platform_variant: platform.variant.clone(),
            lower,
            lower_length,
            created_at: row.try_get("artifact_created_at")?,
            last_used_at: row.try_get("artifact_last_used_at")?,
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::image::oci::tests::LAYERS;
    use crate::image::OciImageConfigMetadata;
    use crate::paths::LocalPaths;
    use crate::storage::pool::StoragePool;
    use crate::store::composition_store::{HeldComposition, RetainedComposition};
    use crate::store::models::{
        ImageCompositionArtifactRecord, ImageConfigRecord, ImageManifestRecord, ImageRefRecord,
        OciImageRecord,
    };
    use crate::store::{ImageStore, Store};

    /// A real retained composition with no image rows; its lease roots it.
    async fn lower(db: &Store, names: &[&str]) -> HeldComposition {
        crate::image::oci::tests::retained_lower(db, names).await
    }

    async fn count(db: &Store, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(&db.pool).await.unwrap()
    }

    fn oci_image_record(lower: &RetainedComposition) -> OciImageRecord {
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
                size_bytes: Some(lower.result.lower_length),
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
            artifact: ImageCompositionArtifactRecord {
                image_id: "sha256:image-id".to_string(),
                manifest_digest: "sha256:manifest".to_string(),
                config_digest: "sha256:config".to_string(),
                platform_os: "linux".to_string(),
                platform_architecture: "amd64".to_string(),
                platform_variant: None,
                lower: lower.id,
                lower_length: lower.result.lower_length,
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
        let held = lower(&db, &LAYERS[..1]).await;
        db.save_oci_image(&oci_image_record(held.retained()))
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
        assert_eq!(
            detail.handle.size_bytes,
            Some(held.retained().result.lower_length)
        );
        assert_eq!(detail.config.entrypoint, Some(Vec::new()));
        assert_eq!(detail.config.cmd, None);
        assert_eq!(detail.config.env, Some(vec!["A=B".to_string()]));
        assert_eq!(detail.config.working_dir.as_deref(), Some(""));
        assert_eq!(detail.config.labels, Some(Default::default()));
        assert_eq!(detail.config.stop_signal.as_deref(), Some("SIGQUIT"));
    }

    #[tokio::test]
    async fn unreferenced_selection_is_retired_only_after_its_lower_pin_closes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let image = oci_image_record(held.retained());
        db.save_oci_image(&image).await.unwrap();
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 0);
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM image_composition_artifact").await,
            1
        );
        drop(held);
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 1);
        for table in [
            "SELECT COUNT(*) FROM image_composition_artifact",
            "SELECT COUNT(*) FROM image_manifest",
            "SELECT COUNT(*) FROM composition_result",
            "SELECT COUNT(*) FROM layer_result",
        ] {
            assert_eq!(count(&db, table).await, 0, "{table}");
        }
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 0);
    }

    #[tokio::test]
    async fn active_publication_lease_blocks_prune_until_released() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        let operation = uuid::Uuid::new_v4();
        let lease = db.begin_storage_operation(operation).await.unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&source).unwrap();
        db.pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let recovery = db.recover_image_cache().await.unwrap();
        assert!(matches!(
            recovery.deferred.as_slice(),
            [crate::store::models::CacheCleanupDeferral::ActiveLease { operation_id }] if *operation_id == operation
        ));
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 0);
        assert_eq!(fs::read(&stream.path).unwrap(), b"rootfs");
        drop(lease);
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 6);
        assert!(!stream.path.exists());
        assert_eq!(db.prune_images().await.unwrap().bytes_removed, 0);
    }

    #[tokio::test]
    async fn duplicate_layer_occurrences_round_trip_in_manifest_order() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let mut image = oci_image_record(held.retained());
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
        let held = lower(&db, &LAYERS[..1]).await;
        sqlx::query("CREATE TRIGGER reject_artifact BEFORE INSERT ON image_composition_artifact BEGIN SELECT RAISE(ABORT, 'reject artifact'); END")
            .execute(&db.pool).await.unwrap();
        let image = oci_image_record(held.retained());
        assert!(db.save_oci_image(&image).await.is_err());
        assert!(db.list_image_handles().await.unwrap().is_empty());
        assert_eq!(count(&db, "SELECT COUNT(*) FROM image_manifest").await, 0);
    }

    #[tokio::test]
    async fn cache_lookup_is_platform_exact_and_the_selection_lower_is_immutable() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let image = oci_image_record(held.retained());
        db.save_oci_image(&image).await.unwrap();
        let reference = &image.reference.requested_reference;
        let cached = db
            .cached_oci_image(reference, &oci::Platform::linux_amd64())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached.artifact, image.artifact);
        assert!(db
            .cached_oci_image(reference, &oci::Platform::linux_arm64())
            .await
            .unwrap()
            .is_none());
        let mut variant = oci::Platform::linux_amd64();
        variant.variant = Some("v3".into());
        assert!(db
            .cached_oci_image(reference, &variant)
            .await
            .unwrap()
            .is_none());

        // Re-saving one selection with another composition never re-points it.
        let other = lower(&db, &LAYERS[1..2]).await;
        assert_ne!(other.retained().id, held.retained().id);
        let mut repointed = oci_image_record(other.retained());
        repointed.reference.requested_reference = "example.test/repointed:latest".into();
        assert!(matches!(
            db.save_oci_image(&repointed).await,
            Err(crate::LibVmError::StateDecode { .. })
        ));
        assert!(db
            .image_handle("example.test/repointed:latest")
            .await
            .unwrap()
            .is_none());
        let unchanged = db
            .cached_oci_image(reference, &oci::Platform::linux_amd64())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.artifact.lower, held.retained().id);
    }

    #[tokio::test]
    async fn prune_transaction_abort_preserves_retained_graph_and_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let retained = held.retained().clone();
        let image = oci_image_record(&retained);
        db.save_oci_image(&image).await.unwrap();
        drop(held);
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        let fsmeta = pool.object_path(&retained.fsmeta());
        sqlx::query("CREATE TRIGGER reject_prune BEFORE DELETE ON image_composition_artifact BEGIN SELECT RAISE(ABORT, 'reject prune'); END")
            .execute(&db.pool).await.unwrap();
        assert!(db.prune_images().await.is_err());
        assert!(fsmeta.is_file());
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM image_composition_artifact").await,
            1
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM composition_result").await,
            1
        );
        sqlx::query("DROP TRIGGER reject_prune")
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(db.prune_images().await.unwrap().artifacts_removed, 1);
        assert!(!fsmeta.exists());
    }

    #[tokio::test]
    async fn pending_stream_collection_is_retry_safe() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let source = paths.home().join("source.raw");
        fs::write(&source, b"rootfs").unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
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
        assert_eq!(count(&db, "SELECT COUNT(*) FROM image_stream_gc").await, 0);
    }

    #[tokio::test]
    async fn digest_bound_facts_are_insert_or_verify_and_failed_aliases_roll_back() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let mut image = oci_image_record(held.retained());
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
    async fn reopening_recovers_orphans_without_pruning_a_catalogued_composition() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let retained = held.retained().clone();
        let image = oci_image_record(&retained);
        db.save_oci_image(&image).await.unwrap();
        drop(held);
        db.remove_image(
            &image.reference.requested_reference,
            crate::ImageRemoveOptions::default(),
        )
        .await
        .unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        let source = paths.home().join("orphan.raw");
        fs::write(&source, b"interrupted-publication").unwrap();
        let orphan = pool.publish_stream(&source).unwrap();
        let fsmeta = pool.object_path(&retained.fsmeta());
        let pack = pool.stream_path(&crate::storage::identity::StreamId::from_sha256(
            *retained.result.packs[0].stream.as_bytes(),
        ));
        db.close().await;
        let reopened = Store::new(&paths).await.unwrap();
        assert!(!orphan.path.exists());
        assert!(fsmeta.is_file() && pack.is_file());
        assert_eq!(
            count(&reopened, "SELECT COUNT(*) FROM image_composition_artifact").await,
            1
        );
        assert_eq!(reopened.prune_images().await.unwrap().artifacts_removed, 1);
        assert!(!fsmeta.exists() && !pack.exists());
    }

    #[tokio::test]
    async fn writable_startup_initializes_snapshot_coordination_without_private_state() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let held = lower(&db, &LAYERS[..1]).await;
        let retained = held.retained().clone();
        let image = oci_image_record(&retained);
        db.save_oci_image(&image).await.unwrap();
        drop(held);
        // Retire closed consumer operations before omitting transient files;
        // a catalog retaining a lease owner must retain that owner's inode.
        db.recover_image_cache().await.unwrap();
        db.close().await;

        // A fresh current-schema catalog/immutable-pool snapshot omits these
        // transient directories. Remove them only after closing the fixture;
        // this is not normal lock-file cleanup or a legacy-state migration.
        fs::remove_dir_all(paths.images_dir().join("tmp")).unwrap();
        fs::remove_dir_all(paths.images_dir().join("locks")).unwrap();
        assert!(StoragePool::open_existing(paths.images_dir()).is_err());
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
        assert!(!paths.home().join("machines").exists());
        let cached = reopened
            .cached_oci_image(
                &image.reference.requested_reference,
                &oci::Platform::linux_amd64(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached.artifact.lower, retained.id);
        let held = crate::store::layer_store::LayerStore::from_store(reopened.clone())
            .hold_composition(cached.artifact.lower)
            .await
            .unwrap();
        assert_eq!(held.retained(), &retained);
    }

    #[tokio::test]
    async fn overlapping_published_stream_pins_survive_until_each_operations_last_ofd_closes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let db = Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let op_a = uuid::Uuid::new_v4();
        let lease_a = db.begin_storage_operation(op_a).await.unwrap();
        let child_a = lease_a.duplicate_inheritable().unwrap();
        let op_b = uuid::Uuid::new_v4();
        let lease_b = db.begin_storage_operation(op_b).await.unwrap();
        let source = temp.path().join("source");
        fs::write(&source, [1; 512]).unwrap();
        let (first, first_roots) = pool.publish_stream_for_catalog(&source).unwrap();
        fs::write(&source, [2; 512]).unwrap();
        let (second, second_roots) = pool.publish_stream_for_catalog(&source).unwrap();
        db.pin_published_storage_dependencies(op_a, &[first.id, second.id], &[])
            .await
            .unwrap();
        db.pin_published_storage_dependencies(op_b, &[second.id], &[])
            .await
            .unwrap();
        drop(first_roots);
        drop(second_roots);
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
