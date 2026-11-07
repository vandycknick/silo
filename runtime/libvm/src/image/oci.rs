use std::path::Path;

use ::oci::{MaterializeOptions, OciError, OciMaterializer, RootfsMetadata};

use crate::image::{
    progress::oci_progress_reporter, ImageCacheState, ImageProgress, ImageProgressSender,
    ImageSourceKind, MaterializedImage, ResolvedOciImage, ResolvedOciImageMaterialization,
};
use crate::storage::pool::{PublishedStream, StoragePool};
use crate::store::models::{
    ImageConfigRecord, ImageLayerRecord, ImageManifestLayerRecord, ImageManifestRecord,
    ImageRefRecord, ImageRootfsArtifactRecord, OciImageRecord,
};
use crate::store::ImageStore;
use crate::LibVmError;

/// The one flattener ABI. It is part of both the OCI rootfs cache identity and
/// the explicit raw-conversion key, so changing the flattener invalidates both.
pub(crate) const CONVERSION_ABI: &str = "flat-ext4-v2:normalized-phase2:minimum-size=536870912";

pub(crate) fn image_error(reference: &str, source: OciError) -> LibVmError {
    match source {
        OciError::InvalidReference { .. }
        | OciError::RegistryPolicyDenied { .. }
        | OciError::VmArtifactRequiresAcquisition { .. } => LibVmError::ImageReferenceRejected {
            reference: reference.into(),
            message: source.to_string(),
        },
        source => LibVmError::Image {
            reference: reference.into(),
            source,
        },
    }
}

pub(crate) fn storage_error(error: crate::storage::StorageError) -> LibVmError {
    LibVmError::Storage(error)
}

/// Returns the map of the exact pool bytes hashed here, so callers never hash
/// the retained stream a second time to describe it.
pub(crate) fn verify_cached_image(
    image: &mut OciImageRecord,
    images_dir: &Path,
) -> Result<crate::storage::stream::StreamMap, LibVmError> {
    let artifact = &mut image.artifact;
    let slot = Path::new("images/streams/sha256").join(artifact.stream_id.hex());
    if !artifact.rootfs_path.is_absolute()
        || !artifact.rootfs_path.ends_with(&slot)
        || artifact.conversion_abi != CONVERSION_ABI
        || artifact.manifest_digest != image.manifest.digest
        || artifact.config_digest != image.config.digest
        || artifact.filesystem != "ext4"
    {
        return Err(LibVmError::StateDecode { field: "image.cache", message: "image artifact does not match its catalog identity, conversion profile, or owned stream path".into() });
    }
    // The stored absolute spelling is provenance, not pool location authority.
    // Resolve the verified stream identity under the current Home after relocation.
    artifact.rootfs_path = images_dir
        .join("streams/sha256")
        .join(artifact.stream_id.hex());
    let before = crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
        &artifact.rootfs_path,
    )?);
    let pool = crate::storage::pool::StoragePool::open_existing(images_dir)
        .map_err(storage_error)?
        .ok_or_else(|| LibVmError::StateDecode {
            field: "image.cache",
            message: "immutable pool is absent".into(),
        })?;
    let map = pool
        .verify_stream(&artifact.stream_id)
        .map_err(storage_error)?;
    if map.id() != artifact.stream_id
        || map.length() != artifact.size_bytes
        || before
            != crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                &artifact.rootfs_path,
            )?)
    {
        return Err(LibVmError::StateDecode {
            field: "image.cache",
            message: format!(
                "retained stream {} failed content verification",
                artifact.stream_id
            ),
        });
    }
    Ok(map)
}

pub(crate) fn cached_resolved_oci_image(
    image: &OciImageRecord,
    reference: String,
) -> ResolvedOciImage {
    ResolvedOciImage {
        requested_reference: reference,
        selected_reference: image.reference.selected_reference.clone(),
        manifest_digest: image.manifest.digest.clone(),
        config_digest: image.config.digest.clone(),
        config: image.config.metadata.clone(),
        platform: ::oci::Platform {
            os: image.manifest.platform_os.clone(),
            architecture: image.manifest.platform_architecture.clone(),
            variant: image.manifest.platform_variant.clone(),
        },
        cache_state: ImageCacheState::Complete,
        materialization: ResolvedOciImageMaterialization::Cached,
    }
}

pub(crate) async fn resolve_oci_image_from_registry(
    producer: &OciMaterializer,
    reference: String,
    options: MaterializeOptions,
    progress: Option<ImageProgressSender>,
) -> Result<ResolvedOciImage, LibVmError> {
    let image = producer
        .resolve(
            &reference,
            &options.platform,
            oci_progress_reporter(progress),
        )
        .await
        .map_err(|error| image_error(&reference, error))?;
    Ok(ResolvedOciImage {
        requested_reference: image.requested_reference.clone(),
        selected_reference: image.selected_reference.clone(),
        manifest_digest: image.manifest_digest.clone(),
        config_digest: image.config_digest.clone(),
        config: image.config.clone(),
        platform: image.platform.clone(),
        cache_state: ImageCacheState::Missing,
        materialization: ResolvedOciImageMaterialization::Registry(Box::new(image)),
    })
}

pub(crate) fn ensure_resolved_oci_identity(
    resolved: &ResolvedOciImage,
    image: &OciImageRecord,
) -> Result<(), LibVmError> {
    if image.reference.selected_reference == resolved.selected_reference
        && image.manifest.digest == resolved.manifest_digest
        && image.config.digest == resolved.config_digest
        && image.config.metadata == resolved.config
        && image.manifest.platform_os == resolved.platform.os
        && image.manifest.platform_architecture == resolved.platform.architecture
        && image.manifest.platform_variant == resolved.platform.variant
    {
        return Ok(());
    }
    Err(LibVmError::StateDecode {
        field: "resolved_oci_image",
        message: "materialized image does not match the resolved OCI identity".into(),
    })
}

pub(crate) fn materialized_image(
    image: OciImageRecord,
    requested_reference: &str,
    lease: crate::storage::locks::StorageLock,
) -> MaterializedImage {
    MaterializedImage {
        stream: Some(image.artifact.stream_id),
        rootfs_path: image.artifact.rootfs_path,
        requested_reference: requested_reference.into(),
        selected_reference: Some(image.reference.selected_reference),
        source_kind: ImageSourceKind::Oci,
        image_id: Some(image.manifest.image_id),
        manifest_digest: Some(image.manifest.digest),
        config_digest: Some(image.config.digest),
        size_bytes: image.artifact.size_bytes,
        platform: ::oci::Platform {
            os: image.manifest.platform_os,
            architecture: image.manifest.platform_architecture,
            variant: image.manifest.platform_variant,
        },
        managed: None,
        authenticated: None,
        _lease: Some(lease),
    }
}

/// Byte key serializing flattening of one selected OCI identity into the
/// rootfs cache. It is not the raw-conversion key, which names an image.
fn rootfs_cache_key(
    resolved: &ResolvedOciImage,
) -> Result<crate::storage::identity::ObjectDigest, LibVmError> {
    let bytes = serde_json::to_vec(&(
        CONVERSION_ABI,
        &resolved.manifest_digest,
        &resolved.config_digest,
        &resolved.platform,
    ))
    .map_err(|error| LibVmError::StateDecode {
        field: "image.conversion-key",
        message: error.to_string(),
    })?;
    Ok(crate::storage::identity::ObjectDigest::of_bytes(&bytes))
}

/// A retained, verified flattened rootfs and the map of its exact pool bytes.
pub(crate) struct AcquiredRootfs {
    pub(crate) record: OciImageRecord,
    pub(crate) map: crate::storage::stream::StreamMap,
}

/// Acquire the one flattened rootfs stream for an already selected OCI
/// identity, for any platform the caller resolved. The caller owns the
/// registered `convert` operation and its lease; on return the stream is
/// verified and retained by that operation until the lease is dropped.
///
/// Callers must run this inside a task that owns the lease (and any staging)
/// until this future completes, never in a caller-cancellable future: its
/// blocking verifier, flattener and publisher keep running after a drop, and
/// a closed lease would let recovery retire the operation beneath them.
///
/// ```text
/// lock(manifest, config, platform, ABI)
///   ├─ cached row ─► retain into operation ─► rehash pool bytes ─► record
///   └─ miss ───────► existing flattener ─► publish stream ─► retain ─► record
/// ```
pub(crate) async fn acquire_rootfs<S: ImageStore + ?Sized>(
    store: &S,
    images_dir: &Path,
    producer: &OciMaterializer,
    progress: Option<&ImageProgressSender>,
    resolved: &ResolvedOciImage,
    operation_id: uuid::Uuid,
) -> Result<AcquiredRootfs, LibVmError> {
    let key = rootfs_cache_key(resolved)?;
    let pool = StoragePool::open(images_dir).map_err(storage_error)?;
    let (pool, _flattening) = tokio::task::spawn_blocking(move || {
        let lock = pool.lock_publication(&key)?;
        Ok::<_, crate::storage::StorageError>((pool, lock))
    })
    .await?
    .map_err(storage_error)?;
    if let Some(mut image) = store
        .cached_oci_image(&resolved.selected_reference, &resolved.platform)
        .await?
    {
        store
            .retain_storage_stream(&image.artifact.stream_id, operation_id)
            .await?;
        let images_dir = images_dir.to_path_buf();
        let (mut image, map) = tokio::task::spawn_blocking(move || {
            let map = verify_cached_image(&mut image, &images_dir)?;
            Ok::<_, LibVmError>((image, map))
        })
        .await??;
        ensure_resolved_oci_identity(resolved, &image)?;
        emit_cached_image_progress(progress, &resolved.requested_reference);
        image.reference.requested_reference = resolved.requested_reference.clone();
        image.reference.last_used_at = Some(crate::utils::now_unix());
        store.save_oci_image(&image).await?;
        emit_image_progress_complete(progress);
        return Ok(AcquiredRootfs { record: image, map });
    }
    if let Some(progress) = progress {
        progress.send(ImageProgress::CheckingCache {
            image_ref: resolved.requested_reference.clone(),
        });
        progress.send(ImageProgress::CacheMiss {
            image_ref: resolved.requested_reference.clone(),
        });
    }
    let ResolvedOciImageMaterialization::Registry(image) = &resolved.materialization else {
        return Err(LibVmError::ImageNotFound {
            reference: resolved.selected_reference.clone(),
        });
    };
    let source_blobs = image
        .layer_digests()
        .map(str::parse)
        .collect::<Result<Vec<crate::ObjectDigest>, _>>()
        .map_err(|error| LibVmError::StateDecode {
            field: "image.source-blob",
            message: error.to_string(),
        })?;
    store.pin_source_blobs(operation_id, &source_blobs).await?;
    let options = MaterializeOptions::new(resolved.platform.clone());
    let staging_operation = ::oci::StagingOperation::try_from(operation_id.to_string())
        .map_err(|error| image_error(&resolved.requested_reference, error))?;
    let staged = producer
        .materialize(
            image,
            &options,
            &staging_operation,
            oci_progress_reporter(progress.cloned()),
        )
        .await
        .map_err(|error| image_error(&resolved.requested_reference, error))?;
    if let Some(progress) = progress {
        progress.send(ImageProgress::PublishingRootfs);
    }
    let (published, roots, staged) = tokio::task::spawn_blocking(move || {
        let (published, roots) = pool.publish_stream_for_catalog(&staged.path)?;
        Ok::<_, crate::storage::StorageError>((published, roots, staged))
    })
    .await?
    .map_err(storage_error)?;
    let record = oci_image_record(&published, &staged.metadata, &resolved.requested_reference)?;
    ensure_resolved_oci_identity(resolved, &record)?;
    store
        .retain_storage_stream(&record.artifact.stream_id, operation_id)
        .await?;
    // The publication roots guard covers the stream until its catalog retention.
    drop(roots);
    store.save_oci_image(&record).await?;
    emit_image_progress_complete(progress);
    Ok(AcquiredRootfs {
        record,
        map: published.map,
    })
}

pub(crate) fn emit_cached_image_progress(progress: Option<&ImageProgressSender>, image_ref: &str) {
    let Some(progress) = progress else {
        return;
    };
    progress.send(ImageProgress::CheckingCache {
        image_ref: image_ref.to_string(),
    });
    progress.send(ImageProgress::CacheHit {
        image_ref: image_ref.to_string(),
    });
}

pub(crate) fn emit_image_progress_complete(progress: Option<&ImageProgressSender>) {
    if let Some(progress) = progress {
        progress.send(ImageProgress::Complete);
    }
}

pub(crate) fn oci_image_record(
    stream: &PublishedStream,
    metadata: &RootfsMetadata,
    requested_reference: &str,
) -> Result<OciImageRecord, LibVmError> {
    let now = crate::utils::now_unix();
    let created_at = metadata.created_at_unix;
    let compressed_size = metadata
        .layers
        .iter()
        .try_fold(0_u64, |total, layer| total.checked_add(layer.size_bytes))
        .ok_or_else(|| LibVmError::StateDecode {
            field: "image.size",
            message: "compressed layer size sum overflows".into(),
        })?;
    let size = i64::try_from(compressed_size).map_err(|error| LibVmError::StateDecode {
        field: "image.size",
        message: error.to_string(),
    })?;
    let layers = metadata
        .layers
        .iter()
        .map(|layer| ImageLayerRecord {
            diff_id: layer.diff_id.clone(),
            blob_digest: layer.blob_digest.clone(),
            compressed_size_bytes: Some(layer.size_bytes),
            uncompressed_size_bytes: None,
            created_at,
            last_used_at: Some(now),
        })
        .collect();
    let manifest_layers = metadata
        .layers
        .iter()
        .enumerate()
        .map(|(position, layer)| {
            Ok(ImageManifestLayerRecord {
                manifest_digest: metadata.manifest_digest.clone(),
                layer_diff_id: layer.diff_id.clone(),
                layer_blob_digest: layer.blob_digest.clone(),
                media_type: layer.media_type.clone(),
                position: i64::try_from(position).map_err(|error| LibVmError::StateDecode {
                    field: "image.layer.position",
                    message: error.to_string(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;
    Ok(OciImageRecord {
        manifest: ImageManifestRecord {
            digest: metadata.manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            image_id: metadata.manifest_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            config_digest: Some(metadata.config_digest.clone()),
            layer_count: i64::try_from(metadata.layers.len()).map_err(|error| {
                LibVmError::StateDecode {
                    field: "image.layers",
                    message: error.to_string(),
                }
            })?,
            total_size_bytes: size,
            created_at,
            last_used_at: Some(now),
        },
        reference: ImageRefRecord {
            requested_reference: requested_reference.into(),
            selected_reference: metadata.selected_reference.clone(),
            manifest_digest: metadata.manifest_digest.clone(),
            image_id: metadata.manifest_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            size_bytes: Some(stream.length),
            created_at,
            updated_at: now,
            last_used_at: Some(now),
        },
        config: ImageConfigRecord {
            manifest_digest: metadata.manifest_digest.clone(),
            digest: metadata.config_digest.clone(),
            metadata: metadata.config.clone(),
            created_at,
        },
        layers,
        manifest_layers,
        artifact: ImageRootfsArtifactRecord {
            image_id: metadata.manifest_digest.clone(),
            manifest_digest: metadata.manifest_digest.clone(),
            config_digest: metadata.config_digest.clone(),
            platform_os: metadata.platform.os.clone(),
            platform_architecture: metadata.platform.architecture.clone(),
            platform_variant: metadata.platform.variant.clone(),
            filesystem: "ext4".into(),
            rootfs_path: stream.path.clone(),
            stream_id: stream.id,
            conversion_abi: CONVERSION_ABI.into(),
            size_bytes: stream.length,
            created_at,
            last_used_at: Some(now),
        },
    })
}
