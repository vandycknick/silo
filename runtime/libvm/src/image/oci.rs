use std::path::Path;

use ::oci::{MaterializeOptions, OciError, OciMaterializer, RootfsMetadata};

use crate::image::{
    progress::oci_progress_reporter, ImageCacheState, ImageProgressSender, ImageSourceKind,
    MaterializedImage, ResolvedOciImage, ResolvedOciImageMaterialization,
};
use crate::storage::pool::PublishedStream;
use crate::store::models::{
    ImageConfigRecord, ImageLayerRecord, ImageManifestLayerRecord, ImageManifestRecord,
    ImageRefRecord, ImageRootfsArtifactRecord, OciImageRecord,
};
use crate::LibVmError;

pub(crate) const CONVERSION_ABI: &str = "flat-ext4-v2:normalized-phase2:minimum-size=536870912";

pub(crate) fn image_error(reference: &str, source: OciError) -> LibVmError {
    match source {
        OciError::InvalidReference { .. } | OciError::RegistryPolicyDenied { .. } => {
            LibVmError::ImageReferenceRejected {
                reference: reference.into(),
                message: source.to_string(),
            }
        }
        source => LibVmError::Image {
            reference: reference.into(),
            source,
        },
    }
}

pub(crate) fn storage_error(error: crate::storage::StorageError) -> LibVmError {
    LibVmError::Storage(error)
}

pub(crate) fn verify_cached_image(
    image: &OciImageRecord,
    images_dir: &Path,
) -> Result<crate::storage::identity_file::SourceFingerprint, LibVmError> {
    let artifact = &image.artifact;
    let before = crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
        &artifact.rootfs_path,
    )?);
    let expected = images_dir
        .join("streams/sha256")
        .join(artifact.stream_id.hex());
    if artifact.rootfs_path != expected
        || artifact.conversion_abi != CONVERSION_ABI
        || artifact.manifest_digest != image.manifest.digest
        || artifact.config_digest != image.config.digest
        || artifact.filesystem != "ext4"
    {
        return Err(LibVmError::StateDecode { field: "image.cache", message: "image artifact does not match its catalog identity, conversion profile, or owned stream path".into() });
    }
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
    Ok(before)
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
        _lease: Some(lease),
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
