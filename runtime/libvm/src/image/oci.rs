use ::oci::{
    ImageStore as RootfsImageStore, MaterializeOptions, OciError, PublishedRootfs, RootfsMetadata,
};

use crate::image::{
    progress::oci_progress_reporter, ImageCacheState, ImageProgressSender, ResolvedOciImage,
    ResolvedOciImageMaterialization,
};
use crate::LibVmError;

pub(crate) fn image_error(reference: &str, source: OciError) -> LibVmError {
    LibVmError::Image {
        reference: reference.to_string(),
        source,
    }
}

pub(crate) fn cached_resolved_oci_image(
    store: &RootfsImageStore,
    reference: &str,
    options: MaterializeOptions,
) -> Result<Option<ResolvedOciImage>, LibVmError> {
    let Some(rootfs) = store
        .get_cached(reference, &options)
        .map_err(|error| image_error(reference, error))?
    else {
        return Ok(None);
    };
    let metadata = store
        .metadata(&rootfs)
        .map_err(|error| image_error(&rootfs.flat_ext4().requested_reference, error))?;

    resolved_cached_oci_image(rootfs, metadata).map(Some)
}

pub(crate) async fn resolve_oci_image_from_registry(
    store: &RootfsImageStore,
    reference: String,
    options: MaterializeOptions,
    progress: Option<ImageProgressSender>,
) -> Result<ResolvedOciImage, LibVmError> {
    let image = store
        .resolve(
            &reference,
            &options.platform,
            oci_progress_reporter(progress),
        )
        .await
        .map_err(|error| image_error(&reference, error))?;
    let cache_state = cache_state(store, &image.selected_reference, &options)?;

    Ok(resolved_registry_oci_image(image, cache_state))
}

pub(crate) fn ensure_resolved_oci_identity(
    resolved: &ResolvedOciImage,
    rootfs: &PublishedRootfs,
    metadata: &RootfsMetadata,
) -> Result<(), LibVmError> {
    if rootfs.flat_ext4().image_id == resolved.manifest_digest
        && metadata.selected_reference == resolved.selected_reference
        && metadata.manifest_digest == resolved.manifest_digest
        && metadata.config_digest == resolved.config_digest
        && metadata.config == resolved.config
        && metadata.platform == resolved.platform
    {
        return Ok(());
    }

    Err(LibVmError::StateDecode {
        field: "resolved_oci_image",
        message: format!(
            "materialized OCI image {} does not match resolved manifest {}",
            metadata.manifest_digest, resolved.manifest_digest
        ),
    })
}

fn resolved_cached_oci_image(
    rootfs: PublishedRootfs,
    metadata: RootfsMetadata,
) -> Result<ResolvedOciImage, LibVmError> {
    ensure_cached_oci_identity(&rootfs, &metadata)?;

    Ok(ResolvedOciImage {
        requested_reference: rootfs.flat_ext4().requested_reference.clone(),
        selected_reference: metadata.selected_reference.clone(),
        manifest_digest: metadata.manifest_digest.clone(),
        config_digest: metadata.config_digest.clone(),
        config: metadata.config.clone(),
        platform: metadata.platform.clone(),
        cache_state: ImageCacheState::Complete,
        materialization: ResolvedOciImageMaterialization::Cached,
    })
}

fn resolved_registry_oci_image(
    image: ::oci::ResolvedImage,
    cache_state: ImageCacheState,
) -> ResolvedOciImage {
    ResolvedOciImage {
        requested_reference: image.requested_reference.clone(),
        selected_reference: image.selected_reference.clone(),
        manifest_digest: image.manifest_digest.clone(),
        config_digest: image.config_digest.clone(),
        config: image.config.clone(),
        platform: image.platform.clone(),
        cache_state,
        materialization: ResolvedOciImageMaterialization::Registry(Box::new(image)),
    }
}

fn cache_state(
    store: &RootfsImageStore,
    reference: &str,
    options: &MaterializeOptions,
) -> Result<ImageCacheState, LibVmError> {
    match store
        .get_cached(reference, options)
        .map_err(|error| image_error(reference, error))?
    {
        Some(_) => Ok(ImageCacheState::Complete),
        None => Ok(ImageCacheState::Missing),
    }
}

fn ensure_cached_oci_identity(
    rootfs: &PublishedRootfs,
    metadata: &RootfsMetadata,
) -> Result<(), LibVmError> {
    if rootfs.flat_ext4().image_id == metadata.manifest_digest {
        return Ok(());
    }

    Err(LibVmError::StateDecode {
        field: "image.metadata.manifest_digest",
        message: format!(
            "cached rootfs image ID {} does not match manifest {}",
            rootfs.flat_ext4().image_id,
            metadata.manifest_digest
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::image::oci::resolved_cached_oci_image;
    use crate::{ImageCacheState, OciImageConfigMetadata, Platform};
    use ::oci::{FlatExt4Artifact, PublishedRootfs, RootfsMetadata};

    fn rootfs(image_id: &str) -> PublishedRootfs {
        PublishedRootfs::FlatExt4(FlatExt4Artifact {
            path: PathBuf::from("/tmp/rootfs.img"),
            requested_reference: "example.test/demo:latest".to_string(),
            image_id: image_id.to_string(),
            manifest_digest: image_id.to_string(),
            platform: Platform::linux_arm64(),
        })
    }

    fn metadata(manifest_digest: &str) -> RootfsMetadata {
        RootfsMetadata {
            version: 2,
            image_ref: "example.test/demo:latest".to_string(),
            image_id: manifest_digest.to_string(),
            requested_reference: "example.test/demo:latest".to_string(),
            selected_reference: format!("example.test/demo@{manifest_digest}"),
            manifest_digest: manifest_digest.to_string(),
            config_digest: "sha256:config".to_string(),
            config: OciImageConfigMetadata::default(),
            layers: Vec::new(),
            platform: Platform::linux_arm64(),
            filesystem: "ext4".to_string(),
            rootfs_file: "rootfs.img".to_string(),
            created_at_unix: 1,
        }
    }

    #[test]
    fn cached_conversion_rejects_mismatched_manifest_identity() {
        let error = resolved_cached_oci_image(rootfs("sha256:rootfs"), metadata("sha256:manifest"))
            .expect_err("cache metadata must match the published rootfs identity");

        assert!(matches!(
            error,
            crate::LibVmError::StateDecode {
                field: "image.metadata.manifest_digest",
                ..
            }
        ));
    }

    #[test]
    fn cached_conversion_returns_complete_public_resolution() {
        let image =
            resolved_cached_oci_image(rootfs("sha256:manifest"), metadata("sha256:manifest"))
                .expect("matching cache metadata should resolve");

        assert_eq!(image.cache_state, ImageCacheState::Complete);
        assert_eq!(image.manifest_digest, "sha256:manifest");
        assert_eq!(
            image.selected_reference,
            "example.test/demo@sha256:manifest"
        );
    }
}
