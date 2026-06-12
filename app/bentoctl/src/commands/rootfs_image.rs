use std::collections::BTreeMap;

use bento_libvm::Runtime;
use bento_ocidisk::{ImageStore, RootfsImage, RootfsOptions};
use eyre::Context;

const IMAGE_ID_METADATA_KEY: &str = "bento.image.id";
const IMAGE_PLATFORM_METADATA_KEY: &str = "bento.image.platform";
const IMAGE_SOURCE_METADATA_KEY: &str = "bento.image.source";

pub(crate) async fn get_base_rootfs_image(
    libvm: &Runtime,
    image_ref: &str,
) -> eyre::Result<RootfsImage> {
    let options = RootfsOptions::for_host().wrap_err("failed to select host OCI platform")?;
    let images_dir = libvm
        .local_images_dir()
        .ok_or_else(|| eyre::eyre!("local runtime images directory is unavailable"))?;
    let store = ImageStore::open(images_dir).wrap_err("failed to open Bento image cache")?;
    store
        .get_or_create(image_ref, options)
        .await
        .wrap_err_with(|| format!("failed to get base rootfs image for {image_ref}"))
}

pub(crate) fn record_base_rootfs_metadata(
    metadata: &mut BTreeMap<String, String>,
    image: &RootfsImage,
) {
    metadata.insert(IMAGE_ID_METADATA_KEY.to_string(), image.image_id.clone());
    metadata.insert(
        IMAGE_PLATFORM_METADATA_KEY.to_string(),
        image.platform.to_string(),
    );
    metadata.insert(
        IMAGE_SOURCE_METADATA_KEY.to_string(),
        image.source.to_string(),
    );
}
