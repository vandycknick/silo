use std::str::FromStr;

use containerregistry_image::{Descriptor, ImageConfig, ImageIndex, Manifest};
use containerregistry_registry::{Client, ManifestOrIndex, Reference};

use crate::{OciDiskError, OciDiskResult, Platform};

pub(crate) struct RegistryClient {
    client: Client,
}

pub(crate) struct ResolvedManifest {
    pub(crate) reference: Reference,
    pub(crate) manifest: Manifest,
    pub(crate) manifest_digest: String,
    pub(crate) config_digest: String,
}

impl RegistryClient {
    pub(crate) fn new() -> OciDiskResult<Self> {
        let client = Client::new().map_err(|source| OciDiskError::registry("registry", source))?;
        Ok(Self { client })
    }

    pub(crate) fn parse_reference(image_ref: &str) -> OciDiskResult<Reference> {
        Reference::from_str(image_ref).map_err(|err| OciDiskError::InvalidReference {
            reference: image_ref.to_string(),
            message: err.to_string(),
        })
    }

    pub(crate) async fn resolve_manifest(
        &self,
        reference: &Reference,
        platform: &Platform,
    ) -> OciDiskResult<ResolvedManifest> {
        let requested_ref = reference.to_string();
        let (manifest_or_index, digest) = self
            .client
            .get_manifest(reference)
            .await
            .map_err(|source| OciDiskError::registry(requested_ref.clone(), source))?;

        let (manifest_reference, manifest, manifest_digest) = match manifest_or_index {
            ManifestOrIndex::Manifest(manifest) => {
                (reference.clone(), *manifest, digest.to_string())
            }
            ManifestOrIndex::Index(index) => {
                let descriptor = select_platform_descriptor(&requested_ref, &index, platform)?;
                let manifest_reference =
                    reference.clone().with_new_digest(descriptor.digest.clone());
                let (selected, selected_digest) = self
                    .client
                    .get_manifest(&manifest_reference)
                    .await
                    .map_err(|source| OciDiskError::registry(requested_ref.clone(), source))?;
                match selected {
                    ManifestOrIndex::Manifest(manifest) => {
                        (manifest_reference, *manifest, selected_digest.to_string())
                    }
                    ManifestOrIndex::Index(_) => {
                        return Err(OciDiskError::ImageConfig {
                            reference: requested_ref,
                            message:
                                "selected platform descriptor resolved to another manifest index"
                                    .to_string(),
                        });
                    }
                }
            }
        };

        let config_digest = manifest.config().digest.to_string();
        let config_bytes = self
            .pull_blob(&manifest_reference, manifest.config(), &requested_ref)
            .await?;
        let config =
            ImageConfig::from_bytes(&config_bytes).map_err(|err| OciDiskError::ImageConfig {
                reference: requested_ref.clone(),
                message: err.to_string(),
            })?;
        validate_config_platform(&requested_ref, platform, &config)?;

        Ok(ResolvedManifest {
            reference: manifest_reference,
            manifest,
            manifest_digest,
            config_digest,
        })
    }

    pub(crate) async fn pull_blob(
        &self,
        reference: &Reference,
        descriptor: &Descriptor,
        requested_ref: &str,
    ) -> OciDiskResult<Vec<u8>> {
        self.client
            .get_blob(reference, &descriptor.digest)
            .await
            .map_err(|source| OciDiskError::registry(requested_ref.to_string(), source))
    }
}

fn select_platform_descriptor(
    reference: &str,
    index: &ImageIndex,
    platform: &Platform,
) -> OciDiskResult<Descriptor> {
    index
        .find_platform(
            &platform.architecture,
            &platform.os,
            platform.variant.as_deref(),
        )
        .cloned()
        .ok_or_else(|| OciDiskError::MissingPlatform {
            reference: reference.to_string(),
            requested: platform.to_string(),
            available: available_platforms(index),
        })
}

fn available_platforms(index: &ImageIndex) -> String {
    let mut platforms = index
        .manifests()
        .iter()
        .filter_map(|descriptor| descriptor.platform.as_ref())
        .map(|platform| {
            let mut value = format!("{}/{}", platform.os, platform.architecture);
            if let Some(variant) = &platform.variant {
                value.push('/');
                value.push_str(variant);
            }
            value
        })
        .collect::<Vec<_>>();
    platforms.sort();
    platforms.dedup();
    if platforms.is_empty() {
        "none declared".to_string()
    } else {
        platforms.join(", ")
    }
}

fn validate_config_platform(
    reference: &str,
    requested: &Platform,
    config: &ImageConfig,
) -> OciDiskResult<()> {
    if requested.matches_config(&config.os, &config.architecture, config.variant.as_deref()) {
        return Ok(());
    }

    let actual = Platform {
        os: config.os.clone(),
        architecture: config.architecture.clone(),
        variant: config.variant.clone(),
    };
    Err(OciDiskError::PlatformMismatch {
        reference: reference.to_string(),
        requested: requested.to_string(),
        actual: actual.to_string(),
    })
}
