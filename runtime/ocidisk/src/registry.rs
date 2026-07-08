use std::str::FromStr;

use futures_util::TryStreamExt;
use oci_client::client::{BlobResponse, SizedStream};
use oci_client::manifest::{ImageIndexEntry, OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::Deserialize;

use crate::{OciDiskError, OciDiskResult, Platform};

#[derive(Clone)]
pub(crate) struct RegistryClient {
    client: Client,
}

pub(crate) struct ResolvedManifest {
    pub(crate) reference: Reference,
    pub(crate) manifest_digest: String,
    pub(crate) config_digest: String,
    pub(crate) layers: Vec<ResolvedLayer>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedLayer {
    pub(crate) digest: String,
    pub(crate) media_type: String,
    pub(crate) size_bytes: u64,
    pub(crate) diff_id: String,
}

#[derive(Debug, Deserialize)]
struct ImageConfig {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    rootfs: RootfsConfig,
}

#[derive(Debug, Deserialize)]
struct RootfsConfig {
    #[serde(default)]
    diff_ids: Vec<String>,
}

impl RegistryClient {
    pub(crate) fn new() -> OciDiskResult<Self> {
        Ok(Self {
            client: Client::new(Default::default()),
        })
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
        let (manifest, digest) = self
            .client
            .pull_manifest(reference, &RegistryAuth::Anonymous)
            .await
            .map_err(|source| OciDiskError::registry_manifest(requested_ref.clone(), source))?;

        let (manifest_reference, manifest, manifest_digest) = match manifest {
            OciManifest::Image(manifest) => (reference.clone(), manifest, digest),
            OciManifest::ImageIndex(index) => {
                let descriptor =
                    select_platform_descriptor(&requested_ref, &index.manifests, platform)?;
                let manifest_reference = reference.clone_with_digest(descriptor.digest.clone());
                let (selected, selected_digest) = self
                    .client
                    .pull_manifest(&manifest_reference, &RegistryAuth::Anonymous)
                    .await
                    .map_err(|source| {
                        OciDiskError::registry_manifest(requested_ref.clone(), source)
                    })?;
                match selected {
                    OciManifest::Image(manifest) => (manifest_reference, manifest, selected_digest),
                    OciManifest::ImageIndex(_) => {
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

        let config_digest = manifest.config.digest.clone();
        let config_bytes = self
            .pull_blob_bytes(&manifest_reference, &manifest.config, &requested_ref)
            .await?;
        let config = serde_json::from_slice::<ImageConfig>(&config_bytes).map_err(|err| {
            OciDiskError::ImageConfig {
                reference: requested_ref.clone(),
                message: err.to_string(),
            }
        })?;
        validate_config_platform(&requested_ref, platform, &config)?;

        if config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(OciDiskError::ImageConfig {
                reference: requested_ref,
                message: format!(
                    "config rootfs diff_id count {} does not match manifest layer count {}",
                    config.rootfs.diff_ids.len(),
                    manifest.layers.len()
                ),
            });
        }

        let layers = resolved_layers(&requested_ref, &manifest, &config)?;

        Ok(ResolvedManifest {
            reference: manifest_reference,
            manifest_digest,
            config_digest,
            layers,
        })
    }

    pub(crate) async fn pull_layer_stream(
        &self,
        reference: &Reference,
        layer: &ResolvedLayer,
        requested_ref: &str,
    ) -> OciDiskResult<SizedStream> {
        let descriptor = layer_descriptor(layer);
        self.client
            .pull_blob_stream(reference, &descriptor)
            .await
            .map_err(|source| OciDiskError::registry(requested_ref.to_string(), source))
    }

    pub(crate) async fn pull_layer_stream_partial(
        &self,
        reference: &Reference,
        layer: &ResolvedLayer,
        requested_ref: &str,
        offset: u64,
        length: Option<u64>,
    ) -> OciDiskResult<BlobResponse> {
        let descriptor = layer_descriptor(layer);
        self.client
            .pull_blob_stream_partial(reference, &descriptor, offset, length)
            .await
            .map_err(|source| OciDiskError::registry(requested_ref.to_string(), source))
    }

    async fn pull_blob_bytes(
        &self,
        reference: &Reference,
        descriptor: &OciDescriptor,
        requested_ref: &str,
    ) -> OciDiskResult<Vec<u8>> {
        let mut stream = self
            .client
            .pull_blob_stream(reference, descriptor)
            .await
            .map_err(|source| OciDiskError::registry(requested_ref.to_string(), source))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.try_next().await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn resolved_layers(
    reference: &str,
    manifest: &OciImageManifest,
    config: &ImageConfig,
) -> OciDiskResult<Vec<ResolvedLayer>> {
    manifest
        .layers
        .iter()
        .zip(config.rootfs.diff_ids.iter())
        .map(|(layer, diff_id)| {
            let size_bytes = u64::try_from(layer.size).map_err(|_| OciDiskError::ImageConfig {
                reference: reference.to_string(),
                message: format!("layer {} has negative size {}", layer.digest, layer.size),
            })?;
            Ok(ResolvedLayer {
                digest: layer.digest.clone(),
                media_type: layer.media_type.clone(),
                size_bytes,
                diff_id: diff_id.clone(),
            })
        })
        .collect()
}

fn layer_descriptor(layer: &ResolvedLayer) -> OciDescriptor {
    OciDescriptor {
        media_type: layer.media_type.clone(),
        digest: layer.digest.clone(),
        size: layer.size_bytes.min(i64::MAX as u64) as i64,
        ..Default::default()
    }
}

fn select_platform_descriptor(
    reference: &str,
    manifests: &[ImageIndexEntry],
    platform: &Platform,
) -> OciDiskResult<ImageIndexEntry> {
    manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|entry_platform| {
                entry_platform.os.to_string() == platform.os
                    && entry_platform.architecture.to_string() == platform.architecture
                    && platform
                        .variant
                        .as_deref()
                        .map(|variant| entry_platform.variant.as_deref() == Some(variant))
                        .unwrap_or(true)
            })
        })
        .cloned()
        .ok_or_else(|| OciDiskError::MissingPlatform {
            reference: reference.to_string(),
            requested: platform.to_string(),
            available: available_platforms(manifests),
        })
}

fn available_platforms(manifests: &[ImageIndexEntry]) -> String {
    let mut platforms = manifests
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
