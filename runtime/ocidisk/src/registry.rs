use std::str::FromStr;

use futures_util::TryStreamExt;
use oci_client::client::{BlobResponse, SizedStream};
use oci_client::manifest::{ImageIndexEntry, OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference, RegistryOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{OciDiskError, OciDiskResult, Platform};

#[derive(Clone)]
pub(crate) struct RegistryClient {
    client: Client,
}

#[derive(Debug, Clone)]
pub struct ResolvedOciImage {
    /// Canonical form of the caller's OCI reference.
    pub requested_reference: String,
    /// Digest-pinned OCI reference selected for the requested platform.
    pub selected_reference: String,
    /// Digest of the selected OCI image manifest.
    pub manifest_digest: String,
    /// Digest of the OCI image configuration.
    pub config_digest: String,
    /// Execution defaults declared by the OCI image configuration.
    pub config: OciImageConfigMetadata,
    /// Platform selected from the requested image.
    pub platform: Platform,
    pub(crate) reference: Reference,
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
struct ImageConfigDocument {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    rootfs: RootfsConfig,
    #[serde(default)]
    config: Option<OciImageConfigMetadata>,
}

#[derive(Debug, Deserialize)]
struct RootfsConfig {
    #[serde(default)]
    diff_ids: Vec<String>,
}

/// OCI image execution defaults retained with a materialized rootfs.
///
/// Every OCI configuration property is optional. `Some(Vec::new())` and
/// `Some(BTreeMap::new())` deliberately remain distinct from an absent field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageConfigMetadata {
    #[serde(
        default,
        rename = "Entrypoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd", skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env", skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(
        default,
        rename = "WorkingDir",
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    #[serde(default, rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    #[serde(
        default,
        rename = "StopSignal",
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_signal: Option<String>,
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
    ) -> OciDiskResult<ResolvedOciImage> {
        let requested_ref = reference.to_string();
        let (manifest, digest) = self
            .client
            .pull_manifest(reference, &RegistryAuth::Anonymous)
            .await
            .map_err(|source| OciDiskError::registry_manifest(requested_ref.clone(), source))?;
        if let Some(requested_digest) = reference.digest() {
            verify_manifest_response_digest(&requested_ref, requested_digest, &digest)?;
        }

        let (manifest, manifest_digest) = match manifest {
            OciManifest::Image(manifest) => (manifest, digest),
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
                verify_manifest_response_digest(
                    &requested_ref,
                    &descriptor.digest,
                    &selected_digest,
                )?;
                match selected {
                    OciManifest::Image(manifest) => (manifest, selected_digest),
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
        let manifest_reference = reference.clone_with_digest(manifest_digest.clone());

        let config_digest = manifest.config.digest.clone();
        let config_bytes = self
            .pull_blob_bytes(&manifest_reference, &manifest.config, &requested_ref)
            .await?;
        verify_descriptor_digest(
            &requested_ref,
            "image configuration",
            &config_digest,
            &config_bytes,
        )?;
        let config =
            serde_json::from_slice::<ImageConfigDocument>(&config_bytes).map_err(|err| {
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

        Ok(ResolvedOciImage {
            requested_reference: requested_ref,
            selected_reference: manifest_reference.to_string(),
            reference: manifest_reference,
            manifest_digest,
            config_digest,
            config: config.config.unwrap_or_default(),
            platform: platform.clone(),
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

    pub(crate) async fn authenticate_pull(
        &self,
        reference: &Reference,
        requested_ref: &str,
    ) -> OciDiskResult<()> {
        self.client
            .auth(reference, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .map(|_| ())
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

fn verify_manifest_response_digest(
    reference: &str,
    expected: &str,
    actual: &str,
) -> OciDiskResult<()> {
    if expected == actual {
        return Ok(());
    }

    Err(OciDiskError::ManifestDigestMismatch {
        reference: reference.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn verify_descriptor_digest(
    reference: &str,
    content: &'static str,
    expected: &str,
    bytes: &[u8],
) -> OciDiskResult<()> {
    let expected_digest = expected.strip_prefix("sha256:").ok_or_else(|| {
        OciDiskError::UnsupportedDigestAlgorithm {
            digest: expected.to_string(),
        }
    })?;
    if expected_digest.len() != 64 || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(OciDiskError::InvalidDigest {
            digest: expected.to_string(),
            message: "sha256 digests must be 64 hexadecimal characters".to_string(),
        });
    }

    let actual = sha256_digest(bytes);
    if actual == expected {
        return Ok(());
    }

    Err(OciDiskError::DescriptorDigestMismatch {
        reference: reference.to_string(),
        content,
        expected: expected.to_string(),
        actual,
    })
}

fn sha256_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn resolved_layers(
    reference: &str,
    manifest: &OciImageManifest,
    config: &ImageConfigDocument,
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
    config: &ImageConfigDocument,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::registry::{
        verify_descriptor_digest, verify_manifest_response_digest, ImageConfigDocument,
    };
    use crate::OciDiskError;

    #[test]
    fn parses_oci_execution_metadata_without_collapsing_empty_values() {
        let config = serde_json::from_str::<ImageConfigDocument>(
            r#"{
                "architecture": "amd64",
                "os": "linux",
                "rootfs": { "diff_ids": [] },
                "config": {
                    "Entrypoint": [],
                    "Cmd": ["serve"],
                    "Env": [],
                    "WorkingDir": "",
                    "User": "1000:1000",
                    "Labels": {},
                    "StopSignal": "SIGTERM"
                }
            }"#,
        )
        .expect("parse OCI image config");

        let metadata = config.config.expect("OCI config metadata");
        assert_eq!(metadata.entrypoint, Some(Vec::new()));
        assert_eq!(metadata.cmd, Some(vec!["serve".to_string()]));
        assert_eq!(metadata.env, Some(Vec::new()));
        assert_eq!(metadata.working_dir.as_deref(), Some(""));
        assert_eq!(metadata.user.as_deref(), Some("1000:1000"));
        assert_eq!(metadata.labels, Some(BTreeMap::new()));
        assert_eq!(metadata.stop_signal.as_deref(), Some("SIGTERM"));
    }

    #[test]
    fn preserves_absent_oci_execution_metadata() {
        let config = serde_json::from_str::<ImageConfigDocument>(
            r#"{
                "architecture": "amd64",
                "os": "linux",
                "rootfs": { "diff_ids": [] }
            }"#,
        )
        .expect("parse OCI image config");

        assert_eq!(config.config, None);
    }

    #[test]
    fn accepts_null_oci_execution_metadata_as_absent() {
        let config = serde_json::from_str::<ImageConfigDocument>(
            r#"{
                "architecture": "amd64",
                "os": "linux",
                "rootfs": { "diff_ids": [] },
                "config": null
            }"#,
        )
        .expect("parse OCI image config");

        assert_eq!(config.config, None);
    }

    #[test]
    fn rejects_config_bytes_that_do_not_match_the_descriptor_digest() {
        let err = verify_descriptor_digest(
            "example.test/demo:latest",
            "image configuration",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"different configuration",
        )
        .expect_err("mismatched config bytes must fail verification");

        assert!(matches!(
            err,
            OciDiskError::DescriptorDigestMismatch {
                content: "image configuration",
                ..
            }
        ));
    }

    #[test]
    fn rejects_manifest_response_digest_that_differs_from_the_requested_digest() {
        let err = verify_manifest_response_digest(
            "example.test/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect_err("digest-pinned response must retain the requested digest");

        assert!(matches!(err, OciDiskError::ManifestDigestMismatch { .. }));
    }
}
