use std::str::FromStr;

use futures_util::TryStreamExt;
use oci_client::client::{BlobResponse, SizedStream};
use oci_client::errors::{OciDistributionError, OciEnvelope};
use oci_client::manifest::{ImageIndexEntry, OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference, RegistryOperation};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::{OciError, OciResult, Platform};

#[derive(Clone)]
pub(crate) struct RegistryClient {
    pub(crate) client: Client,
}

#[derive(Debug)]
pub(crate) struct RegistryManifest {
    pub(crate) manifest: OciManifest,
    pub(crate) digest: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ResolvedImage {
    /// Canonical form of the caller's OCI reference.
    pub requested_reference: String,
    /// Digest-pinned OCI reference selected for the requested platform.
    pub selected_reference: String,
    /// Digest of the selected OCI image manifest.
    pub manifest_digest: String,
    /// Digest of the OCI image configuration.
    pub config_digest: String,
    /// Execution defaults declared by the OCI image configuration.
    pub config: ImageConfig,
    /// Platform selected from the requested image.
    pub platform: Platform,
    pub(crate) reference: Reference,
    pub(crate) layers: Vec<ResolvedLayer>,
}

impl ResolvedImage {
    /// Immutable source blobs that the caller must pin before cache access.
    pub fn layer_digests(&self) -> impl Iterator<Item = &str> {
        self.layers.iter().map(|layer| layer.digest.as_str())
    }

    /// Verified descriptors of every ordered layer occurrence, repeats kept.
    pub fn layer_metadata(&self) -> impl Iterator<Item = crate::RootfsLayerMetadata> + '_ {
        self.layers.iter().map(crate::RootfsLayerMetadata::from)
    }
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
    config: Option<ImageConfig>,
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
pub struct ImageConfig {
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
    pub(crate) fn new() -> OciResult<Self> {
        Ok(Self {
            client: Client::new(Default::default()),
        })
    }

    pub(crate) fn parse_reference(image_ref: &str) -> OciResult<Reference> {
        Reference::from_str(image_ref).map_err(|err| OciError::InvalidReference {
            reference: image_ref.to_string(),
            message: err.to_string(),
        })
    }

    pub(crate) async fn resolve_manifest(
        &self,
        reference: &Reference,
        platform: &Platform,
    ) -> OciResult<ResolvedImage> {
        let requested_ref = reference.to_string();
        let http = reqwest::Client::builder()
            .user_agent(concat!("silo-oci/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| OciError::Io(std::io::Error::other(error)))?;
        let RegistryManifest {
            manifest, digest, ..
        } = self.pull_manifest_bounded(&http, reference, None).await?;

        let (manifest, manifest_digest) = match manifest {
            OciManifest::Image(manifest) => (manifest, digest),
            OciManifest::ImageIndex(index) => {
                if index.artifact_type.as_deref() == Some("application/vnd.silo.vm.v1") {
                    return Err(OciError::VmArtifactRequiresAcquisition {
                        reference: requested_ref,
                        index_digest: digest,
                    });
                }
                let descriptor =
                    select_platform_descriptor(&requested_ref, &index.manifests, platform)?;
                let manifest_reference = reference.clone_with_digest(descriptor.digest.clone());
                let size = u64::try_from(descriptor.size).map_err(|_| OciError::ImageConfig {
                    reference: requested_ref.clone(),
                    message: "selected manifest descriptor has a negative size".into(),
                })?;
                let RegistryManifest {
                    manifest: selected,
                    digest: selected_digest,
                    ..
                } = self
                    .pull_manifest_bounded(&http, &manifest_reference, Some(size))
                    .await?;
                match selected {
                    OciManifest::Image(manifest) => (manifest, selected_digest),
                    OciManifest::ImageIndex(_) => {
                        return Err(OciError::ImageConfig {
                            reference: requested_ref,
                            message:
                                "selected platform descriptor resolved to another manifest index"
                                    .to_string(),
                        });
                    }
                }
            }
        };
        Sha256Digest::parse(&manifest.config.digest)?;
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
                OciError::ImageConfig {
                    reference: requested_ref.clone(),
                    message: err.to_string(),
                }
            })?;
        validate_config_platform(&requested_ref, platform, &config)?;

        if config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(OciError::ImageConfig {
                reference: requested_ref,
                message: format!(
                    "config rootfs diff_id count {} does not match manifest layer count {}",
                    config.rootfs.diff_ids.len(),
                    manifest.layers.len()
                ),
            });
        }

        let layers = resolved_layers(&requested_ref, &manifest, &config)?;

        Ok(ResolvedImage {
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

    pub(crate) async fn pull_manifest_bounded(
        &self,
        http: &reqwest::Client,
        reference: &Reference,
        expected_size: Option<u64>,
    ) -> OciResult<RegistryManifest> {
        let requested = reference.to_string();
        if expected_size.is_some_and(|length| length > METADATA_LIMIT) {
            return Err(OciError::MetadataSize {
                reference: requested,
                content: "OCI manifest",
                expected: expected_size,
                actual: expected_size.unwrap_or(0),
                limit: METADATA_LIMIT,
            });
        }
        if let Some(digest) = reference.digest() {
            Sha256Digest::parse(digest)?;
        }
        let mut url = reqwest::Url::parse(&format!(
            "https://{}/v2/{}/manifests/{}",
            reference.resolve_registry(),
            reference.repository(),
            reference
                .digest()
                .or_else(|| reference.tag())
                .unwrap_or("latest"),
        ))
        .map_err(|error| OciError::InvalidReference {
            reference: requested.clone(),
            message: error.to_string(),
        })?;
        if let Some(namespace) = reference.namespace() {
            url.query_pairs_mut().append_pair("ns", namespace);
        }
        let token = self
            .client
            .auth(reference, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .map_err(|source| OciError::registry_manifest(requested.clone(), source))?;
        let mut request = http
            .get(url)
            .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| OciError::Io(std::io::Error::other(error)))?;
        read_manifest_response(response, &requested, reference.digest(), expected_size).await
    }

    pub(crate) async fn pull_layer_stream(
        &self,
        reference: &Reference,
        layer: &ResolvedLayer,
        requested_ref: &str,
    ) -> OciResult<SizedStream> {
        let descriptor = layer_descriptor(layer);
        self.client
            .pull_blob_stream(reference, &descriptor)
            .await
            .map_err(|source| OciError::registry(requested_ref.to_string(), source))
    }

    pub(crate) async fn authenticate_pull(
        &self,
        reference: &Reference,
        requested_ref: &str,
    ) -> OciResult<()> {
        self.client
            .auth(reference, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .map(|_| ())
            .map_err(|source| OciError::registry(requested_ref.to_string(), source))
    }

    pub(crate) async fn pull_layer_stream_partial(
        &self,
        reference: &Reference,
        layer: &ResolvedLayer,
        requested_ref: &str,
        offset: u64,
        length: Option<u64>,
    ) -> OciResult<BlobResponse> {
        let descriptor = layer_descriptor(layer);
        self.client
            .pull_blob_stream_partial(reference, &descriptor, offset, length)
            .await
            .map_err(|source| OciError::registry(requested_ref.to_string(), source))
    }

    async fn pull_blob_bytes(
        &self,
        reference: &Reference,
        descriptor: &OciDescriptor,
        requested_ref: &str,
    ) -> OciResult<Vec<u8>> {
        let expected = u64::try_from(descriptor.size).map_err(|_| OciError::ImageConfig {
            reference: requested_ref.into(),
            message: "configuration descriptor has a negative size".into(),
        })?;
        let mut body = MetadataBody::new(requested_ref, "image configuration", Some(expected))?;
        let mut stream = self
            .client
            .pull_blob_stream(reference, descriptor)
            .await
            .map_err(|source| OciError::registry(requested_ref.to_string(), source))?;
        while let Some(chunk) = stream.try_next().await? {
            body.push(&chunk)?;
        }
        body.finish()
    }
}

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";

async fn read_manifest_response(
    mut response: reqwest::Response,
    reference: &str,
    expected_digest: Option<&str>,
    expected_size: Option<u64>,
) -> OciResult<RegistryManifest> {
    let status = response.status();
    let success = status == reqwest::StatusCode::OK;
    let expected_size = if success { expected_size } else { None };
    if let (Some(expected), Some(actual)) = (expected_size, response.content_length()) {
        if expected != actual {
            return Err(OciError::MetadataSize {
                reference: reference.into(),
                content: "OCI manifest",
                expected: Some(expected),
                actual,
                limit: METADATA_LIMIT,
            });
        }
    }
    let header_digest = if success {
        response
            .headers()
            .get("docker-content-digest")
            .map(|header| {
                let value = header.to_str().map_err(|error| {
                    OciError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
                })?;
                Sha256Digest::parse(value)
            })
            .transpose()?
    } else {
        None
    };
    let mut body = MetadataBody::new(
        reference,
        "OCI manifest",
        expected_size.or(response.content_length()),
    )?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| OciError::Io(std::io::Error::other(error)))?
    {
        body.push(&chunk)?;
    }
    let bytes = body.finish()?;
    if !success {
        let url = response.url().to_string();
        let source = if status == reqwest::StatusCode::UNAUTHORIZED {
            OciDistributionError::UnauthorizedError { url }
        } else if status.is_success() {
            OciDistributionError::SpecViolationError(format!(
                "expected HTTP 200 for manifest, got {status}"
            ))
        } else if status.is_client_error() {
            match serde_json::from_slice::<OciEnvelope>(&bytes) {
                Ok(envelope) => OciDistributionError::RegistryError { url, envelope },
                Err(_) => OciDistributionError::ServerError {
                    code: status.as_u16(),
                    url,
                    message: String::from_utf8_lossy(&bytes).into_owned(),
                },
            }
        } else {
            OciDistributionError::ServerError {
                code: status.as_u16(),
                url,
                message: String::from_utf8_lossy(&bytes).into_owned(),
            }
        };
        return Err(OciError::registry_manifest(reference, source));
    }
    let actual = Sha256Digest::from_bytes(&bytes);
    let digest = actual.to_string();
    if let Some(header) = header_digest {
        if header != actual {
            return Err(OciError::ManifestDigestMismatch {
                reference: reference.into(),
                expected: header.to_string(),
                actual: digest,
            });
        }
    }
    if let Some(expected) = expected_digest {
        verify_manifest_response_digest(reference, expected, &digest)?;
    }
    let manifest: OciManifest = serde_json::from_slice(&bytes).map_err(|error| {
        OciError::registry_manifest(
            reference,
            OciDistributionError::ManifestParsingError(error.to_string()),
        )
    })?;
    let (schema, media_type, allowed) = match &manifest {
        OciManifest::Image(image) => (
            image.schema_version,
            image.media_type.as_deref(),
            [
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ],
        ),
        OciManifest::ImageIndex(index) => (
            index.schema_version,
            index.media_type.as_deref(),
            [
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            ],
        ),
    };
    if schema != 2 {
        return Err(OciError::registry_manifest(
            reference,
            OciDistributionError::UnsupportedSchemaVersionError(i32::from(schema)),
        ));
    }
    if let Some(media_type) = media_type {
        if !allowed.contains(&media_type) {
            return Err(OciError::registry_manifest(
                reference,
                OciDistributionError::UnsupportedMediaTypeError(media_type.into()),
            ));
        }
    }
    let count_valid = match &manifest {
        OciManifest::Image(image) => {
            let limit =
                if image.artifact_type.as_deref() == Some("application/vnd.silo.vm.payloads.v1") {
                    4096
                } else {
                    1024
                };
            image.layers.len() <= limit
        }
        OciManifest::ImageIndex(index) => {
            let limit = if index.artifact_type.as_deref()
                == Some(crate::vm_artifact::graph::ARTIFACT_TYPE)
            {
                crate::vm_artifact::wire::MAX_PAGE_ENTRIES + 1
            } else {
                4096
            };
            index.manifests.len() <= limit
        }
    };
    if !count_valid {
        return Err(OciError::ImageConfig {
            reference: reference.into(),
            message: "OCI manifest descriptor count exceeds its bound".into(),
        });
    }
    Ok(RegistryManifest {
        manifest,
        digest,
        bytes,
    })
}

const METADATA_LIMIT: u64 = 4 * 1024 * 1024;

struct MetadataBody<'a> {
    reference: &'a str,
    content: &'static str,
    expected: Option<u64>,
    bytes: Vec<u8>,
}

impl<'a> MetadataBody<'a> {
    fn new(reference: &'a str, content: &'static str, expected: Option<u64>) -> OciResult<Self> {
        if expected.is_some_and(|length| length > METADATA_LIMIT) {
            return Err(OciError::MetadataSize {
                reference: reference.into(),
                content,
                expected,
                actual: expected.unwrap_or(0),
                limit: METADATA_LIMIT,
            });
        }
        Ok(Self {
            reference,
            content,
            expected,
            bytes: Vec::with_capacity(expected.unwrap_or(0) as usize),
        })
    }

    fn size_error(&self, actual: u64) -> OciError {
        OciError::MetadataSize {
            reference: self.reference.into(),
            content: self.content,
            expected: self.expected,
            actual,
            limit: METADATA_LIMIT,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> OciResult<()> {
        let length = (self.bytes.len() as u64).saturating_add(chunk.len() as u64);
        if length > METADATA_LIMIT || self.expected.is_some_and(|expected| length > expected) {
            return Err(self.size_error(length));
        }
        if self.bytes.capacity() < length as usize {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .clamp(length as usize, METADATA_LIMIT as usize);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn finish(self) -> OciResult<Vec<u8>> {
        if self
            .expected
            .is_some_and(|expected| expected != self.bytes.len() as u64)
        {
            return Err(self.size_error(self.bytes.len() as u64));
        }
        Ok(self.bytes)
    }
}

fn verify_manifest_response_digest(reference: &str, expected: &str, actual: &str) -> OciResult<()> {
    if Sha256Digest::parse(expected)? == Sha256Digest::parse(actual)? {
        return Ok(());
    }

    Err(OciError::ManifestDigestMismatch {
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
) -> OciResult<()> {
    let expected_digest = Sha256Digest::parse(expected)?;
    let actual = Sha256Digest::from_bytes(bytes);
    if actual == expected_digest {
        return Ok(());
    }

    Err(OciError::DescriptorDigestMismatch {
        reference: reference.to_string(),
        content,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn resolved_layers(
    reference: &str,
    manifest: &OciImageManifest,
    config: &ImageConfigDocument,
) -> OciResult<Vec<ResolvedLayer>> {
    if manifest.layers.len() > 1024 || manifest.layers.len() != config.rootfs.diff_ids.len() {
        return Err(OciError::ImageConfig {
            reference: reference.into(),
            message: "invalid OCI layer occurrence count".into(),
        });
    }
    manifest
        .layers
        .iter()
        .zip(config.rootfs.diff_ids.iter())
        .map(|(layer, diff_id)| {
            Sha256Digest::parse(&layer.digest)?;
            Sha256Digest::parse(diff_id)?;
            let size_bytes = u64::try_from(layer.size).map_err(|_| OciError::ImageConfig {
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
) -> OciResult<ImageIndexEntry> {
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
        .ok_or_else(|| OciError::MissingPlatform {
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
) -> OciResult<()> {
    if requested.matches_config(&config.os, &config.architecture, config.variant.as_deref()) {
        return Ok(());
    }

    let actual = Platform {
        os: config.os.clone(),
        architecture: config.architecture.clone(),
        variant: config.variant.clone(),
    };
    Err(OciError::PlatformMismatch {
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
    use crate::OciError;

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
            OciError::DescriptorDigestMismatch {
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

        assert!(matches!(err, OciError::ManifestDigestMismatch { .. }));
    }
    #[test]
    fn metadata_bodies_enforce_declared_and_global_limits_before_appending() {
        use crate::registry::{MetadataBody, METADATA_LIMIT};
        assert!(MetadataBody::new("test", "config", Some(METADATA_LIMIT + 1)).is_err());
        let mut exact = MetadataBody::new("test", "config", Some(3)).unwrap();
        exact.push(b"abc").unwrap();
        assert!(exact.push(b"d").is_err());
        assert_eq!(exact.finish().unwrap(), b"abc");
        let mut short = MetadataBody::new("test", "config", Some(4)).unwrap();
        short.push(b"abc").unwrap();
        assert!(short.finish().is_err());
        let mut unknown = MetadataBody::new("test", "manifest", None).unwrap();
        assert!(unknown.push(&vec![0; METADATA_LIMIT as usize + 1]).is_err());
        assert!(unknown.bytes.is_empty());
    }

    #[test]
    fn layer_resolution_rejects_invalid_ids_and_excess_occurrences() {
        let valid = format!("sha256:{}", "a".repeat(64));
        let mut manifest: oci_client::manifest::OciImageManifest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType":"application/vnd.oci.image.config.v1+json","digest":valid,"size":2},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":valid,"size":1024}]
        })).unwrap();
        let mut config: ImageConfigDocument = serde_json::from_value(serde_json::json!({
            "architecture":"amd64","os":"linux","rootfs":{"diff_ids":[valid]}
        }))
        .unwrap();
        for invalid in ["sha512:abc", "sha256:not-hex"] {
            manifest.layers[0].digest = invalid.into();
            assert!(crate::registry::resolved_layers("test", &manifest, &config).is_err());
            manifest.layers[0].digest = valid.clone();
            config.rootfs.diff_ids[0] = invalid.into();
            assert!(crate::registry::resolved_layers("test", &manifest, &config).is_err());
            config.rootfs.diff_ids[0] = valid.clone();
        }
        manifest.layers = vec![manifest.layers[0].clone(); 1025];
        config.rootfs.diff_ids = vec![valid; 1025];
        assert!(crate::registry::resolved_layers("test", &manifest, &config).is_err());
    }

    #[test]
    fn unknown_length_metadata_buffer_growth_stays_within_limit() {
        let mut body = crate::registry::MetadataBody::new("test", "OCI manifest", None).unwrap();
        let limit = crate::registry::METADATA_LIMIT as usize;
        let bytes = vec![0; limit / 3 + 1];
        for _ in 0..2 {
            body.push(&bytes).unwrap();
            assert!(body.bytes.capacity() <= limit);
        }
        let remaining = limit - body.bytes.len();
        body.push(&bytes[..remaining]).unwrap();
        assert!(body.bytes.capacity() <= limit);
        assert_eq!(body.finish().unwrap().len(), limit);
    }

    fn manifest_http_fixture(
        status: &str,
        body: Vec<u8>,
        chunked: bool,
        header_digest: Option<String>,
        expected_digest: Option<&str>,
        expected_size: Option<u64>,
    ) -> crate::OciResult<crate::registry::RegistryManifest> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut headers = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\n");
        if chunked {
            headers.push_str("Transfer-Encoding: chunked\r\n");
        } else {
            headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        if let Some(digest) = header_digest {
            headers.push_str(&format!("Docker-Content-Digest: {digest}\r\n"));
        }
        headers.push_str("\r\n");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0 && request.len() + read <= 16384);
                request.extend_from_slice(&buffer[..read]);
            }
            assert!(request.starts_with(b"GET /manifest HTTP/1.1\r\n"));
            if socket.write_all(headers.as_bytes()).is_err() {
                return;
            }
            if chunked {
                for bytes in body.chunks(32768) {
                    if write!(socket, "{:x}\r\n", bytes.len()).is_err()
                        || socket.write_all(bytes).is_err()
                        || socket.write_all(b"\r\n").is_err()
                    {
                        return;
                    }
                }
                let _ = socket.write_all(b"0\r\n\r\n");
            } else {
                let _ = socket.write_all(&body);
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let http = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            let response = http
                .get(format!("http://{address}/manifest"))
                .send()
                .await
                .unwrap();
            crate::registry::read_manifest_response(
                response,
                "example.test/demo:latest",
                expected_digest,
                expected_size,
            )
            .await
        });
        server.join().unwrap();
        result
    }

    fn manifest_fixture_bytes() -> Vec<u8> {
        format!(
            "{{ \"schemaVersion\": 2, \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\", \"config\": {{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":2}}, \"layers\": [] }}\n",
            crate::digest::Sha256Digest::from_bytes(b"{}"),
        ).into_bytes()
    }

    #[test]
    fn bounded_http_manifest_verifies_raw_digest_and_exact_selected_descriptor_size() {
        let body = manifest_fixture_bytes();
        let digest = crate::digest::Sha256Digest::from_bytes(&body).to_string();
        let actual = manifest_http_fixture(
            "200 OK",
            body.clone(),
            false,
            Some(digest.clone()),
            Some(&digest),
            Some(body.len() as u64),
        )
        .unwrap();
        assert_eq!(actual.digest, digest);
        assert_eq!(actual.bytes, body);
        assert!(matches!(
            manifest_http_fixture(
                "200 OK",
                body.clone(),
                true,
                None,
                Some(&digest),
                Some(body.len() as u64 + 1)
            ),
            Err(OciError::MetadataSize { .. })
        ));
        let wrong = format!("sha256:{}", "b".repeat(64));
        assert!(matches!(
            manifest_http_fixture(
                "200 OK",
                body.clone(),
                false,
                Some(wrong.clone()),
                None,
                None
            ),
            Err(OciError::ManifestDigestMismatch { .. })
        ));
        assert!(matches!(
            manifest_http_fixture("200 OK", body, true, None, Some(&wrong), None),
            Err(OciError::ManifestDigestMismatch { .. })
        ));
    }

    #[test]
    fn unknown_length_http_manifest_cannot_exceed_metadata_bound() {
        let body = vec![b' '; crate::registry::METADATA_LIMIT as usize + 1];
        assert!(matches!(
            manifest_http_fixture("200 OK", body, true, None, None, None),
            Err(OciError::MetadataSize { actual, limit, .. }) if actual > limit
        ));
    }

    #[test]
    fn vm_index_allows_metadata_child_beyond_payload_child_limit() {
        let descriptor = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": crate::digest::Sha256Digest::from_bytes(b"child").to_string(),
            "size": 5
        });
        for (artifact_type, count, admitted) in [
            ("application/vnd.silo.vm.v1", 4097, true),
            ("application/vnd.silo.vm.v1", 4098, false),
            ("application/vnd.example.other", 4097, false),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "artifactType": artifact_type,
                "manifests": vec![descriptor.clone(); count],
            }))
            .unwrap();
            let result = manifest_http_fixture("200 OK", bytes.clone(), false, None, None, None);
            if admitted {
                assert_eq!(result.unwrap().bytes, bytes);
            } else {
                assert!(matches!(result, Err(OciError::ImageConfig { .. })));
            }
        }
    }

    #[test]
    fn bounded_http_manifest_preserves_registry_search_miss_and_denial_errors() {
        let missing =
            manifest_http_fixture("404 Not Found", Vec::new(), false, None, None, Some(123))
                .unwrap_err();
        assert!(missing.is_search_miss());
        let denied = manifest_http_fixture("401 Unauthorized", Vec::new(), false, None, None, None)
            .unwrap_err();
        assert!(matches!(denied, OciError::RegistryAccessDenied { .. }));
    }
}
