//! Exact-byte OCI transport. Integrity here never grants publisher trust.
use futures_util::TryStreamExt;
use oci_client::manifest::{OciDescriptor, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Reference, RegistryOperation};

use crate::changeset::model::ContentDigest;
use crate::registry::RegistryClient;
use crate::vm_artifact::graph::{Descriptor, GraphVerifier, VerifiedVmGraph};
use crate::{OciError, OciResult, RegistryPolicy};

const METADATA_LIMIT: u64 = crate::vm_artifact::wire::MAX_METADATA_BYTES as u64;
const PAYLOAD_LIMIT: u64 = crate::vm_artifact::wire::PayloadMediaType::DeviceState.maximum_size();
const VM_ARTIFACT: &str = crate::vm_artifact::graph::ARTIFACT_TYPE;

pub struct ArtifactRegistry {
    registry: RegistryClient,
    http: reqwest::Client,
    policy: RegistryPolicy,
}

/// A resolved immutable envelope, not an authorization to acquire or execute it.
#[derive(Debug)]
pub struct ArtifactResolution {
    reference: Reference,
    index: Vec<u8>,
    digest: ContentDigest,
}

impl ArtifactResolution {
    pub fn reference(&self) -> String {
        self.reference.to_string()
    }

    pub fn repository(&self) -> String {
        format!(
            "{}/{}",
            self.reference.resolve_registry(),
            self.reference.repository()
        )
    }

    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub fn index_bytes(&self) -> &[u8] {
        &self.index
    }
}

impl ArtifactRegistry {
    pub fn new(policy: RegistryPolicy) -> OciResult<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("silo-oci/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| OciError::Io(std::io::Error::other(error)))?;
        Ok(Self {
            registry: RegistryClient::new()?,
            http,
            policy,
        })
    }

    /// Inspect the index type before considering any OCI platform selection.
    pub async fn resolve(&self, reference: &str) -> OciResult<ArtifactResolution> {
        let reference = RegistryClient::parse_reference(reference)?;
        self.policy.check(&reference)?;
        let response = self
            .registry
            .pull_manifest_bounded(&self.http, &reference, None)
            .await?;
        if !matches!(&response.manifest, OciManifest::ImageIndex(index)
            if index.artifact_type.as_deref() == Some(VM_ARTIFACT))
        {
            return Err(OciError::NotVmArtifact {
                reference: reference.to_string(),
            });
        }
        let digest = response.digest.parse()?;
        Ok(ArtifactResolution {
            reference: reference.clone_with_digest(response.digest),
            index: response.bytes,
            digest,
        })
    }

    /// Verify one bounded metadata record at a time. Bulk payloads are not fetched.
    pub async fn inspect(&self, resolution: &ArtifactResolution) -> OciResult<VerifiedVmGraph> {
        self.policy.check(&resolution.reference)?;
        let mut verifier = GraphVerifier::new(resolution.index_bytes())?;
        while let Some(descriptor) = verifier.next_descriptor() {
            let bytes = self.fetch_metadata(resolution, descriptor).await?;
            verifier.accept_metadata(&bytes)?;
        }
        Ok(verifier.finish()?)
    }

    pub async fn fetch_metadata(
        &self,
        resolution: &ArtifactResolution,
        descriptor: &Descriptor,
    ) -> OciResult<Vec<u8>> {
        self.policy.check(&resolution.reference)?;
        if descriptor.size > METADATA_LIMIT {
            return Err(invalid(
                &resolution.reference,
                "artifact metadata exceeds 4 MiB",
            ));
        }
        if descriptor.media_type == "application/vnd.oci.image.manifest.v1+json" {
            let reference = resolution
                .reference
                .clone_with_digest(descriptor.digest.to_string());
            let response = self
                .registry
                .pull_manifest_bounded(&self.http, &reference, Some(descriptor.size))
                .await?;
            return Ok(response.bytes);
        }
        self.fetch_blob(resolution, descriptor).await
    }

    /// Each blob is independently bounded and authenticated before decoding.
    pub async fn fetch_blob(
        &self,
        resolution: &ArtifactResolution,
        descriptor: &Descriptor,
    ) -> OciResult<Vec<u8>> {
        self.policy.check(&resolution.reference)?;
        if descriptor.size > PAYLOAD_LIMIT {
            return Err(invalid(
                &resolution.reference,
                "artifact payload exceeds 32 MiB",
            ));
        }
        self.registry
            .authenticate_pull(&resolution.reference, &resolution.reference.to_string())
            .await?;
        let oci_descriptor = OciDescriptor {
            media_type: descriptor.media_type.clone(),
            digest: descriptor.digest.to_string(),
            size: i64::try_from(descriptor.size)
                .map_err(|_| invalid(&resolution.reference, "blob size overflow"))?,
            ..Default::default()
        };
        let mut stream = self
            .registry
            .client
            .pull_blob_stream(&resolution.reference, &oci_descriptor)
            .await
            .map_err(|error| OciError::registry(resolution.reference.to_string(), error))?;
        let length = usize::try_from(descriptor.size)
            .map_err(|_| invalid(&resolution.reference, "blob size exceeds address space"))?;
        let mut bytes = Vec::with_capacity(length);
        while let Some(chunk) = stream.try_next().await? {
            if chunk.len() > length.saturating_sub(bytes.len()) {
                return Err(invalid(
                    &resolution.reference,
                    "blob exceeds descriptor size",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != length || ContentDigest::of_bytes(&bytes) != descriptor.digest {
            return Err(invalid(
                &resolution.reference,
                "blob does not match descriptor size and digest",
            ));
        }
        Ok(bytes)
    }

    /// Upload verified bounded bytes to the same policy-admitted repository.
    pub async fn push_blob(
        &self,
        target: &str,
        digest: ContentDigest,
        bytes: Vec<u8>,
    ) -> OciResult<()> {
        let reference = RegistryClient::parse_reference(target)?;
        self.policy.check(&reference)?;
        if bytes.len() as u64 > PAYLOAD_LIMIT || ContentDigest::of_bytes(&bytes) != digest {
            return Err(invalid(
                &reference,
                "upload blob does not match its bounded digest",
            ));
        }
        let token = self
            .registry
            .client
            .auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Push,
            )
            .await
            .map_err(|error| OciError::registry(reference.to_string(), error))?;
        let url = format!(
            "https://{}/v2/{}/blobs/{digest}",
            reference.resolve_registry(),
            reference.repository()
        );
        let mut request = self.http.head(url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| OciError::Io(std::io::Error::other(error)))?;
        match response.status() {
            reqwest::StatusCode::OK => {
                let length = response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                let observed = response
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<ContentDigest>().ok());
                if length != Some(bytes.len() as u64) || observed != Some(digest) {
                    return Err(invalid(
                        &reference,
                        "existing registry blob has inconsistent descriptor headers",
                    ));
                }
                return Ok(());
            }
            reqwest::StatusCode::NOT_FOUND => {}
            status => {
                return Err(invalid(
                    &reference,
                    &format!("blob existence request returned {status}"),
                ))
            }
        }
        self.registry
            .client
            .push_blob(&reference, bytes, &digest.to_string())
            .await
            .map_err(|error| OciError::registry(reference.to_string(), error))?;
        Ok(())
    }

    /// Upload exact serialized bytes; the exporter orders blobs, children, then index.
    pub async fn push_manifest(&self, target: &str, bytes: Vec<u8>) -> OciResult<ContentDigest> {
        let reference = RegistryClient::parse_reference(target)?;
        self.policy.check(&reference)?;
        if bytes.len() as u64 > METADATA_LIMIT {
            return Err(invalid(&reference, "upload manifest exceeds 4 MiB"));
        }
        let manifest: OciManifest = serde_json::from_slice(&bytes)?;
        let media_type = match &manifest {
            OciManifest::Image(_) => "application/vnd.oci.image.manifest.v1+json",
            OciManifest::ImageIndex(_) => "application/vnd.oci.image.index.v1+json",
        };
        let digest = ContentDigest::of_bytes(&bytes);
        if reference
            .digest()
            .is_some_and(|expected| expected != digest.to_string())
        {
            return Err(invalid(
                &reference,
                "upload manifest differs from target digest",
            ));
        }
        self.registry
            .client
            .auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Push,
            )
            .await
            .map_err(|error| OciError::registry(reference.to_string(), error))?;
        self.registry
            .client
            .push_manifest_raw(
                &reference,
                bytes,
                reqwest::header::HeaderValue::from_static(media_type),
            )
            .await
            .map_err(|error| OciError::ArtifactRegistryIncompatible {
                reference: reference.to_string(),
                message: error.to_string(),
            })?;
        // Verify that the registry preserved exact bytes rather than rewriting metadata.
        let pinned = reference.clone_with_digest(digest.to_string());
        self.registry
            .pull_manifest_bounded(&self.http, &pinned, None)
            .await
            .map_err(|error| OciError::ArtifactRegistryIncompatible {
                reference: reference.to_string(),
                message: error.to_string(),
            })?;
        Ok(digest)
    }
}

fn invalid(reference: &Reference, message: &str) -> OciError {
    OciError::ImageConfig {
        reference: reference.to_string(),
        message: message.into(),
    }
}
