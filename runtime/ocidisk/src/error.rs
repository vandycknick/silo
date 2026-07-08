use std::path::PathBuf;
use std::str::FromStr;

use oci_client::errors::{OciDistributionError, OciErrorCode};

use thiserror::Error;

pub type OciDiskResult<T> = Result<T, OciDiskError>;

#[derive(Debug, Error)]
pub enum OciDiskError {
    #[error("unsupported host architecture {arch:?}; supported OCI image platforms are linux/amd64 and linux/arm64")]
    UnsupportedHostArchitecture { arch: String },

    #[error("invalid OCI image reference {reference:?}: {message}")]
    InvalidReference { reference: String, message: String },

    #[error("invalid image source {reference:?}: {message}")]
    InvalidImageSource { reference: String, message: String },

    #[error("local image source {reference:?} at {path} is invalid: {message}")]
    LocalImageSource {
        reference: String,
        path: PathBuf,
        message: String,
    },

    #[error("tar source {reference:?} at {path} uses {compression} compression; only plain tar files are supported right now")]
    UnsupportedTarCompression {
        reference: String,
        path: PathBuf,
        compression: &'static str,
    },

    #[error("OCI archive {path} is invalid: {message}")]
    OciArchive { path: PathBuf, message: String },

    #[error("registry request for image {reference:?} failed: {source}")]
    Registry {
        reference: String,
        #[source]
        source: OciDistributionError,
    },

    #[error("image {reference:?} was not found: {message}")]
    RegistryImageNotFound { reference: String, message: String },

    #[error("image {reference:?} was not found: {message}")]
    RegistryImageTagNotFound { reference: String, message: String },

    #[error("image {reference:?} was not found: {message}")]
    RegistryImageDigestNotFound { reference: String, message: String },

    #[error("unsupported OCI digest algorithm in {digest:?}; only sha256 is supported")]
    UnsupportedDigestAlgorithm { digest: String },

    #[error("invalid OCI digest {digest:?}: {message}")]
    InvalidDigest { digest: String, message: String },

    #[error("cached OCI layer {digest} at {path} has digest sha256:{actual}")]
    LayerDigestMismatch {
        digest: String,
        path: PathBuf,
        actual: String,
    },

    #[error("cached OCI layer {digest} at {path} has {actual} bytes; expected {expected}")]
    LayerSizeMismatch {
        digest: String,
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("image {reference:?} does not provide {requested}; available platforms: {available}")]
    MissingPlatform {
        reference: String,
        requested: String,
        available: String,
    },

    #[error("image {reference:?} resolved to {actual}, but {requested} was requested")]
    PlatformMismatch {
        reference: String,
        requested: String,
        actual: String,
    },

    #[error("image config for {reference:?} is invalid: {message}")]
    ImageConfig { reference: String, message: String },

    #[error("unsupported OCI layer media type {media_type}")]
    UnsupportedLayerMediaType { media_type: String },

    #[error("invalid tar entry path {path:?}: {reason}")]
    InvalidTarPath { path: String, reason: &'static str },

    #[error("invalid symlink target for {path}: {target:?}: {reason}")]
    InvalidSymlinkTarget {
        path: String,
        target: String,
        reason: &'static str,
    },

    #[error("cache entry at {path} is corrupt: {reason}")]
    CorruptCacheEntry { path: PathBuf, reason: String },

    #[error("ext4 rootfs conversion failed: {message}")]
    Ext4 { message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl OciDiskError {
    pub(crate) fn registry(reference: impl Into<String>, source: OciDistributionError) -> Self {
        let reference = reference.into();
        if let Some(error) = registry_envelope_image_not_found(&reference, &source) {
            return error;
        }

        Self::Registry { reference, source }
    }

    pub(crate) fn registry_manifest(
        reference: impl Into<String>,
        source: OciDistributionError,
    ) -> Self {
        let reference = reference.into();
        if let Some(error) = registry_envelope_image_not_found(&reference, &source) {
            return error;
        }
        if matches!(
            source,
            OciDistributionError::ImageManifestNotFoundError(_)
                | OciDistributionError::ServerError { code: 404, .. }
        ) {
            return image_not_found_error(&reference);
        }

        Self::Registry { reference, source }
    }

    pub(crate) fn ext4(source: impl std::fmt::Display) -> Self {
        Self::Ext4 {
            message: source.to_string(),
        }
    }
}

fn registry_envelope_image_not_found(
    reference: &str,
    source: &OciDistributionError,
) -> Option<OciDiskError> {
    let OciDistributionError::RegistryError { envelope, .. } = source else {
        return None;
    };

    if envelope
        .errors
        .iter()
        .any(|err| matches!(&err.code, OciErrorCode::NameUnknown))
    {
        return Some(repository_not_found_error(reference));
    }

    envelope
        .errors
        .iter()
        .any(|err| {
            matches!(
                &err.code,
                OciErrorCode::ManifestUnknown | OciErrorCode::NotFound
            )
        })
        .then(|| image_not_found_error(reference))
}

fn repository_not_found_error(reference: &str) -> OciDiskError {
    match oci_client::Reference::from_str(reference) {
        Ok(parsed) => OciDiskError::RegistryImageNotFound {
            reference: reference.to_string(),
            message: format!(
                "repository {:?} does not exist on registry {:?}",
                parsed.repository(),
                parsed.registry()
            ),
        },
        Err(_) => OciDiskError::RegistryImageNotFound {
            reference: reference.to_string(),
            message: "the registry reported that the image repository does not exist".to_string(),
        },
    }
}

fn image_not_found_error(reference: &str) -> OciDiskError {
    match oci_client::Reference::from_str(reference) {
        Ok(parsed) => {
            if let Some(tag) = parsed.tag() {
                return OciDiskError::RegistryImageTagNotFound {
                    reference: reference.to_string(),
                    message: format!(
                        "tag {tag:?} does not exist in repository {:?} on registry {:?}",
                        parsed.repository(),
                        parsed.registry()
                    ),
                };
            }
            if let Some(digest) = parsed.digest() {
                return OciDiskError::RegistryImageDigestNotFound {
                    reference: reference.to_string(),
                    message: format!(
                        "digest {digest:?} does not exist in repository {:?} on registry {:?}",
                        parsed.repository(),
                        parsed.registry()
                    ),
                };
            }

            OciDiskError::RegistryImageNotFound {
                reference: reference.to_string(),
                message: format!(
                    "repository {:?} does not exist on registry {:?}",
                    parsed.repository(),
                    parsed.registry()
                ),
            }
        }
        Err(_) => OciDiskError::RegistryImageNotFound {
            reference: reference.to_string(),
            message: "the registry reported that the image or tag does not exist".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use oci_client::errors::{OciDistributionError, OciEnvelope, OciError, OciErrorCode};

    use crate::OciDiskError;

    #[test]
    fn manifest_unknown_reports_missing_tag() {
        let err = OciDiskError::registry(
            "docker.io/library/ubuntu:24.0",
            registry_error(OciErrorCode::ManifestUnknown, "manifest unknown"),
        );

        assert_eq!(
            err.to_string(),
            "image \"docker.io/library/ubuntu:24.0\" was not found: tag \"24.0\" does not exist in repository \"library/ubuntu\" on registry \"docker.io\""
        );
    }

    #[test]
    fn name_unknown_reports_missing_repository() {
        let err = OciDiskError::registry(
            "ghcr.io/acme/missing-image:latest",
            registry_error(OciErrorCode::NameUnknown, "repository unknown"),
        );

        assert_eq!(
            err.to_string(),
            "image \"ghcr.io/acme/missing-image:latest\" was not found: repository \"acme/missing-image\" does not exist on registry \"ghcr.io\""
        );
    }

    #[test]
    fn manifest_404_reports_missing_digest() {
        let err = OciDiskError::registry_manifest(
            "docker.io/library/ubuntu@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            OciDistributionError::ServerError {
                code: 404,
                url: "https://index.docker.io/v2/library/ubuntu/manifests/sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                message: "not found".to_string(),
            },
        );

        assert_eq!(
            err.to_string(),
            "image \"docker.io/library/ubuntu@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" was not found: digest \"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" does not exist in repository \"library/ubuntu\" on registry \"docker.io\""
        );
    }

    #[test]
    fn blob_404_preserves_registry_error() {
        let err = OciDiskError::registry(
            "docker.io/library/ubuntu:24.04",
            OciDistributionError::ServerError {
                code: 404,
                url: "https://index.docker.io/v2/library/ubuntu/blobs/sha256:bad".to_string(),
                message: "not found".to_string(),
            },
        );

        assert!(matches!(err, OciDiskError::Registry { .. }));
        assert!(err.to_string().contains("registry request for image"));
    }

    #[test]
    fn rate_limit_preserves_registry_error() {
        let err = OciDiskError::registry(
            "docker.io/library/ubuntu:24.04",
            registry_error(OciErrorCode::Toomanyrequests, "pull request limit exceeded"),
        );

        assert!(matches!(err, OciDiskError::Registry { .. }));
        assert!(err.to_string().contains("registry request for image"));
    }

    fn registry_error(code: OciErrorCode, message: &str) -> OciDistributionError {
        OciDistributionError::RegistryError {
            url: "https://registry.example.test/v2/image/manifests/tag".to_string(),
            envelope: OciEnvelope {
                errors: vec![OciError {
                    code,
                    message: message.to_string(),
                    detail: serde_json::Value::Null,
                }],
            },
        }
    }
}
