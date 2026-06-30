use std::path::PathBuf;

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
        source: containerregistry_registry::Error,
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
    pub(crate) fn registry(
        reference: impl Into<String>,
        source: containerregistry_registry::Error,
    ) -> Self {
        Self::Registry {
            reference: reference.into(),
            source,
        }
    }

    pub(crate) fn ext4(source: impl std::fmt::Display) -> Self {
        Self::Ext4 {
            message: source.to_string(),
        }
    }
}
