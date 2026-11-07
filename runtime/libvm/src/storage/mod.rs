//! Immutable storage identities, admission bounds and durable local publication.
//!
//! Byte-object digests and logical stream IDs deliberately occupy different types
//! and directories. These primitives do not assign image or snapshot semantics.
pub mod composition;
pub mod identity;
pub mod identity_file;
pub mod limits;
pub mod locks;
pub mod map;
pub mod pool;
pub mod stream;
pub mod vmdk;

pub use crate::store::layer_store::{LayerStore, RetainedLayer};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Identity(#[from] identity::IdentityError),
    #[error(transparent)]
    Bound(#[from] limits::BoundViolation),
    #[error(transparent)]
    FileDescriptorBudget(#[from] limits::FileDescriptorBudgetError),
    #[error("capture {resource} budget requires {required} bytes, available {available} bytes")]
    CaptureBudget {
        resource: &'static str,
        required: u64,
        available: u64,
    },
    #[error("restore {resource} budget requires {required} bytes, available {available} bytes")]
    RestoreBudget {
        resource: &'static str,
        required: u64,
        available: u64,
    },
    #[error("invalid owned storage path: {0}")]
    InvalidPath(String),
    #[error("stream map has {actual} chunks, expected {expected} for its length")]
    ChunkCount { expected: u64, actual: u64 },
    #[error("immutable content at {0} does not match its identity")]
    ContentMismatch(std::path::PathBuf),
    #[error("source is not a regular file: {0}")]
    NotRegular(std::path::PathBuf),
    #[error("source changed while being retained: {0}")]
    SourceChanged(std::path::PathBuf),
    #[error("lower stream {stream} has length {actual}, expected retained length {expected}")]
    LowerLength {
        stream: identity::StreamId,
        expected: u64,
        actual: u64,
    },
}

impl From<nix::errno::Errno> for StorageError {
    fn from(error: nix::errno::Errno) -> Self {
        Self::Io(std::io::Error::from_raw_os_error(error as i32))
    }
}
