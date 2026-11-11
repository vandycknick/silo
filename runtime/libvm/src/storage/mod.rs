//! Immutable storage identities, admission bounds and durable local publication.
//!
//! Byte-object digests and logical stream IDs deliberately occupy different types
//! and directories. These primitives do not assign image or snapshot semantics.
pub(crate) mod clone;
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
    #[error("restore disk budget requires {}, available {} (short by {})", utils::format_storage_size(*required), utils::format_storage_size(*available), utils::format_storage_size(required.saturating_sub(*available)))]
    RestoreDiskBudget { required: u64, available: u64 },
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
    #[error("lower {backing} has length {}, expected retained length {}", utils::format_storage_size(*actual), utils::format_storage_size(*expected))]
    LowerLength {
        backing: crate::storage::vmdk::LowerBacking,
        expected: u64,
        actual: u64,
    },
}

impl From<nix::errno::Errno> for StorageError {
    fn from(error: nix::errno::Errno) -> Self {
        Self::Io(std::io::Error::from_raw_os_error(error as i32))
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::StorageError;

    #[test]
    fn byte_budgets_show_sizes_and_shortfall_even_when_rounded_equal() {
        assert_eq!(
            StorageError::RestoreDiskBudget {
                required: (1 << 30) + 1,
                available: 1 << 30,
            }
            .to_string(),
            "restore disk budget requires 1.0GiB, available 1GiB (short by 1B)"
        );
        assert_eq!(
            StorageError::RestoreDiskBudget {
                required: 0,
                available: 0,
            }
            .to_string(),
            "restore disk budget requires 0B, available 0B (short by 0B)"
        );
    }
}
