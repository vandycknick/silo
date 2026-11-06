use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Filesystem identity obtained without opening a database inode.
///
/// Path-based stat is lock-preserving on Linux and macOS: unlike opening and
/// closing an ordinary descriptor, it cannot drop SQLite's POSIX record locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    pub fn from_path(path: &Path) -> io::Result<Self> {
        std::fs::metadata(path).map(|metadata| Self::from_metadata(&metadata))
    }

    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceFingerprint {
    identity: FileIdentity,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl SourceFingerprint {
    pub(crate) fn new(metadata: &Metadata) -> Self {
        Self {
            identity: FileIdentity::from_metadata(metadata),
            length: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    pub(crate) fn same_contents_after_metadata_change(&self, metadata: &Metadata) -> bool {
        self.identity == FileIdentity::from_metadata(metadata)
            && self.length == metadata.len()
            && self.mtime == (metadata.mtime(), metadata.mtime_nsec())
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::identity_file::FileIdentity;

    #[test]
    fn identifies_renames_and_replacements_without_opening_files() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("state.db");
        std::fs::write(&original, b"database").unwrap();
        let identity = FileIdentity::from_path(&original).unwrap();
        let moved = dir.path().join("moved");
        std::fs::rename(&original, &moved).unwrap();
        assert_eq!(identity, FileIdentity::from_path(&moved).unwrap());
        std::fs::write(&original, b"replacement").unwrap();
        assert_ne!(identity, FileIdentity::from_path(&original).unwrap());
    }
}
