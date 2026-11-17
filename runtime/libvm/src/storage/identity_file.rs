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
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl SourceFingerprint {
    pub(crate) fn new(metadata: &Metadata) -> Self {
        Self {
            identity: FileIdentity::from_metadata(metadata),
            length: metadata.len(),
            mode: metadata.mode(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    pub(crate) fn to_capture(self) -> vm_spec::capture::SourceFingerprint {
        vm_spec::capture::SourceFingerprint {
            device: self.identity.device,
            inode: self.identity.inode,
            length: self.length,
            mode: self.mode,
            modified_seconds: self.mtime.0,
            modified_nanoseconds: self.mtime.1,
            changed_seconds: self.ctime.0,
            changed_nanoseconds: self.ctime.1,
        }
    }

    pub(crate) fn from_capture(value: &vm_spec::capture::SourceFingerprint) -> Self {
        Self {
            identity: FileIdentity {
                device: value.device,
                inode: value.inode,
            },
            length: value.length,
            mode: value.mode,
            mtime: (value.modified_seconds, value.modified_nanoseconds),
            ctime: (value.changed_seconds, value.changed_nanoseconds),
        }
    }

    /// SQLite stores unsigned device/inode bits in signed INTEGER columns.
    pub(crate) fn verification_key(&self) -> [i64; 6] {
        [
            self.identity.device as i64,
            self.identity.inode as i64,
            self.length as i64,
            i64::from(self.mode),
            self.ctime.0,
            self.ctime.1,
        ]
    }

    pub(crate) fn same_contents_after_metadata_change(&self, metadata: &Metadata) -> bool {
        self.identity == FileIdentity::from_metadata(metadata)
            && self.length == metadata.len()
            && self.mtime == (metadata.mtime(), metadata.mtime_nsec())
    }
}

/// Prove that producer closure did not leave a writable open description behind.
pub(crate) fn reject_surviving_writer(file: &std::fs::File) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // nix does not expose F_SETLEASE. Complete-cut authority and exact
        // descriptor rechecks own lifetime after this short admission probe.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file;
    Ok(())
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

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_admission_refuses_surviving_writers_and_roundtrips_exact_facts() {
        use crate::storage::identity_file::{reject_surviving_writer, SourceFingerprint};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owned");
        std::fs::write(&path, b"complete bytes").unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let reader = std::fs::File::open(&path).unwrap();
        let before = SourceFingerprint::new(&reader.metadata().unwrap());
        assert_eq!(
            SourceFingerprint::from_capture(&before.to_capture()),
            before
        );
        assert!(reject_surviving_writer(&reader).is_err());
        drop(writer);
        reject_surviving_writer(&reader).unwrap();
    }
}
