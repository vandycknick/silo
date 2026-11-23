//! Reboot-stable hibernation checks, deliberately separate from SourceFingerprint.
use std::fs::File;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use vm_spec::hibernate::HibernateFileBinding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HibernateFileFact {
    Path,
    Inode,
    Size,
    Mode,
    ModificationTime,
    ChangeTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HibernateFileKind {
    Saved,
    Disk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HibernateUnusableReason {
    #[error("files are missing")]
    FilesMissing,
    #[error("files were changed")]
    FilesChanged,
    #[error("disks were changed")]
    DisksChanged,
    #[error("not compatible with this system")]
    NotCompatible,
}

#[derive(Debug, thiserror::Error)]
pub enum HibernateFileError {
    #[error("file is missing")]
    Missing,
    #[error("file fact changed: {0:?}")]
    Changed(HibernateFileFact),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl HibernateFileError {
    /// I/O failures remain errors, not invented evidence of a modification.
    pub fn reason(&self, kind: HibernateFileKind) -> Option<HibernateUnusableReason> {
        match (self, kind) {
            (Self::Missing, _) => Some(HibernateUnusableReason::FilesMissing),
            (Self::Changed(_), HibernateFileKind::Saved) => {
                Some(HibernateUnusableReason::FilesChanged)
            }
            (Self::Changed(_), HibernateFileKind::Disk) => {
                Some(HibernateUnusableReason::DisksChanged)
            }
            (Self::Io(_), _) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HibernateFileCheck {
    binding: HibernateFileBinding,
}

impl HibernateFileCheck {
    pub fn capture(path: &Path, file: &File) -> io::Result<Self> {
        let stat = nix::sys::stat::fstat(file).map_err(io::Error::from)?;
        #[cfg(target_os = "macos")]
        let mode = u32::from(stat.st_mode);
        #[cfg(not(target_os = "macos"))]
        let mode = stat.st_mode;
        Ok(Self {
            binding: HibernateFileBinding {
                path: path.to_path_buf(),
                inode: stat.st_ino,
                size: u64::try_from(stat.st_size)
                    .map_err(|_| io::Error::other("negative file size"))?,
                mode,
                modified_seconds: stat.st_mtime,
                modified_nanoseconds: stat.st_mtime_nsec,
                changed_seconds: stat.st_ctime,
                changed_nanoseconds: stat.st_ctime_nsec,
            },
        })
    }

    pub fn binding(&self) -> &HibernateFileBinding {
        &self.binding
    }

    pub fn compare(&self, expected: &HibernateFileBinding) -> Result<(), HibernateFileError> {
        let actual = &self.binding;
        let difference = if actual.path != expected.path {
            Some(HibernateFileFact::Path)
        } else if actual.inode != expected.inode {
            Some(HibernateFileFact::Inode)
        } else if actual.size != expected.size {
            Some(HibernateFileFact::Size)
        } else if actual.mode != expected.mode {
            Some(HibernateFileFact::Mode)
        } else if (actual.modified_seconds, actual.modified_nanoseconds)
            != (expected.modified_seconds, expected.modified_nanoseconds)
        {
            Some(HibernateFileFact::ModificationTime)
        } else if (actual.changed_seconds, actual.changed_nanoseconds)
            != (expected.changed_seconds, expected.changed_nanoseconds)
        {
            Some(HibernateFileFact::ChangeTime)
        } else {
            None
        };
        match difference {
            Some(fact) => Err(HibernateFileError::Changed(fact)),
            None => Ok(()),
        }
    }

    /// Reopen without following a replaced symlink and retain the checked FD.
    pub fn open(expected: &HibernateFileBinding) -> Result<File, HibernateFileError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits(),
            )
            .open(&expected.path)
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => HibernateFileError::Missing,
                _ if error.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) => {
                    HibernateFileError::Changed(HibernateFileFact::Inode)
                }
                _ => HibernateFileError::Io(error),
            })?;
        Self::capture(&expected.path, &file)?.compare(expected)?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, SystemTime};

    use crate::storage::hibernate_file::{
        HibernateFileCheck, HibernateFileError, HibernateFileFact, HibernateFileKind,
        HibernateUnusableReason,
    };

    #[test]
    fn hibernation_file_facts_detect_real_file_changes() {
        for change in [
            "replace",
            "truncate",
            "append",
            "chmod",
            "touch",
            "rewrite",
            "missing",
            "untouched",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state");
            std::fs::write(&path, b"saved bytes").unwrap();
            let held = std::fs::File::open(&path).unwrap();
            let expected = HibernateFileCheck::capture(&path, &held)
                .unwrap()
                .binding()
                .clone();
            let fact = match change {
                "replace" => {
                    let other = directory.path().join("other");
                    std::fs::write(&other, b"saved bytes").unwrap();
                    std::fs::rename(other, &path).unwrap();
                    Some(HibernateFileFact::Inode)
                }
                "truncate" => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(2)
                        .unwrap();
                    Some(HibernateFileFact::Size)
                }
                "append" => {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"!")
                        .unwrap();
                    Some(HibernateFileFact::Size)
                }
                "chmod" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                    Some(HibernateFileFact::Mode)
                }
                "touch" => {
                    held.set_modified(SystemTime::now() + Duration::from_secs(10))
                        .unwrap();
                    Some(HibernateFileFact::ModificationTime)
                }
                "rewrite" => {
                    // Restore mtime so this specifically exercises kernel ctime.
                    let modified = held.metadata().unwrap().modified().unwrap();
                    std::thread::sleep(Duration::from_millis(2));
                    std::fs::write(&path, b"other bytes").unwrap();
                    held.set_modified(modified).unwrap();
                    Some(HibernateFileFact::ChangeTime)
                }
                "missing" => {
                    std::fs::remove_file(&path).unwrap();
                    None
                }
                "untouched" => None,
                _ => unreachable!(),
            };
            match HibernateFileCheck::open(&expected) {
                Ok(_) => assert_eq!(change, "untouched"),
                Err(HibernateFileError::Changed(actual)) => assert_eq!(Some(actual), fact),
                Err(HibernateFileError::Missing) => assert_eq!(change, "missing"),
                Err(error) => panic!("{change}: {error}"),
            }
        }
    }

    #[test]
    fn hibernation_file_reason_and_path_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let expected = HibernateFileCheck::capture(&path, &file).unwrap();
        let other = HibernateFileCheck::capture(&directory.path().join("alias"), &file).unwrap();
        let error = other.compare(expected.binding()).unwrap_err();
        assert!(matches!(
            error,
            HibernateFileError::Changed(HibernateFileFact::Path)
        ));
        assert_eq!(
            error.reason(HibernateFileKind::Saved),
            Some(HibernateUnusableReason::FilesChanged)
        );
        assert_eq!(
            error.reason(HibernateFileKind::Disk),
            Some(HibernateUnusableReason::DisksChanged)
        );
        assert_eq!(
            HibernateFileError::Missing.reason(HibernateFileKind::Disk),
            Some(HibernateUnusableReason::FilesMissing)
        );
    }
}
