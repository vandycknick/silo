//! Held caller-owned disk sources for raw and qcow2 import.
//!
//! The path is resolved exactly once, with `O_NOFOLLOW`, before anything can
//! canonicalize away a final-component symlink. Classification, qcow2
//! admission, decoding, copying and provenance hashing all use the held
//! descriptor; the path is diagnostic spelling only. The caller must quiesce
//! writers: fingerprints detect a change, they do not exclude other writers.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::image::import::{DiskImportError, ForeignContainer};
use crate::image::import_types::ImageContainerKind;
use crate::storage::identity::ObjectDigest;
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::stream::open_regular_source;
use crate::storage::StorageError;
use crate::LibVmError;

/// Bounded sequential read unit for container provenance hashing.
const DIGEST_BUFFER_BYTES: usize = 1 << 20;

/// One admitted caller-owned disk. Not Clone: its descriptor is the authority.
#[derive(Debug)]
pub(crate) struct OpenDiskSource {
    file: File,
    diagnostic_path: PathBuf,
    length: u64,
    fingerprint: SourceFingerprint,
    format: AdmittedInput,
}

/// Classified by bytes, never by file name.
#[derive(Debug)]
pub(crate) enum AdmittedInput {
    Raw { geometry: vm_spec::DiskGeometry },
    Qcow2(disk_image::qcow2::Admission),
}

impl OpenDiskSource {
    pub(crate) fn open(path: &Path) -> Result<Self, DiskImportError> {
        // Lexical only: no symlink resolution and no second filesystem lookup.
        let diagnostic_path =
            std::path::absolute(path).map_err(|source| DiskImportError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        let file =
            open_regular_source(path).map_err(|error| open_error(path, &diagnostic_path, error))?;
        let metadata = file.metadata().map_err(|source| DiskImportError::Read {
            path: diagnostic_path.clone(),
            source,
        })?;
        let length = metadata.len();
        let fingerprint = SourceFingerprint::new(&metadata);
        let format = classify(&file, length, &diagnostic_path)?;
        let source = Self {
            file,
            diagnostic_path,
            length,
            fingerprint,
            format,
        };
        source.ensure_unchanged()?;
        Ok(source)
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn diagnostic_path(&self) -> &Path {
        &self.diagnostic_path
    }

    pub(crate) fn into_diagnostic_path(self) -> PathBuf {
        self.diagnostic_path
    }

    pub(crate) fn format(&self) -> &AdmittedInput {
        &self.format
    }

    /// Admitted container length; equals the decoded length only for raw.
    pub(crate) fn source_length(&self) -> u64 {
        self.length
    }

    pub(crate) fn container(&self) -> ImageContainerKind {
        match self.format {
            AdmittedInput::Raw { .. } => ImageContainerKind::Raw,
            AdmittedInput::Qcow2(_) => ImageContainerKind::Qcow2,
        }
    }

    /// Exact length of the owned raw stream this source produces.
    pub(crate) fn decoded_length(&self) -> u64 {
        match &self.format {
            AdmittedInput::Raw { geometry } => geometry.length,
            AdmittedInput::Qcow2(admission) => admission.virtual_size(),
        }
    }

    /// Detects mutation since open, including same-size same-inode writes
    /// that qcow2 admission's device/inode/length binding cannot see.
    pub(crate) fn ensure_unchanged(&self) -> Result<(), DiskImportError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| DiskImportError::Read {
                path: self.diagnostic_path.clone(),
                source,
            })?;
        if SourceFingerprint::new(&metadata) != self.fingerprint {
            return Err(self.changed());
        }
        Ok(())
    }

    /// SHA-256 of the container bytes exactly as admitted. Provenance only:
    /// it does not claim that a qcow2 container is retained anywhere.
    pub(crate) fn container_digest(&self) -> Result<ObjectDigest, DiskImportError> {
        let mut hash = Sha256::new();
        let mut buffer = vec![0; DIGEST_BUFFER_BYTES];
        let mut offset = 0;
        while offset < self.length {
            let count = (self.length - offset).min(DIGEST_BUFFER_BYTES as u64) as usize;
            let bytes = &mut buffer[..count];
            self.file
                .read_exact_at(bytes, offset)
                .map_err(|error| self.read_error(error))?;
            hash.update(&*bytes);
            offset += count as u64;
        }
        self.ensure_unchanged()?;
        Ok(ObjectDigest::from_sha256(hash.finalize().into()))
    }

    /// A failed read of a source that changed is reported as the change.
    pub(crate) fn read_error(&self, source: std::io::Error) -> DiskImportError {
        match self.ensure_unchanged() {
            Ok(()) => DiskImportError::Read {
                path: self.diagnostic_path.clone(),
                source,
            },
            Err(error) => error,
        }
    }

    pub(crate) fn storage_error(&self, error: StorageError) -> LibVmError {
        match self.ensure_unchanged() {
            Ok(()) => error.into(),
            Err(changed) => changed.into(),
        }
    }

    pub(crate) fn qcow2_error(&self, source: disk_image::qcow2::Error) -> DiskImportError {
        match (self.ensure_unchanged(), source) {
            (Err(changed), _) => changed,
            (Ok(()), disk_image::qcow2::Error::SourceChanged) => self.changed(),
            (Ok(()), source) => DiskImportError::Qcow2 {
                path: self.diagnostic_path.clone(),
                source,
            },
        }
    }

    fn changed(&self) -> DiskImportError {
        DiskImportError::SourceChanged {
            path: self.diagnostic_path.clone(),
        }
    }
}

fn open_error(path: &Path, diagnostic_path: &Path, error: StorageError) -> DiskImportError {
    let path_buf = diagnostic_path.to_path_buf();
    match error {
        StorageError::NotRegular(_) => DiskImportError::NotRegularFile { path: path_buf },
        StorageError::Io(source)
            if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32)
                && std::fs::symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink()) =>
        {
            DiskImportError::SymbolicLink { path: path_buf }
        }
        StorageError::Io(source) => DiskImportError::Open {
            path: path_buf,
            source,
        },
        other => DiskImportError::Open {
            path: path_buf,
            source: std::io::Error::other(other),
        },
    }
}

fn classify(file: &File, length: u64, path: &Path) -> Result<AdmittedInput, DiskImportError> {
    let read = |bytes: &mut [u8], offset: u64| {
        file.read_exact_at(bytes, offset)
            .map_err(|source| DiskImportError::Read {
                path: path.to_path_buf(),
                source,
            })
    };
    let mut head = [0; 512];
    let head = &mut head[..length.min(512) as usize];
    read(head, 0)?;
    if head.starts_with(&disk_image::qcow2::MAGIC) {
        return disk_image::qcow2::admit(file)
            .map(AdmittedInput::Qcow2)
            .map_err(|source| match source {
                disk_image::qcow2::Error::SourceChanged => DiskImportError::SourceChanged {
                    path: path.to_path_buf(),
                },
                source => DiskImportError::Qcow2 {
                    path: path.to_path_buf(),
                    source,
                },
            });
    }
    let mut tail = [0; 512];
    let tail = if length >= 1024 {
        read(&mut tail, length - 512)?;
        Some(&tail[..])
    } else {
        None
    };
    if let Some(container) = foreign_container(head, tail) {
        return Err(DiskImportError::UnsupportedContainer {
            path: path.to_path_buf(),
            container,
        });
    }
    // Raw has no magic: geometry here, table and filesystem admission later
    // over the owned copy establish the raw profile.
    if length == 0
        || !length.is_multiple_of(disk_partition::SECTOR_SIZE)
        || length > disk_partition::MAX_DISK_BYTES
    {
        return Err(DiskImportError::RawGeometry {
            path: path.to_path_buf(),
            length,
        });
    }
    Ok(AdmittedInput::Raw {
        geometry: vm_spec::DiskGeometry {
            length,
            logical_sector_size: disk_partition::SECTOR_SIZE as u32,
        },
    })
}

/// Recognized containers that are not admitted. They need offline conversion
/// to raw or qcow2; none is ever decoded or treated as raw bytes.
fn foreign_container(head: &[u8], tail: Option<&[u8]>) -> Option<ForeignContainer> {
    const SIGNATURES: &[(&[u8], ForeignContainer)] = &[
        (b"KDMV", ForeignContainer::Vmdk),
        (b"COWD", ForeignContainer::Vmdk),
        (b"# Disk DescriptorFile", ForeignContainer::Vmdk),
        (b"vhdxfile", ForeignContainer::Vhdx),
        (b"conectix", ForeignContainer::Vhd),
        (b"QED\0", ForeignContainer::Qed),
        (b"LUKS\xba\xbe", ForeignContainer::Luks),
        (b"\x1f\x8b", ForeignContainer::Gzip),
        (b"\xfd7zXZ\0", ForeignContainer::Xz),
        (b"\x28\xb5\x2f\xfd", ForeignContainer::Zstd),
        (b"BZh", ForeignContainer::Bzip2),
    ];
    const VDI_SIGNATURE: [u8; 4] = 0xbeda_107f_u32.to_le_bytes();
    SIGNATURES
        .iter()
        .find(|(signature, _)| head.starts_with(signature))
        .map(|(_, container)| *container)
        .or_else(|| (head.get(64..68) == Some(&VDI_SIGNATURE[..])).then_some(ForeignContainer::Vdi))
        // A fixed VHD is raw bytes plus a footer; the footer is not disk data.
        .or_else(|| {
            tail.is_some_and(|tail| tail.starts_with(b"conectix"))
                .then_some(ForeignContainer::Vhd)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use sha2::{Digest, Sha256};

    use crate::image::import::{DiskImportError, ForeignContainer};
    use crate::image::import_types::ImageContainerKind;
    use crate::image::local_disk::{AdmittedInput, OpenDiskSource};
    use crate::storage::identity::ObjectDigest;
    use crate::{ReadOnlyRuntime, RuntimeConfig};

    fn open(path: &Path) -> Result<OpenDiskSource, DiskImportError> {
        OpenDiskSource::open(path)
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8 + 1).collect()
    }

    #[test]
    fn admits_a_raw_regular_file_by_bytes_with_exact_geometry() {
        let temp = tempfile::tempdir().unwrap();
        // Name says qcow2; bytes say raw. Classification ignores the name.
        let path = temp.path().join("disk.qcow2");
        let bytes = pattern(1 << 20);
        std::fs::write(&path, &bytes).unwrap();

        let source = open(&path).unwrap();
        assert_eq!(source.container(), ImageContainerKind::Raw);
        assert_eq!(source.decoded_length(), 1 << 20);
        assert!(matches!(
            source.format(),
            AdmittedInput::Raw { geometry } if geometry.length == 1 << 20 && geometry.logical_sector_size == 512
        ));
        assert_eq!(
            source.diagnostic_path(),
            std::path::absolute(&path).unwrap()
        );
        assert_eq!(
            source.container_digest().unwrap(),
            ObjectDigest::from_sha256(Sha256::digest(&bytes).into())
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "source is never modified"
        );
    }

    #[test]
    fn rejects_a_final_symlink_but_admits_symlinked_parent_directories() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("disk.raw"), pattern(4096)).unwrap();
        std::os::unix::fs::symlink(real.join("disk.raw"), temp.path().join("link.raw")).unwrap();
        std::os::unix::fs::symlink(&real, temp.path().join("parent")).unwrap();

        assert!(matches!(
            open(&temp.path().join("link.raw")),
            Err(DiskImportError::SymbolicLink { path }) if path == temp.path().join("link.raw")
        ));
        let through_parent = open(&temp.path().join("parent/disk.raw")).unwrap();
        assert_eq!(
            through_parent.diagnostic_path(),
            temp.path().join("parent/disk.raw"),
            "diagnostic spelling is lexical, never re-resolved"
        );
    }

    #[test]
    fn rejects_directories_fifos_and_devices_without_reading_them() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            open(temp.path()),
            Err(DiskImportError::NotRegularFile { .. })
        ));
        let fifo = temp.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert!(matches!(
            open(&fifo),
            Err(DiskImportError::NotRegularFile { .. })
        ));
        assert!(matches!(
            open(Path::new("/dev/null")),
            Err(DiskImportError::NotRegularFile { .. })
        ));
        assert!(matches!(
            open(&temp.path().join("missing")),
            Err(DiskImportError::Open { .. })
        ));
    }

    #[test]
    fn rejects_unaligned_empty_and_oversized_raw_geometry() {
        let temp = tempfile::tempdir().unwrap();
        for length in [0_u64, 1000, (1 << 40) + 512] {
            let path = temp.path().join(format!("disk-{length}"));
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(length).unwrap();
            assert!(
                matches!(
                    open(&path),
                    Err(DiskImportError::RawGeometry { length: observed, .. }) if observed == length
                ),
                "{length}"
            );
        }
    }

    #[test]
    fn recognized_foreign_containers_need_offline_conversion() {
        let temp = tempfile::tempdir().unwrap();
        let mut vdi = vec![0; 4096];
        vdi[64..68].copy_from_slice(&0xbeda_107f_u32.to_le_bytes());
        let mut fixed_vhd = vec![0; 8192];
        fixed_vhd[8192 - 512..8192 - 504].copy_from_slice(b"conectix");
        let cases: Vec<(Vec<u8>, ForeignContainer)> = vec![
            (b"KDMV".to_vec(), ForeignContainer::Vmdk),
            (b"# Disk DescriptorFile\n".to_vec(), ForeignContainer::Vmdk),
            (b"vhdxfile".to_vec(), ForeignContainer::Vhdx),
            (b"conectix".to_vec(), ForeignContainer::Vhd),
            (fixed_vhd, ForeignContainer::Vhd),
            (b"QED\0".to_vec(), ForeignContainer::Qed),
            (b"LUKS\xba\xbe".to_vec(), ForeignContainer::Luks),
            (vec![0x1f, 0x8b, 8, 0], ForeignContainer::Gzip),
            (b"\xfd7zXZ\0".to_vec(), ForeignContainer::Xz),
            (vec![0x28, 0xb5, 0x2f, 0xfd], ForeignContainer::Zstd),
            (b"BZh9".to_vec(), ForeignContainer::Bzip2),
            (vdi, ForeignContainer::Vdi),
        ];
        for (index, (mut bytes, expected)) in cases.into_iter().enumerate() {
            bytes.resize(bytes.len().max(4096), 0);
            let path = temp.path().join(format!("disk-{index}.raw"));
            std::fs::write(&path, &bytes).unwrap();
            assert!(
                matches!(
                    open(&path),
                    Err(DiskImportError::UnsupportedContainer { container, .. }) if container == expected
                ),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn admits_qcow2_by_magic_and_reports_forbidden_features() {
        let temp = tempfile::tempdir().unwrap();
        let raw = pattern(256 * 1024);
        let path = temp.path().join("disk.img");
        let qcow2 = crate::image::import::tests::qcow2_image(&raw);
        std::fs::write(&path, &qcow2).unwrap();
        let source = open(&path).unwrap();
        assert_eq!(source.container(), ImageContainerKind::Qcow2);
        assert_eq!(source.decoded_length(), raw.len() as u64);
        assert_eq!(
            source.container_digest().unwrap(),
            ObjectDigest::from_sha256(Sha256::digest(&qcow2).into()),
            "provenance hashes the container, not the decoded disk"
        );

        // A backing-file reference is refused before any decoding.
        let mut backed = qcow2.clone();
        backed[8..16].copy_from_slice(&512_u64.to_be_bytes());
        backed[16..20].copy_from_slice(&4_u32.to_be_bytes());
        backed[512..516].copy_from_slice(b"base");
        let path = temp.path().join("backed.qcow2");
        std::fs::write(&path, backed).unwrap();
        assert!(matches!(
            open(&path),
            Err(DiskImportError::Qcow2 {
                source: disk_image::qcow2::Error::Forbidden(
                    disk_image::qcow2::Forbidden::BackingFile
                ),
                ..
            })
        ));
    }

    #[test]
    fn detects_same_size_same_inode_mutation_after_open() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("disk.raw");
        std::fs::write(&path, pattern(4096)).unwrap();
        let source = open(&path).unwrap();
        source.ensure_unchanged().unwrap();

        // Explicit timestamps keep this deterministic on coarse-clock filesystems.
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&writer, b"x", 7).unwrap();
        writer
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            source.ensure_unchanged(),
            Err(DiskImportError::SourceChanged { .. })
        ));
        assert!(matches!(
            source.container_digest(),
            Err(DiskImportError::SourceChanged { .. })
        ));
    }

    #[tokio::test]
    async fn read_only_disk_planning_does_not_write_state() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let data_root = temp.path().join("data");
        let disk = temp.path().join("rootfs.img");
        std::fs::write(&disk, pattern(4096)).expect("write local disk");
        let before = std::fs::read_dir(temp.path())
            .expect("read temporary directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect::<BTreeSet<_>>();
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        assert_eq!(
            runtime
                .validate_disk_source(&disk)
                .expect("plan local disk"),
            std::path::absolute(&disk).expect("absolute local disk")
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read temporary directory")
                .map(|entry| entry.expect("directory entry").file_name())
                .collect::<BTreeSet<_>>(),
            before
        );
        assert!(!data_root.exists());
    }
}
