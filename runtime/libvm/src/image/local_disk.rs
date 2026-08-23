use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::LibVmError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalDiskSource {
    pub(crate) canonical_path: PathBuf,
    pub(crate) image_id: String,
}

pub(crate) fn resolve_local_disk(path: &Path) -> Result<LocalDiskSource, LibVmError> {
    let canonical_path =
        path.canonicalize()
            .map_err(|source| LibVmError::LocalDiskCanonicalize {
                path: path.to_path_buf(),
                source,
            })?;
    let metadata = canonical_path
        .metadata()
        .map_err(|source| LibVmError::LocalDiskMetadata {
            path: canonical_path.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(LibVmError::LocalDiskNotRegularFile {
            path: canonical_path,
        });
    }
    fs::File::open(&canonical_path).map_err(|source| LibVmError::LocalDiskUnreadable {
        path: canonical_path.clone(),
        source,
    })?;

    Ok(LocalDiskSource {
        image_id: format!(
            "local-disk-sha256:{}",
            sha256_hex(canonical_path.to_string_lossy().as_bytes())
        ),
        canonical_path,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sha2::{Digest, Sha256};

    use crate::image::local_disk::resolve_local_disk;
    use crate::{LibVmError, ReadOnlyRuntime, RuntimeConfig};

    #[test]
    fn resolves_a_real_file_to_its_canonical_path_and_exact_identity() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let real = temp.path().join("images/rootfs.img");
        std::fs::create_dir_all(real.parent().expect("image parent")).expect("create image parent");
        std::fs::write(&real, b"local disk").expect("write local disk");

        let source = resolve_local_disk(&temp.path().join("images/../images/rootfs.img"))
            .expect("resolve local disk");
        let canonical = real.canonicalize().expect("canonical local disk");

        assert_eq!(source.canonical_path, canonical);
        let expected_digest = Sha256::digest(canonical.to_string_lossy().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            source.image_id,
            format!("local-disk-sha256:{expected_digest}")
        );
    }

    #[test]
    fn rejects_a_real_directory() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        assert!(matches!(
            resolve_local_disk(temp.path()),
            Err(LibVmError::LocalDiskNotRegularFile { .. })
        ));
    }

    #[tokio::test]
    async fn read_only_disk_planning_does_not_write_state() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let data_root = temp.path().join("data");
        let disk = temp.path().join("rootfs.img");
        std::fs::write(&disk, b"local disk").expect("write local disk");
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
            disk.canonicalize().expect("canonical local disk")
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
