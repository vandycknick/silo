use std::fs::File;
use std::path::Path;

use disk_image::ext4::constants::{file_mode, make_mode};
use disk_image::ext4::{read_superblock, FormatOptions, Formatter, Reader};
use eyre::{bail, Context as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DATA_LABEL: &str = "silo-system";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DataLayout {
    layout: u32,
    installation_id: Uuid,
    data_uuid: Uuid,
}

pub(crate) fn ensure_data_image(
    path: &Path,
    size: u64,
    installation_id: Uuid,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    if path.exists() {
        return validate_data_image(path, size, installation_id, data_uuid);
    }
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("data image path has no parent"))?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temporary = parent.join(format!(".data.img.{}.tmp", Uuid::new_v4()));
    let result = create_data_image(&temporary, size, installation_id, data_uuid);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if path.exists() {
        let _ = std::fs::remove_file(&temporary);
        return validate_data_image(path, size, installation_id, data_uuid);
    }
    std::fs::rename(&temporary, path).with_context(|| format!("install {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    validate_data_image(path, size, installation_id, data_uuid)
}

fn create_data_image(
    path: &Path,
    size: u64,
    installation_id: Uuid,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let options = FormatOptions::new(size).uuid(data_uuid).label(DATA_LABEL);
    let mut formatter =
        Formatter::with_options(path, options).context("format system data ext4 image")?;
    let directory_mode = make_mode(file_mode::S_IFDIR, 0o700);
    formatter.create(
        "/docker",
        directory_mode,
        None,
        None,
        None,
        Some(0),
        Some(0),
        None,
        None,
    )?;
    formatter.create(
        "/containerd",
        directory_mode,
        None,
        None,
        None,
        Some(0),
        Some(0),
        None,
        None,
    )?;
    let layout = DataLayout {
        layout: 1,
        installation_id,
        data_uuid,
    };
    let bytes = serde_json::to_vec_pretty(&layout)?;
    formatter.create(
        "/layout.json",
        make_mode(file_mode::S_IFREG, 0o600),
        None,
        None,
        Some(disk_image::ext4::FileData::Dense(&mut bytes.as_slice())),
        Some(0),
        Some(0),
        None,
        None,
    )?;
    formatter
        .close()
        .context("finalize system data ext4 image")?;
    File::open(path)?.sync_all()?;
    Ok(())
}

/// Check attachment identity without traversing a namespace the guest may have mounted.
/// Layout and directory checks belong to fresh/offline validation and guest activation.
pub(crate) fn validate_data_image_identity(
    path: &Path,
    size: u64,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    open_data_image(path, size, data_uuid).map(|_| ())
}

pub(crate) fn validate_data_image(
    path: &Path,
    size: u64,
    installation_id: Uuid,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let file = open_data_image(path, size, data_uuid)?;
    let reader = Reader::from_file(file).context("open system data ext4 image")?;
    let layout: DataLayout = serde_json::from_slice(&reader.read_file("/layout.json", 0, None)?)
        .context("parse system data layout marker")?;
    if layout
        != (DataLayout {
            layout: 1,
            installation_id,
            data_uuid,
        })
    {
        bail!("system data layout marker does not match installation record");
    }
    if !reader.exists("/docker") || !reader.exists("/containerd") {
        bail!("system data image is missing engine data directories");
    }
    Ok(())
}

fn open_data_image(path: &Path, size: u64, data_uuid: Uuid) -> eyre::Result<File> {
    let file = File::open(path).with_context(|| format!("open data image {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect data image {}", path.display()))?;
    if metadata.len() != size {
        bail!(
            "system data disk size mismatch at {}: found {}, but the daemon expects {}\n\n\
             Silo does not support resizing its data disk yet; the backing file and ext4 filesystem must be resized together. The disk was not changed.\n\n\
             hint: if keeping the data, restore the matching daemon state and daemon.system.storage.data-size setting. If starting fresh, stop Silo and reset both the daemon state and its data disk, not just the state. Removing the disk deletes its Docker images, containers, and volumes.",
            path.display(),
            utils::format_storage_size(metadata.len()),
            utils::format_storage_size(size)
        );
    }
    let superblock = read_superblock(&file).context("read system data ext4 identity")?;
    if superblock.uuid != *data_uuid.as_bytes() {
        bail!("system data filesystem UUID does not match installation record");
    }
    // The daemon formats data volumes with 4096-byte blocks and no 64-bit block count.
    // These immutable facts remain meaningful while the guest owns the live namespace.
    if superblock.log_block_size != 2
        || superblock.first_data_block != 0
        || superblock.blocks_count_hi != 0
        || u64::from(superblock.blocks_count_lo) * 4096 != size
    {
        bail!("system data filesystem geometry does not match installation record");
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::daemon::storage::{
        ensure_data_image, validate_data_image, validate_data_image_identity,
    };

    #[test]
    fn creates_real_ext4_once_and_never_replaces_corruption() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("system/data.img");
        let installation = Uuid::new_v4();
        let data = Uuid::new_v4();
        let size = 512 * 1024 * 1024;
        ensure_data_image(&path, size, installation, data).expect("create");
        ensure_data_image(&path, size, installation, data).expect("reuse");
        assert!(validate_data_image(&path, size, installation, Uuid::new_v4()).is_err());
        assert!(path.exists());
    }

    #[test]
    fn mounted_data_identity_does_not_admit_dirty_namespace_reads() {
        use std::os::unix::fs::FileExt as _;

        use disk_image::ext4::constants::{incompat, SUPERBLOCK_OFFSET};
        use disk_image::ext4::types::SUPERBLOCK_SIZE;
        use disk_image::ext4::{read_superblock, ReadError, Reader};

        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("data.img");
        let installation = Uuid::new_v4();
        let data = Uuid::new_v4();
        let size = 512 * 1024 * 1024;
        ensure_data_image(&path, size, installation, data).expect("create");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("disk");
        let clean = read_superblock(&file).expect("superblock");
        for dirty in 0..3 {
            let mut superblock = clean.clone();
            match dirty {
                0 => superblock.feature_incompat |= incompat::RECOVER,
                1 => superblock.state = 0,
                _ => superblock.last_orphan = 12,
            }
            let mut before = [0; SUPERBLOCK_SIZE];
            superblock.write_to(&mut before);
            file.write_all_at(&before, SUPERBLOCK_OFFSET)
                .expect("dirty");

            validate_data_image_identity(&path, size, data).expect("live identity");
            assert!(validate_data_image_identity(&path, size, Uuid::new_v4()).is_err());
            assert!(matches!(
                Reader::new(&path),
                Err(ReadError::RequiresRecovery(_))
            ));
            let error = validate_data_image(&path, size, installation, data)
                .expect_err("offline layout must refuse recovery");
            assert!(matches!(
                error.downcast_ref::<ReadError>(),
                Some(ReadError::RequiresRecovery(_))
            ));
            let mut after = [0; SUPERBLOCK_SIZE];
            file.read_exact_at(&mut after, SUPERBLOCK_OFFSET)
                .expect("unchanged");
            assert_eq!(
                after, before,
                "identity checks must not replay or clear dirty state"
            );
        }
    }

    #[test]
    fn data_identity_rejects_invalid_magic_and_mismatched_filesystem_geometry() {
        use std::os::unix::fs::FileExt as _;

        use disk_image::ext4::constants::SUPERBLOCK_OFFSET;
        use disk_image::ext4::read_superblock;
        use disk_image::ext4::types::SUPERBLOCK_SIZE;

        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("data.img");
        let installation = Uuid::new_v4();
        let data = Uuid::new_v4();
        let size = 512 * 1024 * 1024;
        ensure_data_image(&path, size, installation, data).expect("create");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("disk");
        let clean = read_superblock(&file).expect("superblock");
        for invalid in 0..5 {
            let mut superblock = clean.clone();
            match invalid {
                0 => superblock.magic = 0,
                1 => superblock.log_block_size = u32::MAX,
                2 => superblock.first_data_block = 1,
                3 => superblock.blocks_count_hi = 1,
                _ => superblock.blocks_count_lo -= 1,
            }
            let mut bytes = [0; SUPERBLOCK_SIZE];
            superblock.write_to(&mut bytes);
            file.write_all_at(&bytes, SUPERBLOCK_OFFSET)
                .expect("invalid identity");
            assert!(validate_data_image_identity(&path, size, data).is_err());
            let mut after = [0; SUPERBLOCK_SIZE];
            file.read_exact_at(&mut after, SUPERBLOCK_OFFSET)
                .expect("unchanged");
            assert_eq!(after, bytes);
        }
    }

    #[test]
    fn offline_layout_validation_still_checks_installation_identity() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("data.img");
        let installation = Uuid::new_v4();
        let data = Uuid::new_v4();
        let size = 512 * 1024 * 1024;
        ensure_data_image(&path, size, installation, data).expect("create");
        validate_data_image_identity(&path, size, data).expect("attachment identity");
        let error = validate_data_image(&path, size, Uuid::new_v4(), data)
            .expect_err("wrong installation layout");
        assert!(error.to_string().contains("layout marker does not match"));
    }

    #[test]
    fn data_identity_rejects_missing_and_truncated_superblocks() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("data.img");
        let data = Uuid::new_v4();
        assert!(validate_data_image_identity(&path, 0, data).is_err());
        for bytes in [b"".as_slice(), b"not an ext4 superblock".as_slice()] {
            std::fs::write(&path, bytes).expect("malformed disk");
            assert!(validate_data_image_identity(&path, bytes.len() as u64, data).is_err());
            assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
        }
    }

    #[test]
    fn size_mismatch_explains_growth_and_shrink_without_changing_the_disk() {
        use std::io::{Read as _, Write as _};

        for (actual, expected) in [(64_u64 << 30, 500_u64 << 30), (500_u64 << 30, 64_u64 << 30)] {
            let temp = tempfile::tempdir().expect("temp");
            let path = temp.path().join("data.img");
            let mut file = std::fs::File::create(&path).expect("disk");
            file.write_all(b"existing data").expect("contents");
            file.set_len(actual).expect("sparse size");
            drop(file);

            let error = ensure_data_image(&path, expected, Uuid::new_v4(), Uuid::new_v4())
                .expect_err("size mismatch")
                .to_string();
            assert!(error.contains(&path.display().to_string()));
            assert!(error.contains(&format!(
                "found {}, but the daemon expects {}",
                utils::format_storage_size(actual),
                utils::format_storage_size(expected)
            )));
            assert!(error.contains("backing file and ext4 filesystem"));
            assert!(error.contains("matching daemon state"));
            assert!(error.contains("Removing the disk deletes"));
            assert_eq!(std::fs::metadata(&path).expect("metadata").len(), actual);
            let mut contents = [0; 13];
            std::fs::File::open(&path)
                .expect("disk")
                .read_exact(&mut contents)
                .expect("contents");
            assert_eq!(&contents, b"existing data");
        }
    }

    #[test]
    fn failed_creation_preserves_existing_file() {
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("data.img");
        std::fs::write(&path, b"user data").expect("fixture");
        assert!(
            ensure_data_image(&path, 64 * 1024 * 1024, Uuid::new_v4(), Uuid::new_v4()).is_err()
        );
        assert_eq!(std::fs::read(path).expect("read"), b"user data");
    }
}
