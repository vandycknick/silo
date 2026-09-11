use std::fs::File;
use std::path::Path;

use disk_image::ext4::constants::{file_mode, make_mode};
use disk_image::ext4::{FormatOptions, Formatter, Reader};
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
        Some(&mut bytes.as_slice()),
        Some(0),
        Some(0),
        None,
    )?;
    formatter
        .close()
        .context("finalize system data ext4 image")?;
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(crate) fn validate_data_image(
    path: &Path,
    size: u64,
    installation_id: Uuid,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("inspect data image {}", path.display()))?;
    if metadata.len() != size {
        bail!(
            "recorded system data image has size {}, expected {}; resizing is not supported",
            metadata.len(),
            size
        );
    }
    let mut reader = Reader::new(path).context("open system data ext4 image")?;
    if reader.superblock().uuid != *data_uuid.as_bytes() {
        bail!("system data filesystem UUID does not match installation record");
    }
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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::system::storage::{ensure_data_image, validate_data_image};

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
