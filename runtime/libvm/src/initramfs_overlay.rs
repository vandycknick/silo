use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_spec::MAX_AGENT_CONFIG_SIZE_BYTES;
use cpio::newc::ModeFileType;
use cpio::NewcBuilder;
use eyre::Context;

use crate::owned_boot_assets::OwnedBootAsset;

const DIRECTORY_MODE: u32 = 0o755;
const AGENT_MODE: u32 = 0o755;
const CONFIG_MODE: u32 = 0o600;

pub(crate) enum CompositeBase<'a> {
    Path(&'a Path),
    Owned(&'a crate::OwnedOverlayBoot),
    Retained(&'a OwnedBootAsset),
}

#[derive(Clone, Copy)]
pub(crate) enum CompositeAgent<'a> {
    Path(&'a Path),
    Retained(&'a OwnedBootAsset),
}

pub(crate) fn write_composite(
    base: CompositeBase<'_>,
    agent_payload: Option<(CompositeAgent<'_>, &[u8])>,
    root_bootstrap: Option<&[u8]>,
    destination: &Path,
) -> eyre::Result<File> {
    if let Some(root) = root_bootstrap {
        if root.len() > rootfs_spec::MAX_JSON_BYTES {
            eyre::bail!("root bootstrap exceeds bounded wire limit");
        }
    }
    if let Some((_, config)) = agent_payload {
        if config.len() > MAX_AGENT_CONFIG_SIZE_BYTES {
            eyre::bail!(
                "serialized agent config exceeds {} limit",
                utils::format_storage_size(MAX_AGENT_CONFIG_SIZE_BYTES as u64)
            );
        }
    }
    let opened_agent = match agent_payload {
        Some((CompositeAgent::Path(path), _)) => Some(OwnedBootAsset::open(path)?),
        _ => None,
    };
    let agent_payload = agent_payload
        .map(|(source, config)| -> eyre::Result<_> {
            let agent = match source {
                CompositeAgent::Path(_) => opened_agent
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("opened agent is missing"))?,
                CompositeAgent::Retained(asset) => asset,
            };
            let size = u32::try_from(agent.length()).context("agent is too large for newc")?;
            Ok((agent, config, size))
        })
        .transpose()?;

    let parent = destination.parent().ok_or_else(|| {
        eyre::eyre!(
            "composite initramfs has no parent: {}",
            destination.display()
        )
    })?;
    let temporary = parent.join(format!(".initramfs.{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut guard = TemporaryFile::new(temporary.clone());
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create temporary initramfs {}", temporary.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protect temporary initramfs {}", temporary.display()))?;

    let base_size = match base {
        CompositeBase::Path(path) => {
            let mut source = File::open(path)
                .with_context(|| format!("open base initramfs {}", path.display()))?;
            io::copy(&mut source, &mut output)
                .with_context(|| format!("copy base initramfs {}", path.display()))?
        }
        CompositeBase::Owned(assets) => assets.copy_initramfs(&mut output)?,
        CompositeBase::Retained(asset) => asset.copy_into(&mut output)?,
    };
    let padding = (4 - (base_size % 4)) % 4;
    if padding != 0 {
        output
            .write_all(&[0; 3][..padding as usize])
            .context("align initramfs overlay")?;
    }

    if let Some((agent, config, size)) = agent_payload {
        write_directory(&mut output, 1)?;
        write_agent(&mut output, agent, size, 2)?;
        write_bytes(
            &mut output,
            "agent/config.json",
            config,
            u32::try_from(config.len()).context("agent config is too large for newc")?,
            CONFIG_MODE,
            3,
        )?;
    }
    if let Some(root) = root_bootstrap {
        entry("silo", 4, DIRECTORY_MODE, ModeFileType::Directory)
            .write(&mut output, 0)
            .finish()
            .context("write root bootstrap directory")?;
        write_bytes(
            &mut output,
            "silo/rootfs.json",
            root,
            u32::try_from(root.len()).context("root bootstrap is too large for newc")?,
            CONFIG_MODE,
            5,
        )?;
    }
    cpio::newc::trailer(&mut output).context("write initramfs overlay trailer")?;
    output.flush().context("flush composite initramfs")?;

    fs::rename(&temporary, destination).with_context(|| {
        format!(
            "replace composite initramfs {} with {}",
            destination.display(),
            temporary.display()
        )
    })?;
    guard.disarm();
    Ok(output)
}

fn entry(name: &str, inode: u32, mode: u32, file_type: ModeFileType) -> NewcBuilder {
    NewcBuilder::new(name)
        .ino(inode)
        .uid(0)
        .gid(0)
        .nlink(if matches!(file_type, ModeFileType::Directory) {
            2
        } else {
            1
        })
        .mode(mode)
        .mtime(0)
        .set_mode_file_type(file_type)
}

fn write_directory(writer: &mut File, inode: u32) -> eyre::Result<()> {
    entry("agent", inode, DIRECTORY_MODE, ModeFileType::Directory)
        .write(writer, 0)
        .finish()
        .context("write agent directory")?;
    Ok(())
}

fn write_agent(
    writer: &mut File,
    source: &OwnedBootAsset,
    size: u32,
    inode: u32,
) -> eyre::Result<()> {
    let mut entry_writer =
        entry("agent/silo-agent", inode, AGENT_MODE, ModeFileType::Regular).write(writer, size);
    let copied = source.copy_into(&mut entry_writer)?;
    if copied != u64::from(size) {
        eyre::bail!("agent changed while composing initramfs");
    }
    entry_writer
        .finish()
        .context("finish agent archive entry")?;
    Ok(())
}

fn write_bytes(
    writer: &mut File,
    name: &str,
    bytes: &[u8],
    size: u32,
    mode: u32,
    inode: u32,
) -> eyre::Result<()> {
    let mut entry_writer = entry(name, inode, mode, ModeFileType::Regular).write(writer, size);
    entry_writer
        .write_all(bytes)
        .with_context(|| format!("write {name}"))?;
    entry_writer
        .finish()
        .with_context(|| format!("finish {name}"))?;
    Ok(())
}

struct TemporaryFile {
    path: Option<PathBuf>,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::os::unix::fs::PermissionsExt;

    use crate::initramfs_overlay::{write_composite, MAX_AGENT_CONFIG_SIZE_BYTES};

    #[test]
    fn preserves_base_and_writes_exact_overlay() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("base");
        let agent = temp.path().join("agent");
        let output = temp.path().join("composite");
        std::fs::write(&base, b"base-bytes").expect("write base");
        std::fs::write(&agent, b"agent-bytes").expect("write agent");

        let published = write_composite(
            crate::initramfs_overlay::CompositeBase::Path(&base),
            Some((
                crate::initramfs_overlay::CompositeAgent::Path(&agent),
                br#"{}"#,
            )),
            None,
            &output,
        )
        .expect("compose initramfs");

        let bytes = std::fs::read(&output).expect("read output");
        assert_eq!(
            published.metadata().expect("published metadata").len(),
            bytes.len() as u64
        );
        assert_eq!(&bytes[..10], b"base-bytes");
        let overlay_offset = 12;
        assert_eq!(&bytes[10..overlay_offset], &[0, 0]);

        let mut input = Cursor::new(&bytes[overlay_offset..]);
        let mut entries = Vec::new();
        loop {
            let mut reader = cpio::NewcReader::new(input).expect("read newc entry");
            if reader.entry().is_trailer() {
                break;
            }
            let name = reader.entry().name().to_string();
            let mode = reader.entry().mode();
            let uid = reader.entry().uid();
            let gid = reader.entry().gid();
            let mtime = reader.entry().mtime();
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents).expect("read entry");
            input = reader.finish().expect("finish entry");
            entries.push((name, mode, uid, gid, mtime, contents));
        }

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "agent");
        assert_eq!(entries[0].1 & 0o170000, 0o040000);
        assert_eq!(entries[0].1 & 0o777, 0o755);
        assert_eq!(entries[1].0, "agent/silo-agent");
        assert_eq!(entries[1].1 & 0o777, 0o755);
        assert_eq!(entries[1].5, b"agent-bytes");
        assert_eq!(entries[2].0, "agent/config.json");
        assert_eq!(entries[2].1 & 0o777, 0o600);
        assert_eq!(entries[2].5, br#"{}"#);
        assert!(entries
            .iter()
            .all(|(_, _, uid, gid, mtime, _)| *uid == 0 && *gid == 0 && *mtime == 0));
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn replacement_does_not_accumulate_overlays() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("base");
        let agent = temp.path().join("agent");
        let output = temp.path().join("composite");
        std::fs::write(&base, b"base").expect("write base");
        std::fs::write(&agent, b"agent").expect("write agent");

        write_composite(
            crate::initramfs_overlay::CompositeBase::Path(&base),
            Some((
                crate::initramfs_overlay::CompositeAgent::Path(&agent),
                b"first",
            )),
            None,
            &output,
        )
        .expect("first composite");
        let first_len = std::fs::metadata(&output).expect("first metadata").len();
        write_composite(
            crate::initramfs_overlay::CompositeBase::Path(&base),
            Some((
                crate::initramfs_overlay::CompositeAgent::Path(&agent),
                b"other",
            )),
            None,
            &output,
        )
        .expect("second composite");
        let second = std::fs::read(&output).expect("second output");

        assert_eq!(second.len() as u64, first_len);
        assert!(!second.windows(5).any(|window| window == b"first"));
        assert_eq!(&second[..4], b"base");
    }

    #[test]
    fn rejects_oversized_config_without_replacing_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("base");
        let agent = temp.path().join("agent");
        let output = temp.path().join("composite");
        std::fs::write(&base, b"base").expect("write base");
        std::fs::write(&agent, b"agent").expect("write agent");
        std::fs::write(&output, b"previous").expect("write previous");

        let error = write_composite(
            crate::initramfs_overlay::CompositeBase::Path(&base),
            Some((
                crate::initramfs_overlay::CompositeAgent::Path(&agent),
                &vec![0; MAX_AGENT_CONFIG_SIZE_BYTES + 1],
            )),
            None,
            &output,
        )
        .expect_err("oversized config must fail");

        assert!(error.to_string().contains("exceeds"));
        assert_eq!(
            std::fs::read(&output).expect("previous output"),
            b"previous"
        );
    }

    #[test]
    fn root_bootstrap_is_injected_without_agent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("base");
        let output = temp.path().join("composite");
        std::fs::write(&base, b"base").unwrap();
        let root = br#"{"schemaVersion":1,"root":{"kind":"opaque-raw-v1"}}"#;
        write_composite(
            crate::initramfs_overlay::CompositeBase::Path(&base),
            None,
            Some(root),
            &output,
        )
        .unwrap();
        let bytes = std::fs::read(output).unwrap();
        let input = Cursor::new(&bytes[4..]);
        let directory = cpio::NewcReader::new(input).unwrap();
        assert_eq!(directory.entry().name(), "silo");
        assert_eq!(directory.entry().uid(), 0);
        let mut root_entry = cpio::NewcReader::new(directory.finish().unwrap()).unwrap();
        assert_eq!(root_entry.entry().name(), "silo/rootfs.json");
        assert_eq!(root_entry.entry().mode() & 0o777, 0o600);
        assert_eq!(root_entry.entry().uid(), 0);
        assert_eq!(root_entry.entry().gid(), 0);
        let mut contents = Vec::new();
        root_entry.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, root);
        let trailer = cpio::NewcReader::new(root_entry.finish().unwrap()).unwrap();
        assert!(trailer.entry().is_trailer());
    }
}
