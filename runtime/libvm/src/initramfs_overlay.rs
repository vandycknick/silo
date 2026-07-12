use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_spec::MAX_AGENT_CONFIG_SIZE_BYTES;
use cpio::newc::ModeFileType;
use cpio::NewcBuilder;
use eyre::Context;

const DIRECTORY_MODE: u32 = 0o755;
const AGENT_MODE: u32 = 0o755;
const CONFIG_MODE: u32 = 0o600;

pub(crate) fn write_composite(
    base_path: &Path,
    agent_path: &Path,
    config: &[u8],
    destination: &Path,
) -> eyre::Result<()> {
    if config.len() > MAX_AGENT_CONFIG_SIZE_BYTES {
        eyre::bail!(
            "serialized agent config exceeds {} byte limit",
            MAX_AGENT_CONFIG_SIZE_BYTES
        );
    }
    let config_size = u32::try_from(config.len()).context("agent config is too large for newc")?;
    let mut agent =
        File::open(agent_path).with_context(|| format!("open agent {}", agent_path.display()))?;
    let agent_metadata = agent
        .metadata()
        .with_context(|| format!("inspect agent {}", agent_path.display()))?;
    if !agent_metadata.is_file() {
        eyre::bail!("agent is not a regular file: {}", agent_path.display());
    }
    let agent_size = u32::try_from(agent_metadata.len())
        .with_context(|| format!("agent is too large for newc: {}", agent_path.display()))?;

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

    let mut base = File::open(base_path)
        .with_context(|| format!("open base initramfs {}", base_path.display()))?;
    let base_size = io::copy(&mut base, &mut output)
        .with_context(|| format!("copy base initramfs {}", base_path.display()))?;
    let padding = (4 - (base_size % 4)) % 4;
    if padding != 0 {
        output
            .write_all(&[0; 3][..padding as usize])
            .context("align initramfs overlay")?;
    }

    write_directory(&mut output, 1)?;
    write_agent(&mut output, &mut agent, agent_path, agent_size, 2)?;
    write_bytes(
        &mut output,
        "agent/config.json",
        config,
        config_size,
        CONFIG_MODE,
        3,
    )?;
    cpio::newc::trailer(&mut output).context("write initramfs overlay trailer")?;
    output.flush().context("flush composite initramfs")?;
    output.sync_all().context("sync composite initramfs")?;
    drop(output);

    fs::rename(&temporary, destination).with_context(|| {
        format!(
            "replace composite initramfs {} with {}",
            destination.display(),
            temporary.display()
        )
    })?;
    guard.disarm();
    Ok(())
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
    source: &mut File,
    path: &Path,
    size: u32,
    inode: u32,
) -> eyre::Result<()> {
    let mut entry_writer =
        entry("agent/silo-agent", inode, AGENT_MODE, ModeFileType::Regular).write(writer, size);
    let copied = io::copy(
        &mut Read::by_ref(source).take(u64::from(size)),
        &mut entry_writer,
    )
    .with_context(|| format!("read agent {}", path.display()))?;
    if copied != u64::from(size) {
        eyre::bail!(
            "agent changed while composing initramfs: {}",
            path.display()
        );
    }
    let mut extra = [0_u8; 1];
    if source
        .read(&mut extra)
        .with_context(|| format!("finish reading agent {}", path.display()))?
        != 0
    {
        eyre::bail!(
            "agent changed while composing initramfs: {}",
            path.display()
        );
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

        write_composite(&base, &agent, br#"{"forward":{}}"#, &output).expect("compose initramfs");

        let bytes = std::fs::read(&output).expect("read output");
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
        assert_eq!(entries[2].5, br#"{"forward":{}}"#);
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

        write_composite(&base, &agent, b"first", &output).expect("first composite");
        let first_len = std::fs::metadata(&output).expect("first metadata").len();
        write_composite(&base, &agent, b"other", &output).expect("second composite");
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
            &base,
            &agent,
            &vec![0; MAX_AGENT_CONFIG_SIZE_BYTES + 1],
            &output,
        )
        .expect_err("oversized config must fail");

        assert!(error.to_string().contains("exceeds"));
        assert_eq!(
            std::fs::read(&output).expect("previous output"),
            b"previous"
        );
    }
}
