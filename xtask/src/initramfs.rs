use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cpio::newc::ModeFileType;
use cpio::NewcBuilder;
use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};
use thiserror::Error;

const DIRECTORY_MODE: u32 = 0o755;
const INIT_MODE: u32 = 0o755;
const ROOT_UID: u32 = 0;
const ROOT_GID: u32 = 0;
const MTIME: u32 = 0;

pub const INITRAMFS_DIRECTORIES: &[&str] = &[
    ".", "bin", "dev", "etc", "mnt", "proc", "run", "sbin", "sys", "tmp", "usr", "usr/bin",
    "usr/sbin",
];

pub const RPROBE_INITRAMFS_DIRECTORIES: &[&str] =
    &[".", "dev", "mnt", "mnt/rosetta", "proc", "sys"];

#[derive(Debug, Clone, Copy)]
enum Inventory {
    Workload,
    Rprobe,
}

#[derive(Debug, Clone)]
pub struct InitramfsOptions {
    pub init_binary: PathBuf,
    pub output: PathBuf,
    inventory: Inventory,
}

impl InitramfsOptions {
    pub fn new(init_binary: impl Into<PathBuf>, output: impl Into<PathBuf>) -> Self {
        Self {
            init_binary: init_binary.into(),
            output: output.into(),
            inventory: Inventory::Workload,
        }
    }

    pub fn rprobe(init_binary: impl Into<PathBuf>, output: impl Into<PathBuf>) -> Self {
        Self {
            init_binary: init_binary.into(),
            output: output.into(),
            inventory: Inventory::Rprobe,
        }
    }
}

#[derive(Debug, Error)]
pub enum InitramfsError {
    #[error("init binary is not a regular file: {path}")]
    InitBinaryNotFile { path: PathBuf },
    #[error("init binary is too large for newc: {path} ({size} bytes)")]
    InitBinaryTooLarge { path: PathBuf, size: u64 },
    #[error("failed to create output directory {path}")]
    CreateOutputDirectory { path: PathBuf, source: io::Error },
    #[error("failed to create initramfs archive {path}")]
    CreateOutput { path: PathBuf, source: io::Error },
    #[error("failed to open init binary {path}")]
    OpenInit { path: PathBuf, source: io::Error },
    #[error("failed to read init binary {path}")]
    ReadInit { path: PathBuf, source: io::Error },
    #[error("failed to write cpio entry {name}")]
    WriteEntry { name: String, source: io::Error },
    #[error("failed to write cpio trailer")]
    WriteTrailer { source: io::Error },
    #[error("failed to finish gzip stream")]
    FinishGzip { source: io::Error },
}

pub type Result<T> = std::result::Result<T, InitramfsError>;

pub fn write_initramfs(options: &InitramfsOptions) -> Result<()> {
    validate_init_binary(&options.init_binary)?;

    if let Some(parent) = options
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| InitramfsError::CreateOutputDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let output = File::create(&options.output).map_err(|source| InitramfsError::CreateOutput {
        path: options.output.clone(),
        source,
    })?;

    write_initramfs_options_to_writer(options, output).map(|_| ())
}

fn write_initramfs_options_to_writer<W: Write>(options: &InitramfsOptions, writer: W) -> Result<W> {
    let init_binary = options.init_binary.as_path();
    let init_size = init_binary_size(init_binary)?;
    let mut init_file = File::open(init_binary).map_err(|source| InitramfsError::OpenInit {
        path: init_binary.to_path_buf(),
        source,
    })?;

    let gzip = GzBuilder::new().mtime(0).write(writer, Compression::best());
    let directories = match options.inventory {
        Inventory::Workload => INITRAMFS_DIRECTORIES,
        Inventory::Rprobe => RPROBE_INITRAMFS_DIRECTORIES,
    };
    let mut gzip = write_cpio_entries(gzip, &mut init_file, init_size, init_binary, directories)?;
    gzip.flush()
        .map_err(|source| InitramfsError::FinishGzip { source })?;
    gzip.finish()
        .map_err(|source| InitramfsError::FinishGzip { source })
}

fn validate_init_binary(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|source| InitramfsError::OpenInit {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(InitramfsError::InitBinaryNotFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn init_binary_size(path: &Path) -> Result<u32> {
    let metadata = fs::metadata(path).map_err(|source| InitramfsError::OpenInit {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(InitramfsError::InitBinaryNotFile {
            path: path.to_path_buf(),
        });
    }

    let size = metadata.len();
    u32::try_from(size).map_err(|_| InitramfsError::InitBinaryTooLarge {
        path: path.to_path_buf(),
        size,
    })
}

fn write_cpio_entries<W: Write>(
    mut writer: GzEncoder<W>,
    init_file: &mut File,
    init_size: u32,
    init_path: &Path,
    directories: &[&str],
) -> Result<GzEncoder<W>> {
    let mut inode = 1;
    for directory in directories {
        write_directory(&mut writer, directory, inode)?;
        inode += 1;
    }

    write_init(&mut writer, inode, init_file, init_size, init_path)?;

    cpio::newc::trailer(writer).map_err(|source| InitramfsError::WriteTrailer { source })
}

fn entry(name: &str, inode: u32, mode: u32, file_type: ModeFileType) -> NewcBuilder {
    NewcBuilder::new(name)
        .ino(inode)
        .uid(ROOT_UID)
        .gid(ROOT_GID)
        .mode(mode)
        .mtime(MTIME)
        .set_mode_file_type(file_type)
}

fn write_directory<W: Write>(writer: &mut W, name: &str, inode: u32) -> Result<()> {
    entry(name, inode, DIRECTORY_MODE, ModeFileType::Directory)
        .nlink(2)
        .write(writer, 0)
        .finish()
        .map(|_| ())
        .map_err(|source| InitramfsError::WriteEntry {
            name: name.to_string(),
            source,
        })
}

fn write_init<W: Write>(
    writer: &mut W,
    inode: u32,
    init_file: &mut File,
    init_size: u32,
    init_path: &Path,
) -> Result<()> {
    let mut cpio_writer =
        entry("init", inode, INIT_MODE, ModeFileType::Regular).write(writer, init_size);
    let bytes =
        io::copy(init_file, &mut cpio_writer).map_err(|source| InitramfsError::ReadInit {
            path: init_path.to_path_buf(),
            source,
        })?;
    if bytes != u64::from(init_size) {
        return Err(InitramfsError::ReadInit {
            path: init_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "init binary changed while archiving",
            ),
        });
    }
    cpio_writer
        .finish()
        .map(|_| ())
        .map_err(|source| InitramfsError::WriteEntry {
            name: "init".to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::read::GzDecoder;

    use crate::initramfs::{write_initramfs, InitramfsOptions, RPROBE_INITRAMFS_DIRECTORIES};

    #[test]
    fn rprobe_archive_is_deterministic_with_exact_inventory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "silo-rprobe-initramfs-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create test directory");
        let init = root.join("silo-rprobe");
        let first = root.join("first.gz");
        let second = root.join("second.gz");
        fs::write(&init, b"synthetic-static-init").expect("write init fixture");

        write_initramfs(&InitramfsOptions::rprobe(&init, &first)).expect("write first archive");
        write_initramfs(&InitramfsOptions::rprobe(&init, &second)).expect("write second archive");
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

        let mut archive = Vec::new();
        GzDecoder::new(fs::File::open(&first).unwrap())
            .read_to_end(&mut archive)
            .expect("decompress archive");
        let entries = newc_inventory(&archive);
        let mut expected = RPROBE_INITRAMFS_DIRECTORIES.to_vec();
        expected.extend(["init", "TRAILER!!!"]);
        assert_eq!(entries, expected);

        fs::remove_dir_all(root).expect("remove test directory");
    }

    fn newc_inventory(mut bytes: &[u8]) -> Vec<&str> {
        let mut names = Vec::new();
        loop {
            assert!(bytes.len() >= 110, "truncated newc header");
            assert_eq!(&bytes[..6], b"070701");
            let file_size = hex_u32(&bytes[54..62]) as usize;
            let name_size = hex_u32(&bytes[94..102]) as usize;
            let mode = hex_u32(&bytes[14..22]);
            let uid = hex_u32(&bytes[22..30]);
            let gid = hex_u32(&bytes[30..38]);
            let mtime = hex_u32(&bytes[46..54]);
            bytes = &bytes[110..];
            assert!(name_size > 0 && bytes.len() >= name_size);
            let name = std::str::from_utf8(&bytes[..name_size - 1]).expect("ASCII entry name");
            assert_eq!(uid, 0, "entry {name} uid");
            assert_eq!(gid, 0, "entry {name} gid");
            assert_eq!(mtime, 0, "entry {name} mtime");
            match name {
                "init" => assert_eq!(mode, 0o100755),
                "TRAILER!!!" => {}
                _ => assert_eq!(mode, 0o040755, "entry {name} mode"),
            }
            names.push(name);
            let name_padding = (4 - (110 + name_size) % 4) % 4;
            bytes = &bytes[name_size + name_padding..];
            let data_padding = (4 - file_size % 4) % 4;
            assert!(bytes.len() >= file_size + data_padding);
            bytes = &bytes[file_size + data_padding..];
            if name == "TRAILER!!!" {
                break;
            }
        }
        names
    }

    fn hex_u32(bytes: &[u8]) -> u32 {
        u32::from_str_radix(std::str::from_utf8(bytes).expect("ASCII newc field"), 16)
            .expect("hex newc field")
    }
}
