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

#[derive(Debug, Clone)]
pub struct InitramfsOptions {
    pub init_binary: PathBuf,
    pub output: PathBuf,
}

impl InitramfsOptions {
    pub fn new(init_binary: impl Into<PathBuf>, output: impl Into<PathBuf>) -> Self {
        Self {
            init_binary: init_binary.into(),
            output: output.into(),
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
    let mut gzip = write_cpio_entries(gzip, &mut init_file, init_size, init_binary)?;
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
) -> Result<GzEncoder<W>> {
    let mut inode = 1;
    for directory in INITRAMFS_DIRECTORIES {
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
    use std::io::Read;

    use flate2::read::GzDecoder;

    use super::*;

    #[derive(Debug)]
    struct ArchiveEntry {
        name: String,
        mode: u32,
        contents: Vec<u8>,
    }

    #[test]
    fn writes_expected_initramfs_layout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let init = temp.path().join("init");
        fs::write(&init, b"#!/init\n").expect("write init");
        let output = temp.path().join("initramfs");

        write_initramfs(&InitramfsOptions::new(&init, &output)).expect("write initramfs");

        let entries = read_archive(&output).expect("read archive");
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        let mut expected_names = INITRAMFS_DIRECTORIES.to_vec();
        expected_names.push("init");
        assert_eq!(names, expected_names);
        assert!(!names.contains(&"mnt/root"));
        assert!(!names.iter().any(|name| name.starts_with("agent")));

        let init_entry = entries
            .iter()
            .find(|entry| entry.name == "init")
            .expect("init entry");
        assert_eq!(init_entry.mode & 0o170000, 0o100000);
        assert_eq!(init_entry.mode & 0o777, INIT_MODE);
        assert_eq!(init_entry.contents, b"#!/init\n");

        let mnt_entry = entries
            .iter()
            .find(|entry| entry.name == "mnt")
            .expect("mnt entry");
        assert_eq!(mnt_entry.mode & 0o170000, 0o040000);
        assert_eq!(mnt_entry.mode & 0o777, DIRECTORY_MODE);
    }

    #[test]
    fn creates_parent_directory_for_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let init = temp.path().join("init");
        fs::write(&init, b"init").expect("write init");
        let output = temp.path().join("nested/initramfs");

        write_initramfs(&InitramfsOptions::new(init, &output)).expect("write initramfs");

        assert!(output.is_file());
    }

    fn read_archive(path: &Path) -> io::Result<Vec<ArchiveEntry>> {
        let file = File::open(path)?;
        let mut decoder = GzDecoder::new(file);
        let mut entries = Vec::new();

        loop {
            let mut reader = cpio::NewcReader::new(decoder)?;
            if reader.entry().is_trailer() {
                break;
            }

            let name = reader.entry().name().to_owned();
            let mode = reader.entry().mode();
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents)?;
            decoder = reader.finish()?;
            entries.push(ArchiveEntry {
                name,
                mode,
                contents,
            });
        }

        Ok(entries)
    }
}
