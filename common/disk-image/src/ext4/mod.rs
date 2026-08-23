//! Pure-Rust ext4 filesystem formatter, reader, and offline grower.
//!
//! This crate creates and reads ext4 filesystem images entirely in userspace,
//! with no kernel mount, no FUSE, and no C dependencies.  It is designed for
//! building bootable block-device images.
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::Path;
//! use disk_image::ext4::Formatter;
//!
//! // Create a new ext4 image.
//! let mut fmt = Formatter::new(Path::new("rootfs.ext4"), 4096, 256 * 1024).unwrap();
//! fmt.create("/hello.txt", 0x8000 | 0o644, None, None,
//!     Some(&mut "hello world".as_bytes()), None, None, None).unwrap();
//! fmt.close().unwrap();
//!
//! // Read it back.
//! let mut reader = disk_image::ext4::Reader::new(Path::new("rootfs.ext4")).unwrap();
//! let data = reader.read_file("/hello.txt", 0, None).unwrap();
//! assert_eq!(&data, b"hello world");
//!
//! // Grow a clean, unmounted image.
//! let target = 512 * 1024 * 1024;
//! std::fs::OpenOptions::new().write(true).open("rootfs.ext4")?.set_len(target)?;
//! disk_image::ext4::grow_image(Path::new("rootfs.ext4"), target)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod checksum;
pub mod constants;
pub mod dir;
pub mod error;
pub mod extent;
pub mod file_tree;
pub mod formatter;
mod journal;
mod layout;
pub mod reader;
pub mod reader_io;
pub mod resizer;
pub mod types;
pub mod xattr;

// Re-export the primary public types at the crate root.
pub use error::{FormatError, FormatResult, ReadError, ReadResult, ResizeError, ResizeResult};
pub use formatter::{FileTimestamps, FormatOptions, Formatter};
pub use reader::Reader;
pub use resizer::{GrowOutcome, grow_image};

/// The result of checking an image for the ext4 superblock magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Ext4,
    NotExt4,
}

/// Checks whether `path` has the ext4 superblock magic.
///
/// This deliberately performs no other filesystem validation.
pub fn probe(path: &std::path::Path) -> ReadResult<ProbeResult> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(constants::SUPERBLOCK_OFFSET + 0x38))?;
    let mut magic = [0u8; 2];
    match file.read_exact(&mut magic) {
        Ok(()) if u16::from_le_bytes(magic) == constants::SUPERBLOCK_MAGIC => Ok(ProbeResult::Ext4),
        Ok(()) => Ok(ProbeResult::NotExt4),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(ProbeResult::NotExt4),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::ext4::{Formatter, ProbeResult, ReadError, probe};

    #[test]
    fn probe_only_checks_the_ext4_magic() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let ext4_path = temp.path().join("rootfs.ext4");
        let non_ext4_path = temp.path().join("not-ext4.img");
        let short_path = temp.path().join("short.img");

        Formatter::new(&ext4_path, 4096, 256 * 1024)
            .expect("create ext4 image")
            .close()
            .expect("finish ext4 image");
        std::fs::write(&non_ext4_path, vec![0; 1082]).expect("write non-ext4 image");
        std::fs::write(&short_path, b"short").expect("write short image");

        assert_eq!(
            probe(&ext4_path).expect("probe ext4 image"),
            ProbeResult::Ext4
        );
        assert_eq!(
            probe(&non_ext4_path).expect("probe non-ext4 image"),
            ProbeResult::NotExt4
        );
        assert_eq!(
            probe(&short_path).expect("probe short image"),
            ProbeResult::NotExt4
        );
        assert!(matches!(
            probe(&temp.path().join("missing.img")),
            Err(ReadError::Io(_))
        ));
    }
}
