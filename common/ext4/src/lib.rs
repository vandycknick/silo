//! Pure-Rust ext4 filesystem formatter, reader, and offline grower.
//!
//! This crate creates and reads ext4 filesystem images entirely in userspace,
//! with no kernel mount, no FUSE, and no C dependencies.  It is designed for
//! converting OCI container image layers into bootable block-device images.
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::Path;
//! use ext4::Formatter;
//!
//! // Create a new ext4 image.
//! let mut fmt = Formatter::new(Path::new("rootfs.ext4"), 4096, 256 * 1024).unwrap();
//! fmt.create("/hello.txt", 0x8000 | 0o644, None, None,
//!     Some(&mut "hello world".as_bytes()), None, None, None).unwrap();
//! fmt.close().unwrap();
//!
//! // Read it back.
//! let mut reader = ext4::Reader::new(Path::new("rootfs.ext4")).unwrap();
//! let data = reader.read_file("/hello.txt", 0, None).unwrap();
//! assert_eq!(&data, b"hello world");
//!
//! // Grow a clean, unmounted image.
//! let target = 512 * 1024 * 1024;
//! std::fs::OpenOptions::new().write(true).open("rootfs.ext4")?.set_len(target)?;
//! ext4::grow_image(Path::new("rootfs.ext4"), target)?;
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
pub mod unpack;
pub mod xattr;

// Re-export the primary public types at the crate root.
pub use formatter::{FileTimestamps, FormatOptions, Formatter};
pub use reader::Reader;
pub use resizer::{GrowOutcome, grow_image};
