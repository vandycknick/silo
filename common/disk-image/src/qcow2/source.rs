//! Read-only imago storage over the already-held source descriptor.
//!
//! imago's own `File` zero-fills reads past EOF. Here every read must lie
//! inside the admitted length and be satisfied completely by the descriptor,
//! so truncation surfaces as an error instead of zeros. Writes and discards
//! are refused; there is no path, so nothing can be reopened or resolved.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use imago::Storage;
use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::drivers::CommonStorageHelper;

#[derive(Debug)]
pub(crate) struct HeldSource {
    file: File,
    len: u64,
    helper: CommonStorageHelper,
}

impl HeldSource {
    pub(crate) fn new(file: File, len: u64) -> Self {
        Self {
            file,
            len,
            helper: CommonStorageHelper::default(),
        }
    }
}

fn read_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "qcow2 import source is read-only",
    )
}

impl Storage for HeldSource {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len)
    }

    unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        let length = bufv.len();
        if offset.checked_add(length).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read of {} at {offset} ends past the {} qcow2 source",
                    utils::format_storage_size(length),
                    utils::format_storage_size(self.len)
                ),
            ));
        }
        let mut position = offset;
        for mut slice in bufv.into_inner() {
            self.file.read_exact_at(&mut slice, position)?;
            position += slice.len() as u64;
        }
        Ok(())
    }

    unsafe fn pure_writev(&self, _bufv: IoVector<'_>, _offset: u64) -> io::Result<()> {
        Err(read_only())
    }

    unsafe fn pure_write_zeroes(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(read_only())
    }

    unsafe fn pure_write_allocated_zeroes(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(read_only())
    }

    unsafe fn pure_discard(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(read_only())
    }

    fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    unsafe fn invalidate_cache(&self) -> io::Result<()> {
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.helper
    }
}

impl fmt::Display for HeldSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "held qcow2 source ({})",
            utils::format_storage_size(self.len)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use imago::StorageExt;

    use crate::qcow2::source::HeldSource;

    fn held(contents: &[u8], len: u64) -> HeldSource {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(contents).unwrap();
        HeldSource::new(file, len)
    }

    #[test]
    fn reads_exactly_inside_admitted_length() {
        let contents: Vec<u8> = (0..=255u8).collect();
        let storage = held(&contents, 256);
        let mut buffer = [0u8; 16];
        storage.read(&mut buffer[..], 240).unwrap();
        assert_eq!(&buffer[..], &contents[240..]);
    }

    #[test]
    fn read_crossing_admitted_length_fails_without_zero_fill() {
        // The file holds more bytes than were admitted; they stay unreachable.
        let storage = held(&[7u8; 512], 256);
        let mut buffer = [0xaau8; 16];
        let err = storage.read(&mut buffer[..], 250).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_overflowing_offset_fails() {
        let storage = held(&[7u8; 16], 16);
        let mut buffer = [0xaau8; 16];
        assert!(storage.read(&mut buffer[..], u64::MAX - 4).is_err());
        assert_eq!(
            buffer, [0xaa; 16],
            "overflow must not wrap into source data"
        );
    }

    #[test]
    fn source_shrunk_after_admission_is_an_error_not_zeros() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&[9u8; 1024]).unwrap();
        let storage = HeldSource::new(file.try_clone().unwrap(), 1024);
        file.set_len(512).unwrap();
        let mut buffer = [0u8; 512];
        let err = storage.read(&mut buffer[..], 256).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn writes_and_discards_are_refused() {
        let storage = held(&[0u8; 4096], 4096);
        let err = storage.write(&[1u8; 512][..], 0).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let err = storage.write_zeroes(0, 512).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let mut check = [1u8; 512];
        storage.read(&mut check[..], 0).unwrap();
        assert_eq!(check, [0u8; 512]);
    }
}
