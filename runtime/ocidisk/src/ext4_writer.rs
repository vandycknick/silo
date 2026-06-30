use std::io::Read;
use std::path::Path;

use ext4::constants::{file_mode, make_mode};
use ext4::{FormatOptions, Formatter};

use crate::{OciDiskError, OciDiskResult};

pub(crate) struct Ext4Writer {
    formatter: Formatter,
}

impl Ext4Writer {
    pub(crate) fn create(path: &Path, size_bytes: u64) -> OciDiskResult<Self> {
        let formatter = Formatter::with_options(path, FormatOptions::new(size_bytes))
            .map_err(OciDiskError::ext4)?;
        Ok(Self { formatter })
    }

    pub(crate) fn mkdir_p(
        &mut self,
        path: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> OciDiskResult<()> {
        self.formatter
            .create(
                path,
                make_mode(file_mode::S_IFDIR, mode_bits(mode)),
                None,
                None,
                None,
                Some(uid),
                Some(gid),
                None,
            )
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn write_file(
        &mut self,
        path: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        reader: &mut dyn Read,
    ) -> OciDiskResult<()> {
        self.formatter
            .create(
                path,
                make_mode(file_mode::S_IFREG, mode_bits(mode)),
                None,
                None,
                Some(reader),
                Some(uid),
                Some(gid),
                None,
            )
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn symlink(
        &mut self,
        path: &str,
        target: &str,
        uid: u32,
        gid: u32,
    ) -> OciDiskResult<()> {
        self.formatter
            .create(
                path,
                make_mode(file_mode::S_IFLNK, 0o777),
                Some(target),
                None,
                None,
                Some(uid),
                Some(gid),
                None,
            )
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn link(&mut self, path: &str, target: &str) -> OciDiskResult<()> {
        self.formatter
            .link(path, target)
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn delete(&mut self, path: &str) -> OciDiskResult<()> {
        self.formatter
            .unlink(path, false)
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn clear_dir(&mut self, path: &str) -> OciDiskResult<()> {
        self.formatter
            .unlink(path, true)
            .map_err(OciDiskError::ext4)
    }

    pub(crate) fn finish(self) -> OciDiskResult<()> {
        self.formatter.close().map_err(OciDiskError::ext4)
    }
}

fn mode_bits(mode: u32) -> u16 {
    (mode & 0o7777) as u16
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ext4::Reader;

    use crate::ext4_writer::Ext4Writer;

    #[test]
    fn writes_readable_ext4_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("rootfs.img");
        let mut writer = Ext4Writer::create(&path, 64 * 1024 * 1024).expect("create ext4");
        let mut data = Cursor::new(b"hello".to_vec());

        writer
            .write_file("/etc/hello", 0o644, 0, 0, &mut data)
            .expect("write file");
        writer.finish().expect("finish ext4");

        let mut reader = Reader::new(&path).expect("open ext4");
        let bytes = reader
            .read_file("/etc/hello", 0, Some(32))
            .expect("read ext4 file");
        assert_eq!(bytes, b"hello");
    }
}
