use std::io::Read;

use crate::ext4::error::{FormatError, FormatResult};

/// Linux new_encode_dev uses twelve major and twenty minor bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId {
    major: u32,
    minor: u32,
}

impl DeviceId {
    pub fn new(major: u32, minor: u32) -> FormatResult<Self> {
        if major >= 1 << 12 || minor >= 1 << 20 {
            return Err(FormatError::InvalidDevice);
        }
        Ok(Self { major, minor })
    }

    pub fn major(self) -> u32 {
        self.major
    }
    pub fn minor(self) -> u32 {
        self.minor
    }

    pub(crate) fn write(self, block: &mut [u8; 60]) {
        block.fill(0);
        if self.major < 256 && self.minor < 256 {
            block[..4].copy_from_slice(&((self.major << 8) | self.minor).to_le_bytes());
        } else {
            let encoded = (self.minor & 0xff) | (self.major << 8) | ((self.minor & !0xff) << 12);
            block[4..8].copy_from_slice(&encoded.to_le_bytes());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRange {
    pub offset: u64,
    pub length: u64,
}

/// `reader` contains only the concatenated stored ranges, in map order; holes
/// are neither scanned nor consumed. Ranges are ordered, disjoint and bounded
/// by logical `length`. A zero-length EOF sentinel is accepted at `length`.
pub struct SparseData<'a> {
    pub reader: &'a mut dyn Read,
    pub length: u64,
    pub ranges: &'a mut dyn Iterator<Item = FileRange>,
}

pub enum FileData<'a> {
    Dense(&'a mut dyn Read),
    Sparse(SparseData<'a>),
}

#[cfg(test)]
mod tests {
    use crate::ext4::input::DeviceId;

    #[test]
    fn checked_linux_device_encoding() {
        assert!(DeviceId::new(4096, 0).is_err());
        assert!(DeviceId::new(0, 1 << 20).is_err());
        let mut block = [0; 60];
        DeviceId::new(1, 3).unwrap().write(&mut block);
        assert_eq!(&block[..8], &[3, 1, 0, 0, 0, 0, 0, 0]);
        DeviceId::new(4095, 0xfffff).unwrap().write(&mut block);
        assert_eq!(&block[..8], &[0, 0, 0, 0, 255, 255, 255, 255]);
    }
}
