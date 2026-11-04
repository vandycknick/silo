//! Fixed geometry of `silo-upper-ext4-v1`, shared by formatter and early init.
//!
//! Backing length is exact. A final group too short for the Linux online-resize
//! metadata admission rule is excluded from the filesystem, not rounded up.
//! This arithmetic is a prediction to qualify against the exact guest kernel,
//! not evidence that an ioctl actually achieved the predicted span.

use core::fmt;

pub const BLOCK_SIZE: u32 = 4096;
pub const BLOCKS_PER_GROUP: u32 = 32768;
pub const INODES_PER_GROUP: u32 = 8192;
pub const INODE_SIZE: u32 = 256;
pub const INODE_TABLE_BLOCKS: u32 = INODES_PER_GROUP * INODE_SIZE / BLOCK_SIZE;
pub const DESCRIPTORS_PER_BLOCK: u32 = BLOCK_SIZE / 32;
pub const MAX_DESCRIPTOR_BLOCKS: u32 = 64;
pub const MIN_CAPACITY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CAPACITY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
/// One flex group covers the 8192-group format maximum, without the signed
/// allocator arithmetic and old-kernel resize limits of a 2^31-group flex.
pub const LOG_GROUPS_PER_FLEX: u8 = 13;
pub const FEATURE_COMPAT: u32 = 0x3c;
pub const FEATURE_INCOMPAT: u32 = 0x242;
pub const FEATURE_RO_COMPAT: u32 = 0x7b;
pub const HASH_VERSION: u8 = 1;
/// EXT2_FLAGS_SIGNED_HASH, never let first mount choose host signedness.
pub const HASH_FLAGS: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeometryError {
    OutOfRange(u64),
    Unaligned(u64),
}

impl fmt::Display for GeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange(bytes) => {
                write!(f, "upper capacity {bytes} is outside 64 MiB through 1 TiB")
            }
            Self::Unaligned(bytes) => write!(f, "upper capacity {bytes} is not 4096-byte aligned"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpperCapacity(u64);

impl core::error::Error for GeometryError {}

impl UpperCapacity {
    pub const fn new(bytes: u64) -> Result<Self, GeometryError> {
        if bytes < MIN_CAPACITY_BYTES || bytes > MAX_CAPACITY_BYTES {
            return Err(GeometryError::OutOfRange(bytes));
        }
        if !bytes.is_multiple_of(BLOCK_SIZE as u64) {
            return Err(GeometryError::Unaligned(bytes));
        }
        Ok(Self(bytes))
    }

    pub const fn bytes(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for UpperCapacity {
    type Error = GeometryError;

    fn try_from(bytes: u64) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpperGeometry {
    pub backing_bytes: u64,
    pub filesystem_bytes: u64,
    pub unusable_tail_bytes: u64,
    pub groups: u32,
    pub descriptor_blocks: u32,
    pub reserved_gdt_blocks: u32,
}

impl UpperGeometry {
    pub const fn for_capacity(capacity: UpperCapacity) -> Self {
        // Validated capacity bounds all intermediate values, including the
        // final 32-bit inode/block counts (67,108,864 / 268,435,456 at 1 TiB).
        let blocks = capacity.bytes() / BLOCK_SIZE as u64;
        let last_group = ((blocks - 1) / BLOCKS_PER_GROUP as u64) as u32;
        let remainder = (blocks - last_group as u64 * BLOCKS_PER_GROUP as u64) as u32;
        let overhead = if has_sparse_super(last_group) {
            1 + MAX_DESCRIPTOR_BLOCKS
        } else {
            0
        };
        // Linux ext4_resize_fs rejects equality as well as smaller groups:
        // overhead + two bitmaps + inode table + one cluster >= remainder.
        let excluded = if remainder <= overhead + 2 + INODE_TABLE_BLOCKS + 1 {
            remainder
        } else {
            0
        };
        let filesystem_blocks = blocks - excluded as u64;
        let groups = filesystem_blocks.div_ceil(BLOCKS_PER_GROUP as u64) as u32;
        let descriptor_blocks = groups.div_ceil(DESCRIPTORS_PER_BLOCK);
        Self {
            backing_bytes: capacity.bytes(),
            filesystem_bytes: filesystem_blocks * BLOCK_SIZE as u64,
            unusable_tail_bytes: excluded as u64 * BLOCK_SIZE as u64,
            groups,
            descriptor_blocks,
            reserved_gdt_blocks: MAX_DESCRIPTOR_BLOCKS - descriptor_blocks,
        }
    }
}

pub const fn has_sparse_super(group: u32) -> bool {
    group == 0
        || group == 1
        || is_power_of(group, 3)
        || is_power_of(group, 5)
        || is_power_of(group, 7)
}

const fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < base {
        return false;
    }
    while value.is_multiple_of(base) {
        value /= base;
    }
    value == 1
}

#[cfg(test)]
mod tests {
    use crate::upper_geometry::*;

    fn geometry(bytes: u64) -> UpperGeometry {
        UpperGeometry::for_capacity(UpperCapacity::new(bytes).unwrap())
    }

    #[test]
    fn upper_capacity_admits_exact_envelope() {
        assert!(UpperCapacity::new(MIN_CAPACITY_BYTES).is_ok());
        assert!(UpperCapacity::new(MAX_CAPACITY_BYTES).is_ok());
        for bytes in [
            0,
            MIN_CAPACITY_BYTES - 4096,
            MAX_CAPACITY_BYTES + 4096,
            u64::MAX,
        ] {
            assert!(matches!(
                UpperCapacity::new(bytes),
                Err(GeometryError::OutOfRange(_))
            ));
        }
        assert!(matches!(
            UpperCapacity::new(MIN_CAPACITY_BYTES + 1),
            Err(GeometryError::Unaligned(_))
        ));
    }

    #[test]
    fn upper_geometry_keeps_minimum_and_maximum_exact() {
        let minimum = geometry(MIN_CAPACITY_BYTES);
        assert_eq!(minimum.filesystem_bytes, MIN_CAPACITY_BYTES);
        assert_eq!(
            (
                minimum.groups,
                minimum.descriptor_blocks,
                minimum.reserved_gdt_blocks
            ),
            (1, 1, 63)
        );
        let maximum = geometry(MAX_CAPACITY_BYTES);
        assert_eq!(maximum.filesystem_bytes, MAX_CAPACITY_BYTES);
        assert_eq!(
            (
                maximum.groups,
                maximum.descriptor_blocks,
                maximum.reserved_gdt_blocks
            ),
            (8192, 64, 0)
        );
        assert_eq!(maximum.groups as u64 * INODES_PER_GROUP as u64, 67_108_864);
    }

    #[test]
    fn upper_geometry_models_strict_partial_group_thresholds() {
        let group_bytes = BLOCKS_PER_GROUP as u64 * BLOCK_SIZE as u64;
        for (group, threshold) in [(1, 580), (2, 515), (3, 580), (128, 515)] {
            let boundary = group_bytes * group;
            for remainder in [1, threshold - 1, threshold] {
                let actual = geometry(boundary + remainder * BLOCK_SIZE as u64);
                assert_eq!(actual.filesystem_bytes, boundary);
                assert_eq!(actual.unusable_tail_bytes, remainder * BLOCK_SIZE as u64);
            }
            let bytes = boundary + (threshold + 1) * BLOCK_SIZE as u64;
            assert_eq!(geometry(bytes).filesystem_bytes, bytes);
        }
    }

    #[test]
    fn upper_geometry_consumes_reserved_descriptors_not_extra_blocks() {
        let boundary = 16 * 1024 * 1024 * 1024;
        let short = geometry(boundary + 4096);
        assert_eq!(
            (
                short.groups,
                short.descriptor_blocks,
                short.reserved_gdt_blocks
            ),
            (128, 1, 63)
        );
        let partial = geometry(boundary + 516 * 4096);
        assert_eq!(
            (
                partial.groups,
                partial.descriptor_blocks,
                partial.reserved_gdt_blocks
            ),
            (129, 2, 62)
        );
        assert_eq!(partial.descriptor_blocks + partial.reserved_gdt_blocks, 64);
    }
}
