//! Checksum routines for on-disk ext4 structures.
//!
//! Only `gdt_csum` (CRC-16/IBM over each group descriptor) is implemented
//! today; future support for `metadata_csum` (CRC-32c over more structures)
//! will land here too.

use crate::types::GroupDescriptor;

/// CRC-16/IBM (a.k.a. CRC-16/ARC).  Polynomial 0x8005, reflected so the
/// bit-by-bit inner loop applies 0xA001 with LSB-first processing.  No
/// final XOR.  `init` is the caller-supplied seed — pass `0xFFFF` for an
/// ext4 group descriptor checksum, or `0` to match the published
/// CRC-16/ARC check vector.  Mirrors the Linux kernel's `lib/crc16.c`.
fn crc16(mut crc: u16, buf: &[u8]) -> u16 {
    for &b in buf {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Compute the group descriptor checksum mandated by the `gdt_csum`
/// feature: CRC-16/IBM seeded with `0xFFFF`, taken over the filesystem
/// UUID, the little-endian group number, and the descriptor body up to —
/// but excluding — the two checksum bytes at offset 0x1E.
pub fn group_descriptor(uuid: &[u8; 16], group_nr: u32, gd: &GroupDescriptor) -> u16 {
    let mut tmp = [0u8; GroupDescriptor::SIZE];
    gd.write_to(&mut tmp);

    let mut crc = 0xFFFFu16;
    crc = crc16(crc, uuid);
    crc = crc16(crc, &group_nr.to_le_bytes());
    crc = crc16(crc, &tmp[..0x1E]);
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published check vector for CRC-16/ARC: `crc16("123456789", 0) == 0xBB3D`.
    /// Catches accidental changes to the polynomial, the LSB-first
    /// reflection convention, or any introduction of a final XOR.
    #[test]
    fn crc16_matches_arc_check_vector() {
        assert_eq!(crc16(0x0000, b"123456789"), 0xBB3D);
    }

    /// Pins the byte ordering and slice boundary of `group_descriptor`
    /// against a precomputed value.  A refactor that reorders uuid /
    /// group_nr / body, or shifts the 30-byte cutoff, breaks this test.
    /// The `checksum` field is deliberately set non-zero to prove it is
    /// excluded from the CRC input.
    #[test]
    fn group_descriptor_layout_is_stable() {
        let mut uuid = [0u8; 16];
        for (i, b) in uuid.iter_mut().enumerate() {
            *b = 0x11 + i as u8;
        }
        let gd = GroupDescriptor {
            block_bitmap_lo: 0x123,
            inode_bitmap_lo: 0x124,
            inode_table_lo: 0x200,
            free_blocks_count_lo: 1000,
            free_inodes_count_lo: 200,
            used_dirs_count_lo: 0,
            flags: 0x0003,
            exclude_bitmap_lo: 0,
            block_bitmap_csum_lo: 0,
            inode_bitmap_csum_lo: 0,
            itable_unused_lo: 8192,
            checksum: 0xFFFF,
        };
        assert_eq!(group_descriptor(&uuid, 7, &gd), 0x0DAF);
    }
}
