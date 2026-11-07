//! Silo-owned qcow2 admission, independent of the decoder.
//!
//! Every structure the decoder would consult is validated here first: the
//! fixed header, the header-extension area (for v2 too, which the decoder
//! skips), refcount table and L1 placement, every L1 entry and every L2 entry
//! of the tables that cover the virtual disk. Referenced ranges must lie
//! inside the held source; nothing is zero-filled. Buffers are bounded by one
//! cluster, one L1 read chunk and the extension-type set (at most C/8 types).
//! Format reference: <https://www.qemu.org/docs/master/interop/qcow2.html>.

use std::collections::HashSet;
use std::fs::File;
use std::os::unix::fs::FileExt;

use crate::qcow2::{
    Error, Forbidden, MAGIC, MAX_CLUSTER_BITS, MAX_L1_ENTRIES, MAX_VIRTUAL_SIZE, MIN_CLUSTER_BITS,
    Malformed, Region, SECTOR_SIZE, Version,
};

const V2_HEADER_LEN: u64 = 72;
const V3_HEADER_MIN_LEN: u64 = 104;
const MAX_REFCOUNT_ORDER: u32 = 6;

// Fixed header field offsets (big-endian).
const VERSION: u64 = 4;
const BACKING_FILE_OFFSET: u64 = 8;
const CLUSTER_BITS: u64 = 20;
const SIZE: u64 = 24;
const CRYPT_METHOD: u64 = 32;
const L1_SIZE: u64 = 36;
const L1_TABLE_OFFSET: u64 = 40;
const REFCOUNT_TABLE_OFFSET: u64 = 48;
const REFCOUNT_TABLE_CLUSTERS: u64 = 56;
const INCOMPATIBLE_FEATURES: u64 = 72;
const AUTOCLEAR_FEATURES: u64 = 88;
const REFCOUNT_ORDER: u64 = 96;
const HEADER_LENGTH: u64 = 100;
const COMPRESSION_TYPE: u64 = 104;

const INCOMPATIBLE_DIRTY: u64 = 1;
const INCOMPATIBLE_CORRUPT: u64 = 1 << 1;
const INCOMPATIBLE_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPATIBLE_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPATIBLE_EXTENDED_L2: u64 = 1 << 4;
const AUTOCLEAR_RAW_EXTERNAL_DATA: u64 = 1 << 1;

const COMPRESSION_DEFLATE: u8 = 0;
const COMPRESSION_ZSTD: u8 = 1;

const EXTENSION_HEADER_LEN: u64 = 8;
const EXTENSION_END: u32 = 0;
const EXTENSION_BACKING_FORMAT: u32 = 0xe279_2aca;
const EXTENSION_FEATURE_NAMES: u32 = 0x6803_f857;
const EXTENSION_FULL_DISK_ENCRYPTION: u32 = 0x0537_be77;
const EXTENSION_EXTERNAL_DATA_NAME: u32 = 0x4441_5441;
const FEATURE_NAME_ENTRY_LEN: u32 = 48;

const ENTRY_LEN: u64 = 8;
const COPIED: u64 = 1 << 63;
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;
const HOST_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L1_RESERVED: u64 = 0x7f00_0000_0000_01fe;
const L2_STANDARD_RESERVED: u64 = 0x3f00_0000_0000_01fe;
const COMPRESSED_DESCRIPTOR_MASK: u64 = COMPRESSED - 1;
/// L1 entries read per bounded chunk (64 KiB).
const L1_CHUNK_ENTRIES: u64 = 8192;

pub(crate) struct Layout {
    pub(crate) version: Version,
    pub(crate) cluster_bits: u32,
    pub(crate) virtual_size: u64,
}

pub(crate) fn check(source: &File, source_len: u64) -> Result<Layout, Error> {
    let mut prefix = [0u8; V2_HEADER_LEN as usize];
    read_exact(source, source_len, 0, &mut prefix, Region::Header)?;
    let prefix = Bytes {
        bytes: &prefix,
        source_len,
    };
    if prefix.array::<4>(0, Region::Header)? != MAGIC {
        return Err(Error::NotQcow2);
    }
    let version = match prefix.u32(VERSION, Region::Header)? {
        2 => Version::V2,
        3 => Version::V3,
        other => return Err(Error::UnsupportedVersion(other)),
    };
    let cluster_bits = prefix.u32(CLUSTER_BITS, Region::Header)?;
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(Malformed::ClusterBits(cluster_bits).into());
    }
    let cluster_size = 1u64 << cluster_bits;

    // The header and its extensions live in the first cluster; read only the
    // part of it the source actually contains.
    let source_prefix_len = usize::try_from(source_len).unwrap_or(usize::MAX);
    let mut first = vec![0u8; (1usize << cluster_bits).min(source_prefix_len)];
    read_exact(source, source_len, 0, &mut first, Region::Header)?;
    let first = Bytes {
        bytes: &first,
        source_len,
    };

    let header = Header::parse(&first, version, cluster_size)?;
    header.check_features()?;
    if header.refcount_order > MAX_REFCOUNT_ORDER {
        return Err(Malformed::RefcountOrder(header.refcount_order).into());
    }
    if header.virtual_size == 0
        || header.virtual_size % SECTOR_SIZE != 0
        || header.virtual_size > MAX_VIRTUAL_SIZE
    {
        return Err(Error::VirtualSize(header.virtual_size));
    }
    check_extensions(&first, header.header_length, cluster_size)?;
    check_refcount_table(&header, cluster_size, source_len)?;
    check_mappings(source, source_len, &header, cluster_bits)?;

    Ok(Layout {
        version,
        cluster_bits,
        virtual_size: header.virtual_size,
    })
}

struct Header {
    version: Version,
    backing_file_offset: u64,
    virtual_size: u64,
    crypt_method: u32,
    l1_entries: u32,
    l1_offset: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    incompatible: u64,
    autoclear: u64,
    refcount_order: u32,
    header_length: u64,
    compression_type: u8,
}

impl Header {
    fn parse(first: &Bytes<'_>, version: Version, cluster_size: u64) -> Result<Self, Error> {
        let region = Region::Header;
        let (incompatible, autoclear, refcount_order, header_length, compression_type) =
            match version {
                // Version 2 has none of these fields; bytes 72.. are extensions.
                Version::V2 => (0, 0, 4, V2_HEADER_LEN, COMPRESSION_DEFLATE),
                Version::V3 => {
                    let raw_length = first.u32(HEADER_LENGTH, region)?;
                    let header_length = u64::from(raw_length);
                    if header_length < V3_HEADER_MIN_LEN
                        || header_length % 8 != 0
                        || header_length > cluster_size
                    {
                        return Err(Malformed::HeaderLength(raw_length).into());
                    }
                    first.bytes(0, header_length, region)?;
                    let compression_type = if header_length > COMPRESSION_TYPE {
                        first
                            .array(COMPRESSION_TYPE, region)
                            .map(u8::from_be_bytes)?
                    } else {
                        COMPRESSION_DEFLATE
                    };
                    (
                        first.u64(INCOMPATIBLE_FEATURES, region)?,
                        first.u64(AUTOCLEAR_FEATURES, region)?,
                        first.u32(REFCOUNT_ORDER, region)?,
                        header_length,
                        compression_type,
                    )
                }
            };
        Ok(Self {
            version,
            backing_file_offset: first.u64(BACKING_FILE_OFFSET, region)?,
            virtual_size: first.u64(SIZE, region)?,
            crypt_method: first.u32(CRYPT_METHOD, region)?,
            l1_entries: first.u32(L1_SIZE, region)?,
            l1_offset: first.u64(L1_TABLE_OFFSET, region)?,
            refcount_table_offset: first.u64(REFCOUNT_TABLE_OFFSET, region)?,
            refcount_table_clusters: first.u32(REFCOUNT_TABLE_CLUSTERS, region)?,
            incompatible,
            autoclear,
            refcount_order,
            header_length,
            compression_type,
        })
    }

    /// Rejects every specified forbidden feature, including ones the decoder
    /// would ignore (`crypt_method`) or resolve (backing, external data).
    /// Backing-file size is undefined when the offset is zero, so it is not
    /// evidence of a backing file on its own.
    fn check_features(&self) -> Result<(), Forbidden> {
        if self.crypt_method != 0 {
            return Err(Forbidden::Encrypted {
                method: self.crypt_method,
            });
        }
        if self.backing_file_offset != 0 {
            return Err(Forbidden::BackingFile);
        }
        if self.incompatible & INCOMPATIBLE_DIRTY != 0 {
            return Err(Forbidden::Dirty);
        }
        if self.incompatible & INCOMPATIBLE_CORRUPT != 0 {
            return Err(Forbidden::Corrupt);
        }
        if self.incompatible & INCOMPATIBLE_EXTERNAL_DATA != 0 {
            return Err(Forbidden::ExternalData);
        }
        match self.compression_type {
            COMPRESSION_DEFLATE => {}
            COMPRESSION_ZSTD => return Err(Forbidden::Zstd),
            other => return Err(Forbidden::CompressionType(other)),
        }
        if self.incompatible & INCOMPATIBLE_COMPRESSION_TYPE != 0 {
            return Err(Forbidden::CompressionTypeBit);
        }
        if self.incompatible & INCOMPATIBLE_EXTENDED_L2 != 0 {
            return Err(Forbidden::ExtendedL2);
        }
        if self.incompatible != 0 {
            return Err(Forbidden::UnknownIncompatible(self.incompatible));
        }
        // Unknown autoclear bits only matter to writers; this is read-only.
        if self.autoclear & AUTOCLEAR_RAW_EXTERNAL_DATA != 0 {
            return Err(Forbidden::RawExternalData);
        }
        Ok(())
    }
}

/// Walks `type | length | data | pad-to-8` records from the end of the header
/// to the end marker, inside the first cluster. Each type may appear once.
fn check_extensions(first: &Bytes<'_>, header_length: u64, cluster_size: u64) -> Result<(), Error> {
    let region = Region::HeaderExtension;
    let mut seen = HashSet::new();
    let mut offset = header_length;
    loop {
        let data_start = offset + EXTENSION_HEADER_LEN;
        if data_start > cluster_size {
            return Err(Malformed::ExtensionOverflow { offset }.into());
        }
        let extension_type = first.u32(offset, region)?;
        if extension_type == EXTENSION_END {
            return Ok(());
        }
        let length = first.u32(offset + 4, region)?;
        let data_end = data_start + u64::from(length);
        if data_end > cluster_size {
            return Err(Malformed::ExtensionOverflow { offset }.into());
        }
        first.bytes(data_start, u64::from(length), region)?;
        if !seen.insert(extension_type) {
            return Err(Malformed::DuplicateExtension { extension_type }.into());
        }
        match extension_type {
            EXTENSION_BACKING_FORMAT => return Err(Forbidden::BackingFormatExtension.into()),
            EXTENSION_FULL_DISK_ENCRYPTION => return Err(Forbidden::EncryptionExtension.into()),
            EXTENSION_EXTERNAL_DATA_NAME => return Err(Forbidden::ExternalDataName.into()),
            EXTENSION_FEATURE_NAMES if length % FEATURE_NAME_ENTRY_LEN != 0 => {
                return Err(Malformed::FeatureNameTable { length }.into());
            }
            // Feature names, bitmaps and unknown types need no interpretation.
            _ => {}
        }
        offset = data_end.next_multiple_of(8);
    }
}

/// The table is never read (decoding is read-only), but must be well placed.
fn check_refcount_table(header: &Header, cluster_size: u64, source_len: u64) -> Result<(), Error> {
    let offset = header.refcount_table_offset;
    if offset % cluster_size != 0 {
        return Err(Malformed::RefcountTableOffset(offset).into());
    }
    let region = Region::RefcountTable;
    let length = u64::from(header.refcount_table_clusters)
        .checked_mul(cluster_size)
        .ok_or(Malformed::OffsetOverflow { region })?;
    ensure_within(source_len, offset, length, region)
}

/// Validates every L1 entry and every L2 entry of the tables covering the
/// virtual disk, matching what the decoder loads, plus source containment of
/// every range it will read for the virtual stream.
fn check_mappings(
    source: &File,
    source_len: u64,
    header: &Header,
    cluster_bits: u32,
) -> Result<(), Error> {
    let cluster_size = 1u64 << cluster_bits;
    let map = Map {
        version: header.version,
        cluster_bits,
        cluster_size,
        virtual_size: header.virtual_size,
        guest_clusters: header.virtual_size.div_ceil(cluster_size),
        l2_entries: cluster_size / ENTRY_LEN,
        source_len,
    };
    let required = map.guest_clusters.div_ceil(map.l2_entries);
    if header.l1_entries > MAX_L1_ENTRIES {
        return Err(Malformed::L1TooLarge {
            entries: header.l1_entries,
        }
        .into());
    }
    let l1_entries = u64::from(header.l1_entries);
    if l1_entries < required {
        return Err(Malformed::L1TooSmall {
            entries: header.l1_entries,
            required,
        }
        .into());
    }
    if header.l1_offset == 0 || header.l1_offset % cluster_size != 0 {
        return Err(Malformed::L1Offset(header.l1_offset).into());
    }
    ensure_within(
        source_len,
        header.l1_offset,
        l1_entries * ENTRY_LEN,
        Region::L1Table,
    )?;

    let mut l1_chunk = Vec::new();
    let mut l2_table = Vec::new();
    let mut first_index = 0u64;
    while first_index < l1_entries {
        let count = (l1_entries - first_index).min(L1_CHUNK_ENTRIES);
        // At most L1_CHUNK_ENTRIES entries: 64 KiB.
        l1_chunk.resize(count as usize * ENTRY_LEN as usize, 0);
        let chunk_offset = header.l1_offset + first_index * ENTRY_LEN;
        read_exact(
            source,
            source_len,
            chunk_offset,
            &mut l1_chunk,
            Region::L1Table,
        )?;
        for (position, raw) in l1_chunk.chunks_exact(ENTRY_LEN as usize).enumerate() {
            let index = first_index + position as u64;
            let entry = be_entry(raw, chunk_offset, Region::L1Table, source_len)?;
            let l2_offset = entry & HOST_OFFSET_MASK;
            if entry & L1_RESERVED != 0 || l2_offset % cluster_size != 0 {
                return Err(Malformed::L1Entry { index, entry }.into());
            }
            // L1 entries past the virtual disk are never followed.
            if index < required && l2_offset != 0 {
                map.check_l2_table(source, index, l2_offset, &mut l2_table)?;
            }
        }
        first_index += count;
    }
    Ok(())
}

struct Map {
    version: Version,
    cluster_bits: u32,
    cluster_size: u64,
    virtual_size: u64,
    guest_clusters: u64,
    l2_entries: u64,
    source_len: u64,
}

impl Map {
    fn check_l2_table(
        &self,
        source: &File,
        l1_index: u64,
        l2_offset: u64,
        table: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let region = Region::L2Table { l1_index };
        table.resize(1usize << self.cluster_bits, 0);
        read_exact(source, self.source_len, l2_offset, table, region)?;
        for (position, raw) in table.chunks_exact(ENTRY_LEN as usize).enumerate() {
            let guest_cluster = l1_index * self.l2_entries + position as u64;
            let entry = be_entry(raw, l2_offset, region, self.source_len)?;
            self.check_l2_entry(guest_cluster, entry)?;
        }
        Ok(())
    }

    /// Entries past the virtual disk are format-checked (the decoder loads the
    /// whole table) but never dereferenced.
    fn check_l2_entry(&self, guest_cluster: u64, entry: u64) -> Result<(), Error> {
        let malformed = Malformed::L2Entry {
            guest_cluster,
            entry,
        };
        let in_range = guest_cluster < self.guest_clusters;
        if entry & COMPRESSED != 0 {
            if entry & COPIED != 0 {
                return Err(malformed.into());
            }
            if !in_range {
                return Ok(());
            }
            // Descriptor: offset in bits 0..x, additional 512-byte sectors in
            // bits x..62, x = 62 - (cluster_bits - 8). The span may start
            // unaligned, cross a host cluster and share its last sector; it is
            // at most two clusters long.
            let descriptor = entry & COMPRESSED_DESCRIPTOR_MASK;
            let offset_bits = 62 - (self.cluster_bits - 8);
            let offset = descriptor & ((1u64 << offset_bits) - 1);
            let sectors = descriptor >> offset_bits;
            let length = (sectors + 1) * SECTOR_SIZE - offset % SECTOR_SIZE;
            return ensure_within(
                self.source_len,
                offset,
                length,
                Region::Compressed { guest_cluster },
            );
        }

        let host_offset = entry & HOST_OFFSET_MASK;
        if entry & L2_STANDARD_RESERVED != 0 || host_offset % self.cluster_size != 0 {
            return Err(malformed.into());
        }
        if !in_range {
            return Ok(());
        }
        if entry & ZERO != 0 {
            return match self.version {
                // A preallocated zero cluster's host bytes are never read.
                Version::V3 => Ok(()),
                Version::V2 => Err(Malformed::V2ZeroCluster { guest_cluster }.into()),
            };
        }
        if host_offset == 0 {
            // Unallocated without a backing file reads as zeros.
            return Ok(());
        }
        // Only the virtual part of a final partial cluster is read.
        let length = self
            .cluster_size
            .min(self.virtual_size - guest_cluster * self.cluster_size);
        ensure_within(
            self.source_len,
            host_offset,
            length,
            Region::Data { guest_cluster },
        )
    }
}

/// Bounded view of bytes read from the start of the source.
struct Bytes<'a> {
    bytes: &'a [u8],
    source_len: u64,
}

impl Bytes<'_> {
    /// The view holds everything the source has up to its own length, so a
    /// range it lacks is past the end of the source.
    fn bytes(&self, offset: u64, length: u64, region: Region) -> Result<&[u8], Error> {
        let truncated = || Error::Truncated {
            region,
            offset,
            length,
            source_len: self.source_len,
        };
        let start = usize::try_from(offset).map_err(|_| truncated())?;
        let end = offset
            .checked_add(length)
            .and_then(|end| usize::try_from(end).ok())
            .ok_or_else(truncated)?;
        self.bytes.get(start..end).ok_or_else(truncated)
    }

    fn array<const N: usize>(&self, offset: u64, region: Region) -> Result<[u8; N], Error> {
        let bytes = self.bytes(offset, N as u64, region)?;
        <[u8; N]>::try_from(bytes).map_err(|_| Error::Truncated {
            region,
            offset,
            length: N as u64,
            source_len: self.source_len,
        })
    }

    fn u32(&self, offset: u64, region: Region) -> Result<u32, Error> {
        self.array(offset, region).map(u32::from_be_bytes)
    }

    fn u64(&self, offset: u64, region: Region) -> Result<u64, Error> {
        self.array(offset, region).map(u64::from_be_bytes)
    }
}

fn be_entry(raw: &[u8], table_offset: u64, region: Region, source_len: u64) -> Result<u64, Error> {
    <[u8; 8]>::try_from(raw)
        .map(u64::from_be_bytes)
        .map_err(|_| Error::Truncated {
            region,
            offset: table_offset,
            length: ENTRY_LEN,
            source_len,
        })
}

fn ensure_within(source_len: u64, offset: u64, length: u64, region: Region) -> Result<(), Error> {
    let end = offset
        .checked_add(length)
        .ok_or(Malformed::OffsetOverflow { region })?;
    if end > source_len {
        return Err(Error::Truncated {
            region,
            offset,
            length,
            source_len,
        });
    }
    Ok(())
}

/// Exact positional read; a short source is an error, never zero padding.
fn read_exact(
    source: &File,
    source_len: u64,
    offset: u64,
    buffer: &mut [u8],
    region: Region,
) -> Result<(), Error> {
    ensure_within(source_len, offset, buffer.len() as u64, region)?;
    source
        .read_exact_at(buffer, offset)
        .map_err(|source| Error::Io { offset, source })
}
