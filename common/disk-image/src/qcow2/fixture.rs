//! Test-only qcow2 encoder and raw DEFLATE writers.
//!
//! An independent model of the on-disk format: tests describe guest clusters
//! as plain bytes, encode them deterministically and compare the decoder's
//! output with [`Image::expected`]. Layout:
//!
//! ```text
//! [header][L1..][refcount table][L2 tables][data clusters][packed compressed][refcount blocks]
//! ```
//!
//! Compressed streams start 100 bytes into their first cluster and are packed
//! back to back, so spans are unaligned, cross host clusters and share final
//! sectors, exactly as QEMU writes them. The file is cluster aligned.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) const HEADER_BACKING_FILE_OFFSET: u64 = 8;
pub(crate) const HEADER_BACKING_FILE_SIZE: u64 = 16;
pub(crate) const HEADER_CLUSTER_BITS: u64 = 20;
pub(crate) const HEADER_SIZE: u64 = 24;
pub(crate) const HEADER_CRYPT_METHOD: u64 = 32;
pub(crate) const HEADER_L1_SIZE: u64 = 36;
pub(crate) const HEADER_L1_TABLE_OFFSET: u64 = 40;
pub(crate) const HEADER_REFCOUNT_TABLE_OFFSET: u64 = 48;
pub(crate) const HEADER_REFCOUNT_TABLE_CLUSTERS: u64 = 56;
pub(crate) const HEADER_NB_SNAPSHOTS: u64 = 60;
pub(crate) const HEADER_SNAPSHOTS_OFFSET: u64 = 64;
pub(crate) const HEADER_INCOMPATIBLE: u64 = 72;
pub(crate) const HEADER_COMPATIBLE: u64 = 80;
pub(crate) const HEADER_AUTOCLEAR: u64 = 88;
pub(crate) const HEADER_REFCOUNT_ORDER: u64 = 96;
pub(crate) const HEADER_LENGTH: u64 = 100;
pub(crate) const HEADER_COMPRESSION_TYPE: u64 = 104;

pub(crate) const COPIED: u64 = 1 << 63;
pub(crate) const COMPRESSED: u64 = 1 << 62;
pub(crate) const ZERO: u64 = 1;

const COMPRESSED_LEAD: u64 = 100;
const REFCOUNT_ORDER: u32 = 4;

#[derive(Clone)]
pub(crate) enum Guest {
    /// One cluster of plain bytes stored in a host cluster.
    Data(Vec<u8>),
    /// v3 explicit zero without a host cluster.
    Zero,
    /// v3 explicit zero over a host cluster that holds these stale bytes.
    PreallocatedZero(Vec<u8>),
    /// A raw DEFLATE stream; `plain` is the cluster it should decode to.
    Compressed { plain: Vec<u8>, stream: Vec<u8> },
}

impl Guest {
    pub(crate) fn stored(plain: Vec<u8>) -> Self {
        let stream = deflate_stored(&plain);
        Self::Compressed { plain, stream }
    }

    pub(crate) fn fixed(plain: Vec<u8>) -> Self {
        let stream = deflate_fixed(&plain);
        Self::Compressed { plain, stream }
    }
}

pub(crate) struct Image {
    pub(crate) version: u32,
    pub(crate) cluster_bits: u32,
    pub(crate) virtual_size: u64,
    /// v3 only; 112 carries the compression type byte, 104 omits it.
    pub(crate) header_length: u32,
    pub(crate) extensions: Vec<(u32, Vec<u8>)>,
    pub(crate) clusters: BTreeMap<u64, Guest>,
    pub(crate) extra_l1_entries: u32,
}

pub(crate) struct Encoded {
    pub(crate) bytes: Vec<u8>,
    pub(crate) l1_offset: u64,
    pub(crate) l2_offsets: BTreeMap<u64, u64>,
    /// Host offset of each data, preallocated or compressed guest cluster.
    pub(crate) host_offsets: BTreeMap<u64, u64>,
    l2_entries: u64,
}

impl Image {
    pub(crate) fn new(version: u32, cluster_bits: u32, virtual_size: u64) -> Self {
        Self {
            version,
            cluster_bits,
            virtual_size,
            header_length: 112,
            extensions: Vec::new(),
            clusters: BTreeMap::new(),
            extra_l1_entries: 0,
        }
    }

    pub(crate) fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    pub(crate) fn with(mut self, guest_cluster: u64, guest: Guest) -> Self {
        self.clusters.insert(guest_cluster, guest);
        self
    }

    pub(crate) fn extension(mut self, extension_type: u32, data: Vec<u8>) -> Self {
        self.extensions.push((extension_type, data));
        self
    }

    /// The logical stream an independent decoder must produce.
    pub(crate) fn expected(&self) -> Vec<u8> {
        let c = self.cluster_size();
        let mut out = vec![0u8; self.virtual_size as usize];
        for (guest_cluster, guest) in &self.clusters {
            let start = guest_cluster * c;
            if start >= self.virtual_size {
                continue;
            }
            let len = c.min(self.virtual_size - start) as usize;
            let plain = match guest {
                Guest::Data(plain) | Guest::Compressed { plain, .. } => plain,
                Guest::Zero | Guest::PreallocatedZero(_) => continue,
            };
            out[start as usize..start as usize + len].copy_from_slice(&plain[..len]);
        }
        out
    }

    pub(crate) fn encode(&self) -> Encoded {
        let c = self.cluster_size();
        let l2_entries = c / 8;
        let guest_clusters = self.virtual_size.div_ceil(c);
        let l1_size = guest_clusters.div_ceil(l2_entries) + u64::from(self.extra_l1_entries);
        let l1_clusters = (l1_size * 8).div_ceil(c).max(1);

        let l1_offset = c;
        let refcount_table_offset = (1 + l1_clusters) * c;
        let mut next_cluster = 2 + l1_clusters;

        let l2_indexes: BTreeSet<u64> = self.clusters.keys().map(|g| g / l2_entries).collect();
        let mut l2_offsets = BTreeMap::new();
        for index in &l2_indexes {
            l2_offsets.insert(*index, next_cluster * c);
            next_cluster += 1;
        }

        let mut host_offsets = BTreeMap::new();
        for (guest_cluster, guest) in &self.clusters {
            if matches!(guest, Guest::Data(_) | Guest::PreallocatedZero(_)) {
                host_offsets.insert(*guest_cluster, next_cluster * c);
                next_cluster += 1;
            }
        }

        let compressed_start = next_cluster * c + COMPRESSED_LEAD;
        let mut compressed_end = compressed_start;
        for (guest_cluster, guest) in &self.clusters {
            if let Guest::Compressed { stream, .. } = guest {
                host_offsets.insert(*guest_cluster, compressed_end);
                compressed_end += stream.len() as u64;
            }
        }
        if compressed_end > compressed_start {
            next_cluster = compressed_end.next_multiple_of(512).div_ceil(c);
        }

        // Refcount blocks go last; find how many cover everything incl. themselves.
        let per_block = (c * 8) >> REFCOUNT_ORDER;
        let mut refcount_blocks = 1;
        while next_cluster + refcount_blocks > refcount_blocks * per_block {
            refcount_blocks += 1;
        }
        assert!(
            refcount_blocks <= l2_entries,
            "fixture too large for one refcount table"
        );
        let refcount_block_start = next_cluster;
        let total_clusters = next_cluster + refcount_blocks;

        let mut bytes = vec![0u8; (total_clusters * c) as usize];
        let mut refcounts = vec![0u16; total_clusters as usize];
        for refcount in &mut refcounts[..(2 + l1_clusters) as usize] {
            *refcount += 1;
        }
        for offset in l2_offsets.values() {
            refcounts[(offset / c) as usize] += 1;
        }

        // Header.
        put(&mut bytes, 0, b"QFI\xfb");
        put_u32(&mut bytes, 4, self.version);
        put_u32(&mut bytes, HEADER_CLUSTER_BITS, self.cluster_bits);
        put_u64(&mut bytes, HEADER_SIZE, self.virtual_size);
        put_u32(&mut bytes, HEADER_L1_SIZE, l1_size as u32);
        put_u64(&mut bytes, HEADER_L1_TABLE_OFFSET, l1_offset);
        put_u64(
            &mut bytes,
            HEADER_REFCOUNT_TABLE_OFFSET,
            refcount_table_offset,
        );
        put_u32(&mut bytes, HEADER_REFCOUNT_TABLE_CLUSTERS, 1);
        let mut extension_offset = 72u64;
        if self.version == 3 {
            put_u32(&mut bytes, HEADER_REFCOUNT_ORDER, REFCOUNT_ORDER);
            put_u32(&mut bytes, HEADER_LENGTH, self.header_length);
            extension_offset = u64::from(self.header_length);
        }
        for (extension_type, data) in &self.extensions {
            put_u32(&mut bytes, extension_offset, *extension_type);
            put_u32(&mut bytes, extension_offset + 4, data.len() as u32);
            put(&mut bytes, extension_offset + 8, data);
            extension_offset = (extension_offset + 8 + data.len() as u64).next_multiple_of(8);
        }
        assert!(
            extension_offset + 8 <= c,
            "extensions overflow the header cluster"
        );

        // L1 and L2 tables.
        for (index, offset) in &l2_offsets {
            put_u64(&mut bytes, l1_offset + index * 8, offset | COPIED);
        }
        for (guest_cluster, guest) in &self.clusters {
            let table = l2_offsets[&(guest_cluster / l2_entries)];
            let entry_offset = table + (guest_cluster % l2_entries) * 8;
            let entry = match guest {
                Guest::Data(plain) => {
                    let host = host_offsets[guest_cluster];
                    assert_eq!(plain.len() as u64, c);
                    put(&mut bytes, host, plain);
                    refcounts[(host / c) as usize] += 1;
                    host | COPIED
                }
                Guest::PreallocatedZero(stale) => {
                    let host = host_offsets[guest_cluster];
                    put(&mut bytes, host, stale);
                    refcounts[(host / c) as usize] += 1;
                    host | COPIED | ZERO
                }
                Guest::Zero => ZERO,
                Guest::Compressed { stream, .. } => {
                    let host = host_offsets[guest_cluster];
                    let len = stream.len() as u64;
                    put(&mut bytes, host, stream);
                    for cluster in (host / c)..=((host + len - 1) / c) {
                        refcounts[cluster as usize] += 1;
                    }
                    compressed_descriptor(self.cluster_bits, host, len)
                }
            };
            put_u64(&mut bytes, entry_offset, entry);
        }

        // Refcount table and blocks.
        for block in 0..refcount_blocks {
            let block_cluster = refcount_block_start + block;
            refcounts[block_cluster as usize] += 1;
            put_u64(
                &mut bytes,
                refcount_table_offset + block * 8,
                block_cluster * c,
            );
        }
        for (cluster, refcount) in refcounts.iter().enumerate() {
            let cluster = cluster as u64;
            let block_offset = (refcount_block_start + cluster / per_block) * c;
            put(
                &mut bytes,
                block_offset + (cluster % per_block) * 2,
                &refcount.to_be_bytes(),
            );
        }

        Encoded {
            bytes,
            l1_offset,
            l2_offsets,
            host_offsets,
            l2_entries,
        }
    }
}

/// QEMU's encoding: `n` additional sectors after the one holding `offset`.
pub(crate) fn compressed_descriptor(cluster_bits: u32, offset: u64, len: u64) -> u64 {
    let offset_bits = 62 - (cluster_bits - 8);
    let sectors = ((offset + len - 1) >> 9) - (offset >> 9);
    assert!(
        sectors < 1 << (cluster_bits - 8),
        "compressed span too long for {cluster_bits}-bit clusters"
    );
    COMPRESSED | (sectors << offset_bits) | offset
}

impl Encoded {
    pub(crate) fn l1_entry_offset(&self, index: u64) -> u64 {
        self.l1_offset + index * 8
    }

    pub(crate) fn l2_entry_offset(&self, guest_cluster: u64) -> u64 {
        self.l2_offsets[&(guest_cluster / self.l2_entries)] + (guest_cluster % self.l2_entries) * 8
    }

    pub(crate) fn u64_at(&self, offset: u64) -> u64 {
        let at = offset as usize;
        u64::from_be_bytes(self.bytes[at..at + 8].try_into().unwrap())
    }

    pub(crate) fn set_u8(&mut self, offset: u64, value: u8) {
        self.bytes[offset as usize] = value;
    }

    pub(crate) fn set_u32(&mut self, offset: u64, value: u32) {
        put_u32(&mut self.bytes, offset, value);
    }

    pub(crate) fn set_u64(&mut self, offset: u64, value: u64) {
        put_u64(&mut self.bytes, offset, value);
    }
}

fn put(bytes: &mut [u8], offset: u64, data: &[u8]) {
    let at = offset as usize;
    bytes[at..at + data.len()].copy_from_slice(data);
}

fn put_u32(bytes: &mut [u8], offset: u64, value: u32) {
    put(bytes, offset, &value.to_be_bytes());
}

fn put_u64(bytes: &mut [u8], offset: u64, value: u64) {
    put(bytes, offset, &value.to_be_bytes());
}

/// Deterministic bytes with no long runs (xorshift).
pub(crate) fn noise(seed: u64, len: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Runs of length 7 cycling through every byte value, so fixed-Huffman
/// encoding uses 8- and 9-bit literals plus distance-1 matches.
pub(crate) fn runs(seed: u64, len: u64) -> Vec<u8> {
    (0..len).map(|i| ((i / 7) * 37 + seed) as u8).collect()
}

/// Raw DEFLATE using stored blocks only (RFC 1951 §3.2.4).
pub(crate) fn deflate_stored(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let blocks: Vec<&[u8]> = plain.chunks(u16::MAX as usize).collect();
    for (index, block) in blocks.iter().enumerate() {
        out.push(u8::from(index + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out
}

/// Raw DEFLATE with one fixed-Huffman block (RFC 1951 §3.2.6): literals and
/// distance-1 run-length matches.
pub(crate) fn deflate_fixed(plain: &[u8]) -> Vec<u8> {
    let mut bits = BitWriter::default();
    bits.bits(1, 1); // BFINAL
    bits.bits(1, 2); // BTYPE = 01
    let mut i = 0;
    while i < plain.len() {
        let byte = plain[i];
        let run = plain[i..].iter().take_while(|b| **b == byte).count();
        bits.literal(byte);
        let mut remaining = run - 1;
        while remaining > 0 {
            let len = if remaining >= 258 {
                258
            } else if remaining >= 10 {
                10
            } else if remaining >= 3 {
                remaining
            } else {
                bits.literal(byte);
                remaining -= 1;
                continue;
            };
            bits.match_distance_one(len);
            remaining -= len;
        }
        i += run;
    }
    bits.code(0, 7); // end of block (symbol 256)
    bits.finish()
}

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    current: u8,
    used: u32,
}

impl BitWriter {
    fn bit(&mut self, bit: u32) {
        self.current |= ((bit & 1) as u8) << self.used;
        self.used += 1;
        if self.used == 8 {
            self.out.push(self.current);
            self.current = 0;
            self.used = 0;
        }
    }

    /// Header and extra bits: least significant bit first.
    fn bits(&mut self, value: u32, count: u32) {
        for i in 0..count {
            self.bit(value >> i);
        }
    }

    /// Huffman codes: most significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.bit(code >> i);
        }
    }

    fn literal(&mut self, byte: u8) {
        let byte = u32::from(byte);
        if byte <= 143 {
            self.code(0x30 + byte, 8);
        } else {
            self.code(0x190 + byte - 144, 9);
        }
    }

    /// Lengths 3..=10 (symbols 257..=264, 7-bit codes) or 258 (symbol 285,
    /// 8-bit code), then distance code 0 (distance 1, 5 bits).
    fn match_distance_one(&mut self, len: usize) {
        match len {
            3..=10 => self.code(len as u32 - 2, 7),
            258 => self.code(0xc5, 8),
            other => panic!("unsupported match length {other}"),
        }
        self.code(0, 5);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.used > 0 {
            self.out.push(self.current);
        }
        self.out
    }
}
