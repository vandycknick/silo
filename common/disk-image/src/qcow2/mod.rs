//! Bounded qcow2 admission and sequential decoding to the raw virtual stream.
//!
//! Only self-contained qcow2 version 2 and 3 images are admitted: no
//! encryption, backing file, external data file, zstd, extended L2 entries,
//! dirty/corrupt state or unknown incompatible feature. Admission is Silo's
//! own policy, enforced before the decoder (imago) is constructed:
//!
//! ```text
//!  held read-only File ──► admit() ──────────────────────► Admission
//!                          │ fixed header + extensions      (facts bound to
//!                          │ refcount/L1 placement          dev, inode and
//!                          │ every covering L2 entry        source length)
//!                          ▼
//!                   typed rejection, nothing decoded
//!
//!  same File + Admission ─► decode() ─► imago Qcow2 over HeldSource ─► Write
//!                                       (deny implicit open; every read is
//!                                        exact and inside the admitted length)
//! ```
//!
//! The caller owns pathname resolution, staging, content identity and
//! publication. On any error the caller discards its staging output: a partial
//! stream is never a successful conversion. Only unallocated and explicit zero
//! clusters produce zeros; truncation and I/O failures are errors. Internal
//! snapshots and bitmaps are ignored; only the active virtual stream is
//! decoded.

mod preflight;
mod source;

#[cfg(test)]
mod fixture;

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;

use imago::qcow2::Qcow2;
use imago::{DenyImplicitOpenGate, FormatAccess, FormatDriverBuilder};

use crate::qcow2::source::HeldSource;

/// qcow2 magic, `QFI\xfb`.
pub const MAGIC: [u8; 4] = *b"QFI\xfb";
/// Logical sector size of the decoded stream.
pub const SECTOR_SIZE: u64 = 512;
/// Largest admitted decoded virtual size (1 TiB).
pub const MAX_VIRTUAL_SIZE: u64 = 1 << 40;
/// Smallest cluster (512 bytes), matching QEMU and the selected decoder.
pub const MIN_CLUSTER_BITS: u32 = 9;
/// Largest cluster (2 MiB), matching QEMU and the selected decoder.
pub const MAX_CLUSTER_BITS: u32 = 21;
/// Largest active L1 table (32 MiB), matching QEMU and the selected decoder.
/// It can cap coverage below [`MAX_VIRTUAL_SIZE`] for small clusters.
pub const MAX_L1_ENTRIES: u32 = 4 * 1024 * 1024;

/// Decode unit; raised to one cluster so no compressed cluster inflates twice.
const DECODE_CHUNK_BITS: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V2,
    V3,
}

/// Validated facts for one held source, consumed by [`decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    version: Version,
    cluster_bits: u32,
    virtual_size: u64,
    source: SourceIdentity,
}

impl Admission {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    /// Exact length of the decoded raw stream: positive, 512-byte aligned and
    /// at most [`MAX_VIRTUAL_SIZE`].
    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    /// Length of the qcow2 container at admission.
    pub fn source_len(&self) -> u64 {
        self.source.len
    }
}

/// Where in the container a referenced range lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Header,
    HeaderExtension,
    RefcountTable,
    L1Table,
    L2Table { l1_index: u64 },
    Data { guest_cluster: u64 },
    Compressed { guest_cluster: u64 },
}

/// A well-formed feature outside the admitted self-contained profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Forbidden {
    #[error("encryption method {method}")]
    Encrypted { method: u32 },
    #[error("full-disk encryption header extension")]
    EncryptionExtension,
    #[error("backing file")]
    BackingFile,
    #[error("backing file format extension")]
    BackingFormatExtension,
    #[error("external data file")]
    ExternalData,
    #[error("external data file name extension")]
    ExternalDataName,
    #[error("raw external data")]
    RawExternalData,
    #[error("dirty image; repair it offline before import")]
    Dirty,
    #[error("image marked corrupt; repair it offline before import")]
    Corrupt,
    #[error("zstd compression")]
    Zstd,
    #[error("unknown compression type {0}")]
    CompressionType(u8),
    #[error("compression type feature bit")]
    CompressionTypeBit,
    #[error("extended L2 entries")]
    ExtendedL2,
    #[error("unknown incompatible feature bits {0:#x}")]
    UnknownIncompatible(u64),
}

/// A structural violation of the qcow2 format or of the decoder's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    ClusterBits(u32),
    HeaderLength(u32),
    RefcountOrder(u32),
    /// The extension area leaves the first cluster or lacks an end marker.
    ExtensionOverflow {
        offset: u64,
    },
    DuplicateExtension {
        extension_type: u32,
    },
    FeatureNameTable {
        length: u32,
    },
    RefcountTableOffset(u64),
    L1Offset(u64),
    L1TooSmall {
        entries: u32,
        required: u64,
    },
    L1TooLarge {
        entries: u32,
    },
    /// Reserved bits set or unaligned L2 table offset.
    L1Entry {
        index: u64,
        entry: u64,
    },
    /// Reserved bits set or unaligned host cluster offset.
    L2Entry {
        guest_cluster: u64,
        entry: u64,
    },
    /// Version 2 reserves the zero-cluster bit.
    V2ZeroCluster {
        guest_cluster: u64,
    },
    OffsetOverflow {
        region: Region,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("inspecting held qcow2 source handle: {0}")]
    Handle(#[source] io::Error),
    #[error("qcow2 source is not a regular file")]
    NotRegularFile,
    #[error("qcow2 source I/O at byte {offset}: {source}")]
    Io {
        offset: u64,
        #[source]
        source: io::Error,
    },
    #[error("{region:?} at byte {offset} (+{length}) ends past the {source_len}-byte source")]
    Truncated {
        region: Region,
        offset: u64,
        length: u64,
        source_len: u64,
    },
    #[error("not a qcow2 image")]
    NotQcow2,
    #[error("unsupported qcow2 version {0}; only versions 2 and 3 are admitted")]
    UnsupportedVersion(u32),
    #[error("qcow2 {0} is not admitted; only self-contained images are imported")]
    Forbidden(Forbidden),
    #[error("malformed qcow2 image: {0:?}")]
    Malformed(Malformed),
    #[error("qcow2 virtual size {0} is not a positive multiple of 512 bytes up to 1 TiB")]
    VirtualSize(u64),
    #[error("qcow2 source no longer matches its admission")]
    SourceChanged,
    #[error("decoding qcow2 at guest byte {offset}: {source}")]
    Decode {
        offset: u64,
        #[source]
        source: io::Error,
    },
    #[error("writing decoded stream at guest byte {offset}: {source}")]
    Output {
        offset: u64,
        #[source]
        source: io::Error,
    },
}

impl From<Forbidden> for Error {
    fn from(value: Forbidden) -> Self {
        Self::Forbidden(value)
    }
}

impl From<Malformed> for Error {
    fn from(value: Malformed) -> Self {
        Self::Malformed(value)
    }
}

/// Validates the held source without decoding or opening anything else.
/// Reads are positional, so the caller's file cursor is untouched.
pub fn admit(source: &File) -> Result<Admission, Error> {
    let identity = SourceIdentity::of(source)?;
    let layout = preflight::check(source, identity.len)?;
    identity.verify(source)?;
    Ok(Admission {
        version: layout.version,
        cluster_bits: layout.cluster_bits,
        virtual_size: layout.virtual_size,
        source: identity,
    })
}

/// Streams exactly [`Admission::virtual_size`] decoded bytes into `output`
/// and flushes it. Memory stays bounded: one decode chunk plus the decoder's
/// L1 table and metadata cache, never the virtual disk.
pub fn decode<W: Write + ?Sized>(
    source: &File,
    admission: &Admission,
    output: &mut W,
) -> Result<(), Error> {
    admission.source.verify(source)?;
    let held = source.try_clone().map_err(Error::Handle)?;
    let image = Qcow2::<HeldSource>::builder(HeldSource::new(held, admission.source.len))
        .write(false)
        .open(DenyImplicitOpenGate::default())
        .map_err(|source| Error::Decode { offset: 0, source })?;
    let image = FormatAccess::new(image);
    if image.size() != admission.virtual_size {
        return Err(Error::SourceChanged);
    }

    let chunk_len = 1usize << admission.cluster_bits.max(DECODE_CHUNK_BITS);
    let mut buffer = vec![0u8; chunk_len];
    let mut offset = 0u64;
    while offset < admission.virtual_size {
        let remaining = admission.virtual_size - offset;
        buffer.truncate(usize::try_from(remaining).unwrap_or(usize::MAX));
        image
            .read(buffer.as_mut_slice(), offset)
            .map_err(|source| Error::Decode { offset, source })?;
        output
            .write_all(&buffer)
            .map_err(|source| Error::Output { offset, source })?;
        offset += buffer.len() as u64;
    }
    output
        .flush()
        .map_err(|source| Error::Output { offset, source })?;
    admission.source.verify(source)
}

/// Binds an admission to the inspected file (device, inode) and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    len: u64,
}

impl SourceIdentity {
    fn of(source: &File) -> Result<Self, Error> {
        let metadata = source.metadata().map_err(Error::Handle)?;
        if !metadata.file_type().is_file() {
            return Err(Error::NotRegularFile);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
        })
    }

    fn verify(&self, source: &File) -> Result<(), Error> {
        if Self::of(source)? == *self {
            Ok(())
        } else {
            Err(Error::SourceChanged)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use crate::qcow2::fixture::{
        self, COPIED, Encoded, Guest, HEADER_AUTOCLEAR, HEADER_BACKING_FILE_OFFSET,
        HEADER_BACKING_FILE_SIZE, HEADER_CLUSTER_BITS, HEADER_COMPATIBLE, HEADER_COMPRESSION_TYPE,
        HEADER_CRYPT_METHOD, HEADER_INCOMPATIBLE, HEADER_L1_SIZE, HEADER_L1_TABLE_OFFSET,
        HEADER_LENGTH, HEADER_NB_SNAPSHOTS, HEADER_REFCOUNT_ORDER, HEADER_REFCOUNT_TABLE_CLUSTERS,
        HEADER_REFCOUNT_TABLE_OFFSET, HEADER_SIZE, HEADER_SNAPSHOTS_OFFSET, Image, ZERO,
    };
    use crate::qcow2::{
        Error, Forbidden, MAX_L1_ENTRIES, MAX_VIRTUAL_SIZE, Malformed, Region, Version, admit,
        decode,
    };

    const FEATURE_NAMES: u32 = 0x6803_f857;
    const BITMAPS: u32 = 0x2385_2875;
    const BACKING_FORMAT: u32 = 0xe279_2aca;
    const FULL_DISK_ENCRYPTION: u32 = 0x0537_be77;
    const EXTERNAL_DATA_NAME: u32 = 0x4441_5441;
    const UNKNOWN_EXTENSION: u32 = 0x1234_5678;

    fn source(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn decoded(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let file = source(bytes);
        let admission = admit(&file)?;
        let mut out = Vec::new();
        decode(&file, &admission, &mut out)?;
        Ok(out)
    }

    fn assert_same(actual: &[u8], expected: &[u8]) {
        assert_eq!(actual.len(), expected.len(), "decoded length");
        if let Some(at) = actual.iter().zip(expected).position(|(a, e)| a != e) {
            panic!("decoded stream differs first at byte {at}");
        }
    }

    fn round_trip(image: &Image) -> Encoded {
        let encoded = image.encode();
        assert_same(&decoded(&encoded.bytes).unwrap(), &image.expected());
        encoded
    }

    fn rejected(bytes: &[u8]) -> Error {
        admit(&source(bytes)).unwrap_err()
    }

    /// 4 KiB clusters, eight of them: data, unallocated, stored DEFLATE.
    fn base(version: u32) -> Image {
        Image::new(version, 12, 8 * 4096)
            .with(0, Guest::Data(fixture::noise(1, 4096)))
            .with(3, Guest::stored(fixture::noise(2, 4096)))
    }

    fn patched(image: &Image, patch: impl FnOnce(&mut Encoded)) -> Vec<u8> {
        let mut encoded = image.encode();
        patch(&mut encoded);
        encoded.bytes
    }

    #[test]
    fn v3_mixed_clusters_across_l2_tables_decode_to_model() {
        // 512-byte clusters: 64 entries per L2 table, so 200 clusters span four.
        let c = 512;
        let image = Image::new(3, 9, 200 * c)
            .with(0, Guest::Data(fixture::noise(1, c)))
            .with(1, Guest::fixed(fixture::runs(0, c)))
            .with(2, Guest::fixed(fixture::runs(5, c)))
            .with(3, Guest::Zero)
            .with(4, Guest::PreallocatedZero(vec![0xab; c as usize]))
            .with(63, Guest::Data(fixture::noise(2, c)))
            .with(130, Guest::fixed(fixture::runs(9, c)))
            .with(150, Guest::Data(fixture::noise(3, c)))
            .with(199, Guest::fixed(fixture::runs(11, c)));
        let encoded = round_trip(&image);
        // L1 entry 1 (guest clusters 64..128) has no L2 table at all.
        assert!(!encoded.l2_offsets.contains_key(&1));
        assert_eq!(encoded.u64_at(encoded.l1_entry_offset(1)), 0);
    }

    #[test]
    fn final_partial_cluster_emits_only_virtual_bytes() {
        let size = 5 * 4096 + 1024;
        round_trip(
            &Image::new(3, 12, size)
                .with(0, Guest::Data(fixture::noise(1, 4096)))
                .with(2, Guest::stored(fixture::noise(2, 4096)))
                .with(5, Guest::stored(fixture::noise(3, 4096))),
        );
        round_trip(
            &Image::new(3, 12, size)
                .with(4, Guest::fixed(fixture::runs(1, 4096)))
                .with(5, Guest::Data(fixture::noise(4, 4096))),
        );
    }

    #[test]
    fn v2_image_decodes() {
        let c = 65536;
        let image = Image::new(2, 16, 3 * c)
            .with(0, Guest::Data(fixture::noise(1, c)))
            .with(1, Guest::stored(fixture::noise(2, c)));
        round_trip(&image);
        round_trip(&image.extension(UNKNOWN_EXTENSION, vec![1, 2, 3]));
    }

    #[test]
    fn smallest_and_largest_clusters_decode() {
        let c = 2 << 20;
        round_trip(
            &Image::new(3, 21, 2 * c + 512)
                .with(0, Guest::fixed(fixture::runs(3, c)))
                .with(1, Guest::Data(fixture::noise(1, c)))
                .with(2, Guest::stored(fixture::noise(2, c))),
        );
        round_trip(
            &Image::new(2, 9, 8 * 512)
                .with(0, Guest::fixed(fixture::runs(0, 512)))
                .with(7, Guest::Data(fixture::noise(1, 512))),
        );
    }

    #[test]
    fn compressed_spans_share_sectors_and_cross_host_clusters() {
        let c = 1024;
        let mut image = Image::new(3, 10, 12 * c);
        for cluster in 0..12 {
            image = image.with(cluster, Guest::stored(fixture::noise(cluster + 1, c)));
        }
        let encoded = image.encode();
        let stream_len = fixture::deflate_stored(&fixture::noise(1, c)).len() as u64;
        let starts: Vec<u64> = encoded.host_offsets.values().copied().collect();
        assert!(starts.iter().all(|start| start % 512 != 0));
        assert!(
            starts
                .iter()
                .any(|start| start / c != (start + stream_len - 1) / c)
        );
        assert!(
            starts
                .windows(2)
                .all(|pair| (pair[0] + stream_len - 1) / 512 == pair[1] / 512)
        );
        assert_same(&decoded(&encoded.bytes).unwrap(), &image.expected());
    }

    #[test]
    fn sparse_image_decodes_to_zeros() {
        let image = Image::new(3, 16, 3 << 20);
        let out = decoded(&image.encode().bytes).unwrap();
        assert_eq!(out.len(), 3 << 20);
        assert!(out.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn inert_metadata_is_tolerated() {
        let mut feature_names = vec![0u8; 48];
        feature_names[2..7].copy_from_slice(b"dirty");
        let image = base(3)
            .extension(FEATURE_NAMES, feature_names)
            .extension(BITMAPS, vec![0; 24])
            .extension(UNKNOWN_EXTENSION, vec![9; 5]);
        let bytes = patched(&image, |encoded| {
            encoded.set_u64(HEADER_COMPATIBLE, 1 | (1 << 5));
            encoded.set_u64(HEADER_AUTOCLEAR, 1 | (1 << 9));
            // An internal snapshot does not select another stream.
            encoded.set_u32(HEADER_NB_SNAPSHOTS, 1);
            encoded.set_u64(HEADER_SNAPSHOTS_OFFSET, 4096);
            // Backing-file size is undefined while the offset is zero.
            encoded.set_u32(HEADER_BACKING_FILE_SIZE, 100);
        });
        assert_same(&decoded(&bytes).unwrap(), &image.expected());
    }

    #[test]
    fn admission_reports_facts() {
        let encoded = base(2).encode();
        let admission = admit(&source(&encoded.bytes)).unwrap();
        assert_eq!(admission.version(), Version::V2);
        assert_eq!(admission.cluster_size(), 4096);
        assert_eq!(admission.virtual_size(), 8 * 4096);
        assert_eq!(admission.source_len(), encoded.bytes.len() as u64);
    }

    #[test]
    fn one_tib_is_admitted_and_one_more_sector_is_not() {
        let image = Image::new(3, 21, MAX_VIRTUAL_SIZE);
        let mut encoded = image.encode();
        let admission = admit(&source(&encoded.bytes)).unwrap();
        assert_eq!(admission.virtual_size(), MAX_VIRTUAL_SIZE);
        encoded.set_u64(HEADER_SIZE, MAX_VIRTUAL_SIZE + 512);
        let err = rejected(&encoded.bytes);
        assert!(matches!(err, Error::VirtualSize(size) if size == MAX_VIRTUAL_SIZE + 512));
    }

    #[test]
    fn virtual_size_must_be_positive_and_sector_aligned() {
        for size in [0, 1000, 512 * 8 + 1] {
            let bytes = patched(&base(3), |encoded| encoded.set_u64(HEADER_SIZE, size));
            let err = rejected(&bytes);
            assert!(matches!(err, Error::VirtualSize(s) if s == size), "{err:?}");
        }
    }

    #[test]
    fn foreign_magic_and_versions_are_rejected() {
        let bytes = patched(&base(3), |encoded| encoded.set_u8(3, 0));
        assert!(matches!(rejected(&bytes), Error::NotQcow2));
        for version in [0, 1, 4] {
            let bytes = patched(&base(3), |encoded| encoded.set_u32(4, version));
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::UnsupportedVersion(v) if v == version),
                "{err:?}"
            );
        }
    }

    #[test]
    fn truncated_header_is_an_error() {
        let bytes = base(3).encode().bytes;
        for len in [0, 50, 100, 108] {
            let err = rejected(&bytes[..len]);
            assert!(
                matches!(
                    err,
                    Error::Truncated {
                        region: Region::Header,
                        ..
                    }
                ),
                "{len}: {err:?}"
            );
        }
    }

    #[test]
    fn cluster_bits_outside_decoder_range_are_rejected() {
        for bits in [0, 8, 22, 63, 64, u32::MAX] {
            let bytes = patched(&base(3), |encoded| {
                encoded.set_u32(HEADER_CLUSTER_BITS, bits)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Malformed(Malformed::ClusterBits(b)) if b == bits),
                "{err:?}"
            );
        }
    }

    #[test]
    fn header_length_must_be_aligned_and_inside_the_first_cluster() {
        for length in [72, 96, 108, 4104] {
            let bytes = patched(&base(3), |encoded| encoded.set_u32(HEADER_LENGTH, length));
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Malformed(Malformed::HeaderLength(l)) if l == length),
                "{err:?}"
            );
        }
    }

    #[test]
    fn encryption_is_rejected() {
        for (version, method) in [(3, 1), (3, 2), (3, 9), (2, 1)] {
            let bytes = patched(&base(version), |encoded| {
                encoded.set_u32(HEADER_CRYPT_METHOD, method)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Forbidden(Forbidden::Encrypted { method: m }) if m == method),
                "{err:?}"
            );
        }
        // An encryption header without a method is inconsistent, not plain.
        let err = rejected(
            &base(3)
                .extension(FULL_DISK_ENCRYPTION, vec![0; 16])
                .encode()
                .bytes,
        );
        assert!(
            matches!(err, Error::Forbidden(Forbidden::EncryptionExtension)),
            "{err:?}"
        );
    }

    #[test]
    fn backing_files_are_rejected() {
        for (version, size) in [(3, 4), (3, 0), (2, 4)] {
            let bytes = patched(&base(version), |encoded| {
                encoded.set_u64(HEADER_BACKING_FILE_OFFSET, 3000);
                encoded.set_u32(HEADER_BACKING_FILE_SIZE, size);
                encoded.set_u32(3000, u32::from_be_bytes(*b"base"));
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Forbidden(Forbidden::BackingFile)),
                "{err:?}"
            );
        }
        for version in [2, 3] {
            let image = base(version).extension(BACKING_FORMAT, b"raw".to_vec());
            let err = rejected(&image.encode().bytes);
            assert!(
                matches!(err, Error::Forbidden(Forbidden::BackingFormatExtension)),
                "{err:?}"
            );
        }
    }

    #[test]
    fn external_data_is_rejected_with_or_without_a_name() {
        let bytes = patched(&base(3), |encoded| {
            encoded.set_u64(HEADER_INCOMPATIBLE, 1 << 2)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Forbidden(Forbidden::ExternalData)),
            "{err:?}"
        );

        for version in [2, 3] {
            let image = base(version).extension(EXTERNAL_DATA_NAME, b"data.raw".to_vec());
            let err = rejected(&image.encode().bytes);
            assert!(
                matches!(err, Error::Forbidden(Forbidden::ExternalDataName)),
                "{err:?}"
            );
        }

        let bytes = patched(&base(3), |encoded| {
            encoded.set_u64(HEADER_AUTOCLEAR, 1 << 1)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Forbidden(Forbidden::RawExternalData)),
            "{err:?}"
        );
    }

    #[test]
    fn only_raw_deflate_compression_is_admitted() {
        let cases: [(u64, u8, Forbidden); 4] = [
            (1 << 3, 1, Forbidden::Zstd),
            (0, 1, Forbidden::Zstd),
            (1 << 3, 2, Forbidden::CompressionType(2)),
            (1 << 3, 0, Forbidden::CompressionTypeBit),
        ];
        for (incompatible, compression_type, expected) in cases {
            let bytes = patched(&base(3), |encoded| {
                encoded.set_u64(HEADER_INCOMPATIBLE, incompatible);
                encoded.set_u8(HEADER_COMPRESSION_TYPE, compression_type);
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Forbidden(f) if f == expected),
                "{err:?}"
            );
        }

        // Without the field, the type defaults to DEFLATE but the bit still fails.
        let mut image = base(3);
        image.header_length = 104;
        round_trip(&image);
        let bytes = patched(&image, |encoded| {
            encoded.set_u64(HEADER_INCOMPATIBLE, 1 << 3)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Forbidden(Forbidden::CompressionTypeBit)),
            "{err:?}"
        );
    }

    #[test]
    fn incompatible_features_are_rejected() {
        let cases = [
            (1, Forbidden::Dirty),
            (1 << 1, Forbidden::Corrupt),
            (1 << 4, Forbidden::ExtendedL2),
            (1 << 5, Forbidden::UnknownIncompatible(1 << 5)),
            (1 << 63, Forbidden::UnknownIncompatible(1 << 63)),
        ];
        for (incompatible, expected) in cases {
            let bytes = patched(&base(3), |encoded| {
                encoded.set_u64(HEADER_INCOMPATIBLE, incompatible)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Forbidden(f) if f == expected),
                "{err:?}"
            );
        }
    }

    #[test]
    fn extension_area_is_bounded_and_unique() {
        for version in [2, 3] {
            let image = base(version)
                .extension(UNKNOWN_EXTENSION, vec![1])
                .extension(UNKNOWN_EXTENSION, vec![1]);
            let err = rejected(&image.encode().bytes);
            assert!(
                matches!(
                    err,
                    Error::Malformed(Malformed::DuplicateExtension {
                        extension_type: UNKNOWN_EXTENSION
                    })
                ),
                "{err:?}"
            );

            let start = if version == 2 { 72 } else { 112 };
            // Exactly fills the cluster, leaving no room for the end marker;
            // then one byte longer than the cluster.
            for length in [4096 - start - 8, 4096 - start - 7] {
                let bytes = patched(&base(version), |encoded| {
                    encoded.set_u32(start, UNKNOWN_EXTENSION);
                    encoded.set_u32(start + 4, length as u32);
                });
                let err = rejected(&bytes);
                assert!(
                    matches!(err, Error::Malformed(Malformed::ExtensionOverflow { .. })),
                    "{err:?}"
                );
            }
        }

        // A v3 header filling its cluster has no room for the end marker.
        let bytes = patched(&base(3), |encoded| encoded.set_u32(HEADER_LENGTH, 4096));
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Malformed(Malformed::ExtensionOverflow { offset: 4096 })
            ),
            "{err:?}"
        );

        let err = rejected(&base(3).extension(FEATURE_NAMES, vec![0; 47]).encode().bytes);
        assert!(
            matches!(
                err,
                Error::Malformed(Malformed::FeatureNameTable { length: 47 })
            ),
            "{err:?}"
        );

        let bytes = base(3)
            .extension(UNKNOWN_EXTENSION, vec![5; 64])
            .encode()
            .bytes;
        let err = rejected(&bytes[..112 + 8 + 10]);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::HeaderExtension,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn refcount_metadata_is_bounded() {
        let bytes = patched(&base(3), |encoded| {
            encoded.set_u32(HEADER_REFCOUNT_ORDER, 7)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Malformed(Malformed::RefcountOrder(7))),
            "{err:?}"
        );

        let bytes = patched(&base(3), |encoded| {
            let offset = encoded.u64_at(HEADER_REFCOUNT_TABLE_OFFSET);
            encoded.set_u64(HEADER_REFCOUNT_TABLE_OFFSET, offset + 8);
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Malformed(Malformed::RefcountTableOffset(_))),
            "{err:?}"
        );

        let bytes = patched(&base(3), |encoded| {
            encoded.set_u32(HEADER_REFCOUNT_TABLE_CLUSTERS, u32::MAX)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::RefcountTable,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn l1_table_placement_and_size_are_validated() {
        let image = base(3);
        let file_len = image.encode().bytes.len() as u64;

        let bytes = patched(&image, |encoded| encoded.set_u32(HEADER_L1_SIZE, 0));
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Malformed(Malformed::L1TooSmall {
                    entries: 0,
                    required: 1
                })
            ),
            "{err:?}"
        );

        let bytes = patched(&image, |encoded| {
            encoded.set_u32(HEADER_L1_SIZE, MAX_L1_ENTRIES + 1)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(err, Error::Malformed(Malformed::L1TooLarge { .. })),
            "{err:?}"
        );

        for offset in [0, 4096 + 512] {
            let bytes = patched(&image, |encoded| {
                encoded.set_u64(HEADER_L1_TABLE_OFFSET, offset)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Malformed(Malformed::L1Offset(o)) if o == offset),
                "{err:?}"
            );
        }

        let bytes = patched(&image, |encoded| {
            encoded.set_u64(HEADER_L1_TABLE_OFFSET, file_len)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::L1Table,
                    ..
                }
            ),
            "{err:?}"
        );

        let bytes = patched(&image, |encoded| {
            encoded.set_u64(HEADER_L1_TABLE_OFFSET, !4095u64);
            encoded.set_u32(HEADER_L1_SIZE, 1024);
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Malformed(Malformed::OffsetOverflow {
                    region: Region::L1Table
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn l1_entries_are_validated() {
        let mut image = base(3);
        image.extra_l1_entries = 2;
        let encoded = image.encode();
        let file_len = encoded.bytes.len() as u64;
        let l2 = encoded.u64_at(encoded.l1_entry_offset(0));

        for (index, entry) in [(0, l2 | (1 << 1)), (0, l2 + 512), (1, 1 << 56)] {
            let bytes = patched(&image, |encoded| {
                encoded.set_u64(encoded.l1_entry_offset(index), entry)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(err, Error::Malformed(Malformed::L1Entry { index: i, .. }) if i == index),
                "{err:?}"
            );
        }

        let bytes = patched(&image, |encoded| {
            encoded.set_u64(encoded.l1_entry_offset(0), file_len | COPIED)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::L2Table { l1_index: 0 },
                    ..
                }
            ),
            "{err:?}"
        );

        // Entries past the virtual disk are never followed.
        let bytes = patched(&image, |encoded| {
            encoded.set_u64(encoded.l1_entry_offset(2), (file_len + 65536) | COPIED)
        });
        assert_same(&decoded(&bytes).unwrap(), &image.expected());
    }

    #[test]
    fn l2_entries_are_validated() {
        let image = base(3);
        let encoded = image.encode();
        let file_len = encoded.bytes.len() as u64;
        let data = encoded.u64_at(encoded.l2_entry_offset(0));
        let compressed = encoded.u64_at(encoded.l2_entry_offset(3));
        let unaligned = (file_len - 4096 + 512) | COPIED;

        let malformed = [
            (0, data | (1 << 56)),
            (0, data | (1 << 1)),
            (0, data + 512),
            (3, compressed | COPIED),
            (1, unaligned | ZERO),
            // Past the virtual disk but inside the loaded table.
            (100, data | (1 << 57)),
        ];
        for (guest_cluster, entry) in malformed {
            let bytes = patched(&image, |encoded| {
                encoded.set_u64(encoded.l2_entry_offset(guest_cluster), entry)
            });
            let err = rejected(&bytes);
            assert!(
                matches!(
                    err,
                    Error::Malformed(Malformed::L2Entry { guest_cluster: g, .. }) if g == guest_cluster
                ),
                "{guest_cluster}: {err:?}"
            );
        }

        let bytes = patched(&image, |encoded| {
            encoded.set_u64(encoded.l2_entry_offset(0), file_len | COPIED)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::Data { guest_cluster: 0 },
                    ..
                }
            ),
            "{err:?}"
        );

        let bytes = patched(&image, |encoded| {
            let entry = fixture::compressed_descriptor(12, file_len - 10, 100);
            encoded.set_u64(encoded.l2_entry_offset(3), entry)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::Compressed { guest_cluster: 3 },
                    ..
                }
            ),
            "{err:?}"
        );

        let bytes = patched(&base(2), |encoded| {
            encoded.set_u64(encoded.l2_entry_offset(1), ZERO)
        });
        let err = rejected(&bytes);
        assert!(
            matches!(
                err,
                Error::Malformed(Malformed::V2ZeroCluster { guest_cluster: 1 })
            ),
            "{err:?}"
        );

        // A data entry past the virtual disk is never read.
        let bytes = patched(&image, |encoded| {
            encoded.set_u64(encoded.l2_entry_offset(100), (file_len + 4096) | COPIED)
        });
        assert_same(&decoded(&bytes).unwrap(), &image.expected());
    }

    #[test]
    fn final_partial_data_cluster_may_end_at_source_end() {
        let plain = fixture::noise(7, 4096);
        let image = Image::new(3, 12, 2 * 4096 + 1024).with(2, Guest::Data(plain.clone()));
        let mut encoded = image.encode();
        let host = encoded.bytes.len() as u64;
        encoded.bytes.extend_from_slice(&plain[..1024]);
        encoded.set_u64(encoded.l2_entry_offset(2), host | COPIED);
        assert_same(&decoded(&encoded.bytes).unwrap(), &image.expected());

        encoded.bytes.pop();
        let err = rejected(&encoded.bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::Data { guest_cluster: 2 },
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn compressed_span_may_end_at_a_sector_padded_source_end() {
        let plain = fixture::runs(4, 4096);
        let stream = fixture::deflate_fixed(&plain);
        let image = Image::new(3, 12, 4 * 4096).with(1, Guest::fixed(plain));
        let mut encoded = image.encode();
        let host = encoded.bytes.len() as u64 + 100;
        encoded.bytes.extend_from_slice(&[0; 100]);
        encoded.bytes.extend_from_slice(&stream);
        let padded = encoded.bytes.len().next_multiple_of(512);
        encoded.bytes.resize(padded, 0);
        let entry = fixture::compressed_descriptor(12, host, stream.len() as u64);
        encoded.set_u64(encoded.l2_entry_offset(1), entry);
        assert_same(&decoded(&encoded.bytes).unwrap(), &image.expected());

        encoded.bytes.pop();
        let err = rejected(&encoded.bytes);
        assert!(
            matches!(
                err,
                Error::Truncated {
                    region: Region::Compressed { guest_cluster: 1 },
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn invalid_deflate_streams_fail_decoding_instead_of_producing_zeros() {
        let plain = fixture::noise(3, 4096);
        let streams = [
            // Reserved block type 11.
            vec![0x07, 0, 0, 0],
            // Truncated stored block.
            fixture::deflate_stored(&plain)[..2048].to_vec(),
            // Complete stream that ends half a cluster early.
            fixture::deflate_stored(&plain[..2048]),
        ];
        for stream in streams {
            let image = Image::new(3, 12, 4 * 4096).with(
                1,
                Guest::Compressed {
                    plain: plain.clone(),
                    stream,
                },
            );
            let err = decoded(&image.encode().bytes).unwrap_err();
            assert!(matches!(err, Error::Decode { .. }), "{err:?}");
        }
    }

    #[test]
    fn decode_requires_the_admitted_unchanged_handle() {
        let bytes = base(3).encode().bytes;
        let file = source(&bytes);
        let admission = admit(&file).unwrap();

        let other = source(&bytes);
        let err = decode(&other, &admission, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, Error::SourceChanged), "{err:?}");

        for len in [bytes.len() as u64 - 4096, bytes.len() as u64 + 4096] {
            file.set_len(len).unwrap();
            let mut out = Vec::new();
            let err = decode(&file, &admission, &mut out).unwrap_err();
            assert!(matches!(err, Error::SourceChanged), "{err:?}");
            assert!(out.is_empty());
        }
    }

    #[test]
    fn output_failure_is_reported() {
        let file = source(&base(3).encode().bytes);
        let admission = admit(&file).unwrap();
        let mut sink = [0u8; 100];
        let err = decode(&file, &admission, &mut &mut sink[..]).unwrap_err();
        assert!(matches!(err, Error::Output { offset: 0, .. }), "{err:?}");
    }

    #[test]
    fn non_regular_files_are_not_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let err = admit(&File::open(dir.path()).unwrap()).unwrap_err();
        assert!(matches!(err, Error::NotRegularFile), "{err:?}");
    }
}
