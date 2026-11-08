use std::fs::File;
use std::os::unix::fs::FileExt;

use crate::changeset::index::{encode_index, LayerRecipe};
use crate::changeset::namespace::{compose, NamespaceKind};
use crate::changeset::{
    ChangeEntry, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset, LayerResult, Metadata,
    MetadataPresence, PayloadRef, SparseRange, StreamIdentity, Xattr,
};
use crate::erofs::{encode, validate, Layer, BLOCK_SIZE};

const RECIPE: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn metadata() -> Metadata {
    Metadata {
        uid: 0,
        gid: 0,
        mode: 0o755,
        mtime_seconds: 0,
        mtime_nanos: 0,
        xattrs: Vec::new(),
    }
}
fn entry(path: &[u8], kind: EntryKind) -> ChangeEntry {
    ChangeEntry {
        ordinal: 0,
        path: path.to_vec(),
        metadata: metadata(),
        presence: MetadataPresence::default(),
        kind,
    }
}
fn regular(path: &[u8], length: u64) -> ChangeEntry {
    let mut e = entry(
        path,
        EntryKind::Regular(PayloadRef {
            pack_offset: 0,
            length,
            sparse: Vec::new(),
        }),
    );
    e.metadata.mode = 0o644;
    e
}
struct Fixture {
    changeset: LayerChangeset,
    result: LayerResult,
    pack: File,
}
impl Fixture {
    fn new(mut entries: Vec<ChangeEntry>, bodies: &[&[u8]]) -> Self {
        let pack = tempfile::tempfile().unwrap();
        let mut at = 0;
        let mut data = bodies.iter();
        for (ordinal, e) in entries.iter_mut().enumerate() {
            e.ordinal = ordinal as u64;
            if let EntryKind::Regular(body) = &mut e.kind {
                body.pack_offset = at;
                let content = data.next().unwrap();
                assert_eq!(content.len() as u64, body.length);
                at += body.length.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
                pack.set_len(at).unwrap();
                pack.write_all_at(content, body.pack_offset).unwrap();
            }
        }
        assert!(data.next().is_none());
        let changeset = LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"unit fixture"),
            pack_length: at,
            entries,
        };
        let result = LayerResult {
            recipe: LayerRecipe {
                diff_id: changeset.diff_id,
            }
            .id()
            .unwrap(),
            // The caller authenticates this identity. These unit tests exercise
            // metadata binding, not the separate libvm stream-hash ABI.
            pack_stream: StreamIdentity::from_sha256([0; 32]),
            pack_length: at,
            index_root: encode_index(&changeset, &ChangesetLimits::default())
                .unwrap()
                .root
                .digest,
        };
        Self {
            changeset,
            result,
            pack,
        }
    }
    fn layer(&self) -> Layer<'_> {
        Layer {
            result: &self.result,
            changeset: &self.changeset,
            pack: &self.pack,
        }
    }
    fn reindex(&mut self) {
        self.result.index_root = encode_index(&self.changeset, &ChangesetLimits::default())
            .unwrap()
            .root
            .digest;
    }
}
fn namespace(layers: &[Layer<'_>]) -> crate::changeset::namespace::ValidatedNamespace {
    compose(
        &layers.iter().map(|l| l.changeset).collect::<Vec<_>>(),
        &ChangesetLimits::default(),
    )
    .unwrap()
}
fn read<const N: usize>(file: &File, at: u64) -> [u8; N] {
    let mut bytes = [0; N];
    file.read_exact_at(&mut bytes, at).unwrap();
    bytes
}
fn encoded(layers: &[Layer<'_>]) -> (File, crate::erofs::EncodedFsmeta) {
    let ns = namespace(layers);
    let mut output = tempfile::tempfile().unwrap();
    let result = encode(&ns, layers, RECIPE, &mut output).unwrap();
    assert_eq!(validate(&output, &ns, layers, RECIPE).unwrap(), result);
    (output, result)
}

#[test]
fn symlink_target_must_fit_the_kernel_page_link_limit() {
    for length in [4095, 4096] {
        let fixture = Fixture::new(
            vec![entry(
                b"link",
                EntryKind::Symlink {
                    target: vec![b'x'; length],
                },
            )],
            &[],
        );
        let layers = [fixture.layer()];
        let ns = namespace(&layers);
        let mut output = tempfile::tempfile().unwrap();
        let result = encode(&ns, &layers, RECIPE, &mut output);
        if length == 4095 {
            assert_eq!(
                validate(&output, &ns, &layers, RECIPE).unwrap(),
                result.unwrap()
            );
        } else {
            assert!(
                result.is_err(),
                "4096-byte page-backed symlink would be truncated by Linux"
            );
            assert_eq!(
                output.metadata().unwrap().len(),
                0,
                "refuse before writing fsmeta"
            );
        }
    }
}

#[test]
fn fixed_profile_golden_bytes_and_uuid_recipe_spelling() {
    // Independently authored field-by-field fixtures, not snapshots emitted by
    // this encoder. Recipe bytes are exactly RECIPE's ASCII bytes, no newline.
    // Raw UUID SHA256: f1c77fad4809dcd65f92ced3ee28440f4939373dbdedd19403001692f1a7d085.
    let empty = Fixture::new(Vec::new(), &[]);
    let data = Fixture::new(vec![regular(b"f", 5)], &[b"hello"]);
    let cases = [
        (
            Vec::new(),
            12288,
            "9fdc04b82de766417a5f3f2e0e6a59f0457f6d93ad0b859de2cfa58230f139b8",
        ),
        (
            vec![empty.layer()],
            16384,
            "b0227caf9d704876f8577e00e1b7b0acc8b806c61ab791d28224de9acb27e6c2",
        ),
        (
            vec![data.layer()],
            16384,
            "1e6624bec8e261d1d9c97194e8cfeb4719c24a7e5af21b128c1e45287bf2eabc",
        ),
    ];
    for (layers, length, digest) in cases {
        let (_, result) = encoded(&layers);
        assert_eq!(result.length, length);
        assert_eq!(result.digest.to_string(), format!("sha256:{digest}"));
        assert_eq!(
            result.uuid,
            [
                0xf1, 0xc7, 0x7f, 0xad, 0x48, 0x09, 0x8c, 0xd6, 0x9f, 0x92, 0xce, 0xd3, 0xee, 0x28,
                0x44, 0x0f
            ]
        );
    }
}

#[test]
fn component_dfs_raw_names_and_hardlinked_inode_types() {
    let entries = vec![
        entry(b"a-", EntryKind::Fifo),
        entry(b"a", EntryKind::Directory),
        regular(b"a/b", 1),
        entry(b"!", EntryKind::Socket),
        entry(
            b"\xff",
            EntryKind::Symlink {
                target: b"/raw/\xfe".to_vec(),
            },
        ),
        entry(
            b"sym",
            EntryKind::Hardlink {
                target: b"\xff".to_vec(),
            },
        ),
        entry(
            b"fifo",
            EntryKind::Hardlink {
                target: b"a-".to_vec(),
            },
        ),
        entry(
            b"char",
            EntryKind::CharacterDevice {
                major: 0xfff,
                minor: 0xfffff,
            },
        ),
        entry(b"block", EntryKind::BlockDevice { major: 8, minor: 1 }),
        entry(
            b"file-link",
            EntryKind::Hardlink {
                target: b"a/b".to_vec(),
            },
        ),
    ];
    let fixture = Fixture::new(entries, &[b"x"]);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let order = plan.records.iter().map(|r| r.id).collect::<Vec<_>>();
    let a = ns.names().get(b"a".as_slice()).unwrap().inode;
    let b = ns.names().get(b"a/b".as_slice()).unwrap().inode;
    let sibling = ns.names().get(b"a-".as_slice()).unwrap().inode;
    assert!(
        order.iter().position(|id| *id == a).unwrap()
            < order.iter().position(|id| *id == b).unwrap()
    );
    assert!(
        order.iter().position(|id| *id == b).unwrap()
            < order.iter().position(|id| *id == sibling).unwrap()
    );
    assert_eq!(
        ns.names()[b"sym".as_slice()].inode,
        ns.names()[b"\xff".as_slice()].inode
    );
    let (file, _) = encoded(&layers);
    let root = &plan.records[0];
    let first_nameoff = u16::from_le_bytes(read::<2>(&file, root.data + 8)) as u64;
    assert_eq!(read::<1>(&file, root.data + first_nameoff), [b'!']);
    assert_eq!(u32::from_le_bytes(read::<4>(&file, root.offset + 44)), 3);
    assert_eq!(
        u32::from_le_bytes(read::<4>(&file, plan.record(sibling).unwrap().offset + 44)),
        2
    );
}

#[test]
fn zero_empty_partial_and_repeated_occurrence_slots() {
    let empty = Fixture::new(Vec::new(), &[]);
    let zeros = vec![0; 4097];
    let fixture = Fixture::new(
        vec![
            regular(b"empty", 0),
            regular(b"zero", 4097),
            regular(b"nonzero", 1),
        ],
        &[b"", &zeros, b"z"],
    );
    let layers = [
        empty.layer(),
        fixture.layer(),
        empty.layer(),
        fixture.layer(),
        empty.layer(),
    ];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let (file, result) = encoded(&layers);
    assert_eq!(result.device_ranges.len(), 5);
    assert_eq!(result.device_ranges[0].length, 0);
    assert_eq!(
        result.device_ranges[0].offset,
        result.device_ranges[1].offset
    );
    assert_eq!(
        result.device_ranges[2].offset,
        result.device_ranges[3].offset
    );
    let zero = plan.record(ns.names()[b"zero".as_slice()].inode).unwrap();
    assert_eq!(
        read::<16>(&file, zero.index_start),
        [0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255]
    );
    let nonzero = plan
        .record(ns.names()[b"nonzero".as_slice()].inode)
        .unwrap();
    assert_eq!(
        read::<8>(&file, nonzero.index_start),
        [0, 0, 4, 0, 2, 0, 0, 0]
    );
    assert!(matches!(zero.inode.kind, NamespaceKind::Regular { .. }));
}

#[test]
fn dense_and_physically_sparse_logical_zeros_are_identical() {
    let mut body = vec![0; 3 * 4096];
    body[4097] = 7;
    let dense = Fixture::new(vec![regular(b"f", body.len() as u64)], &[&body]);
    let sparse_pack = tempfile::tempfile().unwrap();
    sparse_pack.set_len(body.len() as u64).unwrap();
    sparse_pack.write_all_at(&[7], 4097).unwrap();
    let sparse = Fixture {
        changeset: dense.changeset.clone(),
        result: dense.result,
        pack: sparse_pack,
    };
    let (_, a) = encoded(&[dense.layer()]);
    let (_, b) = encoded(&[sparse.layer()]);
    assert_eq!(a, b);
}

#[test]
fn regular_size_boundaries_have_exact_index_counts() {
    for length in [0, 1, 4095, 4096, 4097] {
        let mut bytes = vec![0; length];
        if let Some(last) = bytes.last_mut() {
            *last = 42;
        }
        let fixture = Fixture::new(vec![regular(b"f", length as u64)], &[&bytes]);
        let layers = [fixture.layer()];
        let ns = namespace(&layers);
        let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
        let record = plan.record(ns.names()[b"f".as_slice()].inode).unwrap();
        assert_eq!(
            record.end,
            crate::erofs::align(record.index_start + (length as u64).div_ceil(4096) * 8, 32)
                .unwrap()
        );
        encoded(&layers);
    }
}

fn acl() -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permissions) in [(1u16, 7u16), (4, 5), (32, 5)] {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&permissions.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    bytes
}
#[test]
fn xattrs_acls_extended_times_and_cross_block_metadata() {
    let mut root = entry(b"", EntryKind::RootDirectory);
    root.metadata.uid = u32::MAX - 1;
    root.metadata.gid = u32::MAX - 1;
    root.metadata.mtime_seconds = 15_032_385_535;
    root.metadata.mtime_nanos = 999_999_999;
    root.metadata.xattrs = vec![
        Xattr {
            name: b"system.posix_acl_access".to_vec(),
            value: acl(),
        },
        Xattr {
            name: b"system.posix_acl_default".to_vec(),
            value: acl(),
        },
        Xattr {
            name: b"trusted.a".to_vec(),
            value: Vec::new(),
        },
        Xattr {
            name: b"user.a".to_vec(),
            value: Vec::new(),
        },
        Xattr {
            name: b"user.z".to_vec(),
            value: vec![0xff; 128],
        },
    ];
    let mut entries = vec![root];
    for i in 0..300 {
        let mut e = regular(format!("f{i:03}").as_bytes(), 0);
        e.metadata.xattrs = vec![Xattr {
            name: b"user.test".to_vec(),
            value: vec![i as u8; 79],
        }];
        entries.push(e);
    }
    let bodies = vec![b"".as_slice(); 300];
    let fixture = Fixture::new(entries, &bodies);
    let layers = [fixture.layer()];
    let (file, _) = encoded(&layers);
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    assert!(plan
        .records
        .iter()
        .any(|r| r.offset / 4096 != (r.offset + 64 + r.xattr_size - 1) / 4096));
    let root = &plan.records[0];
    assert!(root.size > 4096);
    assert_eq!(read::<4>(&file, root.offset + 64), [0; 4]);
}

#[test]
fn strict_reader_rejects_slots_inode_xattr_directory_and_alignment_corruption() {
    let mut f = regular(b"f", 1);
    f.metadata.xattrs = vec![Xattr {
        name: b"user.a".to_vec(),
        value: b"value".to_vec(),
    }];
    let fixture = Fixture::new(vec![f], &[b"a"]);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let (file, _) = encoded(&layers);
    let root = &plan.records[0];
    let regular = &plan.records[1];
    let positions = [
        0,
        1024,
        1028,
        1048,
        1129,
        1152,
        4096,
        4096 + 64,
        4096 + 68,
        4096 + 72,
        4096 + 128,
        root.offset,
        root.offset + 6,
        root.offset + 48,
        regular.offset + 2,
        regular.offset + 64,
        regular.offset + 64 + 12 + 1,
        regular.offset + 64 + 12 + 4 + 1 + 5, // xattr alignment padding
        regular.end - 1,
        plan.data_start - 1,
        root.data,
        root.data + 8,
        root.data + 11,
        root.data + 12,
        root.data + root.size,
        plan.length - 1,
    ];
    for at in positions {
        let saved = read::<1>(&file, at);
        file.write_all_at(&[saved[0] ^ 0x80], at).unwrap();
        assert!(
            validate(&file, &ns, &layers, RECIPE).is_err(),
            "accepted corruption at {at}"
        );
        file.write_all_at(&saved, at).unwrap();
    }
    file.set_len(plan.length - 1).unwrap();
    assert!(validate(&file, &ns, &layers, RECIPE).is_err());
}

#[test]
fn chunk_ownership_aliases_and_noncanonical_null_are_rejected() {
    let fixture = Fixture::new(
        vec![
            regular(b"a", 4096),
            regular(b"b", 4096),
            regular(b"zero", 4096),
        ],
        &[&vec![1; 4096], &vec![2; 4096], &vec![0; 4096]],
    );
    let empty = Fixture::new(Vec::new(), &[]);
    let layers = [fixture.layer(), empty.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let (file, _) = encoded(&layers);
    let a = plan.record(ns.names()[b"a".as_slice()].inode).unwrap();
    let saved = read::<8>(&file, a.index_start);
    for corrupt in [
        [0, 0, 1, 0, 1, 0, 0, 0],         // valid pack block, wrong original body
        [0, 0, 2, 0, 0, 0, 0, 0],         // empty device
        [0, 0, 5, 0, 0, 0, 0, 0],         // kernel-masked alias
        [0, 0, 0, 0, 255, 255, 255, 255], // nonzero bytes hidden as NULL
        [1, 0, 1, 0, 0, 0, 0, 0],
    ] {
        file.write_all_at(&corrupt, a.index_start).unwrap();
        assert!(validate(&file, &ns, &layers, RECIPE).is_err());
    }
    file.write_all_at(&saved, a.index_start).unwrap();
    let zero = plan.record(ns.names()[b"zero".as_slice()].inode).unwrap();
    for corrupt in [[0, 0, 1, 0, 255, 255, 255, 255], [0, 0, 1, 0, 2, 0, 0, 0]] {
        file.write_all_at(&corrupt, zero.index_start).unwrap();
        assert!(validate(&file, &ns, &layers, RECIPE).is_err());
    }
}

#[test]
fn source_binding_padding_sparse_gaps_and_output_alias_are_rejected() {
    let mut fixture = Fixture::new(vec![regular(b"f", 1)], &[b"a"]);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let mut output = tempfile::tempfile().unwrap();
    fixture.pack.write_all_at(&[1], 1).unwrap();
    assert!(encode(&ns, &layers, RECIPE, &mut output).is_err());
    fixture.pack.write_all_at(&[0], 1).unwrap();
    fixture.pack.set_len(0).unwrap();
    assert!(encode(&ns, &layers, RECIPE, &mut output).is_err());
    fixture.pack.set_len(4096).unwrap();
    fixture.result.index_root = ContentDigest::from_sha256([9; 32]);
    assert!(encode(&ns, &[fixture.layer()], RECIPE, &mut output).is_err());
    fixture.reindex();
    let mut alias = fixture.pack.try_clone().unwrap();
    assert!(encode(&ns, &[fixture.layer()], RECIPE, &mut alias).is_err());
    assert_eq!(fixture.pack.metadata().unwrap().len(), 4096);
    assert!(encode(&ns, &[], RECIPE, &mut output).is_err());
    assert!(encode(&ns, &[fixture.layer()], "SHA256:bad", &mut output).is_err());
    let mut sparse = regular(b"sparse", 4096);
    if let EntryKind::Regular(body) = &mut sparse.kind {
        body.sparse = vec![SparseRange {
            offset: 1,
            length: 1,
        }];
    }
    let bad_sparse = Fixture::new(vec![sparse], &[&vec![1; 4096]]);
    assert!(encode(
        &namespace(&[bad_sparse.layer()]),
        &[bad_sparse.layer()],
        RECIPE,
        &mut output
    )
    .is_err());
}

#[test]
fn maximum_occurrence_table_retains_every_empty_slot() {
    let fixture = Fixture::new(Vec::new(), &[]);
    let layers = vec![fixture.layer(); 1024];
    let (file, result) = encoded(&layers);
    assert_eq!(result.device_ranges.len(), 1024);
    assert_eq!(u32::from_le_bytes(read::<4>(&file, 1024 + 40)), 33);
    assert!(result
        .device_ranges
        .iter()
        .all(|range| range.length == 0 && range.offset == result.length));
    let too_many = vec![fixture.layer(); 1025];
    assert!(encode(
        &namespace(&[]),
        &too_many,
        RECIPE,
        &mut tempfile::tempfile().unwrap()
    )
    .is_err());
}

#[test]
fn final_occurrence_1024_owns_live_chunks_without_device_mask_aliasing() {
    let empty = Fixture::new(Vec::new(), &[]);
    let data = Fixture::new(vec![regular(b"last", 1)], &[b"x"]);
    let mut layers = vec![empty.layer(); 1023];
    layers.push(data.layer());
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let (file, _) = encoded(&layers);
    let record = plan.record(ns.names()[b"last".as_slice()].inode).unwrap();
    assert_eq!(
        read::<8>(&file, record.index_start),
        [0, 0, 0, 4, 0, 0, 0, 0]
    );
    file.write_all_at(&[0, 0, 0, 12, 0, 0, 0, 0], record.index_start)
        .unwrap();
    assert!(validate(&file, &ns, &layers, RECIPE).is_err());
}

#[test]
fn overwritten_bodies_still_require_whole_pack_padding_and_sparse_zeros() {
    let source = Fixture::new(vec![regular(b"gone", 1)], &[b"a"]);
    let removal = Fixture::new(vec![entry(b".wh.gone", EntryKind::Whiteout)], &[]);
    let layers = [source.layer(), removal.layer()];
    assert!(namespace(&layers).inode_at(b"gone").is_none());
    encoded(&layers);
    source.pack.write_all_at(&[1], 4095).unwrap();
    assert!(encode(
        &namespace(&layers),
        &layers,
        RECIPE,
        &mut tempfile::tempfile().unwrap()
    )
    .is_err());
}

#[test]
fn output_cursor_reset_exact_length_and_oversized_claims() {
    use std::io::{Seek, SeekFrom, Write};
    let fixture = Fixture::new(Vec::new(), &[]);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&vec![7; 32768]).unwrap();
    file.seek(SeekFrom::Start(123)).unwrap();
    let first = encode(&ns, &layers, RECIPE, &mut file).unwrap();
    assert_eq!(file.metadata().unwrap().len(), first.length);
    file.seek(SeekFrom::Start(17)).unwrap();
    assert_eq!(validate(&file, &ns, &layers, RECIPE).unwrap(), first);
    assert_eq!(file.stream_position().unwrap(), 17);
    assert_eq!(encode(&ns, &layers, RECIPE, &mut file).unwrap(), first);
    let mut oversized = fixture.result;
    oversized.pack_length = u64::MAX;
    let bad = [Layer {
        result: &oversized,
        ..fixture.layer()
    }];
    assert!(encode(&ns, &bad, RECIPE, &mut file).is_err());
    // A bounded reader must reject an otherwise correctly checksummed enormous
    // primary block claim without allocating or following its addresses.
    let mut superblock = read::<4096>(&file, 0);
    superblock[1060..1064].copy_from_slice(&u32::MAX.to_le_bytes());
    superblock[1028..1032].fill(0);
    let crc = crate::erofs::crc32c(&superblock[1024..]);
    superblock[1028..1032].copy_from_slice(&crc.to_le_bytes());
    file.write_all_at(&superblock, 0).unwrap();
    assert!(validate(&file, &ns, &layers, RECIPE).is_err());
}

#[test]
fn extended_inode_and_streamed_chunk_indexes_cross_metadata_blocks() {
    let mut entries = vec![regular(b"a", 1)];
    for i in 0..70 {
        entries.push(regular(format!("b{i:03}").as_bytes(), 0));
    }
    let mut bodies = vec![b"q".as_slice()];
    bodies.extend(std::iter::repeat_n(b"".as_slice(), 70));
    let fixture = Fixture::new(entries, &bodies);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    assert!(plan
        .records
        .iter()
        .any(|r| r.offset / 4096 != (r.offset + 63) / 4096));
    encoded(&layers);

    let content = vec![19; 513 * 4096 - 1];
    let indexed = Fixture::new(vec![regular(b"indexed", content.len() as u64)], &[&content]);
    let layers = [indexed.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let record = plan
        .record(ns.names()[b"indexed".as_slice()].inode)
        .unwrap();
    assert!(record.index_start / 4096 != (record.index_start + 513 * 8 - 1) / 4096);
    let (file, _) = encoded(&layers);
    assert_eq!(
        read::<8>(&file, record.index_start + 512 * 8),
        [0, 0, 1, 0, 0, 2, 0, 0]
    );
}

#[test]
fn valid_mixed_sparse_chunks_keep_exact_zero_gaps_and_final_null() {
    let mut e = regular(b"mixed", 8193);
    if let EntryKind::Regular(body) = &mut e.kind {
        body.sparse = vec![SparseRange {
            offset: 4095,
            length: 2,
        }];
    }
    let mut content = vec![0; 8193];
    content[4095..4097].copy_from_slice(b"ab");
    let fixture = Fixture::new(vec![e], &[&content]);
    let layers = [fixture.layer()];
    let ns = namespace(&layers);
    let plan = crate::erofs::plan::Plan::new(&ns, &layers, RECIPE).unwrap();
    let record = plan.record(ns.names()[b"mixed".as_slice()].inode).unwrap();
    let (file, _) = encoded(&layers);
    assert_eq!(
        read::<24>(&file, record.index_start),
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255]
    );
    fixture.pack.write_all_at(&[1], 8193).unwrap();
    assert!(validate(&file, &ns, &layers, RECIPE).is_err());
}
