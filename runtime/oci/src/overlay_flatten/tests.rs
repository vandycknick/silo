//! Real lower compositions and real ext4 uppers, flattened and read back.
//! Uppers are written by the ext4 formatter in the exact shape the admitted
//! kernel leaves them (index hardlinks, 0:0 whiteouts, raw trusted.overlay
//! xattrs), with handles spelled independently of the flattener's parser.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use disk_image::ext4::constants::{file_mode, ROOT_INODE};
use disk_image::ext4::reader::InodeKind;
use disk_image::ext4::{
    DeviceId, FileData, FileRange, FileTimestamps, FormatOptions, Formatter, Reader, SparseData,
};

use crate::changeset::index::{encode_index, LayerRecipe};
use crate::changeset::{
    ChangeEntry, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset, LayerResult, Metadata,
    MetadataPresence, PayloadRef, StreamIdentity,
};
use crate::composition::{CompositionRecipe, CompositionResult};
use crate::erofs::Layer;
use crate::overlay_flatten::{flatten_overlay, FlattenError, FlattenLower, FlattenedFilesystem};
use crate::Platform;

const UPPER_UUID: [u8; 16] = *b"silo-upper-test!";
const INO64: u8 = 0x81;
const INO32: u8 = 1;
const MIB: u64 = 1024 * 1024;

fn metadata(mode: u32) -> Metadata {
    Metadata {
        uid: 0,
        gid: 0,
        mode,
        mtime_seconds: 1_600_000_000,
        mtime_nanos: 0,
        xattrs: Vec::new(),
    }
}

fn entry(path: &[u8], kind: EntryKind, mode: u32) -> ChangeEntry {
    ChangeEntry {
        ordinal: 0,
        path: path.to_vec(),
        kind,
        metadata: metadata(mode),
        presence: MetadataPresence::default(),
    }
}

struct Lower {
    changeset: LayerChangeset,
    result: LayerResult,
    pack: File,
    recipe: CompositionRecipe,
    composition: CompositionResult,
    fsmeta: File,
    nids: BTreeMap<Vec<u8>, u64>,
}

impl Lower {
    /// `d1/a`, `d1/c` and `d2/b` are one lower inode with three names.
    fn new() -> Self {
        let directory = |path: &[u8]| entry(path, EntryKind::Directory, 0o755);
        let regular = |path: &[u8]| {
            entry(
                path,
                EntryKind::Regular(PayloadRef {
                    pack_offset: 0,
                    length: body_of(path).len() as u64,
                    sparse: Vec::new(),
                }),
                0o644,
            )
        };
        let hardlink = |path: &[u8]| {
            entry(
                path,
                EntryKind::Hardlink {
                    target: b"d1/a".to_vec(),
                },
                0o644,
            )
        };
        let mut entries = vec![
            directory(b"d1"),
            regular(b"d1/a"),
            hardlink(b"d1/c"),
            directory(b"d2"),
            hardlink(b"d2/b"),
            directory(b"keep"),
            regular(b"keep/file"),
            directory(b"opq"),
            regular(b"opq/old"),
            regular(b"solo"),
        ];
        let pack = tempfile::tempfile().unwrap();
        let mut at = 0;
        for (ordinal, entry) in entries.iter_mut().enumerate() {
            entry.ordinal = ordinal as u64;
            if let EntryKind::Regular(body) = &mut entry.kind {
                body.pack_offset = at;
                let content = body_of(&entry.path);
                at += (content.len() as u64).div_ceil(4096) * 4096;
                pack.set_len(at).unwrap();
                pack.write_all_at(content, body.pack_offset).unwrap();
            }
        }
        let changeset = LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"overlay flatten lower"),
            pack_length: at,
            entries,
        };
        let result = LayerResult {
            recipe: LayerRecipe {
                diff_id: changeset.diff_id,
            }
            .id()
            .unwrap(),
            pack_stream: StreamIdentity::from_sha256([3; 32]),
            pack_length: at,
            index_root: encode_index(&changeset, &ChangesetLimits::default())
                .unwrap()
                .root
                .digest,
        };
        let layer = Layer {
            result: &result,
            changeset: &changeset,
            pack: &pack,
        };
        let platform = Platform {
            os: "linux".into(),
            architecture: "amd64".into(),
            variant: None,
        };
        let recipe = CompositionRecipe::from_layers(platform, &[layer]).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let composition = crate::composition::prepare(&recipe, &[layer], &mut fsmeta)
            .unwrap()
            .finalize(StreamIdentity::from_sha256([9; 32]))
            .unwrap();
        let (namespace, handles) =
            crate::composition::load_exported(&recipe, &[layer], &composition, &fsmeta).unwrap();
        let nids = namespace
            .names()
            .iter()
            .map(|(path, name)| (path.clone(), handles.nid(name.inode).unwrap()))
            .collect();
        Self {
            changeset,
            result,
            pack,
            recipe,
            composition,
            fsmeta,
            nids,
        }
    }

    fn layer(&self) -> Layer<'_> {
        Layer {
            result: &self.result,
            changeset: &self.changeset,
            pack: &self.pack,
        }
    }

    fn nid(&self, path: &[u8]) -> u64 {
        self.nids[path]
    }

    /// The handle a little-endian guest kernel stores for a lower inode.
    fn origin(&self, path: &[u8], fid_type: u8) -> Vec<u8> {
        origin_handle(self.composition.fsmeta.uuid, self.nid(path), fid_type)
    }

    fn flatten(&self, upper: &Path, output: &Path) -> Result<FlattenedFilesystem, FlattenError> {
        let layers = [self.layer()];
        flatten_overlay(
            FlattenLower {
                recipe: &self.recipe,
                result: &self.composition,
                layers: &layers,
                fsmeta: &self.fsmeta,
            },
            File::open(upper).unwrap(),
            output,
            0,
            &AtomicBool::new(false),
        )
    }
}

fn body_of(path: &[u8]) -> &'static [u8] {
    match path {
        b"d1/a" => b"lower-hardlink",
        b"keep/file" => b"kept",
        b"opq/old" => b"old",
        b"solo" => b"solo-lower",
        _ => unreachable!("fixture body {path:?}"),
    }
}

fn origin_handle(uuid: [u8; 16], nid: u64, fid_type: u8) -> Vec<u8> {
    let mut handle = vec![0, 0xfb, 0, 0, fid_type];
    handle.extend_from_slice(&uuid);
    match fid_type {
        INO64 => {
            handle.extend_from_slice(&((nid >> 32) as u32).to_le_bytes());
            handle.extend_from_slice(&(nid as u32).to_le_bytes());
        }
        INO32 => handle.extend_from_slice(&(nid as u32).to_le_bytes()),
        _ => unreachable!(),
    }
    handle.extend_from_slice(&0_u32.to_le_bytes());
    handle[2] = handle.len() as u8;
    handle
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

type Xattrs = Vec<(String, Vec<u8>)>;

#[derive(Clone)]
enum Item {
    Dir(String, Xattrs),
    File(String, Vec<u8>, Xattrs),
    /// Logical length and stored `(offset, bytes)` runs; the rest are holes.
    Sparse(String, u64, Vec<(u64, Vec<u8>)>),
    Whiteout(String),
    Link(String, String),
    /// `work/index`, bound to the upper root by `trusted.overlay.upper`.
    IndexDir,
}

impl Item {
    fn path(&self) -> &str {
        match self {
            Item::Dir(path, _)
            | Item::File(path, _, _)
            | Item::Sparse(path, _, _)
            | Item::Whiteout(path)
            | Item::Link(path, _) => path,
            Item::IndexDir => "work/index",
        }
    }
}

fn xattr(name: &str, value: impl AsRef<[u8]>) -> (String, Vec<u8>) {
    (name.to_owned(), value.as_ref().to_vec())
}

fn create(
    formatter: &mut Formatter,
    path: &str,
    mode: u16,
    data: Option<FileData<'_>>,
    xattrs: &Xattrs,
    device: Option<DeviceId>,
) {
    let attrs = xattrs
        .iter()
        .map(|(name, value)| (name.as_bytes(), value.as_slice()))
        .collect::<Vec<_>>();
    formatter
        .create(
            format!("/{path}"),
            mode,
            None,
            Some(FileTimestamps::from_mtime(1_700_000_000, 0).unwrap()),
            data,
            Some(0),
            Some(0),
            Some(attrs.as_slice()),
            device,
        )
        .unwrap();
}

fn write_upper(path: &Path, items: &[Item], bound: &[u8]) {
    let mut options = FormatOptions::new(64 * MIB);
    options.uuid = Some(TryFrom::try_from(UPPER_UUID.to_vec()).unwrap());
    let mut formatter = Formatter::with_options(path, options).unwrap();
    for item in items {
        match item {
            Item::Dir(path, xattrs) => create(
                &mut formatter,
                path,
                file_mode::S_IFDIR | 0o755,
                None,
                xattrs,
                None,
            ),
            Item::File(path, data, xattrs) => {
                let mut reader = data.as_slice();
                let body = (!data.is_empty()).then_some(FileData::Dense(&mut reader));
                create(
                    &mut formatter,
                    path,
                    file_mode::S_IFREG | 0o644,
                    body,
                    xattrs,
                    None,
                )
            }
            Item::Sparse(path, length, runs) => {
                let stored = runs
                    .iter()
                    .flat_map(|(_, bytes)| bytes.iter().copied())
                    .collect::<Vec<_>>();
                let mut reader = stored.as_slice();
                let mut ranges = runs.iter().map(|(offset, bytes)| FileRange {
                    offset: *offset,
                    length: bytes.len() as u64,
                });
                create(
                    &mut formatter,
                    path,
                    file_mode::S_IFREG | 0o600,
                    Some(FileData::Sparse(SparseData {
                        reader: &mut reader,
                        length: *length,
                        ranges: &mut ranges,
                    })),
                    &Vec::new(),
                    None,
                );
            }
            Item::Whiteout(path) => create(
                &mut formatter,
                path,
                file_mode::S_IFCHR,
                None,
                &Vec::new(),
                Some(DeviceId::new(0, 0).unwrap()),
            ),
            Item::Link(path, target) => formatter
                .link(format!("/{path}"), format!("/{target}"))
                .unwrap(),
            Item::IndexDir => create(
                &mut formatter,
                "work/index",
                file_mode::S_IFDIR | 0o700,
                None,
                &vec![xattr("trusted.overlay.upper", bound)],
                None,
            ),
        }
    }
    formatter.close().unwrap();
}

/// Two passes: the second binds `work/index` to the first pass's exact upper
/// root inode and generation; identical creation order allocates identically.
fn upper_image(dir: &Path, items: &[Item]) -> PathBuf {
    let path = dir.join("upper.ext4");
    write_upper(&path, items, &[0; 29]);
    let reader = Reader::from_file(File::open(&path).unwrap()).unwrap();
    let root = resolve(&reader, b"upper").unwrap();
    let generation = reader.metadata(root).unwrap().generation;
    let mut bound = vec![0, 0xfb, 29, 1 << 2, 1];
    bound.extend_from_slice(&UPPER_UUID);
    bound.extend_from_slice(&root.to_le_bytes());
    bound.extend_from_slice(&generation.to_le_bytes());
    write_upper(&path, items, &bound);
    let reader = Reader::from_file(File::open(&path).unwrap()).unwrap();
    assert_eq!(resolve(&reader, b"upper"), Some(root));
    path
}

fn resolve(reader: &Reader, path: &[u8]) -> Option<u32> {
    let mut inode = ROOT_INODE;
    for part in path
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
    {
        inode = reader.lookup(inode, part).unwrap()?;
    }
    Some(inode)
}

fn content(reader: &Reader, inode: u32) -> Vec<u8> {
    let body = reader.file_body(inode).unwrap();
    let mut bytes = vec![0; body.size() as usize];
    reader.read_at(&body, 0, &mut bytes).unwrap();
    bytes
}

/// Every visible path with its kind, content and hardlink identity class.
fn visible(path: &Path) -> BTreeMap<Vec<u8>, (String, Vec<u8>, u32)> {
    let reader = Reader::from_file(File::open(path).unwrap()).unwrap();
    let mut out = BTreeMap::new();
    let mut first_name = BTreeMap::new();
    let mut stack = vec![(Vec::new(), ROOT_INODE)];
    while let Some((prefix, directory)) = stack.pop() {
        for child in reader.read_dir(directory).unwrap().entries {
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&child.name);
            let meta = reader.metadata(child.inode).unwrap();
            for name in reader.inode_xattrs(child.inode).unwrap().keys() {
                assert!(
                    !name.starts_with(b"trusted.overlay."),
                    "overlay control leaked into {path:?}"
                );
            }
            let first = first_name
                .entry(child.inode)
                .or_insert_with(|| out.len() as u32)
                .to_owned();
            let (kind, bytes) = match meta.kind {
                InodeKind::Directory => {
                    stack.push((path.clone(), child.inode));
                    ("dir".to_owned(), Vec::new())
                }
                InodeKind::Regular => ("file".to_owned(), content(&reader, child.inode)),
                other => (format!("{other:?}"), Vec::new()),
            };
            out.insert(path, (kind, bytes, first));
        }
    }
    out
}

fn mounted(lower: &Lower, fid_type: u8) -> Vec<Item> {
    let origin = |path: &[u8]| xattr("trusted.overlay.origin", lower.origin(path, fid_type));
    let index = format!("work/index/{}", hex(&lower.origin(b"d1/a", fid_type)));
    vec![
        Item::Dir(
            "upper".into(),
            vec![origin(b""), xattr("trusted.overlay.impure", "y")],
        ),
        Item::Dir(
            "upper/d1".into(),
            vec![origin(b"d1"), xattr("trusted.overlay.impure", "y")],
        ),
        // Only one name of the lower hardlink group was modified.
        Item::File(
            "upper/d1/a".into(),
            b"modified".to_vec(),
            vec![origin(b"d1/a"), xattr("trusted.overlay.nlink", "U+0")],
        ),
        Item::Dir("upper/d2".into(), vec![origin(b"d2")]),
        Item::Whiteout("upper/d2/b".into()),
        Item::Dir(
            "upper/opq".into(),
            vec![xattr("trusted.overlay.opaque", "y")],
        ),
        Item::File("upper/opq/new".into(), b"new".to_vec(), Vec::new()),
        Item::File(
            "upper/solo".into(),
            b"solo-upper".to_vec(),
            vec![origin(b"solo")],
        ),
        Item::File(
            "upper/newfile".into(),
            b"fresh".to_vec(),
            vec![xattr("user.note", "kept")],
        ),
        Item::Link("upper/newlink".into(), "upper/newfile".into()),
        Item::Sparse(
            "upper/sparse".into(),
            8 * MIB + 1,
            vec![(0, b"S".to_vec()), (8 * MIB, b"E".to_vec())],
        ),
        Item::Dir("work".into(), Vec::new()),
        Item::Dir("work/work".into(), Vec::new()),
        Item::IndexDir,
        Item::Link(index, "upper/d1/a".into()),
        // Interrupted-operation temporary; the next mount discards it.
        Item::File("work/index/#2a".into(), Vec::new(), Vec::new()),
    ]
}

fn set_xattr(items: &mut [Item], path: &str, name: &str, value: impl AsRef<[u8]>) {
    let item = items
        .iter_mut()
        .find(|item| item.path() == path)
        .unwrap_or_else(|| panic!("no fixture item {path}"));
    let xattrs = match item {
        Item::Dir(_, xattrs) | Item::File(_, _, xattrs) => xattrs,
        _ => panic!("fixture item {path} has no xattrs"),
    };
    xattrs.retain(|(existing, _)| existing != name);
    xattrs.push(xattr(name, value));
    xattrs.sort();
}

fn remove(items: &mut Vec<Item>, path: &str) {
    let before = items.len();
    items.retain(|item| item.path() != path);
    assert_eq!(before - 1, items.len(), "{path}");
}

fn expect_refusal(lower: &Lower, items: &[Item], reason: &str) {
    let temp = tempfile::tempdir().unwrap();
    let upper = upper_image(temp.path(), items);
    let output = temp.path().join("flat.ext4");
    match lower.flatten(&upper, &output) {
        Err(FlattenError::UnsupportedOverlay(refusal)) => assert!(
            refusal.reason.contains(reason),
            "expected {reason:?}, got {refusal}"
        ),
        other => panic!("expected refusal {reason:?}, got {other:?}"),
    }
    assert!(!output.exists(), "refusal must precede output creation");
}

#[test]
fn modified_hardlink_supplies_every_surviving_alias_and_deleted_aliases_stay_deleted() {
    let lower = Lower::new();
    let temp = tempfile::tempdir().unwrap();
    let upper = upper_image(temp.path(), &mounted(&lower, INO64));
    let output = temp.path().join("flat.ext4");
    let flattened = lower.flatten(&upper, &output).unwrap();
    assert_eq!(flattened.length, std::fs::metadata(&output).unwrap().len());
    assert_ne!(flattened.uuid, UPPER_UUID, "output is a new filesystem");

    let tree = visible(&output);
    let paths = tree.keys().cloned().collect::<Vec<_>>();
    let expected: Vec<&[u8]> = vec![
        b"d1",
        b"d1/a",
        b"d1/c",
        b"d2",
        b"keep",
        b"keep/file",
        b"newfile",
        b"newlink",
        b"opq",
        b"opq/new",
        b"solo",
        b"sparse",
    ];
    assert_eq!(
        paths,
        expected
            .iter()
            .map(|path| path.to_vec())
            .collect::<Vec<_>>(),
        "deleted alias d2/b and opaque-hidden opq/old stay absent; no lost+found"
    );
    let file = |path: &[u8]| tree[path].1.clone();
    let class = |path: &[u8]| tree[path].2;
    // The untouched alias d1/c (absent from upper/) exposes the modified inode.
    assert_eq!(file(b"d1/a"), b"modified");
    assert_eq!(file(b"d1/c"), b"modified");
    assert_eq!(class(b"d1/a"), class(b"d1/c"));
    assert_eq!(file(b"newfile"), b"fresh");
    assert_eq!(class(b"newfile"), class(b"newlink"));
    assert_ne!(class(b"newfile"), class(b"d1/a"));
    assert_eq!(file(b"solo"), b"solo-upper");
    assert_eq!(file(b"keep/file"), b"kept");
    assert_eq!(file(b"opq/new"), b"new");
    let sparse = file(b"sparse");
    assert_eq!(sparse.len() as u64, 8 * MIB + 1);
    assert_eq!((sparse[0], sparse[sparse.len() - 1]), (b'S', b'E'));
    assert!(sparse[1..sparse.len() - 1].iter().all(|byte| *byte == 0));

    let reader = Reader::from_file(File::open(&output).unwrap()).unwrap();
    let aliased = resolve(&reader, b"d1/c").unwrap();
    assert_eq!(reader.metadata(aliased).unwrap().links, 2);
    let note = resolve(&reader, b"newlink").unwrap();
    assert_eq!(
        reader
            .inode_xattrs(note)
            .unwrap()
            .get(b"user.note".as_slice()),
        Some(&b"kept".to_vec()),
        "visible upper xattrs survive while overlay controls are stripped"
    );
    let holes = reader
        .file_body(resolve(&reader, b"sparse").unwrap())
        .unwrap()
        .stored_ranges()
        .map(|range| range.length)
        .sum::<u64>();
    assert!(holes < 2 * 4096, "upper holes stay holes in the output");
}

#[test]
fn pre_six_sixteen_handle_encoding_flattens_to_the_same_namespace() {
    let lower = Lower::new();
    let temp = tempfile::tempdir().unwrap();
    let ino64 = temp.path().join("ino64");
    let ino32 = temp.path().join("ino32");
    std::fs::create_dir(&ino64).unwrap();
    std::fs::create_dir(&ino32).unwrap();
    let upper64 = upper_image(&ino64, &mounted(&lower, INO64));
    let upper32 = upper_image(&ino32, &mounted(&lower, INO32));
    lower.flatten(&upper64, &ino64.join("flat")).unwrap();
    lower.flatten(&upper32, &ino32.join("flat")).unwrap();
    assert_eq!(visible(&ino64.join("flat")), visible(&ino32.join("flat")));
}

#[test]
fn every_alias_deleted_leaves_an_orphan_index_and_no_names() {
    let lower = Lower::new();
    let origin = |path: &[u8]| xattr("trusted.overlay.origin", lower.origin(path, INO64));
    // The kernel linked up and whited out every alias, then unlinked the last
    // upper name; only the index keeps the copy, with overlay nlink 1 - 1.
    let items = vec![
        Item::Dir(
            "upper".into(),
            vec![origin(b""), xattr("trusted.overlay.impure", "y")],
        ),
        Item::Dir(
            "upper/d1".into(),
            vec![origin(b"d1"), xattr("trusted.overlay.impure", "y")],
        ),
        Item::Whiteout("upper/d1/a".into()),
        Item::Whiteout("upper/d1/c".into()),
        Item::Dir("upper/d2".into(), vec![origin(b"d2")]),
        Item::Whiteout("upper/d2/b".into()),
        Item::Dir("work".into(), Vec::new()),
        Item::Dir("work/work".into(), Vec::new()),
        Item::IndexDir,
        Item::File(
            format!("work/index/{}", hex(&lower.origin(b"d1/a", INO64))),
            b"modified".to_vec(),
            vec![origin(b"d1/a"), xattr("trusted.overlay.nlink", "U-1")],
        ),
    ];
    let temp = tempfile::tempdir().unwrap();
    let upper = upper_image(temp.path(), &items);
    let output = temp.path().join("flat.ext4");
    lower.flatten(&upper, &output).unwrap();
    let tree = visible(&output);
    for path in [b"d1/a".as_slice(), b"d1/c", b"d2/b"] {
        assert!(!tree.contains_key(path), "{path:?} stays deleted");
    }
    assert_eq!(tree[b"d1".as_slice()].0, "dir");
    assert_eq!(tree[b"opq/old".as_slice()].1, b"old");
    assert_eq!(tree[b"solo".as_slice()].1, b"solo-lower");

    // The same orphan claiming a surviving alias contradicts the namespace.
    let mut claimed = items.clone();
    set_xattr(
        &mut claimed,
        &format!("work/index/{}", hex(&lower.origin(b"d1/a", INO64))),
        "trusted.overlay.nlink",
        "U+0",
    );
    expect_refusal(&lower, &claimed, "link count disagrees");
}

#[test]
fn retained_lower_renders_alone_like_a_never_mounted_overlay() {
    let lower = Lower::new();
    let temp = tempfile::tempdir().unwrap();
    let upper = temp.path().join("upper.ext4");
    write_upper(
        &upper,
        &[
            Item::Dir("upper".into(), Vec::new()),
            Item::Dir("work".into(), Vec::new()),
        ],
        &[],
    );
    let overlay = temp.path().join("overlay.ext4");
    lower.flatten(&upper, &overlay).unwrap();
    let alone = temp.path().join("lower.ext4");
    let layers = [lower.layer()];
    let rendered = crate::overlay_flatten::flatten_lower(
        FlattenLower {
            recipe: &lower.recipe,
            result: &lower.composition,
            layers: &layers,
            fsmeta: &lower.fsmeta,
        },
        &alone,
        512 * MIB,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(rendered.length, 512 * MIB, "minimum size is a floor");
    assert_eq!(visible(&alone), visible(&overlay));
}

#[test]
fn never_mounted_upper_flattens_to_the_exact_lower() {
    let lower = Lower::new();
    let temp = tempfile::tempdir().unwrap();
    let items = vec![
        Item::Dir("upper".into(), Vec::new()),
        Item::Dir("work".into(), Vec::new()),
    ];
    let path = temp.path().join("upper.ext4");
    write_upper(&path, &items, &[]);
    let output = temp.path().join("flat.ext4");
    lower.flatten(&path, &output).unwrap();
    let tree = visible(&output);
    assert_eq!(tree[b"d1/a".as_slice()].1, b"lower-hardlink");
    assert_eq!(tree[b"d1/a".as_slice()].2, tree[b"d2/b".as_slice()].2);
    assert_eq!(tree[b"d1/a".as_slice()].2, tree[b"d1/c".as_slice()].2);
    assert_eq!(tree[b"opq/old".as_slice()].1, b"old");
    assert_eq!(tree[b"solo".as_slice()].1, b"solo-lower");

    let mut stray = items.clone();
    stray.push(Item::File("upper/new".into(), b"x".to_vec(), Vec::new()));
    let path = temp.path().join("stray.ext4");
    write_upper(&path, &stray, &[]);
    let output = temp.path().join("stray-flat.ext4");
    assert!(matches!(
        lower.flatten(&path, &output),
        Err(FlattenError::UnsupportedOverlay(_))
    ));
    assert!(!output.exists());
}

#[test]
fn origin_and_index_corruption_refuses_before_output() {
    let lower = Lower::new();
    let base = mounted(&lower, INO64);

    let mut foreign = base.clone();
    let mut handle = lower.origin(b"solo", INO64);
    handle[5] ^= 1;
    set_xattr(&mut foreign, "upper/solo", "trusted.overlay.origin", handle);
    expect_refusal(&lower, &foreign, "other than the exact lower");

    let mut unknown = base.clone();
    set_xattr(
        &mut unknown,
        "upper/solo",
        "trusted.overlay.origin",
        origin_handle(lower.composition.fsmeta.uuid, 0x00ff_ffff, INO64),
    );
    expect_refusal(&lower, &unknown, "names no inode of the exact lower");

    let mut truncated = base.clone();
    let mut handle = lower.origin(b"d1", INO64);
    handle.pop();
    set_xattr(&mut truncated, "upper/d1", "trusted.overlay.origin", handle);
    expect_refusal(&lower, &truncated, "length disagrees");

    let mut generation = base.clone();
    let mut handle = lower.origin(b"solo", INO64);
    let last = handle.len() - 1;
    handle[last] = 1;
    set_xattr(
        &mut generation,
        "upper/solo",
        "trusted.overlay.origin",
        handle,
    );
    expect_refusal(&lower, &generation, "names no inode of the exact lower");

    let mut moved = base.clone();
    set_xattr(
        &mut moved,
        "upper/d1",
        "trusted.overlay.origin",
        lower.origin(b"d2", INO64),
    );
    expect_refusal(&lower, &moved, "not the lower directory at its path");

    let mut mixed = base.clone();
    set_xattr(
        &mut mixed,
        "upper/d2",
        "trusted.overlay.origin",
        lower.origin(b"d2", INO32),
    );
    expect_refusal(&lower, &mixed, "kernel family");

    let mut root = base.clone();
    set_xattr(
        &mut root,
        "upper",
        "trusted.overlay.origin",
        lower.origin(b"keep", INO64),
    );
    expect_refusal(&lower, &root, "not the lower root");

    // The modified inode claims a different lower origin than its index name.
    let mut renamed = base.clone();
    set_xattr(
        &mut renamed,
        "upper/d1/a",
        "trusted.overlay.origin",
        lower.origin(b"solo", INO64),
    );
    expect_refusal(&lower, &renamed, "origin differs from its name");

    // A copied-up lower hardlink must be its index inode (index=on).
    let mut unindexed = base.clone();
    let index = format!("work/index/{}", hex(&lower.origin(b"d1/a", INO64)));
    remove(&mut unindexed, &index);
    expect_refusal(&lower, &unindexed, "not its index inode");

    let mut counted = base.clone();
    set_xattr(&mut counted, "upper/d1/a", "trusted.overlay.nlink", "U+5");
    expect_refusal(&lower, &counted, "link count disagrees");

    let mut noncanonical = base.clone();
    let index = format!("work/index/{}", hex(&lower.origin(b"d1/a", INO64)));
    remove(&mut noncanonical, &index);
    let shouted = format!(
        "work/index/{}",
        hex(&lower.origin(b"d1/a", INO64)).to_uppercase()
    );
    noncanonical.push(Item::Link(shouted, "upper/d1/a".into()));
    expect_refusal(&lower, &noncanonical, "canonical handle");
}

#[test]
fn unadmitted_overlay_state_refuses_explicitly() {
    let lower = Lower::new();
    let base = mounted(&lower, INO64);
    type Corruption<'a> = (Box<dyn Fn(&mut Vec<Item>) + 'a>, &'static str);
    let cases: Vec<Corruption<'_>> = vec![
        (
            Box::new(|items| set_xattr(items, "upper/d1", "trusted.overlay.redirect", "/d2")),
            "redirect_dir=nofollow",
        ),
        (
            Box::new(|items| set_xattr(items, "upper/solo", "trusted.overlay.metacopy", "")),
            "metacopy=off",
        ),
        (
            Box::new(|items| set_xattr(items, "upper/solo", "trusted.overlay.protattr", "i")),
            "not representable",
        ),
        (
            Box::new(|items| {
                set_xattr(items, "upper/newfile", "trusted.overlay.overlay.guest", "x")
            }),
            "escaped guest",
        ),
        (
            Box::new(|items| set_xattr(items, "upper", "trusted.overlay.uuid", [0; 16])),
            "unadmitted overlay control",
        ),
        (
            Box::new(|items| set_xattr(items, "upper/opq", "trusted.overlay.opaque", "x")),
            "unadmitted overlay control",
        ),
        (
            Box::new(|items| set_xattr(items, "upper/solo", "trusted.overlay.origin", "")),
            "recorded as unknown",
        ),
        (
            Box::new(|items| set_xattr(items, "upper/newfile", "user.overlay.x", "1")),
            "outside the admitted profile",
        ),
        (
            Box::new(|items| {
                set_xattr(
                    items,
                    "upper/opq",
                    "trusted.overlay.origin",
                    lower.origin(b"opq", INO64),
                )
            }),
            "opaque directory records a copy-up origin",
        ),
        (
            Box::new(|items| {
                items.push(Item::Dir(
                    "upper/keep".into(),
                    vec![xattr("trusted.overlay.impure", "y")],
                ))
            }),
            "without a copy-up origin",
        ),
        (
            Box::new(|items| {
                items.push(Item::Dir(
                    "upper/fresh".into(),
                    vec![xattr(
                        "trusted.overlay.origin",
                        lower.origin(b"keep", INO64),
                    )],
                ))
            }),
            "names no lower directory at its path",
        ),
        (
            Box::new(|items| {
                items.push(Item::File(
                    "upper/keep-copy".into(),
                    b"x".to_vec(),
                    vec![xattr(
                        "trusted.overlay.origin",
                        lower.origin(b"keep", INO64),
                    )],
                ))
            }),
            "type differs from its lower origin",
        ),
        (
            Box::new(|items| {
                items.push(Item::File(
                    "upper/counted".into(),
                    b"x".to_vec(),
                    vec![xattr("trusted.overlay.nlink", "U+0")],
                ))
            }),
            "unindexed inode",
        ),
        (
            Box::new(|items| items.push(Item::Dir("stray".into(), Vec::new()))),
            "unexpected entry in the upper filesystem root",
        ),
        (
            Box::new(|items| items.push(Item::Dir("work/work/incompat".into(), Vec::new()))),
            "incompatible overlay features",
        ),
        (
            Box::new(|items| remove(items, "work/work")),
            "not both present",
        ),
    ];
    for (mutate, reason) in cases {
        let mut items = base.clone();
        mutate(&mut items);
        expect_refusal(&lower, &items, reason);
    }

    // Index entries the nfs_export=off profile never creates.
    let mut directory = base.clone();
    directory.push(Item::Dir(
        format!("work/index/{}", hex(&lower.origin(b"keep", INO64))),
        Vec::new(),
    ));
    expect_refusal(&lower, &directory, "directory index entries");
    let mut whiteout = base.clone();
    whiteout.push(Item::Whiteout(format!(
        "work/index/{}",
        hex(&lower.origin(b"keep/file", INO64))
    )));
    expect_refusal(&lower, &whiteout, "whiteout index entries");
    let mut single = base.clone();
    single.push(Item::Link(
        format!("work/index/{}", hex(&lower.origin(b"solo", INO64))),
        "upper/solo".into(),
    ));
    expect_refusal(&lower, &single, "one name requires nfs_export");
}

#[test]
fn dirty_upper_and_foreign_lower_fail_with_their_own_types() {
    let lower = Lower::new();
    let temp = tempfile::tempdir().unwrap();
    let upper = upper_image(temp.path(), &mounted(&lower, INO64));
    let dirty = temp.path().join("dirty.ext4");
    std::fs::copy(&upper, &dirty).unwrap();
    // s_feature_incompat |= RECOVER: the journal needs replay by a guest.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dirty)
        .unwrap();
    let mut incompat = [0; 4];
    file.read_exact_at(&mut incompat, 1024 + 0x60).unwrap();
    let value = u32::from_le_bytes(incompat) | 0x4;
    file.write_all_at(&value.to_le_bytes(), 1024 + 0x60)
        .unwrap();
    drop(file);
    let output = temp.path().join("dirty-flat.ext4");
    assert!(matches!(
        lower.flatten(&dirty, &output),
        Err(FlattenError::RecoveryRequired(_))
    ));
    assert!(!output.exists());

    let mut bytes = vec![0; lower.fsmeta.metadata().unwrap().len() as usize];
    lower.fsmeta.read_exact_at(&mut bytes, 0).unwrap();
    // A superblock UUID byte: the retained fsmeta no longer authenticates.
    bytes[1024 + 48] ^= 1;
    let tampered = tempfile::tempfile().unwrap();
    tampered.write_all_at(&bytes, 0).unwrap();
    let layers = [lower.layer()];
    let output = temp.path().join("foreign-flat.ext4");
    let result = flatten_overlay(
        FlattenLower {
            recipe: &lower.recipe,
            result: &lower.composition,
            layers: &layers,
            fsmeta: &tampered,
        },
        File::open(&upper).unwrap(),
        &output,
        0,
        &AtomicBool::new(false),
    );
    assert!(matches!(result, Err(FlattenError::Lower(_))));
    assert!(!output.exists());

    let output = temp.path().join("cancelled.ext4");
    let layers = [lower.layer()];
    let cancelled = flatten_overlay(
        FlattenLower {
            recipe: &lower.recipe,
            result: &lower.composition,
            layers: &layers,
            fsmeta: &lower.fsmeta,
        },
        File::open(&upper).unwrap(),
        &output,
        0,
        &AtomicBool::new(true),
    );
    assert!(matches!(cancelled, Err(FlattenError::Cancelled)));
}

#[test]
fn hardlink_groups_beyond_ext4_link_max_refuse_before_writing() {
    let lower = Lower::new();
    let mut items = mounted(&lower, INO64);
    // The upper inode holds the ext4 maximum (64999 upper names + index);
    // the untouched lower aliases d1/c and d2/b make 65001 visible names.
    remove(&mut items, "upper/d2/b");
    for alias in 0..64_998 {
        items.push(Item::Link(
            format!("upper/d1/x{alias}"),
            "upper/d1/a".into(),
        ));
    }
    set_xattr(&mut items, "upper/d1/a", "trusted.overlay.nlink", "U+1");
    let temp = tempfile::tempdir().unwrap();
    let upper = upper_image(temp.path(), &items);
    let output = temp.path().join("flat.ext4");
    match lower.flatten(&upper, &output) {
        Err(FlattenError::Output(error)) => assert!(error.to_string().contains("links")),
        other => panic!("expected an ext4 link bound refusal, got {other:?}"),
    }
    assert!(!output.exists());
}

// Retained-lower rendering, the explicit OCI-to-raw conversion: real layer
// blobs are ingested and composed exactly as acquisition retains them, then
// rendered by `flatten_lower` through the shared fresh-ext4 writer.

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("layer ingestion failed: {0}")]
    Ingest(crate::changeset::ChangesetError),
    #[error("lower composition failed: {0}")]
    Compose(crate::composition::CompositionError),
    #[error("filesystem flattening failed: {0}")]
    Flatten(FlattenError),
}

struct Rendered {
    path: PathBuf,
}

fn operation(index: u64) -> crate::StagingOperation {
    crate::StagingOperation::try_from(format!("00000000-0000-4000-8000-{index:012x}")).unwrap()
}

/// Private ingest staging of layer `occurrence`, removed on every outcome.
fn stage_path(root: &Path, occurrence: u64) -> PathBuf {
    root.join("tmp").join(format!(
        "stage-00000000-0000-4000-8000-{:012x}",
        101 + occurrence
    ))
}

fn render_layers(
    root: &Path,
    layers: Vec<(&str, Vec<u8>, Option<String>)>,
    minimum_size: u64,
) -> Result<Rendered, Failure> {
    let limits = ChangesetLimits::default();
    let mut staged = Vec::new();
    for (occurrence, (media_type, bytes, diff_id)) in layers.into_iter().enumerate() {
        let source = root.join(format!("blob-{occurrence}"));
        std::fs::write(&source, &bytes).unwrap();
        let blob_digest = ContentDigest::of_bytes(&bytes);
        let input = crate::changeset::LayerInput {
            blob_digest,
            media_type: media_type.into(),
            size_bytes: bytes.len() as u64,
            diff_id: diff_id.map_or(blob_digest, |id| id.parse().unwrap()),
        };
        staged.push(
            crate::changeset::ingest_layer(
                &source,
                &input,
                root,
                &operation(101 + occurrence as u64),
                &limits,
            )
            .map_err(Failure::Ingest)?,
        );
    }
    let packs = staged
        .iter()
        .map(|layer| File::open(layer.pack_path()).unwrap())
        .collect::<Vec<_>>();
    let results = staged
        .iter()
        .enumerate()
        .map(|(occurrence, layer)| LayerResult {
            recipe: LayerRecipe {
                diff_id: layer.changeset().diff_id,
            }
            .id()
            .unwrap(),
            pack_stream: StreamIdentity::from_sha256([occurrence as u8; 32]),
            pack_length: layer.pack_length(),
            index_root: encode_index(layer.changeset(), &limits)
                .unwrap()
                .root
                .digest,
        })
        .collect::<Vec<_>>();
    let layers = staged
        .iter()
        .zip(&results)
        .zip(&packs)
        .map(|((layer, result), pack)| Layer {
            result,
            changeset: layer.changeset(),
            pack,
        })
        .collect::<Vec<_>>();
    let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &layers)
        .map_err(Failure::Compose)?;
    let mut fsmeta = tempfile::tempfile().unwrap();
    let composition = crate::composition::prepare(&recipe, &layers, &mut fsmeta)
        .and_then(|prepared| prepared.finalize(StreamIdentity::from_sha256([9; 32])))
        .map_err(Failure::Compose)?;
    let path = root.join("flat.ext4");
    crate::overlay_flatten::flatten_lower(
        FlattenLower {
            recipe: &recipe,
            result: &composition,
            layers: &layers,
            fsmeta: &fsmeta,
        },
        &path,
        minimum_size,
        &AtomicBool::new(false),
    )
    .map_err(Failure::Flatten)?;
    Ok(Rendered { path })
}

#[test]
fn retained_rendering_handles_empty_inputs() {
    for layers in [
        Vec::new(),
        vec![(
            "application/vnd.oci.image.layer.v1.tar",
            vec![0; 1024],
            None,
        )],
    ] {
        let temp = tempfile::tempdir().unwrap();
        let staged = render_layers(temp.path(), layers, 64 * 1024 * 1024).unwrap();
        let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        assert!(reader.list_dir("/").unwrap().is_empty());
        let root = reader.stat("/").unwrap().1;
        assert_eq!(root.mode & 0o7777, 0o755);
        assert_eq!(root.mtime, 0);
    }
}

#[test]
fn retained_rendering_refuses_unrepresentable_symlinks_before_output() {
    for length in [4095, 4096] {
        let temp = tempfile::tempdir().unwrap();
        let target = vec![b't'; length];
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("linkpath", target.as_slice())])
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(0);
        builder
            .append_link(&mut header, "link", "placeholder")
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        let source = temp.path().join("source.tar");
        std::fs::write(&source, &bytes).unwrap();
        let digest = crate::changeset::ContentDigest::of_bytes(&bytes);
        let admitted = crate::changeset::ingest_layer(
            &source,
            &crate::changeset::LayerInput {
                blob_digest: digest,
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                size_bytes: bytes.len() as u64,
                diff_id: digest,
            },
            &temp.path().join("normalized"),
            &operation(101),
            &crate::changeset::ChangesetLimits::default(),
        )
        .unwrap();
        assert!(
            matches!(
                &admitted.changeset().entries[0].kind,
                crate::changeset::EntryKind::Symlink { target: actual } if actual == &target
            ),
            "normalized admission retains both boundary inputs unchanged"
        );
        drop(admitted);
        let result = render_layers(
            temp.path(),
            vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
            64 * 1024 * 1024,
        );
        if length == 4095 {
            let staged = result.unwrap();
            let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
            assert_eq!(reader.read_link("link").unwrap(), target);
            drop(staged);
        } else {
            // The retained EROFS lower rejects targets the VFS would truncate.
            assert!(matches!(
                result,
                Err(Failure::Compose(
                    crate::composition::CompositionError::Erofs(_)
                ))
            ));
            assert!(!temp.path().join("flat.ext4").exists());
        }
        assert!(!stage_path(temp.path(), 0).exists());
    }
}
#[test]
fn retained_rendering_hashes_padding_and_every_gzip_member() {
    use std::io::Write;

    let padding = vec![0_u8; 2048];
    let suffix = vec![0_u8; 1024];
    let mut decoded = padding.clone();
    decoded.extend_from_slice(&suffix);
    let mut compressed = Vec::new();
    for bytes in [padding.as_slice(), suffix.as_slice()] {
        let mut member = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        member.write_all(bytes).unwrap();
        compressed.extend(member.finish().unwrap());
    }
    let temp = tempfile::tempdir().unwrap();
    let staged = render_layers(
        temp.path(),
        vec![(
            "application/vnd.oci.image.layer.v1.tar+gzip",
            compressed.clone(),
            Some(ContentDigest::of_bytes(&decoded).to_string()),
        )],
        64 * 1024 * 1024,
    )
    .unwrap();
    drop(staged);
    std::fs::remove_file(temp.path().join("flat.ext4")).unwrap();
    let result = render_layers(
        temp.path(),
        vec![(
            "application/vnd.oci.image.layer.v1.tar+gzip",
            compressed,
            Some(ContentDigest::of_bytes(&padding).to_string()),
        )],
        64 * 1024 * 1024,
    );
    assert!(matches!(
        result,
        Err(Failure::Ingest(crate::changeset::ChangesetError::Invalid(
            _
        )))
    ));
    assert!(!stage_path(temp.path(), 0).exists());
}

#[test]
fn retained_rendering_decodes_all_supported_media_types() {
    use std::io::Write;

    let payload = b"layer contents from a real compressed file\n";
    let raw = test_tar("contents", payload);
    let diff_id = ContentDigest::of_bytes(&raw).to_string();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw).unwrap();
    let gzip = encoder.finish().unwrap();
    let zstd = zstd::stream::encode_all(raw.as_slice(), 0).unwrap();
    for (media_type, bytes) in [
        ("application/vnd.oci.image.layer.v1.tar", &raw),
        (
            "application/vnd.oci.image.layer.nondistributable.v1.tar",
            &raw,
        ),
        ("application/vnd.docker.image.rootfs.diff.tar", &raw),
        ("application/vnd.oci.image.layer.v1.tar+gzip", &gzip),
        ("application/vnd.docker.image.rootfs.diff.tar.gzip", &gzip),
        (
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            &gzip,
        ),
        ("application/vnd.oci.image.layer.v1.tar+zstd", &zstd),
        (
            "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
            &zstd,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let staged = render_layers(
            temp.path(),
            vec![(media_type, bytes.clone(), Some(diff_id.clone()))],
            64 * 1024 * 1024,
        )
        .unwrap();
        let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
        assert_eq!(
            reader.read_file("contents", 0, None).unwrap(),
            payload,
            "{media_type}"
        );
    }
}

#[test]
fn retained_rendering_rejects_unsupported_media_type_and_cleans_staging() {
    let temp = tempfile::tempdir().unwrap();
    let result = render_layers(
        temp.path(),
        vec![(
            "application/vnd.example.layer.v1.tar",
            test_tar("contents", b"x"),
            None,
        )],
        64 * 1024 * 1024,
    );
    assert!(matches!(
        result,
        Err(Failure::Ingest(
            crate::changeset::ChangesetError::Unsupported(_)
        ))
    ));
    assert!(!stage_path(temp.path(), 0).exists());
}

#[test]
fn retained_rendering_preserves_acl_capability_and_hardlink_metadata() {
    use base64::Engine;
    use std::io::Cursor;

    let temp = tempfile::tempdir().unwrap();
    let mut archive = tar::Builder::new(Vec::new());
    let near_limit = vec![b'x'; 2750];
    archive
        .append_pax_extensions([
            ("SCHILY.xattr.user.near-limit", near_limit.as_slice()),
            (
                "SCHILY.acl.access",
                b"user::rw-,user:1234:r--,group::r--,mask::r--,other::r--".as_slice(),
            ),
        ])
        .unwrap();
    let mut file = tar::Header::new_gnu();
    file.set_mode(0o644);
    file.set_uid(0);
    file.set_gid(0);
    file.set_mtime(42);
    file.set_size(b"original-hardlink\n".len() as u64);
    file.set_cksum();
    archive
        .append_data(
            &mut file,
            "overlay-fixture/a",
            Cursor::new(b"original-hardlink\n"),
        )
        .unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_mode(0o700);
    link.set_uid(99);
    link.set_gid(98);
    link.set_mtime(17);
    link.set_size(0);
    link.set_entry_type(tar::EntryType::Link);
    archive
        .append_link(&mut link, "overlay-fixture/b", "overlay-fixture/a")
        .unwrap();
    let capability = [1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let capability_text = base64::engine::general_purpose::STANDARD.encode(capability);
    archive
        .append_pax_extensions([(
            "LIBARCHIVE.xattr.security.capability",
            capability_text.as_bytes(),
        )])
        .unwrap();
    file.set_size(b"capability".len() as u64);
    file.set_cksum();
    archive
        .append_data(
            &mut file,
            "overlay-fixture/capability",
            Cursor::new(b"capability"),
        )
        .unwrap();
    let bytes = archive.into_inner().unwrap();
    let staged = render_layers(
        temp.path(),
        vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
        64 * 1024 * 1024,
    )
    .unwrap();
    let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
    let (number, inode) = reader.stat_no_follow("/overlay-fixture/a").unwrap();
    let attrs = flat_inode_xattrs(&staged.path, &inode);
    assert_eq!(
        attrs.get(&(1, b"near-limit".to_vec())),
        Some(&near_limit),
        "production-created lower must retain the source user xattr"
    );
    // ext4's on-disk ACL v1 has short object records, unlike the Linux API
    // xattr v2 retained by the normalized changeset.
    let disk_acl = vec![
        1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 4, 0, 210, 4, 0, 0, 4, 0, 4, 0, 16, 0, 4, 0, 32, 0, 4, 0,
    ];
    assert_eq!(attrs.get(&(2, Vec::new())), Some(&disk_acl));
    assert_eq!(
        reader.stat_no_follow("/overlay-fixture/b").unwrap().0,
        number
    );
    assert_eq!(inode.links_count, 2);
    assert_eq!(inode.mode & 0o7777, 0o644);
    assert_eq!(inode.uid_full(), 0);
    assert_eq!(inode.gid_full(), 0);
    assert_eq!(inode.mtime, 42);
    assert_eq!(
        reader.read_file("/overlay-fixture/a", 0, None).unwrap(),
        b"original-hardlink\n"
    );
    let inode = reader
        .stat_no_follow("/overlay-fixture/capability")
        .unwrap()
        .1;
    assert_eq!(
        flat_inode_xattrs(&staged.path, &inode).get(&(6, b"capability".to_vec())),
        Some(&capability.to_vec())
    );
}

#[test]
fn retained_rendering_composes_whiteouts_aliases_and_source_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let mut lower = tar::Builder::new(Vec::new());
    append_test_file(&mut lower, "d/old", b"old");
    append_test_file(&mut lower, "d/keep", b"keep");
    append_test_file(&mut lower, "target", b"original");
    let mut link = tar::Header::new_gnu();
    link.set_mode(0o777);
    link.set_uid(0);
    link.set_gid(0);
    link.set_mtime(1);
    link.set_size(0);
    link.set_entry_type(tar::EntryType::Link);
    lower.append_link(&mut link, "alias", "target").unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_mode(0o777);
    link.set_uid(0);
    link.set_gid(0);
    link.set_mtime(1);
    link.set_size(0);
    link.set_entry_type(tar::EntryType::Symlink);
    lower.append_link(&mut link, "dirlink", "d").unwrap();
    let mut upper = tar::Builder::new(Vec::new());
    // Markers apply to untouched lower objects, not this layer's new ones.
    append_test_file(&mut upper, "dirlink/new", b"new");
    append_test_file(&mut upper, "d/.wh..wh..opq", b"");
    append_test_file(&mut upper, "d/.wh.old", b"");
    append_test_file(&mut upper, "target", b"replacement");
    upper
        .append_pax_extensions([
            ("SCHILY.xattr.user.root", b"\0\xff".as_slice()),
            ("mtime", b"2147483648.123456789".as_slice()),
        ])
        .unwrap();
    let mut directory = tar::Header::new_gnu();
    directory.set_entry_type(tar::EntryType::Directory);
    directory.set_mode(0o710);
    directory.set_uid(54);
    directory.set_gid(56);
    directory.set_mtime(2);
    directory.set_size(0);
    directory.set_cksum();
    upper
        .append_data(&mut directory, ".", std::io::empty())
        .unwrap();
    let mut owned = tar::Header::new_gnu();
    owned.set_mode(0o6754);
    owned.set_uid(0x1234_5678);
    owned.set_gid(0x9abc_def0);
    owned.set_mtime(7);
    owned.set_size(5);
    owned.set_cksum();
    upper
        .append_data(&mut owned, "d/owned", b"owned".as_slice())
        .unwrap();
    upper
        .append_pax_extensions([("SCHILY.xattr.user.directory", b"final".as_slice())])
        .unwrap();
    directory.set_mode(0o750);
    directory.set_uid(68);
    directory.set_gid(69);
    directory.set_mtime(9);
    directory.set_cksum();
    upper
        .append_data(&mut directory, "d", std::io::empty())
        .unwrap();
    let staged = render_layers(
        temp.path(),
        vec![
            (
                "application/vnd.oci.image.layer.v1.tar",
                lower.into_inner().unwrap(),
                None,
            ),
            (
                "application/vnd.oci.image.layer.v1.tar",
                upper.into_inner().unwrap(),
                None,
            ),
        ],
        64 * 1024 * 1024,
    )
    .unwrap();
    let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
    assert!(!reader.exists("d/old"));
    assert!(!reader.exists("d/keep"));
    assert!(!reader.exists("lost+found"));
    assert_eq!(reader.read_file("d/new", 0, None).unwrap(), b"new");
    assert_eq!(reader.read_file("dirlink/new", 0, None).unwrap(), b"new");
    assert_eq!(reader.read_file("alias", 0, None).unwrap(), b"original");
    assert_eq!(reader.read_file("target", 0, None).unwrap(), b"replacement");
    assert_ne!(
        reader.stat("alias").unwrap().0,
        reader.stat("target").unwrap().0
    );
    let inode = reader.stat("d/owned").unwrap().1;
    assert_eq!(inode.mode & 0o7777, 0o6754);
    assert_eq!(inode.uid_full(), 0x1234_5678);
    assert_eq!(inode.gid_full(), 0x9abc_def0);
    assert_eq!(inode.mtime, 7);
    let root = reader.stat("/").unwrap().1;
    assert_eq!(root.mode & 0o7777, 0o710);
    assert_eq!(root.uid_full(), 54);
    assert_eq!(root.gid_full(), 56);
    assert_eq!(root.mtime, 0x8000_0000);
    assert_eq!(root.mtime_extra, (123_456_789 << 2) | 1);
    assert_eq!(
        flat_inode_xattrs(&staged.path, &root).get(&(1, b"root".to_vec())),
        Some(&vec![0, 255])
    );
    let directory = reader.stat("d").unwrap().1;
    assert_eq!(directory.mode & 0o7777, 0o750);
    assert_eq!(directory.uid_full(), 68);
    assert_eq!(directory.gid_full(), 69);
    assert_eq!(directory.mtime, 9);
    assert_eq!(
        flat_inode_xattrs(&staged.path, &directory).get(&(1, b"directory".to_vec())),
        Some(&b"final".to_vec())
    );
}

#[test]
fn retained_rendering_preserves_raw_names_targets_and_special_inodes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    let temp = tempfile::tempdir().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("LIBARCHIVE.xattr.user.%FF", b"AP8K".as_slice())])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1);
    header.set_size(3);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            PathBuf::from(OsString::from_vec(b"raw-\xff".to_vec())),
            b"raw".as_slice(),
        )
        .unwrap();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("symlink").unwrap();
    header.set_link_name_literal(b"raw-\xff").unwrap();
    header.set_cksum();
    builder.append(&header, std::io::empty()).unwrap();
    for (path, kind, major, minor) in [
        ("char", tar::EntryType::Char, 0xfff, 0xfffff),
        ("block", tar::EntryType::Block, 0xabc, 0xcdef),
        ("fifo", tar::EntryType::Fifo, 0, 0),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o600);
        header.set_uid(23);
        header.set_gid(24);
        header.set_mtime(3);
        header.set_size(0);
        header.set_entry_type(kind);
        header.set_device_major(major).unwrap();
        header.set_device_minor(minor).unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
    }
    builder
        .append_pax_extensions([("SCHILY.filetype", b"socket".as_slice())])
        .unwrap();
    append_test_file(&mut builder, "socket", b"");
    let staged = render_layers(
        temp.path(),
        vec![(
            "application/vnd.oci.image.layer.v1.tar",
            builder.into_inner().unwrap(),
            None,
        )],
        64 * 1024 * 1024,
    )
    .unwrap();
    let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
    assert_eq!(reader.read_file(b"raw-\xff", 0, None).unwrap(), b"raw");
    assert_eq!(reader.read_link("symlink").unwrap(), b"raw-\xff");
    assert_eq!(reader.read_file("symlink", 0, None).unwrap(), b"raw");
    assert_eq!(
        reader
            .xattrs(b"raw-\xff")
            .unwrap()
            .get(b"user.\xff".as_slice()),
        Some(&vec![0, 255, 10])
    );
    for (path, kind, major, minor) in [
        ("char", 0o020000, 0xfff_u32, 0xfffff_u32),
        ("block", 0o060000, 0xabc, 0xcdef),
    ] {
        let inode = reader.stat_no_follow(path).unwrap().1;
        assert_eq!(inode.mode, kind | 0o600);
        assert_eq!(inode.uid_full(), 23);
        assert_eq!(inode.gid_full(), 24);
        let encoded = u32::from_le_bytes(inode.block[4..8].try_into().unwrap());
        assert_eq!(inode.block[..4], [0; 4]);
        assert_eq!(
            encoded,
            (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
        );
    }
    assert_eq!(reader.stat_no_follow("fifo").unwrap().1.mode, 0o010600);
    assert_eq!(reader.stat_no_follow("socket").unwrap().1.mode, 0o140644);
}

#[test]
fn retained_rendering_preserves_sparse_logical_bytes_without_allocating_holes() {
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    let length = 256 * 1024 * 1024 + 17;
    let size = length.to_string();
    let map = format!("0,1,{},1", length - 1);
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([
            ("GNU.sparse.size", size.as_bytes()),
            ("GNU.sparse.numblocks", b"2".as_slice()),
            ("GNU.sparse.map", map.as_bytes()),
        ])
        .unwrap();
    append_test_file(&mut builder, "sparse", b"AB");
    let staged = render_layers(
        temp.path(),
        vec![(
            "application/vnd.oci.image.layer.v1.tar",
            builder.into_inner().unwrap(),
            None,
        )],
        64 * 1024 * 1024,
    )
    .unwrap();
    let metadata = std::fs::metadata(&staged.path).unwrap();
    assert!(
        metadata.len() < length as u64,
        "sizing uses stored data, not the logical hole"
    );
    assert!(metadata.blocks() * 512 < 32 * 1024 * 1024);
    let reader = disk_image::ext4::Reader::new(&staged.path).unwrap();
    let inode = reader.stat("sparse").unwrap().1;
    assert_eq!(inode.file_size(), length as u64);
    assert_eq!(reader.read_file("sparse", 0, Some(2)).unwrap(), b"A\0");
    assert_eq!(
        reader
            .read_file("sparse", length as u64 - 2, Some(2))
            .unwrap(),
        b"\0B"
    );
    assert_eq!(
        reader
            .read_file("sparse", 128 * 1024 * 1024, Some(4096))
            .unwrap(),
        vec![0; 4096]
    );
}

#[test]
fn retained_rendering_rejects_malformed_layers_and_forward_links_before_output() {
    let mut malformed = Vec::new();
    for (key, value) in [
        ("path", b"../escape".as_slice()),
        ("path", b"nul\0suffix".as_slice()),
        ("SCHILY.xattr.trusted.overlay.opaque", b"y".as_slice()),
    ] {
        let mut builder = tar::Builder::new(Vec::new());
        builder.append_pax_extensions([(key, value)]).unwrap();
        append_test_file(&mut builder, "placeholder", b"x");
        malformed.push(builder.into_inner().unwrap());
    }
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("linkpath", b"target\0suffix".as_slice())])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o777);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1);
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    builder.append_link(&mut header, "link", "target").unwrap();
    malformed.push(builder.into_inner().unwrap());
    malformed.push(test_tar(".wh.", b""));
    let mut builder = tar::Builder::new(Vec::new());
    header.set_entry_type(tar::EntryType::Link);
    builder.append_link(&mut header, "link", "target").unwrap();
    append_test_file(&mut builder, "target", b"x");
    malformed.push(builder.into_inner().unwrap());
    for bytes in malformed {
        let temp = tempfile::tempdir().unwrap();
        let result = render_layers(
            temp.path(),
            vec![("application/vnd.oci.image.layer.v1.tar", bytes, None)],
            64 * 1024 * 1024,
        );
        assert!(matches!(
            result,
            Err(Failure::Ingest(_))
                | Err(Failure::Compose(
                    crate::composition::CompositionError::Namespace(_)
                ))
        ));
        assert!(!stage_path(temp.path(), 0).exists());
        assert!(!temp.path().join("flat.ext4").exists());
        assert!(!temp.path().join("escape").exists());
    }
}

fn flat_inode_xattrs(
    image: &std::path::Path,
    inode: &disk_image::ext4::types::Inode,
) -> std::collections::BTreeMap<(u8, Vec<u8>), Vec<u8>> {
    use std::io::{Seek, SeekFrom};

    fn entries(
        bytes: &[u8],
        mut offset: usize,
        value_base: usize,
        output: &mut std::collections::BTreeMap<(u8, Vec<u8>), Vec<u8>>,
    ) {
        assert_eq!(&bytes[..4], &0xea02_0000_u32.to_le_bytes());
        while bytes[offset..offset + 4] != [0; 4] {
            let name_length = usize::from(bytes[offset]);
            let index = bytes[offset + 1];
            let value_offset = usize::from(u16::from_le_bytes(
                bytes[offset + 2..offset + 4].try_into().unwrap(),
            ));
            let value_length =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            let name = bytes[offset + 16..offset + 16 + name_length].to_vec();
            let start = value_base + value_offset;
            assert!(output
                .insert((index, name), bytes[start..start + value_length].to_vec())
                .is_none());
            offset += (16 + name_length + 3) & !3;
        }
    }

    let mut result = std::collections::BTreeMap::new();
    if inode.inline_xattrs[..4] != [0; 4] {
        entries(&inode.inline_xattrs, 4, 4, &mut result);
    }
    let block = u64::from(inode.xattr_block_lo) | (u64::from(inode.xattr_block_hi) << 32);
    if block != 0 {
        let mut file = std::fs::File::open(image).unwrap();
        file.seek(SeekFrom::Start(block * 4096)).unwrap();
        let mut bytes = [0; 4096];
        file.read_exact(&mut bytes).unwrap();
        entries(&bytes, 32, 0, &mut result);
    }
    result
}

fn append_test_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder.append_data(&mut header, path, bytes).unwrap();
}

fn test_tar(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    append_test_file(&mut builder, path, bytes);
    builder.into_inner().unwrap()
}
