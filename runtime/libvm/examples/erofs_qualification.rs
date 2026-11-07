//! Controlled producer for independent fsck and actual guest-kernel qualification.
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use libvm::storage::{composition, pool::StoragePool, stream::StreamHasher, vmdk::FlatLowerPlan};
use oci::changeset::index::encode_index_to;
use oci::changeset::{
    ChangeEntry, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset, LayerRecipe,
    LayerResult, Metadata, MetadataPresence, PayloadRef, StreamIdentity, Xattr,
};
use oci::composition::CompositionRecipe;
use oci::erofs::Layer;

fn new_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

fn entry(path: &[u8], kind: EntryKind) -> ChangeEntry {
    let directory = matches!(kind, EntryKind::Directory | EntryKind::RootDirectory);
    ChangeEntry {
        ordinal: 0,
        path: path.to_vec(),
        metadata: Metadata {
            uid: 0,
            gid: 0,
            mode: if directory { 0o755 } else { 0o640 },
            mtime_seconds: 4_294_967_297,
            mtime_nanos: 123_456_789,
            xattrs: Vec::new(),
        },
        presence: MetadataPresence {
            uid: true,
            gid: true,
            mode: true,
            mtime: true,
            xattrs: true,
            acl_access: false,
            acl_default: false,
        },
        kind,
    }
}

fn regular(path: &[u8], offset: u64, length: u64) -> ChangeEntry {
    entry(
        path,
        EntryKind::Regular(PayloadRef {
            pack_offset: offset,
            length,
            sparse: Vec::new(),
        }),
    )
}

fn layer_result(changeset: &LayerChangeset, pack: &File) -> Result<LayerResult, Box<dyn Error>> {
    let root = encode_index_to(changeset, &ChangesetLimits::default(), |_| Ok(()))?;
    let scan = StreamHasher::new().hash_open_file(pack, changeset.pack_length)?;
    Ok(LayerResult {
        recipe: LayerRecipe {
            diff_id: changeset.diff_id,
        }
        .id()?,
        pack_stream: StreamIdentity::from_sha256(*scan.map.id().as_bytes()),
        pack_length: changeset.pack_length,
        index_root: root.digest,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(
            "usage: erofs_qualification OUTPUT_DIRECTORY empty|metadata|rich|many|split".into(),
        );
    }
    let directory = Path::new(&args[1]);
    let mode = args[2].to_str().ok_or("fixture mode is not UTF-8")?;
    if !matches!(mode, "empty" | "metadata" | "rich" | "many" | "split") {
        return Err("unknown fixture mode".into());
    }
    fs::create_dir(directory)?;
    let directory = directory.canonicalize()?;
    let images = directory.join("images");
    fs::create_dir(&images)?;
    fs::set_permissions(&images, fs::Permissions::from_mode(0o700))?;
    let pool = StoragePool::open(&images)?;
    let mut pack = new_file(&directory.join("payload.pack"))?;
    let mut entries = Vec::new();
    if mode != "empty" {
        entries.push(entry(b"", EntryKind::RootDirectory));
        entries.push(entry(b"a", EntryKind::Directory));
        entries.push(entry(b"a/b", EntryKind::Directory));
        entries.push(entry(b"a-", EntryKind::Directory));
        entries.push(regular(b"empty", 0, 0));
        entries.push(entry(
            b"link",
            EntryKind::Symlink {
                target: b"a/../raw-\xff".to_vec(),
            },
        ));
    }
    if matches!(mode, "rich" | "many" | "split") {
        let payload: Vec<u8> = (0..4113)
            .map(|index| ((index * 17 + 3) % 251) as u8)
            .collect();
        pack.write_all(&payload)?;
        pack.set_len(8192)?;
        entries.push(regular(b"payload", 0, payload.len() as u64));
        entries.push(entry(
            b"hardlink",
            EntryKind::Hardlink {
                target: b"payload".to_vec(),
            },
        ));
        entries.push(regular(b"raw-\xff", 8192, payload.len() as u64));
        pack.seek(SeekFrom::Start(8192))?;
        pack.write_all(&payload)?;
        pack.seek(SeekFrom::Start(16384))?;
        pack.write_all(&[0x5a; 16])?;
        pack.seek(SeekFrom::Start(24577))?;
        pack.write_all(&[0x7f])?;
        pack.set_len(28672)?;
        entries.push(regular(b"sparse", 16384, 12288));
        entries.push(entry(
            b"char",
            EntryKind::CharacterDevice { major: 1, minor: 3 },
        ));
        entries.push(entry(
            b"block",
            EntryKind::BlockDevice { major: 7, minor: 0 },
        ));
        entries.push(entry(b"fifo", EntryKind::Fifo));
        entries.push(entry(b"socket", EntryKind::Socket));
        let mut metadata = regular(b"metadata", 28672, 0);
        metadata.metadata.uid = u32::MAX - 1;
        metadata.metadata.gid = u32::MAX - 2;
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 77),
            (4, 4, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let directory_entry = entries
            .iter_mut()
            .find(|entry| entry.path == b"a")
            .ok_or("missing fixture directory")?;
        directory_entry.metadata.xattrs.push(Xattr {
            name: b"system.posix_acl_default".to_vec(),
            value: acl.clone(),
        });
        directory_entry.presence.acl_default = true;
        let mut capability = 0x0200_0001u32.to_le_bytes().to_vec();
        for word in [1u32 << 10, 0, 0, 0] {
            capability.extend_from_slice(&word.to_le_bytes());
        }
        metadata.metadata.xattrs = vec![
            Xattr {
                name: b"security.capability".to_vec(),
                value: capability,
            },
            Xattr {
                name: b"security.selinux".to_vec(),
                value: b"system_u:object_r:container_file_t:s0\0".to_vec(),
            },
            Xattr {
                name: b"system.posix_acl_access".to_vec(),
                value: acl,
            },
            Xattr {
                name: b"user.empty".to_vec(),
                value: Vec::new(),
            },
            Xattr {
                name: b"user.raw".to_vec(),
                value: vec![0, 255, 1],
            },
        ];
        metadata.presence.acl_access = true;
        entries.push(metadata);
        if mode == "split" {
            let offset = 28672;
            let length = 2 * 1024 * 1024 * 1024 + 8192;
            pack.set_len(offset + length)?;
            pack.seek(SeekFrom::Start(offset))?;
            pack.write_all(b"BEGIN")?;
            pack.seek(SeekFrom::Start(offset + length - 3))?;
            pack.write_all(b"END")?;
            entries.push(regular(b"large", offset, length));
        }
    }
    for (ordinal, entry) in entries.iter_mut().enumerate() {
        entry.ordinal = ordinal as u64;
    }
    let changeset = LayerChangeset {
        diff_id: ContentDigest::of_bytes(format!("controlled-erofs-fixture:{mode}").as_bytes()),
        pack_length: pack.metadata()?.len(),
        entries,
    };
    let result = layer_result(&changeset, &pack)?;
    let empty_pack = new_file(&directory.join("empty.pack"))?;
    let metadata_only = LayerChangeset {
        diff_id: ContentDigest::of_bytes(b"controlled-erofs-metadata-occurrence"),
        pack_length: 0,
        entries: vec![entry(b"a", EntryKind::Directory)],
    };
    let empty_result = layer_result(&metadata_only, &empty_pack)?;
    let mut layers = vec![Layer {
        result: &result,
        changeset: &changeset,
        pack: &pack,
    }];
    if mode == "many" {
        layers.extend((0..1022).map(|_| Layer {
            result: &empty_result,
            changeset: &metadata_only,
            pack: &empty_pack,
        }));
        layers.push(Layer {
            result: &result,
            changeset: &changeset,
            pack: &pack,
        });
    }
    let recipe = CompositionRecipe::from_layers(oci::Platform::linux_amd64(), &layers)?;
    let mut fsmeta = new_file(&directory.join("fsmeta.erofs"))?;
    let composed = composition::compose(&recipe, &layers, &mut fsmeta)?;
    let mut second = new_file(&directory.join("fsmeta-second.erofs"))?;
    let rebuilt = composition::regenerate_exact(&recipe, &layers, &composed.result, &mut second)?;
    if rebuilt.result != composed.result || rebuilt.map != composed.map {
        return Err("exact regeneration changed composition identity".into());
    }
    let loaded = composition::load_exact(&recipe, &layers, &composed.result, &fsmeta)?;
    if loaded.result != composed.result {
        return Err("exact loading changed composition identity".into());
    }
    let (fsmeta_stream, fsmeta_guard) =
        pool.publish_stream_for_catalog(&directory.join("fsmeta.erofs"))?;
    let (pack_stream, pack_guard) =
        pool.publish_stream_for_catalog(&directory.join("payload.pack"))?;
    let (empty_stream, empty_guard) =
        pool.publish_stream_for_catalog(&directory.join("empty.pack"))?;
    let _guards = [fsmeta_guard, pack_guard, empty_guard];
    let mut occurrences = vec![pool.lower_occurrence(&fsmeta_stream.id)?];
    for layer in &layers {
        let stream = if layer.result.pack_length == 0 {
            empty_stream.id
        } else {
            pack_stream.id
        };
        occurrences.push(pool.lower_occurrence(&stream)?);
    }
    let plan = FlatLowerPlan::new(&occurrences)?.preflight(0)?;
    plan.verify(&pool)?;
    fs::write(directory.join("lower.vmdk"), plan.descriptor()?)?;
    fs::write(directory.join("recipe.json"), recipe.canonical_bytes()?)?;
    fs::write(
        directory.join("result.json"),
        composed.result.canonical_bytes()?,
    )?;
    fs::write(
        directory.join("lower-map.json"),
        composed.map.canonical_bytes()?,
    )?;
    println!(
        "{}",
        serde_json::json!({
            "fixture": mode, "occurrences": layers.len(), "logicalLowerBytes": composed.map.length(),
            "descriptorRecords": plan.record_count(), "fsmetaStream": fsmeta_stream.id.to_string(),
            "lowerStream": composed.map.id().to_string(),
        })
    );
    Ok(())
}
