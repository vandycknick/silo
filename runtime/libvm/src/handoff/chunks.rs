//! Sparse root differences and bounded decoded payload reads.
use std::collections::BTreeSet;
use std::fs::File;

use crate::storage::limits::CHUNK_SIZE;
use crate::storage::map::AuthenticatedMap;
use crate::LibVmError;
use vm_spec::stream_map::{diff, Chunk, StreamRoot};

/// Changed nonzero payloads only. Equal subtrees are never visited by the codec.
pub(crate) fn changed_payloads(
    before: Option<&AuthenticatedMap>,
    after: &AuthenticatedMap,
) -> Result<BTreeSet<u64>, LibVmError> {
    let empty = StreamRoot::empty(after.length(), after.chunk_size())
        .map_err(crate::handoff::plan::invalid)?;
    let before_root = before.map_or(&empty, AuthenticatedMap::root);
    let mut before_source = before.unwrap_or(after).node_source();
    let mut after_source = after.node_source();
    let changes = diff(
        before_root,
        after.root(),
        &mut before_source,
        &mut after_source,
    )
    .map_err(crate::handoff::plan::invalid)?;
    let mut payloads = BTreeSet::new();
    for change in changes {
        let change = change.map_err(crate::handoff::plan::invalid)?;
        if change.index < after.root().chunk_count() {
            payloads.insert(change.index * after.chunk_size().bytes() / CHUNK_SIZE as u64);
        }
    }
    let mut nonzero = BTreeSet::new();
    for index in payloads {
        let first = index * CHUNK_SIZE as u64 / after.chunk_size().bytes();
        let end = ((index + 1) * CHUNK_SIZE as u64)
            .min(after.length())
            .div_ceil(after.chunk_size().bytes());
        for unit in first..end {
            if matches!(after.lookup(unit)?, Chunk::Data(_)) {
                nonzero.insert(index);
                break;
            }
        }
    }
    Ok(nonzero)
}

pub(crate) fn payload_length(map: &AuthenticatedMap, index: u64) -> Result<u64, LibVmError> {
    let offset = index
        .checked_mul(CHUNK_SIZE as u64)
        .filter(|offset| *offset < map.length())
        .ok_or_else(|| crate::handoff::plan::invalid("payload index outside agreed stream"))?;
    Ok((map.length() - offset).min(CHUNK_SIZE as u64))
}

pub(crate) fn read_payload(
    file: &File,
    map: &AuthenticatedMap,
    index: u64,
) -> Result<Vec<u8>, LibVmError> {
    let length = payload_length(map, index)?;
    let mut bytes = vec![0; length as usize];
    crate::handoff::files::read_exact_at(file, &mut bytes, index * CHUNK_SIZE as u64)?;
    crate::image::transport::identity::verify_payload(map, index, &bytes)?;
    Ok(bytes)
}

/// Authenticate one root-relative node path, never enumerate unrelated subtrees.
pub(crate) fn read_node(
    map: &AuthenticatedMap,
    expected: crate::ObjectDigest,
    height: crate::handoff::plan::MapNodeHeight,
    first_index: crate::handoff::plan::MapNodeIndex,
) -> Result<Vec<u8>, LibVmError> {
    use vm_spec::stream_map::{NodeSource, StreamNode, MAX_NODE_BYTES, ROOT_HEIGHT};
    let first = first_index.get();
    if first >= map.root().chunk_count() || !first.is_multiple_of(height.span()) {
        return Err(crate::handoff::plan::invalid(
            "map node position is outside or unaligned with the agreed stream",
        ));
    }
    let mut source = map.node_source();
    let mut digest = map.root().tree_digest();
    for current in (height.get()..=ROOT_HEIGHT).rev() {
        let digest_value = digest.ok_or_else(|| {
            crate::handoff::plan::invalid("requested node lies in an implicit-zero subtree")
        })?;
        let mut output = [0; MAX_NODE_BYTES];
        let length = source
            .read_node(digest_value, &mut output)
            .map_err(crate::handoff::plan::invalid)?;
        if vm_spec::capture::Sha256Digest::of_bytes(&output[..length]) != digest_value {
            return Err(crate::handoff::plan::invalid(
                "corrupt source map node: digest mismatch",
            ));
        }
        let node = StreamNode::decode(&output[..length], current)
            .map_err(crate::handoff::plan::invalid)?;
        if current == height.get() {
            if digest_value.as_bytes() != expected.as_bytes() {
                return Err(crate::handoff::plan::invalid(
                    "map node digest is not on the requested path of the agreed stream",
                ));
            }
            return Ok(output[..length].to_vec());
        }
        let slot = ((first >> (6 * u32::from(current))) & 63) as u8;
        digest = node.entry(slot);
    }
    Err(crate::handoff::plan::invalid(
        "requested map node path is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use crate::handoff::chunks::read_node;
    use crate::handoff::plan::{MapNodeHeight, MapNodeIndex};
    use crate::storage::identity::ObjectDigest;
    use crate::storage::map::{AuthenticatedMap, MapAuthority};
    use crate::storage::pool::StoragePool;
    use crate::storage::stream::StreamHasher;
    use std::os::unix::fs::FileExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use vm_spec::capture::Sha256Digest;
    use vm_spec::stream_map::{
        ChunkSize, MapError, NodeSource, StreamNode, StreamRole, MAX_NODE_BYTES, TREE_DEPTH,
    };

    struct CountReads {
        authority: Arc<dyn MapAuthority>,
        reads: Arc<AtomicUsize>,
    }
    impl MapAuthority for CountReads {
        fn read_node(
            &self,
            digest: Sha256Digest,
            output: &mut [u8; MAX_NODE_BYTES],
        ) -> Result<usize, MapError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.authority.read_node(digest, output)
        }
    }

    #[test]
    fn node_requests_authenticate_only_the_named_root_path() {
        let home = tempfile::tempdir().unwrap();
        let pool = StoragePool::open(&home.path().join("images")).unwrap();
        let file = tempfile::tempfile().unwrap();
        file.set_len(1 << 40).unwrap();
        // Different leaf pages and remote branches, backed by real sparse bytes.
        for (index, value) in [
            (0, 0x51),
            (64, 0x72),
            ((1u64 << 40) / ChunkSize::DISK.bytes() - 1, 0x39),
        ] {
            file.write_all_at(&[value; 4096], index * ChunkSize::DISK.bytes())
                .unwrap();
        }
        let map = StreamHasher::new(ChunkSize::DISK)
            .hash_open_file(&file, 1 << 40)
            .unwrap()
            .map;
        let (_, roots) = pool.publish_map_for_catalog(&map).unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let authority = Arc::new(CountReads {
            authority: pool.map_authority(Arc::new(roots)).unwrap(),
            reads: reads.clone(),
        });
        let retained =
            AuthenticatedMap::from_root(*map.root(), StreamRole::Disk, authority).unwrap();
        let mut digest = map.root().tree_digest().unwrap();
        for height in (0..TREE_DEPTH).rev() {
            let expected = ObjectDigest::from_sha256(*digest.as_bytes());
            reads.store(0, Ordering::Relaxed);
            let bytes = read_node(
                &retained,
                expected,
                MapNodeHeight::new(height).unwrap(),
                MapNodeIndex::new(0).unwrap(),
            )
            .unwrap();
            assert_eq!(ObjectDigest::of_bytes(&bytes), expected);
            assert_eq!(
                reads.load(Ordering::Relaxed),
                usize::from(TREE_DEPTH - height)
            );
            if height > 0 {
                digest = StreamNode::decode(&bytes, height)
                    .unwrap()
                    .entry(0)
                    .unwrap();
            }
        }
        let leaf = ObjectDigest::from_sha256(*digest.as_bytes());
        assert!(read_node(
            &retained,
            leaf,
            MapNodeHeight::new(0).unwrap(),
            MapNodeIndex::new(64).unwrap()
        )
        .is_err());
        reads.store(0, Ordering::Relaxed);
        assert!(read_node(
            &retained,
            leaf,
            MapNodeHeight::new(1).unwrap(),
            MapNodeIndex::new(1).unwrap()
        )
        .is_err());
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        assert!(read_node(
            &retained,
            leaf,
            MapNodeHeight::new(0).unwrap(),
            MapNodeIndex::new(map.root().chunk_count()).unwrap()
        )
        .is_err());
        assert!(MapNodeHeight::new(TREE_DEPTH).is_err());
        assert!(MapNodeIndex::new(vm_spec::stream_map::MAX_INDICES).is_err());

        let mut source = retained.node_source();
        let mut output = [0; MAX_NODE_BYTES];
        assert!(source
            .read_node(Sha256Digest::from_bytes([0x91; 32]), &mut output)
            .is_err());
    }
}
