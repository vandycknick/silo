//! Identity admission from decoded transport buffers, independent of payload geometry.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use vm_spec::capture::Sha256Digest;
use vm_spec::stream_map::{build_sorted, Chunk, MapError, PresentChunk, StreamRole, StreamRoot};

use crate::image::transport::blobs::{create_private_file, invalid};
use crate::paths::OwnedDirectory;
use crate::storage::map::{AuthenticatedMap, MapNodeWriter};
use crate::LibVmError;

/// Only nonzero identities are spooled. Payload bytes are never reread to build a map.
pub(crate) struct IdentityBuilder {
    root: StreamRoot,
    role: StreamRole,
    records: File,
    offset: u64,
    count: u64,
}

impl IdentityBuilder {
    pub(crate) fn new(
        directory: &OwnedDirectory,
        length: u64,
        role: StreamRole,
    ) -> Result<Self, LibVmError> {
        let name = format!("identity-{}", uuid::Uuid::new_v4());
        let records = create_private_file(directory, &name)?;
        directory.remove_tree(&name)?;
        let root = StreamRoot::empty(length, role.chunk_size())
            .map_err(|error| invalid("stream identity", error))?;
        root.validate_role(role)
            .map_err(|error| invalid("stream identity", error))?;
        Ok(Self {
            root,
            role,
            records,
            offset: 0,
            count: 0,
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), LibVmError> {
        let unit = self.root.chunk_size().bytes();
        let end = self.checked_end(bytes.len() as u64)?;
        if !vm_spec::capture::is_all_zero(bytes) {
            for (slot, bytes) in bytes.chunks(unit as usize).enumerate() {
                let index = self.offset / unit + slot as u64;
                if let Chunk::Data(digest) = self
                    .root
                    .classify_chunk(index, bytes)
                    .map_err(|error| invalid("stream identity", error))?
                {
                    self.records.write_all(&index.to_le_bytes())?;
                    self.records.write_all(digest.as_bytes())?;
                    self.count += 1;
                }
            }
        }
        self.offset = end;
        Ok(())
    }

    /// Advance over already authenticated zero coverage without reading holes.
    pub(crate) fn push_zeros(&mut self, length: u64) -> Result<(), LibVmError> {
        self.offset = self.checked_end(length)?;
        Ok(())
    }

    fn checked_end(&self, length: u64) -> Result<u64, LibVmError> {
        let unit = self.root.chunk_size().bytes();
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid("stream identity", "decoded offset overflow"))?;
        if !self.offset.is_multiple_of(unit)
            || end > self.root.length()
            || (end != self.root.length() && !length.is_multiple_of(unit))
        {
            return Err(invalid(
                "stream identity",
                "unaligned or out-of-range decoded payload",
            ));
        }
        Ok(end)
    }

    pub(crate) fn finish(mut self) -> Result<AuthenticatedMap, LibVmError> {
        if self.offset != self.root.length() {
            return Err(invalid("stream identity", "incomplete decoded stream"));
        }
        self.records.seek(SeekFrom::Start(0))?;
        let entries = (0..self.count).map(|_| {
            let mut index = [0; 8];
            let mut digest = [0; 32];
            self.records.read_exact(&mut index)?;
            self.records.read_exact(&mut digest)?;
            Ok::<_, MapError>(PresentChunk {
                index: u64::from_le_bytes(index),
                digest: Sha256Digest::from_bytes(digest),
            })
        });
        let mut nodes = MapNodeWriter::new()?;
        let root = build_sorted(
            self.root.length(),
            self.root.chunk_size(),
            entries,
            &mut nodes,
        )
        .map_err(|error| invalid("stream identity", error))?;
        Ok(nodes.finish(root, self.role, None)?.into_map())
    }
}

/// Authenticate one 8 MiB transport range against the root's identity profile.
pub(crate) fn verify_payload(
    map: &AuthenticatedMap,
    payload_index: u64,
    bytes: &[u8],
) -> Result<(), LibVmError> {
    let payload_size = oci::vm_artifact::wire::CHUNK_SIZE;
    let offset = payload_index
        .checked_mul(payload_size)
        .filter(|offset| *offset < map.length())
        .ok_or_else(|| invalid("stream identity", "payload index outside stream"))?;
    let expected = (map.length() - offset).min(payload_size);
    if bytes.len() as u64 != expected {
        return Err(invalid(
            "stream identity",
            "decoded payload length mismatch",
        ));
    }
    let unit = map.chunk_size().bytes();
    let mut nodes = map.node_source();
    let mut present = map.root().present_chunks_from(offset / unit, &mut nodes);
    let mut next = present
        .next()
        .transpose()
        .map_err(|error| invalid("stream identity", error))?;
    for (slot, chunk) in bytes.chunks(unit as usize).enumerate() {
        let index = offset / unit + slot as u64;
        let expected = match next {
            Some(entry) if entry.index == index => {
                next = present
                    .next()
                    .transpose()
                    .map_err(|error| invalid("stream identity", error))?;
                Chunk::Data(entry.digest)
            }
            _ => Chunk::Zero,
        };
        map.root()
            .verify_chunk(index, expected, chunk)
            .map_err(|error| invalid("stream identity", error))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use oci::vm_artifact::codec::{ChunkEncoder, ChunkEncoding};
    use oci::vm_artifact::wire::{ChunkEntry, CHUNK_SIZE};
    use vm_spec::stream_map::{ChunkSize, StreamRole};

    use crate::image::transport::identity::{verify_payload, IdentityBuilder};
    use crate::paths::OwnedDirectory;
    use crate::storage::stream::StreamHasher;

    #[test]
    fn scattered_ram_pages_transfer_payloads_not_identity_objects() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(temporary.path()).unwrap();
        let mut bytes = vec![0; (3 * CHUNK_SIZE) as usize];
        for offset in [65536 + 4096, 2 * CHUNK_SIZE as usize + 17 * 65536 + 8192] {
            bytes[offset..offset + 4096].fill(42);
        }
        let mut builder =
            IdentityBuilder::new(&directory, bytes.len() as u64, StreamRole::Ram).unwrap();
        let mut encoder = ChunkEncoder::new(ChunkEncoding::Zstd).unwrap();
        let mut transferred = Vec::new();
        for (index, payload) in bytes.chunks(CHUNK_SIZE as usize).enumerate() {
            builder.push(payload).unwrap();
            if let ChunkEntry::Data { .. } = encoder.encode(payload).unwrap().entry {
                transferred.push(index);
            }
        }
        let map = builder.finish().unwrap();
        assert_eq!(transferred, [0, 2]);
        assert_eq!(
            map.present_chunks()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            2
        );
        let full = StreamHasher::new(ChunkSize::RAM)
            .hash_reader(&bytes[..])
            .unwrap();
        assert_eq!(map.id(), full.id());
        for (index, payload) in bytes.chunks(CHUNK_SIZE as usize).enumerate() {
            verify_payload(&map, index as u64, payload).unwrap();
        }
        let mut corrupted_zero_payload = vec![0; CHUNK_SIZE as usize];
        corrupted_zero_payload[4096] = 1;
        assert!(verify_payload(&map, 1, &corrupted_zero_payload).is_err());
        assert!(verify_payload(&map, 0, &[0]).is_err());
        assert!(verify_payload(&map, 3, &[]).is_err());
    }

    #[test]
    fn repeated_payloads_keep_distinct_ram_leaves_and_one_encoded_object() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(temporary.path()).unwrap();
        let mut payload = vec![0; CHUNK_SIZE as usize];
        for index in 1..128 {
            let offset = index * 65536;
            payload[offset..offset + 4096].fill(index as u8);
        }
        for encoding in [ChunkEncoding::Raw, ChunkEncoding::Zstd] {
            let mut encoder = ChunkEncoder::new(encoding).unwrap();
            let mut builder =
                IdentityBuilder::new(&directory, 2 * CHUNK_SIZE + 3, StreamRole::Ram).unwrap();
            let mut objects = std::collections::BTreeSet::new();
            for bytes in [&payload[..], &payload[..], &[1, 0, 2][..]] {
                builder.push(bytes).unwrap();
                if let ChunkEntry::Data { encoded, .. } = encoder.encode(bytes).unwrap().entry {
                    objects.insert(encoded.digest);
                }
            }
            let map = builder.finish().unwrap();
            assert_eq!(objects.len(), 2);
            assert_eq!(
                map.present_chunks()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                255
            );
            verify_payload(&map, 0, &payload).unwrap();
            verify_payload(&map, 1, &payload).unwrap();
            verify_payload(&map, 2, &[1, 0, 2]).unwrap();
            let bytes = payload
                .iter()
                .chain(&payload)
                .copied()
                .chain([1, 0, 2])
                .collect::<Vec<_>>();
            assert_eq!(
                map.id(),
                StreamHasher::new(ChunkSize::RAM)
                    .hash_reader(&bytes[..])
                    .unwrap()
                    .id()
            );
        }
    }

    #[test]
    fn zero_tail_empty_and_incomplete_streams_keep_exact_geometry() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(temporary.path()).unwrap();
        for role in [StreamRole::Ram, StreamRole::Disk] {
            let empty = IdentityBuilder::new(&directory, 0, role)
                .unwrap()
                .finish()
                .unwrap();
            assert_eq!(empty.length(), 0);
            assert!(empty.root().tree_digest().is_none());
            let mut zero = IdentityBuilder::new(&directory, 17, role).unwrap();
            zero.push_zeros(17).unwrap();
            let zero = zero.finish().unwrap();
            assert_ne!(empty.id(), zero.id());
            assert!(zero.root().tree_digest().is_none());
            verify_payload(&zero, 0, &[0; 17]).unwrap();
            assert!(IdentityBuilder::new(&directory, 17, role)
                .unwrap()
                .finish()
                .is_err());
            let mut incomplete =
                IdentityBuilder::new(&directory, role.chunk_size().bytes() + 1, role).unwrap();
            assert!(incomplete.push(&[1; 17]).is_err());
            assert!(incomplete.push_zeros(17).is_err());
        }
    }
}
