//! Chunk geometry and verified chunk reads shared by both participants.
use std::collections::HashMap;
use std::fs::File;

use crate::storage::identity::ObjectDigest;
use crate::storage::limits::CHUNK_SIZE;
use crate::storage::stream::{Chunk, StreamMap};
use crate::LibVmError;

/// `(offset, length, chunk)` for every canonical range of `map`.
pub(crate) fn extents(map: &StreamMap) -> impl Iterator<Item = (u64, u64, Chunk)> + '_ {
    let total = map.length();
    map.chunks().iter().enumerate().map(move |(index, chunk)| {
        let offset = index as u64 * CHUNK_SIZE as u64;
        (offset, (total - offset).min(CHUNK_SIZE as u64), *chunk)
    })
}

/// Read one chunk and return it only when its bytes hash to `digest`.
pub(crate) fn read_verified(
    file: &File,
    offset: u64,
    length: u64,
    digest: &ObjectDigest,
) -> Result<Option<Vec<u8>>, LibVmError> {
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= CHUNK_SIZE)
        .ok_or_else(|| crate::handoff::plan::invalid("chunk length exceeds its bound"))?;
    let mut bytes = vec![0; length];
    crate::handoff::files::read_exact_at(file, &mut bytes, offset)?;
    Ok((ObjectDigest::of_bytes(&bytes) == *digest).then_some(bytes))
}

/// Where one decoded chunk can be read inside a set of local files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkPlace {
    pub(crate) file: usize,
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

/// First occurrence of every nonzero chunk across indexed files.
#[derive(Debug, Default)]
pub(crate) struct ChunkIndex {
    places: HashMap<ObjectDigest, ChunkPlace>,
}

impl ChunkIndex {
    pub(crate) fn add(&mut self, file: usize, map: &StreamMap) {
        for (offset, length, chunk) in extents(map) {
            if let Chunk::Data(digest) = chunk {
                self.places.entry(digest).or_insert(ChunkPlace {
                    file,
                    offset,
                    length,
                });
            }
        }
    }

    pub(crate) fn get(&self, digest: &ObjectDigest, length: u64) -> Option<ChunkPlace> {
        self.places
            .get(digest)
            .copied()
            .filter(|place| place.length == length)
    }
}
