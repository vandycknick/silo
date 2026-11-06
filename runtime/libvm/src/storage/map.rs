//! Bounded persisted maps. Page boundaries never participate in stream identity.
use serde::{Deserialize, Serialize};

use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::limits::{Resource, CHUNK_SIZE};
use crate::storage::pool::StoragePool;
use crate::storage::stream::StreamMap;
use crate::storage::StorageError;

pub const MAP_PAGE_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamMapRoot {
    pub schema: u32,
    pub kind: String,
    pub stream: StreamId,
    pub length: u64,
    pub pages: Vec<ObjectDigest>,
}

impl StreamMapRoot {
    pub fn new(map: &StreamMap, pages: Vec<ObjectDigest>) -> Result<Self, StorageError> {
        let root = Self {
            schema: 1,
            kind: "stream-map".into(),
            stream: map.id(),
            length: map.length(),
            pages,
        };
        root.validate()?;
        Ok(root)
    }

    fn validate(&self) -> Result<(), StorageError> {
        Resource::ArtifactStreamBytes.check(self.length)?;
        let expected = self
            .length
            .div_ceil(CHUNK_SIZE as u64)
            .div_ceil(MAP_PAGE_ENTRIES as u64);
        if self.schema != 1 || self.kind != "stream-map" || self.pages.len() as u64 != expected {
            return Err(invalid("invalid stream map root schema or page count"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| invalid(error.to_string()))?;
        Resource::MetadataPageBytes.check(bytes.len() as u64)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        Resource::MetadataPageBytes.check(bytes.len() as u64)?;
        let root: Self =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        root.validate()?;
        Ok(root)
    }

    pub fn read_map(&self, pool: &StoragePool) -> Result<StreamMap, StorageError> {
        self.validate()?;
        let count = self.length.div_ceil(CHUNK_SIZE as u64) as usize;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(count)
            .map_err(|error| invalid(error.to_string()))?;
        let mut remaining = self.length;
        for digest in &self.pages {
            let length = remaining.min(MAP_PAGE_ENTRIES as u64 * CHUNK_SIZE as u64);
            let bytes = pool.read_object(digest, Resource::MetadataPageBytes.maximum())?;
            let page = StreamMap::decode(&bytes)?;
            if page.length() != length
                || page.chunks().len() > MAP_PAGE_ENTRIES
                || page.canonical_bytes()? != bytes
            {
                return Err(invalid(
                    "stream map page length or canonical encoding mismatch",
                ));
            }
            chunks.extend_from_slice(page.chunks());
            remaining -= length;
        }
        let map = StreamMap::new(self.length, chunks)?;
        if map.id() != self.stream {
            return Err(invalid("paged stream map identity mismatch"));
        }
        Ok(map)
    }
}

pub fn pages(map: &StreamMap) -> impl Iterator<Item = Result<Vec<u8>, StorageError>> + '_ {
    map.chunks()
        .chunks(MAP_PAGE_ENTRIES)
        .enumerate()
        .map(|(index, chunks)| {
            let offset = index as u64 * MAP_PAGE_ENTRIES as u64 * CHUNK_SIZE as u64;
            StreamMap::new(
                (map.length() - offset).min(MAP_PAGE_ENTRIES as u64 * CHUNK_SIZE as u64),
                chunks.to_vec(),
            )?
            .canonical_bytes()
        })
}

fn invalid(message: impl Into<String>) -> StorageError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

#[cfg(test)]
mod tests {
    use crate::storage::identity::ObjectDigest;
    use crate::storage::limits::CHUNK_SIZE;
    use crate::storage::map::{pages, StreamMapRoot, MAP_PAGE_ENTRIES};
    use crate::storage::stream::{Chunk, StreamMap};

    #[test]
    fn checkpoint_map_pages_preserve_one_tib_nonzero_identity() {
        let chunks = vec![Chunk::Data(ObjectDigest::of_bytes(b"nonzero")); 131072];
        let map = StreamMap::new(1024u64.pow(4), chunks).unwrap();
        assert!(map.canonical_bytes().unwrap().len() > 4 * 1024 * 1024);
        let mut recovered = Vec::new();
        let mut digests = Vec::new();
        for bytes in pages(&map) {
            let bytes = bytes.unwrap();
            assert!(bytes.len() < 4 * 1024 * 1024);
            let page = StreamMap::decode(&bytes).unwrap();
            assert!(page.chunks().len() <= MAP_PAGE_ENTRIES);
            recovered.extend_from_slice(page.chunks());
            digests.push(ObjectDigest::of_bytes(&bytes));
        }
        assert_eq!(
            StreamMap::new(map.length(), recovered).unwrap().id(),
            map.id()
        );
        let root = StreamMapRoot::new(&map, digests).unwrap();
        assert_eq!(
            StreamMapRoot::decode(&root.encode().unwrap()).unwrap(),
            root
        );
    }

    #[test]
    fn checkpoint_map_empty_partial_and_page_count_are_exact() {
        for count in [0, 1, MAP_PAGE_ENTRIES, MAP_PAGE_ENTRIES + 1] {
            let length = count as u64 * CHUNK_SIZE as u64;
            let map = StreamMap::new(length, vec![Chunk::Zero; count]).unwrap();
            let digests = pages(&map)
                .map(|page| ObjectDigest::of_bytes(&page.unwrap()))
                .collect();
            let mut root = StreamMapRoot::new(&map, digests).unwrap();
            assert!(root.encode().is_ok());
            root.pages.push(ObjectDigest::of_bytes(b"extra"));
            assert!(root.encode().is_err());
        }
    }
}
