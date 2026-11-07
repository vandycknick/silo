//! Authenticate ordered pack inputs and bind EROFS composition to the existing
//! logical-stream identity. OCI owns filesystem bytes, not the stream hash ABI.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

use oci::composition::{CompositionRecipe, CompositionResult, PreparedComposition};
use oci::erofs::Layer;
use sha2::{Digest, Sha256};

use crate::storage::identity::StreamId;
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::stream::{StreamHasher, StreamMap};
use crate::storage::StorageError;

pub struct ComposedLower {
    pub result: CompositionResult,
    pub map: StreamMap,
}

/// Inputs must remain leased by the caller through publication. This function
/// authenticates the actual held descriptors, never a path reopened by OCI.
pub fn compose(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    fsmeta: &mut File,
) -> Result<ComposedLower, StorageError> {
    let fingerprints = authenticate_packs(layers)?;
    let prepared = oci::composition::prepare(recipe, layers, fsmeta).map_err(invalid)?;
    finish(prepared, layers, fsmeta, &fingerprints)
}

/// Exact artifacts stay loadable without executing a historical encoder.
pub fn load_exact(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    expected: &CompositionResult,
    fsmeta: &File,
) -> Result<ComposedLower, StorageError> {
    let fingerprints = authenticate_packs(layers)?;
    let prepared =
        oci::composition::load_exact(recipe, layers, expected, fsmeta).map_err(invalid)?;
    finish(prepared, layers, fsmeta, &fingerprints)
}

/// A locally available encoder may regenerate only the exact retained bytes.
/// A mismatch is a refusal, not a replacement lower identity.
pub fn regenerate_exact(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    expected: &CompositionResult,
    fsmeta: &mut File,
) -> Result<ComposedLower, StorageError> {
    let fingerprints = authenticate_packs(layers)?;
    let prepared =
        oci::composition::regenerate_exact(recipe, layers, expected, fsmeta).map_err(invalid)?;
    finish(prepared, layers, fsmeta, &fingerprints)
}

fn authenticate_packs(layers: &[Layer<'_>]) -> Result<Vec<SourceFingerprint>, StorageError> {
    crate::storage::limits::Resource::LayerOccurrences.check(layers.len() as u64)?;
    crate::storage::limits::Resource::LogicalLowerBytes
        .sum(layers.iter().map(|layer| layer.result.pack_length))?;
    let mut verified = BTreeMap::new();
    let mut fingerprints = Vec::with_capacity(layers.len());
    let mut hasher = StreamHasher::new();
    for layer in layers {
        let metadata = layer.pack.metadata()?;
        if !metadata.is_file() || metadata.len() != layer.result.pack_length {
            return Err(invalid(
                "composition pack type or length differs from its result",
            ));
        }
        let fingerprint = SourceFingerprint::new(&metadata);
        let expected = StreamId::from_sha256(*layer.result.pack_stream.as_bytes());
        let fact = (expected, metadata.len(), fingerprint);
        match verified.get(&layer.pack.as_raw_fd()) {
            Some(previous) if previous != &fact => {
                return Err(invalid(
                    "one composition descriptor has conflicting bindings",
                ));
            }
            Some(_) => {}
            None => {
                let scan = hasher.hash_open_file(layer.pack, metadata.len())?;
                if scan.map.id() != expected {
                    return Err(invalid("composition pack stream identity mismatch"));
                }
                recheck(layer.pack, fingerprint)?;
                verified.insert(layer.pack.as_raw_fd(), fact);
            }
        }
        fingerprints.push(fingerprint);
    }
    Ok(fingerprints)
}

fn finish(
    prepared: PreparedComposition,
    layers: &[Layer<'_>],
    fsmeta: &File,
    fingerprints: &[SourceFingerprint],
) -> Result<ComposedLower, StorageError> {
    let metadata = fsmeta.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("composition fsmeta is not a regular file"));
    }
    let fingerprint = SourceFingerprint::new(&metadata);
    crate::storage::limits::Resource::FsmetaBytes.check(metadata.len())?;
    crate::storage::limits::Resource::LogicalLowerBytes.sum(
        std::iter::once(metadata.len()).chain(layers.iter().map(|layer| layer.result.pack_length)),
    )?;
    let mut parts = Vec::with_capacity(layers.len() + 1);
    parts.push((fsmeta, metadata.len()));
    parts.extend(
        layers
            .iter()
            .map(|layer| (layer.pack, layer.result.pack_length)),
    );
    let mut input = Concatenation {
        parts: &parts,
        part: 0,
        offset: 0,
        fsmeta_hash: Sha256::new(),
    };
    let map = StreamHasher::new().hash_reader(&mut input)?;
    recheck(fsmeta, fingerprint)?;
    for (layer, fingerprint) in layers.iter().zip(fingerprints) {
        recheck(layer.pack, *fingerprint)?;
    }
    let result = prepared
        .finalize(oci::changeset::StreamIdentity::from_sha256(
            *map.id().as_bytes(),
        ))
        .map_err(invalid)?;
    if result.lower_length != map.length() {
        return Err(invalid(
            "composition logical length differs from authenticated concatenation",
        ));
    }
    if result.fsmeta.digest
        != oci::changeset::ContentDigest::from_sha256(input.fsmeta_hash.finalize().into())
    {
        return Err(invalid("fsmeta bytes changed after composition validation"));
    }
    Ok(ComposedLower { result, map })
}

fn recheck(file: &File, expected: SourceFingerprint) -> Result<(), StorageError> {
    if SourceFingerprint::new(&file.metadata()?) != expected {
        return Err(invalid("composition input changed during authentication"));
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> StorageError {
    StorageError::InvalidPath(format!("EROFS composition: {error}"))
}

/// Positioned reads preserve every caller's file offset, including repeated
/// occurrences of the same descriptor. Empty packs occupy no logical bytes.
struct Concatenation<'a> {
    parts: &'a [(&'a File, u64)],
    part: usize,
    offset: u64,
    fsmeta_hash: Sha256,
}

impl Read for Concatenation<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while let Some((file, length)) = self.parts.get(self.part) {
            if self.offset == *length {
                self.part += 1;
                self.offset = 0;
                continue;
            }
            let count = usize::try_from((*length - self.offset).min(buffer.len() as u64))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let read = match file.read_at(&mut buffer[..count], self.offset) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "composition input truncated",
                ));
            }
            self.offset += read as u64;
            if self.part == 0 {
                self.fsmeta_hash.update(&buffer[..read]);
            }
            return Ok(read);
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use oci::changeset::index::encode_index_to;
    use oci::changeset::{
        ChangesetLimits, ContentDigest, LayerChangeset, LayerRecipe, LayerResult, StreamIdentity,
    };
    use oci::composition::CompositionRecipe;
    use oci::erofs::Layer;
    use sha2::{Digest, Sha256};

    use crate::storage::composition::{compose, load_exact, Concatenation};
    use crate::storage::stream::StreamHasher;

    #[test]
    fn repeated_parts_cross_stream_chunk_boundaries_without_moving_file_offsets() {
        let mut fsmeta = tempfile::tempfile().unwrap();
        let mut pack = tempfile::tempfile().unwrap();
        let empty = tempfile::tempfile().unwrap();
        let metadata = vec![13; 4096];
        let bytes: Vec<_> = (0..8 * 1024 * 1024 + 17).map(|n| (n % 251) as u8).collect();
        fsmeta.write_all(&metadata).unwrap();
        pack.write_all(&bytes).unwrap();
        fsmeta.seek(SeekFrom::Start(19)).unwrap();
        pack.seek(SeekFrom::Start(31)).unwrap();
        let parts = [
            (&fsmeta, metadata.len() as u64),
            (&empty, 0),
            (&pack, bytes.len() as u64),
            (&pack, bytes.len() as u64),
            (&empty, 0),
        ];
        let mut input = Concatenation {
            parts: &parts,
            part: 0,
            offset: 0,
            fsmeta_hash: Sha256::new(),
        };
        let actual = StreamHasher::new().hash_reader(&mut input).unwrap();
        let expected_bytes = [metadata.as_slice(), bytes.as_slice(), bytes.as_slice()].concat();
        let expected = StreamHasher::new()
            .hash_reader(expected_bytes.as_slice())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(input.fsmeta_hash.finalize(), Sha256::digest(&metadata));
        assert_eq!(fsmeta.stream_position().unwrap(), 19);
        assert_eq!(pack.stream_position().unwrap(), 31);
    }

    #[test]
    fn a_truncated_part_is_not_silently_replaced_by_the_next_occurrence() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"short").unwrap();
        let parts = [(&file, 8), (&file, 5)];
        let mut input = Concatenation {
            parts: &parts,
            part: 0,
            offset: 0,
            fsmeta_hash: Sha256::new(),
        };
        let mut output = Vec::new();
        assert_eq!(
            input.read_to_end(&mut output).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(output, b"short");
    }

    fn empty_layer(file: &File) -> (LayerChangeset, LayerResult) {
        let changeset = LayerChangeset {
            diff_id: ContentDigest::of_bytes(b"empty-layer"),
            pack_length: 0,
            entries: Vec::new(),
        };
        let root = encode_index_to(&changeset, &ChangesetLimits::default(), |_| Ok(())).unwrap();
        let stream = StreamHasher::new()
            .hash_open_file(file, 0)
            .unwrap()
            .map
            .id();
        let result = LayerResult {
            recipe: LayerRecipe {
                diff_id: changeset.diff_id,
            }
            .id()
            .unwrap(),
            pack_stream: StreamIdentity::from_sha256(*stream.as_bytes()),
            pack_length: 0,
            index_root: root.digest,
        };
        (changeset, result)
    }

    #[test]
    fn pack_and_retained_lower_identities_are_authenticated_not_caller_assertions() {
        let pack = tempfile::tempfile().unwrap();
        let (changeset, result) = empty_layer(&pack);
        let layers = [Layer {
            result: &result,
            changeset: &changeset,
            pack: &pack,
        }];
        let recipe = CompositionRecipe::from_layers(oci::Platform::linux_amd64(), &layers).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let composed = compose(&recipe, &layers, &mut fsmeta).unwrap();
        let mut wrong_lower = composed.result.clone();
        wrong_lower.lower_stream = StreamIdentity::from_sha256([7; 32]);
        assert!(load_exact(&recipe, &layers, &wrong_lower, &fsmeta).is_err());
        let mut wrong_pack = result;
        wrong_pack.pack_stream = StreamIdentity::from_sha256([9; 32]);
        let layers = [Layer {
            result: &wrong_pack,
            changeset: &changeset,
            pack: &pack,
        }];
        let recipe = CompositionRecipe::from_layers(oci::Platform::linux_amd64(), &layers).unwrap();
        fsmeta.write_all_at(b"preserve", 0).unwrap();
        assert!(compose(&recipe, &layers, &mut fsmeta).is_err());
        let mut unchanged = [0; 8];
        fsmeta.read_exact_at(&mut unchanged, 0).unwrap();
        assert_eq!(&unchanged, b"preserve");
    }
}
