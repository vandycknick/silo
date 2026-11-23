use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vm_spec::capture::{
    CaptureRamChange, CaptureRamChanges, CaptureRamCoverage, RamChangeReader, Sha256Digest,
};
use vm_spec::stream_map::{
    build_sorted, Chunk, ChunkChange, ChunkSize, MapError, NodeSink, NodeSource, PresentChunk,
    StreamRole, StreamRoot, MAX_NODE_BYTES, MAX_ROOT_BYTES,
};

/// One retained store for the native proof session, shared by every capture.
/// Releasing a capture never removes nodes inherited by a later root.
#[derive(Clone)]
pub(crate) struct DirectoryNodes {
    directory: PathBuf,
}

impl DirectoryNodes {
    pub(crate) fn new(directory: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path(&self, digest: Sha256Digest) -> PathBuf {
        self.directory
            .join(digest.to_string().trim_start_matches("sha256:"))
    }

    pub(crate) fn root(&self, digest: Sha256Digest) -> eyre::Result<StreamRoot> {
        let root = read_root(&File::open(self.path(digest))?)?;
        eyre::ensure!(root.id() == digest, "retained root digest mismatch");
        Ok(root)
    }

    pub(crate) fn retain_root(&mut self, root: &StreamRoot) -> eyre::Result<()> {
        self.write_node(&root.canonical_bytes()?)?;
        Ok(())
    }
}

impl NodeSource for DirectoryNodes {
    fn read_node(
        &mut self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        let mut file = File::open(self.path(digest))?;
        let length =
            usize::try_from(file.metadata()?.len()).map_err(|_| MapError::ArithmeticOverflow)?;
        if length > output.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized map node").into());
        }
        file.read_exact(&mut output[..length])?;
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "map node grew").into());
        }
        Ok(length)
    }
}

impl NodeSink for DirectoryNodes {
    fn write_node(&mut self, bytes: &[u8]) -> Result<Sha256Digest, MapError> {
        let digest = Sha256Digest::of_bytes(bytes);
        let path = self.path(digest);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
        {
            Ok(mut output) => {
                let result = output.write_all(bytes).and_then(|()| output.sync_all());
                drop(output);
                if let Err(error) = result {
                    std::fs::remove_file(path)?;
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut scratch = [0; MAX_NODE_BYTES];
                let length = self.read_node(digest, &mut scratch)?;
                if &scratch[..length] != bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "existing map object differs",
                    )
                    .into());
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(digest)
    }
}

pub(crate) fn read_root(file: &File) -> eyre::Result<StreamRoot> {
    let length = usize::try_from(file.metadata()?.len())?;
    eyre::ensure!(length <= MAX_ROOT_BYTES, "RAM root bound");
    let mut bytes = [0; MAX_ROOT_BYTES];
    std::os::unix::fs::FileExt::read_exact_at(file, &mut bytes[..length], 0)?;
    let root = StreamRoot::decode(&bytes[..length])?;
    root.validate_role(StreamRole::Ram)?;
    Ok(root)
}

pub(crate) fn assemble(
    directory: &Path,
    length: u64,
    summary: &CaptureRamChanges,
    nodes: &mut DirectoryNodes,
) -> eyre::Result<StreamRoot> {
    let reader = RamChangeReader::new(
        File::open(directory.join(vm_spec::capture::CAPTURE_RAM_CHANGES_FILE))?,
        length,
        summary,
    )?;
    let root = match summary.coverage {
        CaptureRamCoverage::Full => build_sorted(
            length,
            ChunkSize::RAM,
            reader.map(|record| match record? {
                CaptureRamChange::Data { index, digest } => Ok(PresentChunk { index, digest }),
                CaptureRamChange::Zero { .. } => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "full changes must omit zero records",
                )
                .into()),
            }),
            nodes,
        )?,
        CaptureRamCoverage::Incremental => {
            let baseline = summary
                .baseline_stream
                .ok_or_else(|| eyre::eyre!("incremental root missing"))?;
            let baseline = nodes.root(baseline)?;
            eyre::ensure!(
                baseline.length() == length,
                "incremental RAM length changed"
            );
            let changes = ExpandedChanges {
                reader,
                pending: 0..0,
            };
            baseline.update_sorted(changes, &mut nodes.clone(), nodes)?
        }
    };
    nodes.retain_root(&root)?;
    Ok(root)
}

struct ExpandedChanges<R> {
    reader: RamChangeReader<R>,
    pending: std::ops::Range<u64>,
}

impl<R: Read> Iterator for ExpandedChanges<R> {
    type Item = Result<ChunkChange, MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(index) = self.pending.next() {
            return Some(Ok(ChunkChange {
                index,
                value: Chunk::Zero,
            }));
        }
        match self.reader.next()? {
            Ok(CaptureRamChange::Data { index, digest }) => Some(Ok(ChunkChange {
                index,
                value: Chunk::Data(digest),
            })),
            Ok(CaptureRamChange::Zero { first_index, count }) => {
                // The shared reader checks bounds and overflow before yielding.
                self.pending = first_index..first_index + count;
                self.next()
            }
            Err(error) => Some(Err(error.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::native_stream_map::{assemble, read_root, DirectoryNodes};
    use vm_spec::capture::{
        CaptureRamChanges, CaptureRamCoverage, Sha256Digest, CAPTURE_RAM_CHANGES_FILE,
    };
    use vm_spec::stream_map::{build_sorted, Chunk, ChunkChange, ChunkSize, PresentChunk};

    #[test]
    fn retained_directory_nodes_support_incremental_zero_and_corruption() {
        let directory =
            std::env::temp_dir().join(format!("silo-native-map-{}", uuid::Uuid::new_v4()));
        let mut nodes = DirectoryNodes::new(directory.clone()).unwrap();
        let data = vec![7; ChunkSize::RAM.bytes() as usize];
        let digest = Sha256Digest::of_bytes(&data);
        let root = build_sorted(
            2 * ChunkSize::RAM.bytes(),
            ChunkSize::RAM,
            [Ok(PresentChunk { index: 1, digest })],
            &mut nodes,
        )
        .unwrap();
        nodes.retain_root(&root).unwrap();
        let reopened = nodes.root(root.id()).unwrap();
        assert_eq!(
            read_root(&std::fs::File::open(nodes.path(root.id())).unwrap()).unwrap(),
            root
        );
        let entries = reopened
            .present_chunks(&mut nodes)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries, vec![PresentChunk { index: 1, digest }]);
        root.verify_chunk(1, Chunk::Data(digest), &data).unwrap();
        let zero = root
            .update_sorted(
                [Ok(ChunkChange {
                    index: 1,
                    value: Chunk::Zero,
                })],
                &mut nodes.clone(),
                &mut nodes,
            )
            .unwrap();
        assert_eq!(zero.tree_digest(), None);
        assert_eq!(nodes.root(root.id()).unwrap(), root);
        let path = nodes.path(root.tree_digest().unwrap());
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        std::fs::write(path, b"corrupt").unwrap();
        assert!(root.present_chunks(&mut nodes).next().unwrap().is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_change_files_build_update_reuse_and_authenticate_roots() {
        let directory =
            std::env::temp_dir().join(format!("silo-native-changes-{}", uuid::Uuid::new_v4()));
        let mut nodes = DirectoryNodes::new(directory.join("nodes")).unwrap();
        let length = 3 * ChunkSize::RAM.bytes();
        let digest = Sha256Digest::of_bytes(b"admitted native data");
        let mut bytes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0".to_vec();
        let mut record = [0; 56];
        record[..8].copy_from_slice(&1u64.to_le_bytes());
        record[8..16].copy_from_slice(&1u64.to_le_bytes());
        record[16] = 1;
        record[24..].copy_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&record);
        let path = directory.join(CAPTURE_RAM_CHANGES_FILE);
        std::fs::write(&path, &bytes).unwrap();
        let mut summary = CaptureRamChanges {
            byte_len: bytes.len() as u64,
            sha256: Sha256Digest::of_bytes(&bytes),
            record_count: 1,
            coverage: CaptureRamCoverage::Full,
            baseline_stream: None,
        };
        let root = assemble(&directory, length, &summary, &mut nodes).unwrap();
        assert_eq!(root.lookup(1, &mut nodes).unwrap(), Chunk::Data(digest));

        bytes.truncate(16);
        bytes[11] = 1;
        summary.coverage = CaptureRamCoverage::Incremental;
        summary.baseline_stream = Some(root.id());
        summary.record_count = 0;
        summary.byte_len = bytes.len() as u64;
        summary.sha256 = Sha256Digest::of_bytes(&bytes);
        std::fs::write(&path, &bytes).unwrap();
        let before = std::fs::read_dir(directory.join("nodes")).unwrap().count();
        assert_eq!(
            assemble(&directory, length, &summary, &mut nodes).unwrap(),
            root
        );
        assert_eq!(
            std::fs::read_dir(directory.join("nodes")).unwrap().count(),
            before
        );

        record.fill(0);
        record[8..16].copy_from_slice(&3u64.to_le_bytes());
        bytes.extend_from_slice(&record);
        summary.record_count = 1;
        summary.byte_len = bytes.len() as u64;
        summary.sha256 = Sha256Digest::of_bytes(&bytes);
        std::fs::write(&path, &bytes).unwrap();
        let zero = assemble(&directory, length, &summary, &mut nodes).unwrap();
        assert_eq!(zero.tree_digest(), None);
        assert_eq!(nodes.root(root.id()).unwrap(), root);

        summary.sha256 = Sha256Digest::of_bytes(b"wrong change receipt");
        assert!(assemble(&directory, length, &summary, &mut nodes).is_err());
        summary.sha256 = Sha256Digest::of_bytes(&bytes);
        bytes.push(0);
        std::fs::write(&path, bytes).unwrap();
        assert!(assemble(&directory, length, &summary, &mut nodes).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
