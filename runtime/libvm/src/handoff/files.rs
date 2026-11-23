//! Durable per-operation documents, binary root headers and staged map nodes.
//!
//! ```text
//! <home>/handoff/<operation>/
//!     operation.lock stable cross-process transition lock (never removed)
//!     plan        canonical approved plan (both roles)
//!     manifest    canonical capture manifest (once bound or offered)
//!     cleanup     destination replaced-generation cleanup authority
//!     maps/<hex>  binary stream-map v1 root header
//!     nodes/<hex> authenticated canonical map node objects
//!     staging/    incomplete payload writes; never authoritative
//! ```
//!
//! Documents survive daemon restarts independently of pool collection, so
//! recovery can always reread the exact plan an operation was bound to.
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::handoff::plan::{invalid, SealedDocument, MAX_DOCUMENT_BYTES};
use crate::handoff::types::{HandoffError, OperationId};
use crate::paths::OwnedDirectory;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::map::{AuthenticatedMap, MapAuthority};
use crate::storage::pool::StoragePool;
use crate::LibVmError;
use std::sync::Arc;
use vm_spec::capture::Sha256Digest;
use vm_spec::stream_map::{
    MapError, StreamNode, StreamRole, StreamRoot, MAX_NODE_BYTES, MAX_ROOT_BYTES,
};

const ROOT: &str = "handoff";
const MAPS: &str = "maps";
const STAGING: &str = "staging";
const NODES: &str = "nodes";
const CLEANUP: &str = "cleanup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocumentName {
    Plan,
    Manifest,
}

impl DocumentName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Manifest => "manifest",
        }
    }
}

pub(crate) struct OperationFiles {
    directory: OwnedDirectory,
}

impl OperationFiles {
    pub(crate) fn create(home: &Path, operation: OperationId) -> Result<Self, LibVmError> {
        let directory = OwnedDirectory::open_root(home)?
            .ensure_dir(ROOT)?
            .ensure_dir(&operation.to_string())?;
        Ok(Self { directory })
    }

    /// Stable cross-process serialization, independent of service-local caches.
    /// Never remove this file: queued participants must lock the same inode.
    pub(crate) fn lock(&self) -> Result<crate::storage::locks::StorageLock, LibVmError> {
        Ok(crate::storage::locks::blocking(
            &self.directory,
            "operation.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?)
    }

    pub(crate) fn open(home: &Path, operation: OperationId) -> Result<Option<Self>, LibVmError> {
        let Some(home) = OwnedDirectory::open_existing_root(home)? else {
            return Ok(None);
        };
        let Some(root) = home.open_dir(ROOT)? else {
            return Ok(None);
        };
        Ok(root
            .open_dir(&operation.to_string())?
            .map(|directory| Self { directory }))
    }

    pub(crate) fn existing(home: &Path, operation: OperationId) -> Result<Self, LibVmError> {
        Self::open(home, operation)?
            .ok_or_else(|| LibVmError::from(HandoffError::UnknownOperation { operation }))
    }

    /// Publish once. An equal document is a replay; a different one conflicts
    /// unless `replace` says the earlier one never left this participant.
    pub(crate) fn store_document(
        &self,
        name: DocumentName,
        document: &SealedDocument,
        replace: bool,
    ) -> Result<(), LibVmError> {
        if let Some(existing) = self.load_document(name)? {
            if existing == *document {
                return Ok(());
            }
            if !replace {
                return Err(HandoffError::ReceiptMismatch.into());
            }
        }
        self.directory
            .write_file_atomic(name.as_str(), document.bytes())
    }

    pub(crate) fn load_document(
        &self,
        name: DocumentName,
    ) -> Result<Option<SealedDocument>, LibVmError> {
        let Some(file) = self.directory.open_file(name.as_str())? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(u64::from(MAX_DOCUMENT_BYTES) + 1)
            .read_to_end(&mut bytes)?;
        let digest = crate::storage::identity::ObjectDigest::of_bytes(&bytes);
        SealedDocument::new(digest, bytes).map(Some)
    }

    /// Destination cleanup authority, durable before publication side effects.
    pub(crate) fn store_cleanup(&self, bytes: &[u8]) -> Result<(), LibVmError> {
        if bytes.len() as u64 > u64::from(MAX_DOCUMENT_BYTES) {
            return Err(invalid("handoff cleanup record exceeds its bound"));
        }
        self.directory.write_file_atomic(CLEANUP, bytes)
    }

    pub(crate) fn load_cleanup(&self) -> Result<Option<Vec<u8>>, LibVmError> {
        let Some(file) = self.directory.open_file(CLEANUP)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(u64::from(MAX_DOCUMENT_BYTES) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > u64::from(MAX_DOCUMENT_BYTES) {
            return Err(invalid("handoff cleanup record exceeds its bound"));
        }
        Ok(Some(bytes))
    }

    fn maps(&self) -> Result<OwnedDirectory, LibVmError> {
        self.directory.ensure_dir(MAPS)
    }

    /// Persist exact canonical map bytes for `stream`, verified first.
    pub(crate) fn store_map(
        &self,
        stream: &StreamId,
        bytes: &[u8],
    ) -> Result<StreamRoot, LibVmError> {
        let map = decode_map(stream, bytes)?;
        let maps = self.maps()?;
        if let Some(file) = self.map_file(stream)? {
            let mut existing = Vec::new();
            file.take(MAX_ROOT_BYTES as u64 + 1)
                .read_to_end(&mut existing)?;
            if existing == bytes {
                return Ok(map);
            }
            return Err(invalid("stored stream root contradicts its identity"));
        }
        maps.write_file_atomic(&stream.hex(), bytes)?;
        Ok(map)
    }

    pub(crate) fn has_map(&self, stream: &StreamId) -> Result<bool, LibVmError> {
        Ok(self.map_file(stream)?.is_some())
    }

    pub(crate) fn map_file(&self, stream: &StreamId) -> Result<Option<File>, LibVmError> {
        match self.directory.open_dir(MAPS)? {
            Some(maps) => maps.open_file(&stream.hex()),
            None => Ok(None),
        }
    }

    pub(crate) fn load_map(
        &self,
        stream: &StreamId,
        pool: &StoragePool,
    ) -> Result<Option<AuthenticatedMap>, LibVmError> {
        let Some(root) = self.load_root(stream)? else {
            return Ok(None);
        };
        let role = if root.chunk_size() == vm_spec::stream_map::ChunkSize::RAM {
            StreamRole::Ram
        } else {
            StreamRole::Disk
        };
        let authority = Arc::new(OperationAuthority {
            nodes: self.directory.ensure_dir(NODES)?,
            pool: pool.map_authority(Arc::new(()))?,
        });
        Ok(Some(AuthenticatedMap::from_root(root, role, authority)?))
    }

    pub(crate) fn load_root(&self, stream: &StreamId) -> Result<Option<StreamRoot>, LibVmError> {
        let Some(file) = self.map_file(stream)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(MAX_ROOT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        decode_map(stream, &bytes).map(Some)
    }

    pub(crate) fn store_node(&self, digest: ObjectDigest, bytes: &[u8]) -> Result<(), LibVmError> {
        if ObjectDigest::of_bytes(bytes) != digest {
            return Err(invalid(format!(
                "corrupt map node {digest}: digest mismatch"
            )));
        }
        let valid = (0..vm_spec::stream_map::TREE_DEPTH)
            .any(|height| StreamNode::decode(bytes, height).is_ok());
        if !valid {
            return Err(invalid(format!(
                "corrupt map node {digest}: invalid canonical node"
            )));
        }
        self.directory
            .ensure_dir(NODES)?
            .write_file_atomic(&digest.hex(), bytes)
    }

    pub(crate) fn node_bytes(
        &self,
        digest: ObjectDigest,
        pool: &StoragePool,
    ) -> Result<Option<Vec<u8>>, LibVmError> {
        let mut output = [0; MAX_NODE_BYTES];
        let authority = OperationAuthority {
            nodes: self.directory.ensure_dir(NODES)?,
            pool: pool.map_authority(Arc::new(()))?,
        };
        match authority.read_node(Sha256Digest::from_bytes(*digest.as_bytes()), &mut output) {
            Ok(length) => {
                let bytes = output[..length].to_vec();
                if ObjectDigest::of_bytes(&bytes) != digest {
                    return Err(invalid(format!(
                        "corrupt map node {digest}: digest mismatch"
                    )));
                }
                Ok(Some(bytes))
            }
            Err(MapError::MissingNode(_)) => Ok(None),
            Err(error) => Err(invalid(error)),
        }
    }

    pub(crate) fn revision(&self) -> Result<u64, LibVmError> {
        let Some(mut file) = self.directory.open_file("revision")? else {
            return Ok(0);
        };
        let mut bytes = [0; 8];
        file.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn advance(&self) -> Result<(), LibVmError> {
        let revision = self
            .revision()?
            .checked_add(1)
            .ok_or_else(|| invalid("handoff revision exhausted"))?;
        self.directory
            .write_file_atomic("revision", &revision.to_le_bytes())
    }

    pub(crate) fn payload(&self, stream: StreamId, index: u64) -> Result<Option<File>, LibVmError> {
        self.staging()?
            .open_file(&format!("{}-{index}.payload", stream.hex()))
    }

    pub(crate) fn store_payload(
        &self,
        stream: StreamId,
        index: u64,
        bytes: &[u8],
    ) -> Result<(), LibVmError> {
        self.staging()?
            .write_file_atomic(&format!("{}-{index}.payload", stream.hex()), bytes)
    }

    pub(crate) fn staging(&self) -> Result<OwnedDirectory, LibVmError> {
        self.directory.ensure_dir(STAGING)
    }

    /// Drop bulk working state after a terminal decision. Documents stay.
    pub(crate) fn release_bulk(&self) -> Result<(), LibVmError> {
        for name in [MAPS, NODES, STAGING] {
            if self.directory.open_dir(name)?.is_some() {
                self.directory.remove_tree(name)?;
            }
        }
        self.directory.sync()
    }
}

pub(crate) fn decode_map(stream: &StreamId, bytes: &[u8]) -> Result<StreamRoot, LibVmError> {
    if bytes.len() > MAX_ROOT_BYTES {
        return Err(invalid("stream root exceeds its 57-byte bound"));
    }
    let root = StreamRoot::decode(bytes).map_err(|error| {
        invalid(format!(
            "unsupported or corrupt stream-map v1 root: {error}"
        ))
    })?;
    if root.id().as_bytes() != stream.as_bytes() {
        return Err(invalid(
            "wrong stream root: header does not match agreed identity",
        ));
    }
    Ok(root)
}

struct OperationAuthority {
    nodes: OwnedDirectory,
    pool: Arc<dyn MapAuthority>,
}

impl MapAuthority for OperationAuthority {
    fn read_node(
        &self,
        digest: Sha256Digest,
        output: &mut [u8; MAX_NODE_BYTES],
    ) -> Result<usize, MapError> {
        let name = ObjectDigest::from_sha256(*digest.as_bytes()).hex();
        match self
            .nodes
            .open_file(&name)
            .map_err(|error| MapError::Io(std::io::Error::other(error.to_string())))?
        {
            Some(file) => crate::storage::map::read_node_file(Ok(file), digest, output),
            None => self.pool.read_node(digest, output),
        }
    }
}

/// Read exactly `bytes.len()` bytes at `offset`.
pub(crate) fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> Result<(), LibVmError> {
    file.read_exact_at(bytes, offset)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::handoff::files::OperationFiles;
    use crate::handoff::types::OperationId;
    use crate::storage::locks::acquire_existing;

    #[test]
    fn operation_lock_serializes_processes_and_survives_bulk_release() {
        const TEST: &str =
            "handoff::files::tests::operation_lock_serializes_processes_and_survives_bulk_release";
        if let Some(path) = std::env::var_os("SILO_HANDOFF_LOCK_PROBE") {
            let directory =
                crate::paths::OwnedDirectory::open_existing_root(std::path::Path::new(&path))
                    .unwrap()
                    .unwrap();
            let acquired = acquire_existing(
                &directory,
                "operation.lock",
                nix::fcntl::FlockArg::LockExclusiveNonblock,
            )
            .unwrap();
            assert_eq!(
                acquired.is_some(),
                std::env::var("SILO_HANDOFF_LOCK_AVAILABLE").as_deref() == Ok("1"),
            );
            return;
        }

        let home = tempfile::tempdir().unwrap();
        let operation = OperationId::new(uuid::Uuid::new_v4()).unwrap();
        let files = OperationFiles::create(home.path(), operation).unwrap();
        let directory = home.path().join("handoff").join(operation.to_string());
        let run_probe = |available: bool| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env("SILO_HANDOFF_LOCK_PROBE", &directory)
                .env(
                    "SILO_HANDOFF_LOCK_AVAILABLE",
                    if available { "1" } else { "0" },
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        };
        let lock = files.lock().unwrap();
        let identity = lock.file_identity().unwrap();
        run_probe(false);
        files.staging().unwrap();
        files.store_cleanup(b"durable cleanup authority").unwrap();
        files.release_bulk().unwrap();
        assert!(!directory.join("staging").exists());
        assert_eq!(
            files.load_cleanup().unwrap().unwrap(),
            b"durable cleanup authority"
        );
        run_probe(false);
        drop(lock);
        run_probe(true);
        let replay = OperationFiles::existing(home.path(), operation).unwrap();
        assert_eq!(replay.lock().unwrap().file_identity().unwrap(), identity);
    }
}
