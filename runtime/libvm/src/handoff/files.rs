//! Durable per-operation documents and canonical stream maps.
//!
//! ```text
//! <home>/handoff/<operation>/
//!     operation.lock stable cross-process transition lock (never removed)
//!     plan        canonical approved plan (both roles)
//!     manifest    canonical capture manifest (once bound or offered)
//!     cleanup     destination replaced-generation cleanup authority
//!     maps/<hex>  canonical silo-chunks-v1 map of each transferred stream
//!     staging/    incomplete payload writes; never authoritative
//! ```
//!
//! Documents survive daemon restarts independently of pool collection, so
//! recovery can always reread the exact plan an operation was bound to.
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::handoff::plan::{invalid, max_map_bytes, SealedDocument, MAX_DOCUMENT_BYTES};
use crate::handoff::types::{HandoffError, OperationId};
use crate::paths::OwnedDirectory;
use crate::storage::identity::StreamId;
use crate::storage::stream::StreamMap;
use crate::LibVmError;

const ROOT: &str = "handoff";
const MAPS: &str = "maps";
const STAGING: &str = "staging";
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
    ) -> Result<StreamMap, LibVmError> {
        let map = decode_map(stream, bytes)?;
        let maps = self.maps()?;
        if let Some(existing) = self.load_map(stream)? {
            if existing == map {
                return Ok(map);
            }
            return Err(invalid("stored stream map contradicts its identity"));
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

    pub(crate) fn load_map(&self, stream: &StreamId) -> Result<Option<StreamMap>, LibVmError> {
        let Some(file) = self.map_file(stream)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(max_map_bytes() + 1).read_to_end(&mut bytes)?;
        decode_map(stream, &bytes).map(Some)
    }

    pub(crate) fn staging(&self) -> Result<OwnedDirectory, LibVmError> {
        self.directory.ensure_dir(STAGING)
    }

    /// Drop bulk working state after a terminal decision. Documents stay.
    pub(crate) fn release_bulk(&self) -> Result<(), LibVmError> {
        for name in [MAPS, STAGING] {
            if self.directory.open_dir(name)?.is_some() {
                self.directory.remove_tree(name)?;
            }
        }
        self.directory.sync()
    }
}

pub(crate) fn decode_map(stream: &StreamId, bytes: &[u8]) -> Result<StreamMap, LibVmError> {
    if bytes.len() as u64 > max_map_bytes() {
        return Err(invalid("stream map exceeds its bound"));
    }
    let map = StreamMap::decode(bytes)?;
    if map.id() != *stream || map.canonical_bytes()? != bytes {
        return Err(invalid(
            "stream map does not encode its identity canonically",
        ));
    }
    Ok(map)
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
