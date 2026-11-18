//! Runtime-scoped snapshot management. Snapshots resolve like `silo restore`
//! without pulling: a local name, a pulled registry reference (short
//! references expand via `search_registries`), an id or a unique id prefix.
use std::sync::Arc;

use crate::store::snapshot_store::SnapshotStore;
use crate::{
    LibVmError, Runtime, SnapshotInfo, SnapshotRef, SnapshotRemoval, SnapshotVerificationReport,
};

/// Snapshot listing, inspection, verification and removal. Snapshots are
/// created with `Runtime::snapshot` and turned into machines with
/// `Runtime::restore`.
#[derive(Debug, Clone)]
pub struct Snapshots {
    runtime: Runtime,
}

impl Snapshots {
    pub(crate) fn new(runtime: Runtime) -> Self {
        Self { runtime }
    }

    fn store(&self) -> Result<SnapshotStore, LibVmError> {
        Ok(SnapshotStore::from_store(Arc::new(
            self.runtime.native_store()?,
        )))
    }

    /// The exact local name `reference` matched, or the id it resolved to.
    async fn resolve(&self, reference: &SnapshotRef) -> Result<SnapshotRef, LibVmError> {
        let input = reference.to_string();
        let store = self.runtime.native_store()?;
        let mut connection = store.pool.acquire().await?;
        let local = crate::resolve::resolve_local(
            &mut connection,
            self.runtime.registry_policy(),
            &input,
            crate::resolve::Kind::Snapshot,
        )
        .await?;
        match (local.record, local.name) {
            (crate::resolve::LocalRecord::Snapshot(_), Some(name)) => Ok(SnapshotRef::Name(name)),
            (crate::resolve::LocalRecord::Snapshot(id), None) => Ok(SnapshotRef::Id(id)),
            (crate::resolve::LocalRecord::Image(_), _) => {
                Err(LibVmError::ImageIsNotASnapshot { reference: input })
            }
        }
    }

    /// Every local snapshot, ordered by id.
    pub async fn list(&self) -> Result<Vec<SnapshotInfo>, LibVmError> {
        self.store()?.list().await
    }

    pub async fn inspect(&self, reference: &SnapshotRef) -> Result<SnapshotInfo, LibVmError> {
        let reference = self.resolve(reference).await?;
        self.store()?.inspect(&reference).await
    }

    /// Reread and rehash every byte of the snapshot's closure.
    pub async fn verify(
        &self,
        reference: &SnapshotRef,
    ) -> Result<SnapshotVerificationReport, LibVmError> {
        let reference = self.resolve(reference).await?;
        self.store()?.verify(&reference).await
    }

    /// Docker tag semantics: a name removes that name, and the snapshot once
    /// no name remains; an id (or unique prefix) removes the snapshot and all
    /// its names. Machines restored from it are unaffected.
    pub async fn remove(&self, reference: &SnapshotRef) -> Result<SnapshotRemoval, LibVmError> {
        let reference = self.resolve(reference).await?;
        self.store()?.remove(&reference).await
    }
}
