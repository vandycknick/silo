use crate::planning::ResolvedImage;
use libvm::ResolvedOciImage;
use silo_vm_control::images::OciIdentity;

#[derive(Debug)]
pub(crate) struct SourceResolution {
    pub(crate) plan_image: ResolvedImage,
    pub(crate) is_positional: bool,
    pub(crate) source: ResolvedSource,
}

#[derive(Debug)]
pub(crate) enum ResolvedSource {
    LocalResolvedOci(ResolvedOciImage),
    DaemonOciIdentity(OciIdentity),
    /// Complete typed import metadata; creation never publishes an alias.
    Disk(libvm::DiskImportRequest),
    /// A typed image or snapshot identity, never an alias that could move.
    Managed(libvm::ManagedSourceRef),
}

/// Source selection inputs that are not part of the source spelling itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct SourceOptions {
    /// Requested Linux userspace platform: OCI selection or disk import metadata.
    pub(crate) platform: Option<libvm::LinuxPlatform>,
    /// Root selection for a `disk:` source; whole disk when absent.
    pub(crate) root: Option<libvm::ImportRootSelection>,
}

/// Planning metadata only: a dry run cannot be materialized by either backend.
#[derive(Debug)]
pub(crate) struct ReadOnlySourceResolution {
    pub(crate) plan_image: ResolvedImage,
    pub(crate) is_positional: bool,
}

#[derive(Debug)]
pub(crate) struct ReadOnlyCreationResolution {
    pub(crate) name: String,
    pub(crate) source: ReadOnlySourceResolution,
}
