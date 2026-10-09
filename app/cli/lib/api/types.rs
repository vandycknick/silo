use std::path::PathBuf;

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
    Disk(PathBuf),
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
