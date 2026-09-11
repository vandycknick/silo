use std::path::PathBuf;

use libvm::ResolvedOciImage;

use crate::planning::ResolvedImage;

#[derive(Debug)]
pub(crate) struct SourceResolution {
    pub(crate) plan_image: ResolvedImage,
    pub(crate) is_positional: bool,
    pub(crate) resolved_oci: Option<ResolvedOciImage>,
    pub(crate) disk: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct ReadOnlyCreationResolution {
    pub(crate) name: String,
    pub(crate) source: SourceResolution,
}
