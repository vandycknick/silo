//! Parent-independent lossless OCI layer artifacts and pure namespace composition.
pub mod index;
pub mod ingest;
pub mod limits;
pub(crate) mod metadata;
pub mod model;
pub mod namespace;
mod pack;
mod tar;

pub use crate::changeset::index::{
    decode_index, encode_index, EncodedIndex, IndexObject, LayerRecipe, LayerResult,
};
pub use crate::changeset::ingest::{ingest_layer, LayerInput, StagedChangeset};
pub use crate::changeset::limits::ChangesetLimits;
pub use crate::changeset::model::StreamIdentity;
pub use crate::changeset::model::{
    ChangeEntry, ContentDigest, EntryKind, LayerChangeset, LayerRecipeId, LayerResultId, Metadata,
    MetadataPresence, PayloadRef, SparseRange, Xattr,
};

#[derive(Debug, thiserror::Error)]
pub enum ChangesetError {
    #[error("invalid changeset: {0}")]
    Invalid(String),
    #[error("unsupported changeset feature: {0}")]
    Unsupported(String),
    #[error("host resource reservation requires {required} bytes but only {available} bytes are available")]
    Resource { required: u64, available: u64 },
    #[error("metadata allocation failed: {0}")]
    Allocation(String),
    #[error("{resource} is {actual}, exceeding maximum {maximum}")]
    Limit {
        resource: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
pub type ChangesetResult<T> = Result<T, ChangesetError>;

/// Structural acceptance never resolves a path against a lower namespace.
pub fn validate_layer(layer: &LayerChangeset, limits: &ChangesetLimits) -> ChangesetResult<()> {
    use crate::changeset::limits::{aligned, bounded, PACK_ALIGNMENT};
    use std::collections::BTreeSet;
    limits.validate()?;
    bounded(
        "layer entries",
        layer.entries.len() as u64,
        limits.max_entries,
    )?;
    bounded("pack bytes", layer.pack_length, limits.max_pack_bytes)?;
    let mut paths = BTreeSet::new();
    let mut cursor = 0;
    for (ordinal, entry) in layer.entries.iter().enumerate() {
        if entry.ordinal != ordinal as u64 {
            return Err(ChangesetError::Invalid(
                "noncontiguous operation ordinals".into(),
            ));
        }
        let root = matches!(entry.kind, EntryKind::RootDirectory);
        if root != entry.path.is_empty()
            || crate::changeset::tar::normalize_path(&entry.path, root, limits)? != entry.path
        {
            return Err(ChangesetError::Invalid(
                "entry path is not normalized or root kind is invalid".into(),
            ));
        }
        if !paths.insert(&entry.path) {
            return Err(ChangesetError::Invalid(
                "duplicate normalized entry path".into(),
            ));
        }
        if matches!(entry.kind, EntryKind::Hardlink { .. }) {
            let mut access = false;
            let mut default = false;
            for attr in &entry.metadata.xattrs {
                match attr.name.as_slice() {
                    b"system.posix_acl_access" => {
                        access = true;
                        if !entry.presence.acl_access {
                            return Err(ChangesetError::Invalid(
                                "hardlink access ACL lacks presence".into(),
                            ));
                        }
                    }
                    b"system.posix_acl_default" => {
                        default = true;
                        if !entry.presence.acl_default {
                            return Err(ChangesetError::Invalid(
                                "hardlink default ACL lacks presence".into(),
                            ));
                        }
                    }
                    _ => {
                        if !entry.presence.xattrs {
                            return Err(ChangesetError::Invalid(
                                "hardlink xattr lacks presence".into(),
                            ));
                        }
                    }
                }
            }
            if access != entry.presence.acl_access || default != entry.presence.acl_default {
                return Err(ChangesetError::Invalid(
                    "hardlink ACL presence lacks its value".into(),
                ));
            }
            crate::changeset::metadata::validate_hardlink_metadata(&entry.metadata, limits)?;
        } else {
            crate::changeset::metadata::validate_metadata(
                &entry.metadata,
                root || matches!(entry.kind, EntryKind::Directory),
                limits,
            )?;
        }
        match &entry.kind {
            EntryKind::Regular(body) => {
                bounded("regular file bytes", body.length, limits.max_file_bytes)?;
                bounded(
                    "sparse ranges",
                    body.sparse.len() as u64,
                    limits.max_sparse_ranges,
                )?;
                if body.pack_offset != cursor || body.pack_offset % PACK_ALIGNMENT != 0 {
                    return Err(ChangesetError::Invalid(
                        "body is outside its ordered aligned pack extent".into(),
                    ));
                }
                let stored = body
                    .sparse
                    .iter()
                    .try_fold(0u64, |sum, r| sum.checked_add(r.length))
                    .ok_or_else(|| ChangesetError::Invalid("sparse data length overflow".into()))?;
                crate::changeset::pack::validate_ranges(&body.sparse, body.length, stored, limits)?;
                cursor = cursor
                    .checked_add(aligned(body.length)?)
                    .ok_or_else(|| ChangesetError::Invalid("pack length overflow".into()))?;
                bounded("pack bytes", cursor, layer.pack_length)?;
            }
            EntryKind::Hardlink { target } => {
                if crate::changeset::tar::normalize_path(target, false, limits)? != *target {
                    return Err(ChangesetError::Invalid(
                        "hardlink target is not normalized".into(),
                    ));
                }
            }
            EntryKind::Symlink { target } => {
                if target.is_empty() || target.contains(&0) {
                    return Err(ChangesetError::Invalid(
                        "empty or NUL symlink target".into(),
                    ));
                }
                bounded(
                    "symlink target bytes",
                    target.len() as u64,
                    limits.max_path_bytes,
                )?;
            }
            EntryKind::Whiteout | EntryKind::Opaque => {
                let name = entry
                    .path
                    .rsplit(|b| *b == b'/')
                    .next()
                    .ok_or_else(|| ChangesetError::Invalid("missing whiteout name".into()))?;
                if entry
                    .path
                    .rsplitn(2, |b| *b == b'/')
                    .nth(1)
                    .is_some_and(|parent| {
                        parent
                            .split(|b| *b == b'/')
                            .any(|part| part.starts_with(b".wh."))
                    })
                {
                    return Err(ChangesetError::Invalid(
                        "whiteout marker used as a parent".into(),
                    ));
                }
                if matches!(entry.kind, EntryKind::Opaque) {
                    if name != b".wh..wh..opq" {
                        return Err(ChangesetError::Invalid("invalid opaque marker".into()));
                    }
                } else if !name.starts_with(b".wh.")
                    || matches!(&name[4..], b"" | b"." | b"..")
                    || name == b".wh..wh..opq"
                {
                    return Err(ChangesetError::Invalid("invalid whiteout name".into()));
                }
            }
            EntryKind::CharacterDevice { major, minor }
            | EntryKind::BlockDevice { major, minor }
                if *major > 0xfff
                    || *minor > 0xfffff
                    || (*major == 0
                        && *minor == 0
                        && matches!(entry.kind, EntryKind::CharacterDevice { .. })) =>
            {
                return Err(ChangesetError::Invalid(
                    "invalid or reserved Linux device number".into(),
                ));
            }
            _ => {}
        }
        if !matches!(entry.kind, EntryKind::Whiteout | EntryKind::Opaque)
            && entry
                .path
                .split(|b| *b == b'/')
                .any(|part| part.starts_with(b".wh."))
        {
            return Err(ChangesetError::Invalid(
                "whiteout name used as an inode or parent".into(),
            ));
        }
    }
    if cursor != layer.pack_length {
        return Err(ChangesetError::Invalid("unreferenced pack suffix".into()));
    }
    Ok(())
}
