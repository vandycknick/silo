//! Host-only flattening of a stopped `linux-erofs-overlay-v1` root into a
//! fresh ext4 filesystem.
//!
//! ```text
//!  retained recipe/result ──► authenticated namespace + exact fsmeta ──┐
//!  held layer packs ───────────────────────────────────────────────────┤
//!                                                                      ├─► merged ──► fresh ext4
//!  held clean upper ──► audited ext4 reader ──► upper/ + work/index ───┘   tree       (shared writer)
//! ```
//!
//! Only the admitted overlay profile
//! (`index=on,metacopy=off,redirect_dir=nofollow,xino=on,nfs_export=off,uuid=null`)
//! is interpreted: visible upper entries, whiteouts, opaque directories, and
//! `work/index` / `trusted.overlay.origin` associations validated against the
//! exact retained lower's EROFS export identities. An indexed copied-up inode
//! supplies every surviving lower alias, including names absent from `upper/`;
//! deleted aliases stay deleted. Unknown or inconsistent control state is an
//! explicit refusal, never an approximate tree. Upper bodies are streamed by
//! position from the held upper, lower bodies from the held packs; nothing is
//! staged. The upper is never written, replayed or repaired.

mod handle;
mod merge;

use std::borrow::Cow;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use disk_image::ext4::{ReadError, Reader};

use crate::composition::{CompositionError, CompositionRecipe, CompositionResult};
use crate::erofs::Layer;
use crate::flat_ext4::{RenderTree, Sources};
use crate::OciError;

/// Byte offset of `s_uuid` in an ext4 image (superblock at 1024, field 0x68).
const EXT4_UUID_OFFSET: u64 = 1024 + 0x68;

/// The exact retained lower: canonical records plus held immutable bytes.
#[derive(Clone, Copy)]
pub struct FlattenLower<'a> {
    pub recipe: &'a CompositionRecipe,
    pub result: &'a CompositionResult,
    /// Held, stream-authenticated packs in exact occurrence order.
    pub layers: &'a [Layer<'a>],
    pub fsmeta: &'a File,
}

/// Identity of the written output, a new filesystem rather than a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlattenedFilesystem {
    /// Fresh random ext4 superblock UUID.
    pub uuid: [u8; 16],
    /// Exact output file length in bytes.
    pub length: u64,
}

/// Explicit overlay state the flattener does not admit, with the upper
/// filesystem path (lossy UTF-8 for display) where it was found.
#[derive(Debug, thiserror::Error)]
#[error("unsupported or inconsistent overlay state at {path:?}: {reason}")]
pub struct OverlayRefusal {
    pub path: String,
    pub reason: Cow<'static, str>,
}

impl OverlayRefusal {
    fn new(path: &[u8], reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            path: String::from_utf8_lossy(path).into_owned(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlattenError {
    /// Dirty journal, orphans or error state: only a guest boot may recover.
    #[error("overlay upper requires filesystem recovery before flattening")]
    RecoveryRequired(#[source] ReadError),
    /// A valid ext4 encoding or bound outside the admitted upper profile.
    #[error("overlay upper uses an unsupported ext4 layout")]
    UnsupportedLayout(#[source] ReadError),
    #[error(transparent)]
    UnsupportedOverlay(#[from] OverlayRefusal),
    #[error("overlay upper filesystem is corrupt")]
    Corrupt(#[source] ReadError),
    #[error("retained lower does not authenticate")]
    Lower(#[from] CompositionError),
    #[error("flattened filesystem could not be written")]
    Output(#[source] OciError),
    #[error("flattening was cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<ReadError> for FlattenError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::RequiresRecovery(_) => Self::RecoveryRequired(error),
            ReadError::Unsupported(_) => Self::UnsupportedLayout(error),
            ReadError::Io(error) => Self::Io(error),
            other => Self::Corrupt(other),
        }
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), FlattenError> {
    if cancel.load(Ordering::Acquire) {
        return Err(FlattenError::Cancelled);
    }
    Ok(())
}

/// Flatten a stopped overlay root into a fresh ext4 image at `output`.
///
/// `upper` is a held descriptor of the private upper (callers keep the
/// lifecycle lock and pass a duplicate); it is only read. `output` is a
/// caller-owned staging path that the writer creates or truncates; it is sized
/// against ext4 bounds before any byte is written. On error the caller removes
/// staging; on success the caller synchronizes and publishes it. `minimum_size`
/// is a floor, not a target; the result never exceeds 1 TiB.
pub fn flatten_overlay(
    lower: FlattenLower<'_>,
    upper: File,
    output: &Path,
    minimum_size: u64,
    cancel: &AtomicBool,
) -> Result<FlattenedFilesystem, FlattenError> {
    // Recovery-required state is reported before any lower work begins.
    let reader = Reader::from_file(upper)?;
    check_cancel(cancel)?;
    reader.audit()?;
    check_cancel(cancel)?;
    let (namespace, handles) =
        crate::composition::load_exported(lower.recipe, lower.layers, lower.result, lower.fsmeta)?;
    check_cancel(cancel)?;
    let tree = crate::overlay_flatten::merge::merge(&namespace, &handles, &reader, cancel)?;
    render(&tree, lower, Some(&reader), output, minimum_size, cancel)
}

/// Render only the exact retained lower namespace (explicit OCI-to-raw
/// conversion), with the same authentication, bounds and output contract as
/// `flatten_overlay` and no source blob or staged pack.
pub fn flatten_lower(
    lower: FlattenLower<'_>,
    output: &Path,
    minimum_size: u64,
    cancel: &AtomicBool,
) -> Result<FlattenedFilesystem, FlattenError> {
    let namespace =
        crate::composition::load_namespace(lower.recipe, lower.layers, lower.result, lower.fsmeta)?;
    check_cancel(cancel)?;
    render(&namespace, lower, None, output, minimum_size, cancel)
}

fn render<T: RenderTree>(
    tree: &T,
    lower: FlattenLower<'_>,
    upper: Option<&Reader>,
    output: &Path,
    minimum_size: u64,
    cancel: &AtomicBool,
) -> Result<FlattenedFilesystem, FlattenError> {
    let sources = Sources {
        layers: lower.layers,
        upper,
        cancel: Some(cancel),
    };
    let length = crate::flat_ext4::render(output, tree, &sources, minimum_size).map_err(
        |error| match error {
            OciError::UpperRead { source } => FlattenError::from(source),
            _ if cancel.load(Ordering::Acquire) => FlattenError::Cancelled,
            other => FlattenError::Output(other),
        },
    )?;
    let mut uuid = [0; 16];
    File::open(output)?.read_exact_at(&mut uuid, EXT4_UUID_OFFSET)?;
    Ok(FlattenedFilesystem { uuid, length })
}

#[cfg(test)]
mod tests;
