//! OverlayFS `struct ovl_fb` file handles, as stored in `trusted.overlay.*`
//! xattrs and spelled in `work/index` entry names.
//!
//! ```text
//! byte 0     1      2    3      4     5..21  21..len
//!      ver=0 0xfb   len  flags  type  uuid   fid (filesystem-defined)
//! ```
//!
//! `uuid=null` keeps the real lower `s_uuid` in origin handles; it only stops
//! OverlayFS from inventing its own filesystem UUID. Admitted guests are
//! little-endian, so the kernel writes no endianness flag.

use crate::changeset::namespace::InodeId;
use crate::erofs::handles::{ExportHandles, FidEncoding};

const VERSION: u8 = 0;
const MAGIC: u8 = 0xfb;
const FLAG_PATH_UPPER: u8 = 1 << 2;
const HEADER_BYTES: usize = 21;
/// ext4 encodes the generic `{inode number, generation}` fid.
const FILEID_INO32_GEN: u8 = 1;

struct Handle<'a> {
    flags: u8,
    fid_type: u8,
    uuid: &'a [u8],
    fid: &'a [u8],
}

fn parse(bytes: &[u8]) -> Result<Handle<'_>, &'static str> {
    if bytes.len() < HEADER_BYTES {
        return Err("overlay handle is shorter than its header");
    }
    if bytes[0] != VERSION || bytes[1] != MAGIC {
        return Err("overlay handle has an unknown version or magic");
    }
    if usize::from(bytes[2]) != bytes.len() {
        return Err("overlay handle length disagrees with its header");
    }
    Ok(Handle {
        flags: bytes[3],
        fid_type: bytes[4],
        uuid: &bytes[5..HEADER_BYTES],
        fid: &bytes[HEADER_BYTES..],
    })
}

/// Resolve a lower origin handle against the exact retained lower. `expected`
/// pins the fid encoding: one upper is only ever mounted by kernels that agree
/// with the upper root's origin, which every mount re-verifies byte for byte.
pub(crate) fn lower_origin(
    bytes: &[u8],
    handles: &ExportHandles,
    expected: Option<FidEncoding>,
) -> Result<(FidEncoding, InodeId), &'static str> {
    let handle = parse(bytes)?;
    if handle.flags != 0 {
        return Err("origin handle flags do not describe a little-endian lower handle");
    }
    if handle.uuid != handles.uuid() {
        return Err("origin handle names a filesystem other than the exact lower");
    }
    let encoding = FidEncoding::from_type(handle.fid_type)
        .ok_or("origin handle has a fid type no admitted kernel emits for EROFS")?;
    if expected.is_some_and(|expected| expected != encoding) {
        return Err("origin handle encoding differs from the upper root's mounted kernel family");
    }
    let inode = handles
        .decode(encoding, handle.fid)
        .ok_or("origin handle names no inode of the exact lower")?;
    Ok((encoding, inode))
}

/// Verify `trusted.overlay.upper` on the index directory: the upper root's
/// ext4 handle, marking this index as belonging to exactly that upper.
pub(crate) fn upper_root(
    bytes: &[u8],
    uuid: [u8; 16],
    inode: u32,
    generation: u32,
) -> Result<(), &'static str> {
    let handle = parse(bytes)?;
    let mut fid = [0; 8];
    fid[..4].copy_from_slice(&inode.to_le_bytes());
    fid[4..].copy_from_slice(&generation.to_le_bytes());
    if handle.flags != FLAG_PATH_UPPER
        || handle.fid_type != FILEID_INO32_GEN
        || handle.uuid != uuid
        || handle.fid != fid
    {
        return Err("index directory is not bound to this upper root");
    }
    Ok(())
}

/// Decode a canonical index entry name: the lowercase hex of the whole handle.
pub(crate) fn index_name<'o>(name: &[u8], out: &'o mut [u8; 255]) -> Option<&'o [u8]> {
    if !name.len().is_multiple_of(2) || name.len() / 2 > out.len() {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    for (slot, pair) in out.iter_mut().zip(name.chunks_exact(2)) {
        *slot = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    out.get(..name.len() / 2)
}
