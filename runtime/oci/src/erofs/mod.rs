//! Deterministic `silo-erofs-v1` metadata, with occurrence-owned external packs.
//!
//! Pack stream authentication belongs to the caller. Both entry points verify
//! the exact descriptors' lengths, authenticated index bindings, source padding,
//! sparse gaps and namespace before accepting any chunk references. Validation
//! parses the fixed on-disk subset independently of the encoder; it never repairs
//! fields or accepts kernel device-ID aliases. Memory is bounded by the namespace
//! and fixed I/O buffers, not the number of regular-file chunks.

mod plan;
mod reader;
mod writer;

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};

use crate::changeset::namespace::ValidatedNamespace;
use crate::changeset::{
    ChangesetError, ContentDigest, LayerChangeset, LayerResult, StreamIdentity,
};

pub const ENCODER_ABI: &str = "silo-erofs-v1";
pub const BLOCK_SIZE: u64 = 4096;
pub const MAX_FSMETA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_LOWER_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const BLOCK: usize = BLOCK_SIZE as usize;
const IO_SIZE: usize = 64 * 1024;

/// An ordered occurrence, even when the same authenticated pack occurs twice.
#[derive(Clone, Copy)]
pub struct Layer<'a> {
    pub result: &'a LayerResult,
    pub changeset: &'a LayerChangeset,
    pub pack: &'a File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRange {
    pub stream: StreamIdentity,
    /// Byte offset in the complete logical lower (including fsmeta).
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFsmeta {
    pub digest: ContentDigest,
    pub length: u64,
    pub uuid: [u8; 16],
    /// Occurrence order, including zero-length and repeated packs.
    pub device_ranges: Vec<DeviceRange>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErofsError {
    #[error("invalid silo-erofs-v1 image: {0}")]
    Invalid(String),
    #[error(transparent)]
    Changeset(#[from] ChangesetError),
    #[error(transparent)]
    Namespace(#[from] crate::changeset::namespace::NamespaceError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T, E = ErofsError> = std::result::Result<T, E>;

/// Replace `output` with canonical fsmeta. The output must not alias an input
/// pack. The caller must discard any partial output on an I/O failure.
pub fn encode(
    namespace: &ValidatedNamespace,
    layers: &[Layer<'_>],
    recipe_id: &str,
    output: &mut File,
) -> Result<EncodedFsmeta> {
    let plan = crate::erofs::plan::Plan::new(namespace, layers, recipe_id)?;
    let metadata = output.metadata()?;
    for layer in layers {
        let pack = layer.pack.metadata()?;
        if metadata.dev() == pack.dev() && metadata.ino() == pack.ino() {
            return Err(invalid("fsmeta output aliases an input pack"));
        }
    }
    crate::erofs::writer::encode(&plan, layers, output)
}

/// Strict, bounded fixed-profile reading against the expected original bodies.
/// Accepting bytes here is not a substitute for caller-owned stream identity
/// authentication of the supplied immutable pack descriptors.
pub fn validate(
    fsmeta: &File,
    namespace: &ValidatedNamespace,
    layers: &[Layer<'_>],
    recipe_id: &str,
) -> Result<EncodedFsmeta> {
    let plan = crate::erofs::plan::Plan::new(namespace, layers, recipe_id)?;
    crate::erofs::reader::validate(fsmeta, &plan, layers)
}

fn invalid(message: &str) -> ErofsError {
    ErofsError::Invalid(message.to_owned())
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| invalid("offset overflow"))
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    Ok(add(value, alignment - 1)? / alignment * alignment)
}

fn u32_field(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid("32-bit disk field overflow"))
}

fn read_at(file: &File, bytes: &mut [u8], offset: u64) -> Result<()> {
    file.read_exact_at(bytes, offset)?;
    Ok(())
}

fn zeros(bytes: &[u8]) -> Result<()> {
    if bytes.iter().any(|b| *b != 0) {
        return Err(invalid("nonzero reserved bytes, sparse gap or padding"));
    }
    Ok(())
}

fn zero_region(file: &File, mut start: u64, end: u64) -> Result<()> {
    if start > end {
        return Err(invalid("reversed zero region"));
    }
    let mut buffer = [0; IO_SIZE];
    while start < end {
        let length = (end - start).min(IO_SIZE as u64) as usize;
        read_at(file, &mut buffer[..length], start)?;
        zeros(&buffer[..length])?;
        start += length as u64;
    }
    Ok(())
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

#[cfg(test)]
mod tests;
