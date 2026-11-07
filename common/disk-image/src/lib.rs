//! Synchronous disk image formatting, inspection, and mutation.

pub mod ext4;

#[cfg(feature = "qcow2")]
pub mod qcow2;
