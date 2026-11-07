//! Init admission and handoff helpers, shared by the binary and host unit tests.
#![no_std]

extern crate alloc;

pub mod boot_args;
#[cfg(target_os = "linux")]
pub mod handoff;
pub mod overlay_verify;
pub mod raw_root;
pub mod root_checks;
pub mod rosetta_checks;
