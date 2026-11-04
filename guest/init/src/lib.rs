//! Init admission and handoff helpers, shared by the binary and host unit tests.
#![no_std]

extern crate alloc;

#[cfg(target_os = "linux")]
pub mod handoff;
pub mod overlay_verify;
pub mod root_checks;
