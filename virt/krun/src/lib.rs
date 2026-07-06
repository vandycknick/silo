//! Process-backed libkrun helper API for Silo.
//!
//! See `virt/krun/README.md` for the libkrun build-feature policy.

mod builder;
mod config;
mod error;
mod serial;
mod vm;
mod watchdog;

pub use crate::builder::VirtualMachineBuilder;
pub use crate::config::{
    validate_config, Disk, KrunConfig, Mount, NetTap, NetUnixgram, NetUnixstream, Network,
    VsockPort, DEFAULT_ID,
};
pub use crate::error::{KrunBackendError, Result};
pub use crate::serial::SerialConnection;
pub use crate::vm::VirtualMachine;
