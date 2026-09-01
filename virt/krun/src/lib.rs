//! Process-backed libkrun helper API for Silo.
//!
//! See `virt/krun/README.md` for the libkrun build-feature policy.

mod builder;
mod config;
mod error;
#[cfg(target_os = "linux")]
mod host;
mod serial;
mod vm;
mod watchdog;

pub use crate::builder::VirtualMachineBuilder;
pub use crate::config::{
    validate_config, Disk, KrunConfig, Mount, NetTap, NetUnixgram, NetUnixstream, Network,
    DEFAULT_ID,
};
pub use crate::error::{KrunBackendError, Result};
#[cfg(target_os = "linux")]
pub use crate::host::{check_host, check_host_with_vm_creation, KvmHostError, KvmHostInfo};
pub use crate::serial::SerialConnection;
pub use crate::vm::VirtualMachine;
