//! Process-backed libkrun helper API for Silo.
//!
//! See `virt/krun/README.md` for the libkrun build-feature policy.

mod builder;
mod config;
mod error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod host;
mod rosetta;
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
#[cfg(target_os = "macos")]
pub use crate::host::{check_host, HvfHostError, HvfHostInfo};
pub use crate::rosetta::{
    CapturedResponse, RosettaConfigError, RosettaLaunchConfig, RosettaProfileId,
};
pub use crate::serial::SerialConnection;
pub use crate::vm::VirtualMachine;
