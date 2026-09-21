//! Libkrun configuration and process-owning engine.
//!
//! The `engine` feature exposes synchronous execution for dedicated worker
//! processes. Normal VM shutdown terminates the caller; it is not embeddable.
//!
//! See `virt/krun/README.md` for the libkrun build-feature policy.

mod config;
#[cfg(feature = "engine")]
pub mod engine;
mod error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod host;
#[cfg(feature = "engine")]
mod network;
mod rosetta;
mod status;

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
pub use crate::status::{HostMemoryReclaimQualification, HostMemoryReclaimStatus};
