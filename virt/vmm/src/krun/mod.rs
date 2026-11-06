//! Libkrun configuration, the process-owning engine, and the `krun`
//! worker that runs it. Normal VM shutdown terminates the calling process; the
//! engine is only ever executed inside the dedicated worker.

mod config;
pub(crate) mod engine;
mod error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod host;
mod network;
pub(crate) mod restore;
mod rosetta;
mod status;
pub(crate) mod storage_holder;
pub(crate) mod worker;

pub(crate) use crate::krun::config::{validate_config, KrunConfig, Mount, NetUnixgram, Network};
pub(crate) use crate::krun::error::KrunBackendError;
#[cfg(target_os = "linux")]
pub(crate) use crate::krun::host::check_host;
#[cfg(target_os = "macos")]
pub(crate) use crate::krun::host::{check_host, HvfHostError, HvfHostInfo};
pub(crate) use crate::krun::rosetta::{RosettaLaunchConfig, RosettaProfileId};
pub(crate) use crate::krun::status::{
    HostMemoryReclaimBacking, HostMemoryReclaimQualification, HostMemoryReclaimReason,
    HostMemoryReclaimStatus,
};
