//! Private storage models used by libvm's store backends.
//!
//! Types in this module are the serialized database/domain rows used inside the
//! crate. They are intentionally `pub(crate)` so public callers cannot couple to
//! SQLite schema details, machine IDs, lock IDs, vmmon PID bookkeeping, or the
//! exact persisted network representation. Public read and input types live in
//! `machine` and `network` and are converted at the crate boundary.

mod db_config;
mod machine;
mod machine_id;
mod network;

pub(crate) use db_config::DbConfig;
pub(crate) use machine::{MachineConfig, MachineRuntimeState, MachineState};
pub(crate) use machine_id::{looks_like_id_prefix, MachineId};
pub(crate) use network::{
    MachineNetworkConfig, NetworkDefinition, NetworkDriverPreference, NetworkInstanceState,
    NetworkTopology,
};
pub(crate) use network::{NetworkAttachment, NetworkInstance};
