//! Rust library boundary for managing Bento virtual machines.
//!
//! `Runtime` is the service entry point. It creates or resolves machines and
//! returns `Machine` handles for lifecycle and stream operations. Read output is
//! returned as owned `MachineData` snapshots so callers do not depend on
//! internal persistence models.
//!
//! ```rust,no_run
//! use bento_libvm::{MachineRef, Runtime};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), bento_libvm::LibVmError> {
//!     let runtime = Runtime::from_env().await?;
//!     let machine = runtime.get_machine(&MachineRef::parse("devbox")?).await?;
//!     let data = machine.inspect().await?;
//!
//!     println!("{} is {:?}", data.name, data.status);
//!     Ok(())
//! }
//! ```

mod error;
pub mod host;
mod instance;
mod lock_manager;
mod machine;
mod mount_path;
mod network;
mod network_policy;
mod paths;
mod root_disk;
mod runtime;
mod store;
mod vmmon;

pub use crate::error::LibVmError;
pub use crate::host::{ensure_certificate_authority, CertificateAuthority};
pub use crate::machine::{
    Machine, MachineCreate, MachineData, MachineExitCommand, MachineRef, MachineStartOptions,
    MachineStatus, MachineUpdate,
};
pub use crate::mount_path::resolve_mount_location;
pub use crate::network::{
    MachineNetworkConfig, NetworkDefinition, NetworkDriverKind, NetworkDriverPreference,
    NetworkTopology,
};
pub use crate::network_policy::NetworkPolicyRef;
pub use crate::runtime::{
    NetdRuntimeConfig, PathChoice, Runtime, RuntimeConfig, RuntimeNetworkingConfig,
};
pub use crate::vmmon::DEFAULT_GUEST_READINESS_TIMEOUT;
