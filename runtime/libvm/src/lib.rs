//! Rust library boundary for managing Bento virtual machines.
//!
//! `Runtime` is the service entry point. It creates or resolves machines and
//! returns `Machine` handles for lifecycle and stream operations. Read output is
//! returned as owned `MachineData` snapshots so callers do not depend on
//! internal persistence models.
//!
//! ```rust,no_run
//! use libvm::{MachineRef, Runtime};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), libvm::LibVmError> {
//!     let runtime = Runtime::from_env().await?;
//!     let machine = runtime.get_machine(&MachineRef::parse("devbox")?).await?;
//!     let data = machine.inspect().await?;
//!
//!     println!("{} is {:?}", data.name, data.status);
//!     Ok(())
//! }
//! ```

mod constants;
mod error;
mod guest_agent;
pub mod host;
mod image;
mod lock_manager;
mod machine;
mod network;
mod paths;
mod runtime;
mod store;
mod utils;
mod vmmon;

pub use crate::error::LibVmError;
pub use crate::host::{ensure_certificate_authority, CertificateAuthority};
pub use crate::image::{
    ImageBuilder, ImageDetail, ImageHandle, ImageLayerDetail, ImageProgress, ImageProgressReceiver,
    ImageProgressSender, ImagePruneReport, ImagePullOptions, ImagePullPolicy, ImageRemoveOptions,
    ImageSource, ImageSourceKind, Images,
};
pub use crate::machine::{
    resolve_mount_location, AttachOptions, AttachOptionsBuilder, ExecControl, ExecEvent,
    ExecHandle, ExecOptions, ExecOptionsBuilder, ExecOutput, ExecSink, ExitStatus, Machine,
    MachineBuilder, MachineData, MachineExit, MachineExitCommand, MachineExitOutcome,
    MachineKillOptions, MachineRef, MachineStartOptions, MachineStatus, MachineStopOptions,
    MachineUpdate, MachineWaitOptions, Memory, NetworkPolicyUpdate, StdinMode,
    DEFAULT_MACHINE_WAIT_TIMEOUT,
};
pub use crate::network::{
    MachineNetworkConfig, NetworkBuilder, NetworkDefinition, NetworkDriver, NetworkDriverKind,
    NetworkPolicyRef, NetworkTopology, PrivateNetworkPolicy,
};
pub use crate::runtime::{
    NetdRuntimeConfig, PathChoice, Runtime, RuntimeBuilder, RuntimeConfig, RuntimeNetworkingConfig,
};
pub use crate::vmmon::DEFAULT_GUEST_READINESS_TIMEOUT;
pub use bento_policy::NetworkPolicy;
