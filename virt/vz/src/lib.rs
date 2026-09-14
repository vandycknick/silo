//! Safe Rust abstractions over Apple's Virtualization.framework for Silo.

#[cfg(not(target_os = "macos"))]
compile_error!("vz only supports macOS hosts");

mod error;
mod vm;

pub mod configuration;
pub mod device;
pub mod dispatch;

mod utils;

pub use crate::configuration::{
    GenericMachineIdentifier, GenericPlatform, LinuxBootLoader, VirtualMachineConfiguration,
};
pub use crate::error::VzError;
pub use crate::utils::{
    rosetta_availability, virtual_machine_limits, RosettaAvailability, VirtualMachineLimits,
};
pub use crate::vm::{VirtualMachine, VirtualMachineDelegate, VirtualMachineState};
