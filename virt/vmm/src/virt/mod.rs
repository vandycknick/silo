//! Virtualization backend abstraction.
//!
//! This module owns everything between silo-vmm and the hypervisor: a
//! backend-independent machine description ([`VmConfig`]), a clone-able
//! runtime handle ([`VirtualMachine`]), the serial console fan-out
//! ([`SerialConsole`]), and vsock stream types shared by all backends.
//!
//! Backends implement the crate-private [`backend::VirtBackend`] trait:
//! `krun` (libkrun via a helper process) on Linux and macOS, `vz`
//! (Virtualization.framework) on macOS, and — behind the `mock-backend`
//! feature — an in-process mock that fakes the guest side for tests.
//! The startup capability selection resolves the backend once; every machine
//! is created on that explicit backend via [`VirtualMachine::with_backend`].

// The re-exports below are the module's full public surface. Which of them
// are referenced varies by target platform, compiled features, and test cfg,
// so unused-import warnings here are expected noise.
#![allow(unused_imports)]

mod backend;
pub(crate) mod capacity;
mod config;
mod error;
pub(crate) mod exit;
pub mod lifecycle;
mod machine;
mod serial;
mod stream;

#[cfg(all(test, feature = "mock-backend"))]
pub(crate) use backend::mock::test_storage_launch;
pub use backend::BackendKind;
pub(crate) use backend::CaptureSource;
pub use backend::HostMemoryReclaimReport;
pub(crate) use backend::StorageFinalization;
pub(crate) use capacity::VsockLease;
pub use config::{
    KrunOptions, MachineIdentifier, MockOptions, NetworkMode, RosettaIntent, RosettaProfile,
    SharedDirectory, VmConfig, VmConfigBuilder, VzOptions,
};
pub(crate) use config::{RestoreLaunch, StorageLaunch};
pub use error::VirtError;
pub use exit::VmExit;
pub use machine::VirtualMachine;
pub use serial::{SerialConsole, SerialStream};
pub use stream::{VsockListener, VsockStream};
