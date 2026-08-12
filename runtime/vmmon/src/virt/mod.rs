//! Virtualization backend abstraction.
//!
//! This module owns everything between vmmon and the hypervisor: a
//! backend-independent machine description ([`VmConfig`]), a clone-able
//! runtime handle ([`VirtualMachine`]), the serial console fan-out
//! ([`SerialConsole`]), and vsock stream types shared by all backends.
//!
//! Backends implement the crate-private [`backend::VirtBackend`] trait:
//! `krun` (libkrun via a helper process) on Linux, `vz`
//! (Virtualization.framework) on macOS, and — behind the `mock-backend`
//! feature — an in-process mock that fakes the guest side for tests.
//! Selection is pinned per platform today ([`BackendKind::default_for_host`])
//! but every machine can be created on an explicit backend via
//! [`VirtualMachine::with_backend`].

// The re-exports below are the module's full public surface. Which of them
// are referenced varies by target platform, compiled features, and test cfg,
// so unused-import warnings here are expected noise.
#![allow(unused_imports)]

mod backend;
mod config;
mod error;
mod machine;
mod serial;
mod stream;

pub use backend::{Availability, BackendKind};
pub use config::{
    DiskImage, KrunOptions, MachineIdentifier, MockOptions, NetworkMode, SharedDirectory, VmConfig,
    VmConfigBuilder, VmExit, VsockPort, VsockPortMode, VzOptions,
};
pub use error::VirtError;
pub use machine::VirtualMachine;
pub use serial::{SerialAccess, SerialConsole, SerialStream};
pub use stream::{VsockListener, VsockStream};
