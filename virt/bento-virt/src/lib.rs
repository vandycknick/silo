#[cfg(target_os = "linux")]
mod krun;
mod machine;
mod platform;
mod serial;
mod stream;
mod types;
#[cfg(target_os = "macos")]
mod vz;

pub use crate::machine::VirtualMachine;
pub use crate::serial::{spawn_serial_tunnel, SerialAccess, SerialConsole, SerialStream};
pub use crate::stream::{VsockListener, VsockStream};
pub use crate::types::{
    DiskImage, MachineIdentifier, NetworkMode, SharedDirectory, VirtError, VmConfig,
    VmConfigBuilder, VmExit, VsockPort, VsockPortMode,
};
