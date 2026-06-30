mod balloon;
mod entropy;
mod filesystem;
mod network;
mod serial;
mod socket;
mod storage;

pub use balloon::MemoryBalloonDeviceConfiguration;
pub use entropy::EntropyDeviceConfiguration;
pub use filesystem::{
    LinuxRosettaDirectoryShare, SharedDirectory, SingleDirectoryShare,
    VirtioFileSystemDeviceConfiguration,
};
pub use network::NetworkDeviceConfiguration;
pub use serial::{SerialPortConfiguration, SerialPortStream};
pub use socket::{
    SocketDevice, SocketDeviceConfiguration, VirtioSocketConnection, VirtioSocketDevice,
    VirtioSocketListener,
};
pub use storage::StorageDeviceConfiguration;
