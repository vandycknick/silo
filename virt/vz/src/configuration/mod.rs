mod boot_loader;
mod platform;
mod vm_config;

pub use boot_loader::LinuxBootLoader;
pub use platform::{GenericMachineIdentifier, GenericPlatform};
pub use vm_config::VirtualMachineConfiguration;
