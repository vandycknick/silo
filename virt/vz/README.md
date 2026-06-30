# vz

`vz` is a safe Rust wrapper around Apple's `Virtualization.framework` for the Linux guest path used by BentoBox today.

The crate exposes:

- builder-based virtual machine configuration
- typed device configuration modules
- async virtual machine lifecycle APIs
- safe device wrappers for serial ports and virtio sockets

`vz` may use `unsafe` internally to bridge Objective-C and Grand Central Dispatch, but it does not expose unsafe methods or require callers to uphold unsafe invariants across the crate boundary.

## Scope

Current scope focuses on the Linux guest path supported today:

- Linux boot loader
- generic platform and machine identifiers
- NAT networking
- virtio block devices
- virtio filesystem shares
- serial ports
- virtio sockets
- entropy devices
- memory balloon devices

## Requirements

- macOS 11 or later
- `com.apple.security.virtualization` entitlement
- Apple `Virtualization.framework`

## Example

```rust,no_run
use std::path::PathBuf;

use vz::{
    device::{
        EntropyDeviceConfiguration, MemoryBalloonDeviceConfiguration, NetworkDeviceConfiguration,
        SerialPortConfiguration, SharedDirectory, SingleDirectoryShare,
        SocketDevice, SocketDeviceConfiguration, StorageDeviceConfiguration,
        VirtioFileSystemDeviceConfiguration,
    },
    GenericPlatform, LinuxBootLoader, VirtualMachine,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut boot_loader = LinuxBootLoader::new("/path/to/kernel");
    boot_loader
        .set_initial_ramdisk("/path/to/initramfs")
        .set_command_line("console=hvc0 root=/dev/vda");

    let shared_dir = SharedDirectory::new(PathBuf::from("/path/to/share"), false);
    let single_share = SingleDirectoryShare::new(shared_dir);
    let mut fs_config = VirtioFileSystemDeviceConfiguration::new("share");
    fs_config.set_share(single_share);

    let serial_port = SerialPortConfiguration::virtio_console();

    let vm = VirtualMachine::builder()?
        .set_cpu_count(2)
        .set_memory_size(512 * 1024 * 1024)
        .set_platform(GenericPlatform::new())
        .set_boot_loader(boot_loader)
        .add_entropy_device(EntropyDeviceConfiguration::new())
        .add_memory_balloon_device(MemoryBalloonDeviceConfiguration::new())
        .add_network_device(NetworkDeviceConfiguration::nat())
        .add_serial_port(serial_port)
        .add_socket_device(SocketDeviceConfiguration::new())
        .add_storage_device(StorageDeviceConfiguration::new(
            PathBuf::from("/path/to/rootfs.img"),
            false,
        )?)
        .add_directory_share(fs_config)
        .build()?;

    let mut state_updates = vm.subscribe_state();
    vm.start().await?;
    vm.wait_for_state(vz::VirtualMachineState::Running).await?;

    if state_updates.changed().await.is_ok() {
        println!("vm state changed: {:?}", *state_updates.borrow());
    }

    let mut serial = serial_port.open_stream()?;
    tokio::io::AsyncWriteExt::write_all(&mut serial, b"hello serial\n").await?;

    let socket = vm
        .open_devices()?
        .into_iter()
        .next()
        .expect("socket device configured");
    let mut stream = socket.connect(1024).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello").await?;

    vm.stop().await?;
    Ok(())
}
```
