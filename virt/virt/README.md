# virt

`virt` is Silo's host virtualization facade.

The crate exposes:

- a `VirtualMachine` handle for creating and managing host VMs
- serial and vsock access types consumed by `vmmon`
- typed VM configuration structs shared by the monitor and backend drivers

`virt` does not expose user-selectable backend routing. Silo chooses the host implementation at compile time. The exported `VirtualMachine` type is Silo's per-instance VM handle; it is not the guest OS and not the underlying VMM implementation.

## Scope

Current scope focuses on the VM execution path used by Silo today:

- direct Linux kernel and initramfs boot
- root and data disks
- shared directory mounts
- userspace networking attachments
- serial console access
- host-to-guest and guest-to-host vsock access
- VM lifecycle management from `vmmon`

## Platform Behavior

| Host platform | Driver | Underlying implementation |
| ------------- | ------ | ------------------------- |
| macOS | `vz` | Apple `Virtualization.framework` |
| Linux | `krun` | libkrun through the `krun` helper |

The public VM spec does not include a backend field. Callers describe the VM they want; `virt` compiles the appropriate host path.

## Boundary

`vmmon` owns supervision, monitor APIs, guest readiness, and process lifecycle around one running VM.

`virt` owns only the host virtualization boundary:

- validate host VM configuration
- create the host-selected VM implementation
- start and stop the VM
- open serial and vsock handles
- report VM exit state

Do not put manager policy, image resolution, global machine inventory, or monitor daemon behavior in this crate.

## Example

```rust,no_run
use virt::{DiskImage, NetworkMode, VirtualMachine, VmConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VmConfig::builder("dev")
        .vm_id("vm123")
        .cpus(2)
        .memory(2048)
        .base_directory("/tmp/silo-dev")
        .kernel("/path/to/kernel")
        .initramfs("/path/to/initramfs")
        .network(NetworkMode::None)
        .root_disk(DiskImage {
            path: "/path/to/rootfs.img".into(),
            read_only: false,
        })
        .build();

    let vm = VirtualMachine::new(config)?;
    vm.start().await?;
    vm.stop().await?;
    Ok(())
}
```

See [`docs/terminology.md`](../../docs/terminology.md) for the vocabulary used around VMs, VMMs, hypervisors, KVM, microVMs, backend drivers, and the Silo runtime layers.
