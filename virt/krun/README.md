# krun

`krun` is Silo's libkrun integration crate and helper binary.

The crate exposes:

- a process-backed `VirtualMachineBuilder`
- a `VirtualMachine` handle for lifecycle management
- a `SerialConnection` wrapper for helper stdio access
- typed disk, mount, and vsock configuration structs

The `krun` binary is intentionally small. It parses Silo's flat helper arguments, configures libkrun directly, and then enters the VM. It does not use the library builder and does not expose subcommands.

## Boundary

The library and binary have different jobs, and keeping that split intact prevents callers like `vmmon` from linking against libkrun directly.

Library responsibilities:

- hold typed configuration structs
- perform structural config validation only, such as non-zero CPU and memory values
- build the flat helper command line
- spawn and manage the `krun` helper process
- set up PTY-backed stdio when `stdio_console(true)` is requested
- expose process lifecycle and serial ownership handles

Binary responsibilities:

- parse flat helper arguments
- call the source-integrated libkrun APIs through a helper-private adapter
- convert paths, strings, and libkrun return codes into contextual errors
- enter the VM

Do not import `libkrun` from library modules. Direct libkrun access belongs in the helper-private adapter below `src/bin/krun`. The library is a launcher/wrapper around the helper binary, not a libkrun API facade.

## Scope

Current scope focuses on the libkrun path used by Silo today:

- direct kernel and initramfs boot
- raw block devices
- virtiofs mounts
- vsock ports backed by Unix sockets
- stdio console output
- process-backed VM lifecycle management from Rust callers

Planned follow-up scope includes:

- richer `VirtualMachine` lifecycle state
- graceful shutdown when libkrun exposes a host-side shutdown path we can rely on
- higher-level serial and vsock convenience helpers

## Requirements

- Rust toolchain
- access to the pinned public libkrun fork when Cargo dependencies are fetched
- Linux or macOS host support matching the compiled libkrun backend

## Source Integration

The optional `krun-bin` Cargo feature compiles the pinned libkrun fork directly into the helper executable. Building the launcher library alone does not activate or link libkrun, preserving the process boundary for `vmmon` and other callers.

The helper uses a narrow private adapter rather than generated C bindings. It owns context cleanup, string conversion, the small set of C API constants Silo uses, and negative return-code handling. The resulting runtime does not require `libkrun.so`, `libkrun.dylib`, or `libkrunfw`.

The `blk` and `net` APIs are selected at compile time through fixed Cargo features. Runtime feature probing is unnecessary because a helper missing either API cannot compile.

## libkrun Build Features

Silo's intended libkrun build keeps the upstream library narrow while preserving the current krun backend behavior:

```text
--no-default-features --features blk --features net
```

That means Silo intentionally builds libkrun with these features enabled:

| Feature | Purpose | Silo policy |
| --- | --- | --- |
| `blk` | Enables virtio-block devices. | Keep. Required for `--disk` and Silo disk images. |
| `net` | Enables virtio-net devices for unixgram, unixstream, and tap networking. | Keep. Required for Silo networking modes. |

Silo intentionally leaves these libkrun features disabled for now:

| Feature | Purpose | Silo policy |
| --- | --- | --- |
| `init-blob` | Embeds libkrun's default guest init binary. This is an upstream default feature. | Disable with `--no-default-features`. Silo requires explicit boot inputs and the helper disables implicit init. |
| `gpu` | Enables virtio-gpu, Venus, and native-context graphics support. | Disable. Silo has no krun GPU path today. |
| `snd` | Enables virtio-snd audio support. | Disable. Silo has no krun audio path today. |
| `input` | Enables input device support for GUI/input passthrough. | Disable. Silo has no krun input-device path today. |
| `efi` | Enables EFI boot support and implies `blk` and `net`. | Disable. Silo uses explicit external kernel/initramfs boot instead of EFI firmware boot. |
| `tee` | Enables trusted execution environment plumbing. | Disable unless Silo grows a confidential-compute krun backend. |
| `amd-sev` | Enables AMD SEV, SEV-ES, and SEV-SNP support. Implies `blk` and `tee`. | Disable unless Silo grows an SEV backend. |
| `tdx` | Enables Intel TDX support. Implies `blk` and `tee`. | Disable unless Silo grows a TDX backend. |
| `aws-nitro` | Enables AWS Nitro Enclaves support and its specialized init path. | Disable unless Silo grows a Nitro backend. |
| `virgl_resource_map2` | Enables an optional virglrenderer GPU API used by some virtio-gpu builds. | Disable with `gpu`. It has no use without the GPU path. |

If a new krun feature is exposed through Silo, update this table, enable the matching Cargo feature, and add only the required helper adapter methods. Do not enable upstream libkrun features speculatively. The tiny VM goblin gets one feature only when it can point to the code that uses it.

## Example

```rust,no_run
use std::io::{Read, Write};

use krun::{Disk, VirtualMachineBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vm = VirtualMachineBuilder::new("/usr/local/bin/krun")
        .cpus(2)
        .memory_mib(1024)
        .kernel("/path/to/kernel")
        .initramfs("/path/to/initramfs")
        .cmdline(vec!["console=hvc0".to_string(), "panic=1".to_string()])
        .disk(Disk {
            block_id: "root".to_string(),
            path: "/path/to/rootfs.img".into(),
            read_only: false,
        })
        .stdio_console(true)
        .start()?;

    let mut serial = vm.serial()?;
    serial.write_all(b"hello serial\n")?;

    let mut buffer = [0; 1024];
    let _ = serial.read(&mut buffer)?;

    vm.shutdown()?;
    Ok(())
}
```

The public crate API is process-backed because Silo uses the `krun` helper as the libkrun execution boundary. The helper binary remains single-purpose and direct-to-libkrun, while Rust callers use the builder and VM handle facade without linking libkrun themselves.
