# libvm

`libvm` is the Rust library boundary for managing Silo virtual machines.
It gives callers a `Runtime` entry point, then returns `Machine` handles for
lifecycle operations.

Use it when you need to create, resolve, inspect, start, stop, restart, or
remove Silo VMs from Rust code. The crate keeps database rows, runtime state
files, image materialization, and monitor processes behind the API boundary.

```rust,no_run
use libvm::{Memory, Runtime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), libvm::LibVmError> {
    let runtime = Runtime::from_env().await?;
    let machine = runtime
        .machine()
        .image("docker.io/library/alpine:latest")
        .name("devbox")
        .cpus(2)
        .memory(Memory::mebibytes(1024))
        .create()
        .await?;

    // A normal start boots an idle machine.
    machine.start().await?;
    let data = machine.inspect().await?;
    println!("{} is {:?}", data.name, data.status);

    machine.stop().await?;

    Ok(())
}
```

The main shapes are:

- `Runtime`, the service entry point.
- `MachineBuilder`, the durable image-first creation request.
- `Machine`, an operable handle for one VM.
- `MachineData`, an owned snapshot returned by inspect and lifecycle calls.

## Creation And Lifecycle

`MachineBuilder::image` always accepts an OCI reference. Use
`image_source(ImageSource::disk(path))` for a local disk. `create` materializes
the selected root disk and persists a stopped machine; it never starts the VM.

`Machine::start` and `Machine::stop` manage a persisted machine. A normal start
creates an idle VM. `Machine::start_with` can instead set one
`Entrypoint`; startup succeeds only after that guest program launches, and
`silo-vmm` stops the VM when the program exits:

```rust,no_run
use libvm::Runtime;

# async fn example(runtime: Runtime) -> Result<(), libvm::LibVmError> {
# let machine = runtime.machine().image("docker.io/library/alpine:latest").create().await?;
let start = machine
    .start_with(|options| {
        options.entrypoint("/usr/bin/printf", |entrypoint| {
            entrypoint.arg("hello from silo\\n")
        })
    })
    .await?;
let exit = machine.wait().await?;
println!("run {} ended: {:?}", start.run_id, exit.outcome);
# Ok(())
# }
```

`MachineRetention::Persistent` keeps a machine until removal.
`MachineRetention::Ephemeral` permits a lifecycle owner to attempt removal after
the run exits. Cleanup is best effort and is not persisted or retried.

## Process Configuration

`ProcessConfig` is durable desired process configuration stored with the
machine. It preserves OCI `Entrypoint` and `Cmd` separately, including the
distinction between omitted and explicitly empty values, plus the environment,
working directory, and user selector. Configure it at creation with
`MachineBuilder::process`, or with the individual process builder methods, and
read it from `MachineData::process`.

The process configuration does not turn an ordinary `start` into a workload
launch. It lets higher-level callers retain and resolve their intended process
without reconstructing image metadata.

## Runtime Roots

A local runtime has two roots (see
[ADR 0017](../../docs/adr/0017-single-host-state-root.md)):

- The **home** holds all persistent state. It defaults to `~/.silo`;
  `SILO_HOME` overrides it and must be absolute. Pass an explicit home with
  `RuntimeConfig::local(home)` or `RuntimeBuilder::home(..)`, and read the
  resolved value back with `Runtime::local_home()`.
- The **run root** is always `/tmp/silo-<effective-uid>` and holds generated
  sockets, pidfiles, and locks. A fixed short root keeps Unix socket paths under
  the `sun_path` limit regardless of the home path. Its final directory must be
  a non-symlink directory owned by the effective user with exact mode `0700`.

Configuration is separate: `libvm::HostPaths` resolves the config directory
`${XDG_CONFIG_HOME:-~/.config}/silo`, with `<home>/config.yaml` as a fallback
config file read only when the XDG one is absent. No other XDG variable is
consulted.

`db_config` is a singleton row with `id = 1` that records only the host `os`,
`created_at`, and `modified_at`. No root path is stored in the database. The
derivation is:

| Path           | Derived from             |
| -------------- | ------------------------ |
| `state.db`     | `home/state.db`          |
| `machines/<id>/` | `home/machines/<id>` (launch config, disks, initramfs) |
| `keys/`        | `home/keys`              |
| `secrets.json` | `home/secrets.json`      |
| `images/`      | `home/images`            |
| machine logs and exit records | `home/logs/machines/<id>/` |
| private-network logs | `home/logs/machines/<id>/network/` |
| `locks/`       | `run_root/locks`         |
| `machines/<id>/vm.pid` | `run_root/machines/<id>/vm.pid` |
| `machines/<id>/vm.sock` | `run_root/machines/<id>/vm.sock` |
| `machines/<id>/vm.lock` | `run_root/machines/<id>/vm.lock` |
| `machines/<id>/<uds>` | enabled public vsock mux |
| `machines/<id>/<uds>_<port>` | extension-owned guest-to-host listener |
| `networks/`    | `run_root/networks`      |

### State Database Reset

This release has one new state and image-cache baseline and does not upgrade old
migrations or cache metadata. With every Silo process stopped, remove all local
Silo state from the previous release, including `state.db`, machine directories,
logs, and the image cache, before opening the new runtime. Silo does not adopt old
database, machine, runtime, or cache files.

## Runtime Components

`Runtime::new` resolves `silo-vmm`, `netd`, `kernel-default`, `initramfs`,
and `agent` once, validates them as absolute paths, and retains that immutable
set for the runtime lifetime. `SILO_VMM_PATH`, or
`RuntimeConfig::with_supervisor_path` / `RuntimeBuilder::supervisor_path`,
replaces only the `silo-vmm` path. Machine starts launch the resolved absolute
`silo-vmm` path directly. For the krun backend,
silo-vmm re-executes itself with argv[0] `krun` to run libkrun in a
private worker, so there is no separate krun component to resolve (see
[silo-vmm architecture](../../docs/architecture/silo-vmm.md)).
Private networking launches the resolved absolute `netd` path directly.

## Hybrid Vsock Paths

`Machine::vsock_socket()` returns the public host-to-guest mux path when
`VmSpec.vsock.enabled` is true. `Machine::vsock_listener_socket(port)` returns
the path an extension can bind for guest-to-host traffic. Both methods read the
current stored configuration, use the default `vsock.sock` filename or the
configured `uds`, and return `None` when vsock is omitted or disabled. Listener
paths also return `None` for Silo's reserved host port 1027.

Resolving an enabled path creates the owner-only machine runtime directory so an
extension can bind a listener before VM startup. The extension owns that
listener and must close it during shutdown. silo-vmm cleans up its mux and private
backend sockets, then libvm removes the complete machine runtime tree; extension
unlink attempts must therefore tolerate an already-removed path. See the
[hybrid vsock guide](../../docs/hybrid-vsock.md) for protocol examples, retries,
security, limits, and shutdown behavior.

Machine kernel, initramfs, and agent overrides remain independent. An omitted
asset always uses its matching file from the resolved installation set, so one
launch never combines defaults from separate installations. `libvm` performs
all component environment and controlled PATH resolution while opening the
runtime; launched helpers do not repeat discovery.

## Lifecycle States

`libvm` treats VM lifecycle mutations as lock-owned transactions. Commands
that change a VM, such as start, stop, update, and remove, serialize on the
machine lock. Observing commands, such as inspect and list, prefer returning the
last persisted state over blocking when another process owns the machine lock.

The persisted machine states mean:

- `stopped`: no live `silo-vmm` is associated with the VM.
- `starting`: a start transaction owns the VM and is waiting for the host-side
  `silo-vmm` startup handshake to finish.
- `running`: `silo-vmm` is alive and the host-side startup handshake succeeded.
- `stopping`: a stop signal was sent to `silo-vmm` and Silo is waiting for the
  monitor to exit.
- `error`: the VM is not usable until an explicit lifecycle command repairs or
  replaces the state.

Guest-agent readiness is not part of the host-side lifecycle lock. A VM can be
`running` while the CLI is still waiting for the guest agent to register.

See the generated Rust docs for the full method and field-level API.
