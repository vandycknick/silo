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
`vmmon` stops the VM when the program exits:

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

The first runtime open resolves root defaults from process configuration,
creates `state.db`, and stores the durable root contract in `db_config`.
Later opens require explicit durable roots to match that contract. The run root
is resolved again for each open and is intentionally not database identity.

The persisted root contract stores only main roots:

- `data_root`: durable manager state. `state.db`, machines, assets, keys, and
  `secrets.json` derive from this root.
- `state_root`: durable operational state, defaulting to
  `$XDG_STATE_HOME/silo` or `$HOME/.local/state/silo`.
- `image_root`: local image and cache storage.

The run root is selected per open from an explicit configuration value,
`$XDG_RUNTIME_DIR/silo`, or `/tmp/silo-<effective-uid>`. It is never stored in
the database. Its final directory must be a non-symlink directory owned by the
effective user with exact mode `0700`.

`db_config` is a singleton row with `id = 1`. It records the host `os`,
`data_root`, `state_root`, `image_root`, `created_at`, and `modified_at`. Derived
paths are not duplicated in the row unless they become independently
configurable. The derivation is:

| Path           | Derived from             |
| -------------- | ------------------------ |
| `state.db`     | `data_root/state.db`     |
| `machines/`    | `data_root/machines`     |
| `assets/`      | `data_root/assets`       |
| `keys/`        | `data_root/keys`         |
| `secrets.json` | `data_root/secrets.json` |
| `images/`      | `image_root`             |
| `locks/`       | `run_root/locks`         |
| `machines/<id>/vm.pid` | `run_root/machines/<id>/vm.pid` |
| `machines/<id>/vm.sock` | `run_root/machines/<id>/vm.sock` |
| `machines/<id>/<uds>` | enabled public vsock mux |
| `machines/<id>/<uds>_<port>` | extension-owned guest-to-host listener |
| `networks/`    | `run_root/networks`      |
| machine logs and exit records | `state_root/logs/machines/<id>/` |
| private-network logs | `state_root/logs/machines/<id>/network/` |

### State Database Reset

This release has one new state and image-cache baseline and does not upgrade old
migrations or cache metadata. With every Silo process stopped, remove all local
Silo state from the previous release, including `state.db`, machine directories,
logs, and the image cache, before opening the new runtime. Silo does not adopt old
database, machine, runtime, or cache files.

## Runtime Components

`Runtime::new` resolves `vmmon`, `netd`, `krun`, `kernel-default`, `initramfs`,
and `agent` once, validates them as absolute paths, and retains that immutable
set for the runtime lifetime. Machine starts launch the resolved absolute
`vmmon` path directly. `vmmon` receives the resolved absolute `krun` path as
private launch state and keeps the `vmmon -> krun` process boundary intact.
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
listener and must close and unlink it; vmmon owns and cleans up only its mux and
private backend sockets. See the [hybrid vsock guide](../../docs/hybrid-vsock.md)
for protocol examples, retries, security, limits, and shutdown behavior.

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

- `stopped`: no live `vmmon` is associated with the VM.
- `starting`: a start transaction owns the VM and is waiting for the host-side
  `vmmon` startup handshake to finish.
- `running`: `vmmon` is alive and the host-side startup handshake succeeded.
- `stopping`: a stop signal was sent to `vmmon` and Silo is waiting for the
  monitor to exit.
- `error`: the VM is not usable until an explicit lifecycle command repairs or
  replaces the state.

Guest-agent readiness is not part of the host-side lifecycle lock. A VM can be
`running` while the CLI is still waiting for the guest agent to register.

See the generated Rust docs for the full method and field-level API.
