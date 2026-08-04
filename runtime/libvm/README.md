# libvm

`libvm` is the Rust library boundary for managing Silo virtual machines.
It gives callers a `Runtime` entry point, then returns `Machine` handles for
lifecycle operations.

Use it when you need to create, resolve, inspect, start, stop, or remove Silo
VMs from Rust code. The crate keeps database rows, runtime state files, and
process details behind the API boundary.

```rust
use libvm::{MachineRef, Runtime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), libvm::LibVmError> {
    let runtime = Runtime::from_env().await?;
    let machine = runtime.get_machine(&MachineRef::parse("devbox")?).await?;

    let data = machine.inspect().await?;
    println!("{} is {:?}", data.name, data.status);

    if !data.is_running() {
        machine.start().await?;
    }

    Ok(())
}
```

The main shapes are:

- `Runtime`, the service entry point.
- `Machine`, an operable handle for one VM.
- `MachineCreate` and `MachineUpdate`, request DTOs for caller input.
- `MachineInspectData`, an owned snapshot returned by inspect and mutation calls.

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
| `networks/`    | `run_root/networks`      |
| machine logs and exit records | `state_root/logs/machines/<id>/` |
| private-network logs | `state_root/logs/machines/<id>/network/` |

## Machine Logs

Machine-owned durable logs have one configured state-root layout. The immutable
machine ID, rather than a display name or changing private-network instance ID,
selects the owner directory:

```text
<state-root>/logs/machines/<machine-id>/
  vm.trace.log
  serial.log
  vm.exit.json
  network/
    netd.log
    audit.jsonl
  executions/
    <machine-run-id>/<execution-id>/
```

`vm.trace.log`, `serial.log`, `network/netd.log`, and
`network/audit.jsonl` append across machine starts. `vm.exit.json` is a private,
atomically replaced lifecycle record, not a byte-log source. The `executions/`
subtree is reserved for card 119's startup-execution segments and terminal
records; ordinary `Machine::exec` sessions never create durable execution
history.

Use `Machine::logs` to read logs. It selects exactly one semantic
`MachineLogSource` (`Monitor`, `Serial`, `Network`, or `NetworkAudit`) and
returns byte chunks with an output channel. It deliberately does not expose log
paths or filenames. Network sources return `MachineLogSourceUnavailable` when
the machine has no private network.

With `MachineLogOptions::default()`, the returned stream is a finite snapshot
of bytes present when the selected file is opened. With `follow: true`, it emits
that same snapshot and then appended bytes without a snapshot-to-follow gap. A
missing file is an empty snapshot. A following stream waits for initial file
creation and remains attached while the machine is stopped and across later
starts. It ends when the reader drops the stream.

The CLI currently exposes monitor diagnostics through `silo logs [--follow]`.
Card 120 will map public stream names to the same semantic sources, including
workload replay added by card 119, without exposing filesystem layout.

### State Database Reset

This release has one new database baseline and does not upgrade old migration
history. With every Silo process stopped, manually archive or remove an existing
`state.db` before opening the new runtime. Silo does not adopt old database or
runtime files.

## Runtime Components

`Runtime::new` resolves `vmmon`, `netd`, `krun`, `kernel-default`, `initramfs`,
and `agent` once, validates them as absolute paths, and retains that immutable
set for the runtime lifetime. Machine starts launch the resolved absolute
`vmmon` path directly. `vmmon` receives the resolved absolute `krun` path as
private launch state and keeps the `vmmon -> krun` process boundary intact.
Private networking launches the resolved absolute `netd` path directly.

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
