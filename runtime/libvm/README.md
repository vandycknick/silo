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
creates `state.db`, and stores the resolved root contract in `db_config`. Later
opens use that row to keep existing installs stable even if code defaults change.

The persisted root contract stores only main roots:

- `data_root`: durable manager state. `state.db`, machines, assets, keys, and
  `secrets.json` derive from this root.
- `run_root`: transient runtime state. Locks and network runtime directories
  derive from this root.
- `image_root`: local image and cache storage.

`db_config` is a singleton row with `id = 1`. It records the host `os`,
`data_root`, `run_root`, `image_root`, `created_at`, and `modified_at`. Derived
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
| `net/`         | `run_root/net`           |

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
