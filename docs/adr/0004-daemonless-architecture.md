# 4. Daemonless VM Monitor Architecture

Date: 2026-04-06

## Status

Implemented

## Context

Silo needs a VM architecture that keeps the runtime surface small, focused, and flexible. Focussed on the following:

- keeps one monitor process scoped to one VM,
- starts from canonical machine configuration on disk,
- keeps the CLI thin,
- works well without a central always-on daemon,
- preserves room for a future daemon or tunnel mode without changing the machine model.

The chosen architecture is daemonless. `silo` calls into `libvm`, and `libvm` owns machine lifecycle in local ABI mode. When a machine starts, `libvm` spawns a dedicated `vmmon` process for that machine. `vmmon` reads the machine configuration from the instance directory, starts the VM, supervises it, and exposes the per-VM control surface.

This gives Silo the operational flexibility of a daemonless system while still leaving room for a future manager daemon. `libvm` is the boundary that preserves that split. It is the local engine today, and it can also become the client-side boundary for future daemon or tunnel mode without changing the monitor model.

## Decision

Silo adopts a daemonless, config-driven architecture with these roles:

- `silo` is a thin frontend over `libvm`.
- `silo-core` owns the canonical shared domain model, including `VmSpec`, machine identity types, and guest service configuration types.
- `libvm` owns manager-side lifecycle, machine inventory, on-disk layout, image policy, bootstrap materialization, host gRPC client behavior, and `vmmon` process spawning.
- `vmmon` is the canonical per-VM monitor. It is a small-footprint runtime supervisor that owns one running VM.
- `virt` is the host virtualization facade used by `vmmon`.

Canonical vocabulary for these layers lives in [`../terminology.md`](../terminology.md).

This architecture is intentionally daemonless by default. A future daemon or tunnel mode may be added later, but it must preserve the same `libvm` to `vmmon` boundary and the same per-VM monitor model.

## Goals

- Keep one `vmmon` process responsible for one VM.
- Make `silo` a thin consumer of `libvm`.
- Keep `vmmon` focused on runtime supervision instead of manager concerns.
- Make machine startup config-driven from the per-instance `config.yaml`.
- Keep `libvm` as the architectural boundary between daemonless local ABI mode and future daemon or tunnel mode.
- Keep one machine-scoped gRPC control socket for monitor, filesystem, serial, and shell access.
- Keep machine identity and manager metadata in manager-owned state, not in the monitor.

## Non-goals

- Introducing a central always-on daemon as the primary architecture.
- Moving global machine inventory into `vmmon`.
- Replacing `config.yaml` with database-only machine definitions.
- Defining the detailed host and guest gRPC contract, which belongs to [ADR 0008](0008-vmmon-host-and-guest-grpc-api.md).
- Defining the final future daemon API in this ADR.

## Component Boundaries

### `silo`

`silo` is a thin command-line frontend.

It owns:

- argument parsing,
- output formatting,
- terminal and stdio handling,
- calling `libvm`.

It does not own:

- machine lifecycle policy,
- direct monitor spawning,
- pidfile polling for startup,
- direct host gRPC protocol ownership,
- direct `vmmon` lifecycle management.

### `silo-core`

`silo-core` owns shared domain types.

It owns:

- the canonical `VmSpec`,
- machine identity types,
- well-known instance filenames,
- guest runtime and guest service configuration types,
- shared enums and structs used across crates.

It does not own:

- SQLite,
- filesystem policy,
- image policy,
- process management,
- RPC servers or RPC clients,
- host virtualization execution logic.

### `libvm`

`libvm` is the manager-side engine library.

It owns:

- machine create, start, stop, inspect, list, and remove,
- machine lookup by name, UUID, and UUID prefix,
- the top-level data directory and per-instance layout,
- SQLite manager state at `state.db`,
- UUID allocation,
- canonical `config.yaml` writing from `silo-core::VmSpec`,
- image resolution and instance materialization,
- bootstrap and guest runtime materialization,
- spawning `vmmon`,
- monitor stop signaling,
- generated host gRPC client behavior,
- manager-side status and stream attachment through `vmmon`.

It does not own:

- long-running per-VM supervision,
- host virtualization execution,
- guest-agent implementation.

The manager API is currently a library boundary implemented by `libvm`. A future remote manager may expose an equivalent API over the network, but that wire service does not exist yet and is not required for the daemonless architecture.

### `vmmon`

`vmmon` is the canonical per-VM monitor and supervisor.

It owns:

- reading `config.yaml` from the instance directory,
- self-daemonization by default,
- a foreground mode for tests and debugging,
- creating and supervising one VM,
- serving the host gRPC services defined by ADR 0008,
- runtime state for VM and guest readiness,
- serial attach, shell attach, and guest filesystem proxying,
- signal-driven shutdown.

It does not own:

- global machine inventory,
- machine lookup across all machines,
- manager metadata,
- image resolution,
- create or remove policy,
- future manager-daemon responsibilities.

`vmmon` should remain small and focused. It is a runtime monitor, not a general manager.

### `virt`

`virt` is the host virtualization facade.

It owns:

- host-specific VM execution,
- host VM configuration validation,
- VM lifecycle primitives,
- serial and vsock hooks consumed by `vmmon`.

It does not own:

- machine identity,
- machine inventory,
- manager APIs,
- monitor daemonization,
- manager-owned state.

## Canonical State Model

### Machine identity

- Every machine has a stable UUID.
- The manager identity is stored in SQLite.
- The per-instance directory name is the UUID rendered as 32 lowercase hex characters without dashes.
- Human-readable machine names are manager-owned aliases resolved through SQLite.

### Machine configuration

- `config.yaml` in the instance directory is the canonical machine configuration.
- `config.yaml` is written by `libvm` from `silo-core::VmSpec`.
- `vmmon` is data-dir-driven. It accepts `--data-dir` and reads `config.yaml` from that directory.

### Manager metadata

`state.db` stores manager-owned metadata, including:

- UUID to name mapping,
- name to UUID mapping,
- creation time,
- machine directory path.

SQLite does not replace `config.yaml` as the canonical VM boot contract.

### Runtime truth

- Runtime truth comes from `vmmon` while it is running.
- `libvm` may derive convenience status from monitor artifacts, but liveness and readiness are monitor-owned runtime concerns.

## On-disk Layout

The current canonical layout is:

```text
~/.local/share/silo/
  state.db
  machines/
    <uuid>/
      config.yaml
      vm.pid
      vm.sock
      vm.trace.log
      serial.log
      apple-machine-id
      rootfs.img
      cidata.img
  images/
    ...
```

`images/` remains manager-owned data.

Future work:

- runtime artifact filenames use `vm.pid`, `vm.sock`, and `vm.trace.log`,
- add a durable exit-state file if we decide that belongs in the canonical runtime contract.

Those filenames are part of the current implementation and should be treated as the canonical runtime contract.

## Canonical `VmSpec`

The canonical machine config type is `silo_core::VmSpec`.

Its current shape is:

```rust
pub struct VmSpec {
    pub version: u32,
    pub name: String,
    pub platform: Platform,
    pub resources: Resources,
    pub boot: Boot,
    pub storage: Storage,
    pub mounts: Vec<Mount>,
    pub network: Network,
    pub settings: Settings,
}

pub struct Platform {
    pub guest_os: GuestOs,
    pub architecture: Architecture,
}

pub struct Resources {
    pub cpus: u8,
    pub memory_mib: u32,
}

pub struct Boot {
    pub kernel: Option<std::path::PathBuf>,
    pub initramfs: Option<std::path::PathBuf>,
    pub kernel_cmdline: Vec<String>,
    pub bootstrap: Option<Bootstrap>,
}

pub struct Bootstrap {
    pub cloud_init: Option<std::path::PathBuf>,
}

pub struct Storage {
    pub disks: Vec<Disk>,
}

pub struct Disk {
    pub path: std::path::PathBuf,
    pub kind: DiskKind,
    pub read_only: bool,
}

pub enum DiskKind {
    Root,
    Data,
    Seed,
}

pub struct Mount {
    pub source: std::path::PathBuf,
    pub tag: String,
    pub read_only: bool,
}

pub struct Network {
    pub mode: NetworkMode,
}

pub struct Settings {
    pub nested_virtualization: bool,
    pub rosetta: bool,
    pub guest_enabled: bool,
}

pub enum GuestOs {
    Linux,
}

pub enum Architecture {
    Aarch64,
    X86_64,
}

pub enum NetworkMode {
    None,
    User,
    Bridged,
}
```

Guest service configuration used during bootstrap and readiness lives in `silo-core`, but it is not embedded directly inside `VmSpec` today.

## `vmmon` API and Protocol Ownership

`vmmon` exposes one machine-scoped gRPC endpoint on its Unix socket. The host
surface groups monitor state, readiness, metrics, SSH and serial streams, and
the guest filesystem proxy. `libvm` owns the generated clients and presents
manager-side domain types to the CLI.

[ADR 0008](0008-vmmon-host-and-guest-grpc-api.md) owns the service inventory,
protobuf contract, streaming behavior, readiness, health, reflection, and
guest-vsock API. This ADR owns only the process boundary.

The host API does not include a VM `Stop` RPC. Shutdown remains signal-driven
and manager-owned.

## `vmmon` Process Model

`vmmon` is data-dir-driven and per-instance.

The executable accepts:

- `--data-dir <instance-dir>`
- `--startup-fd <fd>`
- `--foreground`

`main.rs` handles argument parsing, logging setup, Tokio runtime creation, and process bootstrap. Startup, service hosting, runtime state, and shutdown are split into helper modules.

## Startup and Shutdown Semantics

### Startup

`libvm` spawns `vmmon` and passes a startup pipe.

`vmmon` reports a one-shot startup result over that pipe. The current wire format is simple:

```text
started
```

or:

```text
failed\t<message>
```

This startup handshake is used instead of an RPC `Start` call so the manager does not need to infer readiness by polling sockets or pidfiles.

Start succeeds once `vmmon` has successfully initialized supervision for the VM. It does not require guest readiness, SSH reachability, or guest service readiness.

### Shutdown

`libvm` stops a machine by signaling `vmmon`.

The current implementation uses `SIGINT` for the manager-triggered stop path, and `vmmon` also handles `SIGTERM`.

Shutdown behavior is:

- first signal requests graceful shutdown,
- `vmmon` transitions runtime state toward stopping,
- `vmmon` asks `virt` to stop the VM,
- a second signal forces immediate exit,
- `vmmon` exits after supervision shuts down.

Future work may refine signal choice and add a stronger durable exit-state contract, but the architecture remains signal-driven rather than monitor-RPC-driven.

## Consequences

### Positive

- The CLI stays thin and can remain stable across local and future remote modes.
- One monitor per VM creates a clean operational boundary.
- Machine startup is config-driven from canonical on-disk state.
- `vmmon` stays focused on runtime supervision with a small surface area.
- `libvm` can preserve a clean split between daemonless mode now and daemon or tunnel mode later.
- One typed gRPC endpoint keeps protocol ownership in `libvm` and `vmmon` while the CLI remains transport-agnostic.

### Negative

- The architecture introduces more explicit crate and process boundaries.
- Manager state in SQLite must remain consistent with instance directories.
- Signal-based stop and startup-pipe synchronization require careful contract maintenance.
- Some naming cleanup in runtime artifacts is still pending.

## Open Questions

- Whether a future remote manager should expose an `InstanceService` wire protocol, and what that exact surface should be.
- Whether `vmmon` should persist a canonical durable exit-state file as part of the runtime contract.
- Whether runtime artifact filenames should be renamed from the current `id.*` convention to explicit `vmmon` names.
- How future tunnel mode should transport manager operations without weakening the daemonless local ABI model.
