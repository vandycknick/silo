# libvm State Model

`libvm` keeps its public API above the storage boundary. A `Runtime` is a client facade for a Silo target; today the only target is local SQLite plus local instance directories, but the API is shaped so a future remote target can implement the same machine-management operations without exposing SQLite details.

The local target follows the same split Podman's libpod uses for containers, pods, and volumes: keep columns for identity, uniqueness, relationships, and hot lookups, and keep object-shaped static config and mutable state as JSON documents.

## Runtime Root

Each local runtime resolves one persistent home and one generated-state run
root (see [ADR 0017](../adr/0017-single-host-state-root.md)). `db_config` is a
singleton guard row that records only the host OS the database was created on;
it stores no root paths.

- Home defaults to `~/.silo` (`SILO_HOME` overrides it and must be absolute).
  It holds `state.db`, `machines/<id>/` (launch config, disks, initramfs),
  `logs/machines/<id>/` (durable machine logs and exit records),
  `logs/daemon/`, `images/`, `keys/`, `secrets.json`, and `run/` for
  fixed-name control sockets such as `docker.sock`.
- Run root is always `/tmp/silo-<euid>`, created `0700` and checked for owner
  and symlinks. It holds sockets, PID files, locks, and network runtime state.
  A fixed short root keeps Unix socket paths under the `sun_path` limit (104
  bytes on macOS, 108 on Linux) regardless of how long the home path is.

Schema compatibility is owned by SQLite migrations. `db_config` has no schema
version column.

This lets callers create independent Silo installations by constructing separate local runtime configs:

```rust,no_run
# use libvm::{Runtime, RuntimeConfig};
# async fn example() -> Result<(), libvm::LibVmError> {
let runtime = Runtime::new(RuntimeConfig::local("/var/lib/silo-dev")).await?;
# let _ = runtime;
# Ok(())
# }
```

The CLI still uses the default home through `RuntimeConfig::from_env()`, but the API does not require that default.

## Static Config

`machine_config` stores the stable machine identity and lookup fields as columns:

- `id`: stable machine UUID, rendered as 32 lowercase hex characters.
- `name`: user-facing unique alias.
- `config_json`: the full static `MachineConfig` document encoded as SQLite JSONB.

`config_json` contains the full static machine config snapshot, including:

- `id` and `name`, duplicated intentionally so the JSON document is self-describing.
- `spec`, the durable `vm_spec::VmSpec` launch contract.
- `retention`, which is persistent for named machines and may permit cleanup for
  unnamed workload machines.
- `process`, the durable OCI-style entrypoint, command, environment, working
  directory, and user selection.
- `templateName`, when strict version-1 template defaults were selected.
- `machineDir`, the local durable directory for the machine.
- `imageRef`, labels, metadata, and requested network.
- `createdAt` and `modifiedAt`.

The relational `id` and `name` columns must match the same fields in `config_json`. Decode paths validate that invariant so the indexed values and object document cannot silently drift.

`spec` is not exploded into relational tables. Boot, hardware, storage, mounts, public vsock settings, and annotations remain part of the VM spec because they are object-shaped launch data, not fields the manager currently needs for uniqueness or relationship constraints. silo-vmm always attaches the backend vsock device for internal guest destinations 22 and 1027. The stored public setting independently controls the hybrid mux and listener discovery surface; libvm resolves those effective runtime paths from the latest stored spec.

## Mutable State

`machine_state` stores the latest mutable runtime snapshot:

- `machine_id`: one-to-one key back to `machine_config`.
- `status`: queryable process status for quick list/status reads.
- `state_json`: the full mutable `MachineState` document encoded as SQLite JSONB.

`state_json` contains `machineId`, `status`, `vmmPid`, `startedAt`, `runId`,
`lastError`, and `updatedAt`. Decode paths validate that `machine_id` and
`status` match the relational columns.

All durable timestamps, including the timestamps in `MachineConfig` and
`MachineState`, are signed Unix seconds. The report timestamps supplied by the
guest agent are separate telemetry and use Unix milliseconds.

Runtime truth still comes from `silo-vmm` while a VM is running. Local inspect/list paths reconcile the DB state with pidfiles and monitor liveness before returning snapshots.

## Launch Artifacts

The per-instance `config.json` file remains the launch artifact read by `silo-vmm`.
It is generated from `MachineConfig.spec`. The database is the source of durable
machine intent, including image identity, retention, and process configuration;
the launch artifact contains only the VM specification required by `silo-vmm`.

This mirrors libpod's two-spec model:

- `ContainerConfig.JSON` stores the create-time container config, including the OCI spec libpod was given.
- The final OCI bundle `config.json` is generated later after libpod adds runtime-managed mounts, namespaces, devices, network details, and other launch-time data.

## Network State

Named network definitions and runtime network instances remain relational because the manager needs cross-object relationships and cleanup behavior. The database enforces attachments' machine and instance references; an instance's optional definition name is a manager-owned logical association rather than a SQLite foreign key.

- `network_definitions` stores named user definitions.
- `network_instances` stores driver runtime records.
- `network_attachments` joins one machine to one network instance and cascades with the machine.

## Lifecycle Semantics

Creation is image-first. An OCI reference or explicit local disk is materialized
at `MachineBuilder::create`, which persists a stopped machine. Ordinary
`Machine::start` and `Machine::stop` change VM lifecycle only; starting an idle
machine does not consume its durable process configuration. A restart is a stop
followed by that same idle start.

An explicit `MachineStartOptions::entrypoint` is separate launch-only state.
`silo-vmm` acknowledges start after the guest program has launched, then owns the
VM until that program exits. The entrypoint is not written into the machine's
durable process configuration.

## ERD

```mermaid
erDiagram
    DB_CONFIG {
        integer id PK
        text os
        integer created_at
        integer modified_at
    }

    MACHINE_CONFIG {
        text id PK
        text name UK
        blob config_json
    }

    MACHINE_STATE {
        text machine_id PK FK
        text status
        blob state_json
    }

    NETWORK_DEFINITIONS {
        text name PK
        text mode
        text driver_preference
        integer created_at
        integer modified_at
    }

    NETWORK_INSTANCES {
        text id PK
        text driver
        text definition_name
        blob attachment_json
        blob driver_state_json
        text state
        integer created_at
        integer modified_at
    }

    NETWORK_ATTACHMENTS {
        text machine_id PK FK
        text network_instance_id FK
        text guest_mac
        integer created_at
        integer modified_at
    }

    MACHINE_CONFIG ||--|| MACHINE_STATE : has
    MACHINE_CONFIG ||--o| NETWORK_ATTACHMENTS : attaches
    NETWORK_INSTANCES ||--o{ NETWORK_ATTACHMENTS : has
    NETWORK_DEFINITIONS ||--o{ NETWORK_INSTANCES : defines
```

`DB_CONFIG` is intentionally not shown as a parent table. It is a singleton database guard, not a normal entity relationship.

## API Boundary

The public API exposes resource handles and owned snapshots:

- `Runtime`: target facade.
- `Machine`: resource handle containing a runtime and machine ID.
- `MachineBuilder`: image-first durable creation builder.
- `MachineData`: owned public read snapshot assembled from internal config and state.

`MachineConfig` and `MachineState` are internal persistence models, not public API shapes.

The low-level database trait stays private to the local runtime. A future remote runtime should implement machine-management operations at the `Runtime`/`Machine` level, not the SQLite CRUD layer.
