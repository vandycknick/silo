# libvm State Model

`libvm` keeps its public API above the storage boundary. A `Runtime` is a client facade for a Silo target; today the only target is local SQLite plus local instance directories, but the API is shaped so a future remote target can implement the same machine-management operations without exposing SQLite details.

The local target follows the same split Podman's libpod uses for containers, pods, and volumes: keep columns for identity, uniqueness, relationships, and hot lookups, and keep object-shaped static config and mutable state as JSON documents.

## Runtime Root

Each local runtime opens one state root. `db_config` is a singleton guard row that pins the database to the layout that created it. Opening the same database with a different data directory, instance directory, image directory, or network directory is an error.

This lets callers create independent Silo installations by constructing separate local runtime configs:

```rust
let runtime = Runtime::new(RuntimeConfig::local("/var/lib/silo-dev")).await?;
```

The CLI still uses the default local root through `Runtime::from_env()`, but the API does not require that default.

## Static Config

`machine_config` stores the stable machine identity and lookup fields as columns:

- `id`: stable machine UUID, rendered as 32 lowercase hex characters.
- `name`: user-facing unique alias.
- `created_at` and `modified_at`: timestamps for listing and sorting.
- `config_json`: the full static `MachineConfig` document encoded as SQLite JSONB.

`config_json` contains the full static machine config snapshot, including:

- `id` and `name`, duplicated intentionally so the JSON document is self-describing.
- `spec`, the durable `vm_spec::VmSpec` launch contract.
- `instanceDir`, the local instance directory for the machine.
- `imageRef`, labels, metadata, and requested network.
- `createdAt` and `modifiedAt`.

The relational `id` and `name` columns must match the same fields in `config_json`. Decode paths validate that invariant so the indexed values and object document cannot silently drift.

`spec` is not exploded into relational tables. Boot, hardware, storage, mounts, vsock endpoints, and annotations remain part of the VM spec because they are object-shaped launch data, not fields the manager currently needs for uniqueness or relationship constraints.

## Mutable State

`machine_state` stores the latest mutable runtime snapshot:

- `machine_id`: one-to-one key back to `machine_config`.
- `status`: queryable process status for quick list/status reads.
- `updated_at`: queryable update timestamp.
- `state_json`: the full mutable `MachineState` document encoded as SQLite JSONB.

`state_json` contains `machineId`, `status`, `vmmonPid`, `startedAt`, `lastError`, and `updatedAt`. Decode paths validate that `machine_id`, `status`, and `updated_at` match the relational columns.

Runtime truth still comes from `vmmon` while a VM is running. Local inspect/list paths reconcile the DB state with pidfiles and monitor liveness before returning snapshots.

## Launch Artifacts

The per-instance `config.json` file remains the launch artifact read by `vmmon`. Today it is generated from `MachineConfig.spec` and should match that spec after create or replace-config. If Silo later needs libpod-style late binding, the database should continue to hold the desired static config, while per-instance `config.json` can become the generated runtime artifact.

This mirrors libpod's two-spec model:

- `ContainerConfig.JSON` stores the create-time container config, including the OCI spec libpod was given.
- The final OCI bundle `config.json` is generated later after libpod adds runtime-managed mounts, namespaces, devices, network details, and other launch-time data.

## Network State

Named network definitions and runtime network instances remain relational because the manager needs cross-object relationships and cleanup behavior.

- `network_definitions` stores named user definitions.
- `network_instances` stores driver runtime records.
- `network_attachments` joins one machine to one network instance and cascades with the machine.

## ERD

```mermaid
erDiagram
    DB_CONFIG {
        integer id PK
        integer schema_version
        text data_dir
        text state_db_path
        integer created_at
        integer modified_at
    }

    MACHINE_CONFIG {
        text id PK
        text name UK
        blob config_json
        integer created_at
        integer modified_at
    }

    MACHINE_STATE {
        text machine_id PK FK
        text status
        blob state_json
        integer updated_at
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
        text definition_name FK
        text runtime_dir
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
- `MachineCreate` and `MachineUpdate`: request DTOs for caller input.
- `MachineInspectData`: owned public read snapshot assembled from internal config and state.

`MachineConfig` and `MachineState` are internal persistence models, not public API shapes.

The low-level database trait stays private to the local runtime. A future remote runtime should implement machine-management operations at the `Runtime`/`Machine` level, not the SQLite CRUD layer.
