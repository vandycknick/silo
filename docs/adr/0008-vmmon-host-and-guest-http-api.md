# 8. Vmmon Host and Guest Agent HTTP APIs

Date: 2026-07-08

## Status

Proposed

## The Problem

Managing a VM requires a stable way to interact with the process that owns it.
Silo needs to read current state and metrics, establish SSH and serial sessions,
and transfer files. These capabilities need a versioned, well-defined API that
does not depend on a particular vmm backend.

That interface spans two processes. `vmmon` owns VM lifecycle and host-side
connections. The guest agent observes state and metrics inside the VM and
performs guest filesystem operations. Neither API is sufficient by itself:
host callers need the `vmmon` API, and `vmmon` needs the agent API.

This ADR defines both APIs and the boundary between them.

## Two Control Surfaces

The host surface is the interface a manager or local administrative tool uses.
It reports monitor facts, exposes cached guest observations, transfers files,
and upgrades connections to opaque SSH and serial streams. It is available on a
local Unix socket and is protected by host socket permissions.

The guest surface is not a public callback channel. It is an HTTP service inside
the VM. `vmmon` initiates every connection to it through
the VM's machine-scoped vsock transport. This gives the monitor control over
poll cadence and concurrency, but it does not authenticate the guest process.

The two surfaces cross different trust boundaries. Access to the host socket
grants administrative control over the VM. The guest agent is untrusted: guest
root or the guest kernel can replace it, fabricate results, and return malformed
or unbounded responses. `vmmon` must validate and bound everything it accepts
from the agent while keeping host lifecycle work available.

HTTP/1.1, resource-oriented operations, typed JSON, and binary streaming give
both surfaces a familiar model with broad library support. HTTP Upgrade lets us
preserve native SSH and serial byte streams rather than invent a framing layer
around them.

```text
manager or local tool
        |
        | HTTP over vm.sock
        v
     vmmon --------------------> VMM lifecycle and raw streams
        |
        | host-initiated HTTP over machine-scoped vsock:1027
        v
   guest agent
```

## A Typical VM Session

A manager starts a VM and supplies a path for `vm.sock`. One `vmmon` process
creates that listener and supervises that one boot. A host caller can immediately
ask the socket for status, even while the VM is still starting.

If guest-agent services are enabled, the VMM exposes vsock port 1027 in
host-connect mode. The agent validates its injected configuration, starts its
listener before long-running provisioning completes, and can first report
`starting`. `vmmon` connects to that service, polls `/v1/status`, and later
polls metrics. The caller waits on the host status operation if it needs
readiness. Readiness emerges only when the monitor has a fresh status report
whose guest state is `ready`; it is not a promise made by a launch call or an
agent connection.

Once the caller has a usable VM, it can upload a file through the same socket
without requiring guest networking. It can instead upgrade to SSH when that is
the right tool, or use the serial stream for early-boot diagnosis. Neither raw
stream requires readiness, and neither makes `vmmon` understand the protocol it
is relaying.

## What The Design Must Preserve

These workflows are useful only while the monitor remains dependable. Four
constraints shape the design:

- The host remains the authority for lifecycle, time, and readiness. Guest
  reports remain explicitly untrusted assertions.
- Every retained observation identifies its agent and records when the host
  received it, so callers can distinguish current information from stale state.
- Polling, finite requests, file transfers, SSH, and serial have independent
  capacity. A hostile agent or long-lived stream cannot consume the capacity
  needed for lifecycle work.
- The HTTP, filesystem, Upgrade, shutdown, and evolution rules are precise
  enough for independent implementations to interoperate within `/v1`.

## Determination

One `vmmon` invocation owns exactly one VM boot and participates in two HTTP/1.1
APIs. It serves the host API on the manager-supplied `vm.sock` Unix socket. The
guest agent serves the agent API on machine-scoped vsock port 1027 in
host-connect mode, and `vmmon` connects to and polls it.

Both servers use Axum routing and Serde typed models over explicitly configured
Hyper HTTP/1.1 connections. The `vmmon` agent client uses Hyper and the same
shared wire models. These libraries own protocol parsing, routing, framing, and
serialization; Silo defines resources and policy rather than another framing
layer.

This ADR defines the complete initial v1 contract. Operational limits remain
implementation configuration rather than permanent wire promises. There are
twenty method-route pairs: eleven host operations and nine guest-agent
operations.

## API Overview

### Host Operations

| Method   | Route              | Purpose                                       |
| -------- | ------------------ | --------------------------------------------- |
| `GET`    | `/healthz`         | Prove the host listener can answer.           |
| `GET`    | `/v1/status`       | Read status or wait for readiness.            |
| `GET`    | `/v1/metrics`      | Read the latest cached guest metric snapshot. |
| `GET`    | `/v1/ssh`          | Upgrade to a raw SSH relay.                   |
| `GET`    | `/v1/serial`       | Upgrade to the raw serial stream.             |
| `GET`    | `/v1/fs/entry`     | Read guest filesystem entry attributes.       |
| `DELETE` | `/v1/fs/entry`     | Remove a guest filesystem entry.              |
| `GET`    | `/v1/fs/file`      | Stream a regular file from the guest.         |
| `PUT`    | `/v1/fs/file`      | Atomically create or replace a regular file.  |
| `GET`    | `/v1/fs/directory` | List guest directory entries.                 |
| `PUT`    | `/v1/fs/directory` | Create a guest directory.                     |

### Guest Agent Operations

| Method   | Route              | Purpose                                      |
| -------- | ------------------ | -------------------------------------------- |
| `GET`    | `/healthz`         | Prove the agent listener can answer.         |
| `GET`    | `/v1/status`       | Read the current complete agent status.      |
| `GET`    | `/v1/metrics`      | Read a current complete metric snapshot.     |
| `GET`    | `/v1/fs/entry`     | Read filesystem entry attributes.            |
| `DELETE` | `/v1/fs/entry`     | Remove a filesystem entry.                   |
| `GET`    | `/v1/fs/file`      | Stream a regular file to the host.           |
| `PUT`    | `/v1/fs/file`      | Atomically create or replace a regular file. |
| `GET`    | `/v1/fs/directory` | List directory entries.                      |
| `PUT`    | `/v1/fs/directory` | Create a directory.                          |

The two filesystem surfaces have the same request and success-response
contract. `vmmon` still validates and bounds every agent response; it does not
blindly proxy an untrusted byte stream.

V1 has no events, retained history, metric stream, readiness-only route,
shutdown route, VM restart route, archive transfer, or generic command route.
Logs provide historical diagnostics. Status and metrics are finite current
snapshots.

## Keeping One VM Boot Coherent

### Process Model

One `vmmon` invocation owns exactly one VMM instance and one VM boot. It
creates one random public `monitor_instance_id`. A transition to `stopping`,
`stopped`, or `failed` is terminal for that process. Restarting a VM means
starting a new `vmmon`, which creates a new host listener, state store, agent
supervisor, and `monitor_instance_id`.

There is consequently no separate VM generation identifier. No monitor state
can cross a boot without also crossing a process boundary. Agent and raw
connections belong to the current `VirtualMachine` and end with the monitor.

HTTP handlers and poll workers validate bounded syntax and typed schemas, then
submit typed observations to one monitor-owned serialized transition boundary.
The boundary linearizes:

- VM lifecycle changes;
- agent process identity changes;
- status and metric snapshot replacement and freshness;
- readiness decisions; and
- shutdown admission decisions.

Network, disk, backend connection, response writing, file streaming, and raw
relay work never runs while holding the transition boundary. Timers are only
wake-ups. Freshness is decided using monotonic time observed at the serialized
transition, and staleness wins when `now >= stale_at`.

### Finding The Agent

When guest-agent services are enabled, the VMM exposes port 1027 in host-connect
mode. The agent listens on that port after validating its injected
configuration and before long-running provisioning completes. This permits an
early status response whose state is `starting`.

Once the VM is running, the agent supervisor attempts a bounded connection and
requests `/v1/status`. Connection refusal, timeout, malformed HTTP, invalid
JSON, an invalid schema, or an oversized response is a failed observation. The
supervisor retries under capped exponential backoff with jitter until shutdown
or terminal VM state. Backoff resets only after a valid status response, not
after a raw vsock connection succeeds.

Status and metric polling have independent configured intervals and absolute
deadlines. Status is always polled before metrics for a newly observed agent
process. Public host status and metric requests read monitor-owned snapshots;
they never synchronously call the agent.

The agent listener accepts multiple connections. Control polling and
filesystem operations do not depend on one persistent HTTP/1.1 connection.

### Knowing Which Agent We Observed

Every agent process generates one random `agent_instance_id`. The agent status
response also contains its software version and claimed guest `boot_id`.
Together these values form an untrusted process identity observed by `vmmon`.

The first valid status response establishes the current identity. A different
`agent_instance_id` immediately clears retained status and metrics before the
new response becomes visible. Reusing one instance identifier with a different
version or boot identifier is a protocol error and does not update monitor
state.

Metric responses carry `agent_instance_id`. A metric response whose identifier
does not match the current status identity is discarded and causes an
immediate status poll. Filesystem responses are operation-local and do not
establish or replace the observed status identity.

Identity fields are consistency aids, not authentication. Guest root can
fabricate them.

### Knowing Whether An Observation Is Current

Each valid status or metric response is accepted at one serialized transition.
`vmmon` records its own `received_at` and computes `stale_at` from the configured
maximum receipt age. Guest timestamps never control ordering or freshness.

A failed poll records agent connectivity failure but retains the latest report
for diagnosis. A retained report remains fresh until its deadline. A later
successful response from the same identity replaces it and computes a new
deadline. There is no report history.

Only a status response refreshes status freshness and readiness. Health and
metric responses cannot keep readiness alive. Metric freshness is independent
from status freshness.

### Trust Boundaries

#### Host Administrators

The host socket is `0600` for owner-only access. When `libvm` configures an
administrator group, it is `0660` with that GID. World access is forbidden.
The immediate runtime directory is owner-controlled and not group-writable.

The optional group is a full VM-administrator role. Every authorized peer can
read status and metrics, modify the guest filesystem, and open SSH and serial.
The API has no observer role or per-route authorization. Group removal prevents
future accepts but does not close existing connections. Stop and restart the
monitor when active revocation is needed.

The kernel enforces Unix socket access. `vmmon` may record available peer
credentials but does not add an effective-UID equality check that would break
configured group access.

#### Guest Agent

The agent service is reachable through the current VM's machine-scoped vsock
transport. The agent requires the host peer where the backend exposes peer
identity. A future backend using a host-global transport must establish the
expected machine or CID before constructing an HTTP stream.

The transport identifies the VM, not the intended guest process. Guest root or
the guest kernel can replace the agent service and fabricate every response.
Status, process identity, system information, provisioning reports, metrics,
filesystem attributes, and file content are untrusted guest assertions.

Agent response heads, bodies, decoded models, tasks, queues, streams, and
execution time are bounded in `vmmon`. Agent parsing and execution are also
bounded so an authorized host filesystem client cannot accidentally exhaust
the guest service. Wire tests and fuzzing exercise both HTTP boundaries.

### Reserving The Agent Port

Port 1027 is reserved for the built-in agent API when guest-agent services are
enabled. Before VM creation, configuration validation rejects another
host-connect endpoint on port 1027. Existing SSH connect behavior on port 22
is a separate reserved service.

### Owning The Host Socket Path

`libvm`, not `vmmon`, owns managed per-machine runtime paths. While
holding its per-machine lifecycle lock, `libvm` proves the recorded monitor is
inactive before inspecting and removing an expected stale socket. Under that
same lock, it removes the managed socket after confirmed monitor termination or
during the next reconciliation.

`vmmon` never blindly removes or replaces a pre-existing target. It binds the
path supplied by the manager and fails if any entry already exists. It does not
perform late cleanup because an exiting process must never unlink a successor's
socket.

## Turning Guest Status Into Host Readiness

Readiness is monitor policy, not a guest fact.

The monitor-observed VM must be `running`. When guest-agent services are
disabled, that condition alone is ready. When enabled, readiness also requires
a fresh status report whose guest state is `ready`. SSH availability is not
gated on readiness.

The response exposes one reason selected in this order:

| Condition                                | `ready` | Reason                 |
| ---------------------------------------- | ------- | ---------------------- |
| VM is `starting`                         | false   | `vm_starting`          |
| VM is `stopping`                         | false   | `vm_stopping`          |
| VM is `stopped`                          | false   | `vm_stopped`           |
| VM is `failed`                           | false   | `vm_failed`            |
| Agent mode is disabled and VM is running | true    | `agent_not_required`   |
| No valid status has been observed        | false   | `agent_unavailable`    |
| The latest status is stale               | false   | `agent_status_stale`   |
| Guest state is `starting`                | false   | `guest_starting`       |
| Guest state is `failed`                  | false   | `guest_failed`         |
| Guest state is `ready`                   | true    | `guest_reported_ready` |

`guest_reported_ready` explicitly means readiness depends on an untrusted guest
assertion. A transient failed poll does not revoke readiness until the retained
status reaches `stale_at`.

## Structured API Contract

The examples and schema descriptions below define the initial structured
contract. The complete initial structured reference is embedded as standalone
OpenAPI appendices at the end of this ADR. Changing route behavior or field
semantics requires amending this ADR.

### Conventions

- Structured bodies are UTF-8 JSON with `snake_case` field names.
- Request models are closed. Unknown fields, duplicate model fields, unknown
  enum values, invalid UTF-8, non-finite numbers, and trailing non-whitespace
  data are rejected.
- Clients must ignore unknown response fields. Incompatible request or
  semantic changes require `/v2`; v1 has no in-band feature negotiation.
- Host timestamps are RFC 3339 UTC with `Z` and millisecond precision. Guest
  timestamps accept RFC 3339 UTC with `Z` and remain assertions.
- UUIDs use canonical lowercase hyphenated text.
- Structured requests and responses use `Content-Type: application/json`.
- Binary file bodies use `Content-Type: application/octet-stream`.
- Routes without documented query parameters reject all query parameters.
- Duplicate query keys are always invalid.
- Every finite response includes `Cache-Control: no-store`.
- Ordinary errors use a bounded envelope:

```json
{
    "code": "path_not_found",
    "message": "the requested guest path does not exist"
}
```

The HTTP status carries broad meaning. `code` is stable within v1 and
`message` is bounded diagnostic text. Errors never copy request bodies, guest
file content, guest report messages, or raw stream content.

Shared application errors include `400 invalid_request`, `408 request_timeout`,
`413 request_too_large`, `415 unsupported_media_type`, and
`503 resource_exhausted` with `Retry-After`. Unknown routes and wrong methods
use `404 not_found` and `405 method_not_allowed`. Hyper may reject malformed
HTTP and close before an application envelope can be produced.

### Health

Both `GET /healthz` routes return `200 OK` with:

```json
{
    "ok": true
}
```

This proves only that the selected listener and router answered. It does not
report VM readiness, agent status freshness, SSH, serial, or filesystem health.
`vmmon` uses status polling, not health polling, for readiness.

### Agent Status

Agent `GET /v1/status` returns one complete current report:

```json
{
    "agent_instance_id": "953fe0d6-2a5f-43db-81ec-e94e3c3a20df",
    "agent_version": "0.1.0",
    "boot_id": "d65d7f43-9b8f-4490-bab5-7ef2ef8b87f8",
    "observed_at": "2026-07-10T12:00:00Z",
    "state": "ready",
    "code": null,
    "message": null,
    "system": {
        "kernel_version": "6.12.0",
        "os_name": "Alpine Linux",
        "os_version": "3.22",
        "architecture": "aarch64",
        "hostname": "dev",
        "ip_addresses": ["192.168.105.2"]
    },
    "boot": {
        "mode": "agent_pid1",
        "requested_init": "/sbin/init",
        "handoff_init_path": "/sbin/init",
        "probed_init_paths": ["/sbin/init"],
        "agent_path": "/run/agent/silo-agent",
        "agent_pid": 1,
        "agent_is_pid1": true,
        "message": ""
    },
    "provisioning": {
        "status": "succeeded",
        "started_at": "2026-07-10T11:59:31Z",
        "finished_at": "2026-07-10T11:59:39Z",
        "duration_ms": 8000,
        "message": "",
        "steps": []
    }
}
```

All listed fields are required, including nullable fields. The response and
every nested object are closed in the initial schema.

Status state is `starting`, `ready`, or `failed` and may change in either
direction. `ready` requires null `code` and `message`; `failed` requires bounded
non-empty values; `starting` permits either both null or both present.

`system`, `boot`, and `provisioning` are required nullable fields. Boot mode is
`standard`, `agent_pid1`, or `init_child`. Provisioning status is `succeeded`,
`degraded`, `skipped`, or `failed_boot`. Step status is `succeeded`, `failed`,
`skipped`, or `unsupported`; failure policy is `best_effort` or `fail_boot`.

The exact nested shapes remain:

| Object            | Fields                                                                                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status            | UUID `agent_instance_id`, string `agent_version`, UUID `boot_id`, guest timestamp `observed_at`, enum `state`, nullable strings `code` and `message`, and nullable `system`, `boot`, and `provisioning`. |
| `system`          | Strings `kernel_version`, `os_name`, `os_version`, `architecture`, and `hostname`, plus string array `ip_addresses`.                                                                                     |
| `boot`            | Enum `mode`, strings `requested_init`, `handoff_init_path`, `agent_path`, and `message`, string array `probed_init_paths`, unsigned 32-bit `agent_pid`, and boolean `agent_is_pid1`.                     |
| `provisioning`    | Enum `status`, nullable guest timestamps `started_at` and `finished_at`, nonnegative JSON-safe integer `duration_ms`, string `message`, and bounded `steps`.                                             |
| Provisioning step | String `id`, enums `status` and `failure_policy`, boolean `changed`, strings `backend`, `message`, and `error_chain`, and nonnegative JSON-safe integer `duration_ms`.                                   |

The boot fields are observed guest diagnostics. They do not define target-init
selection, kernel `init=` interpretation, PID 1 ownership, fork or exec
behavior, automatic probing policy, or a process argument contract.

Every value is an untrusted guest assertion. The agent computes and retains the
complete report locally so a poll does not repeat provisioning work.

### Agent Metrics

Agent `GET /v1/metrics` returns one complete current snapshot:

```json
{
    "agent_instance_id": "953fe0d6-2a5f-43db-81ec-e94e3c3a20df",
    "observed_at": "2026-07-10T12:00:00Z",
    "snapshot": {
        "memory": {
            "total_bytes": 4294967296,
            "available_bytes": 1832910848
        },
        "cpu": {
            "logical_cpu_count": 4,
            "user_seconds": 18.42,
            "nice_seconds": 0,
            "system_seconds": 4.11,
            "idle_seconds": 72.3,
            "iowait_seconds": 0.2,
            "irq_seconds": 0,
            "softirq_seconds": 0.03,
            "steal_seconds": 0
        },
        "load_average": {
            "one_minute": 0.12,
            "five_minutes": 0.08,
            "fifteen_minutes": 0.03
        },
        "uptime_seconds": 95.4,
        "filesystems": [],
        "network_interfaces": [],
        "block_devices": []
    }
}
```

The metric response and every nested object are closed. Snapshot fields are
nullable `memory`, `cpu`, `load_average`, and `uptime_seconds`, plus bounded
arrays `filesystems`, `network_interfaces`, and `block_devices`. Arrays are
empty when no entries were observed.

Numeric values are finite and nonnegative. Memory and filesystem subvalues
cannot exceed totals. Filesystem mount points, network interface names, and
block device names are unique. Counters are cumulative absolute values and
decreases are accepted as guest-side resets.

`block_devices` reports only whole block devices, never partitions, so aggregate
host-side use does not double count I/O. The agent derives these values from
Linux `/proc/diskstats`, normalizing the kernel's 512-byte sector counts to
bytes. `read_bytes`, `read_operations`, `write_bytes`, and `write_operations`
are cumulative nonnegative JSON-safe integers. They may decrease after guest
boot, device reattachment, device reinitialization, or counter overflow; such a
decrease is accepted as a guest-side reset. `in_flight_operations` is a current
nonnegative JSON-safe integer gauge, not a cumulative counter. The array is
bounded and remains an untrusted guest assertion.

The exact metric shapes are:

| Object            | Fields                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metric response   | UUID `agent_instance_id`, guest timestamp `observed_at`, and closed `snapshot`.                                                                                                                                                 |
| `snapshot`        | Nullable `memory`, `cpu`, `load_average`, and `uptime_seconds`, plus bounded arrays `filesystems`, `network_interfaces`, and `block_devices`.                                                                                   |
| `memory`          | Nonnegative JSON-safe integers `total_bytes` and `available_bytes`.                                                                                                                                                             |
| `cpu`             | Integer `logical_cpu_count` in `1..65535` and finite nonnegative numbers `user_seconds`, `nice_seconds`, `system_seconds`, `idle_seconds`, `iowait_seconds`, `irq_seconds`, `softirq_seconds`, and `steal_seconds`.             |
| `load_average`    | Finite nonnegative numbers `one_minute`, `five_minutes`, and `fifteen_minutes`.                                                                                                                                                 |
| Filesystem entry  | String `mount_point`, string `filesystem_type`, and nonnegative JSON-safe integers `total_bytes`, `used_bytes`, and `available_bytes`.                                                                                          |
| Network interface | Non-empty string `name`, nullable canonical lowercase colon-separated string `mac`, and nonnegative JSON-safe integers `receive_bytes` and `transmit_bytes`.                                                                    |
| Block device      | Non-empty unique whole-device `name`; cumulative nonnegative JSON-safe integers `read_bytes`, `read_operations`, `write_bytes`, and `write_operations`; and current nonnegative JSON-safe integer gauge `in_flight_operations`. |

### Host Status

Host `GET /v1/status` returns `200 OK` whenever a document can be encoded,
including when the VM is not ready or terminal. With no query it returns
immediately. The only wait form is:

```text
GET /v1/status?wait=ready&timeout_ms=30000
```

`timeout_ms` is valid only with `wait=ready`. A wait returns the latest full
status when readiness becomes true, the VM becomes terminal, or the deadline
expires. The body explains the outcome. Client disconnect cancels only the
waiter.

```json
{
    "machine_id": "018ff6f2-7b2a-7697-9b32-778ecdfc5f2c",
    "name": "dev",
    "monitor": {
        "instance_id": "3bbbd891-0fd5-4a13-9737-8ac91db245b5",
        "observed_at": "2026-07-10T12:00:05.000Z"
    },
    "vm": {
        "state": "running",
        "state_changed_at": "2026-07-10T11:59:30.000Z",
        "running_since": "2026-07-10T11:59:30.000Z",
        "code": null,
        "message": null
    },
    "readiness": {
        "ready": true,
        "reason": "guest_reported_ready"
    },
    "agent": {
        "mode": "enabled",
        "connection": {
            "state": "responsive",
            "last_success_at": "2026-07-10T12:00:00.100Z",
            "last_failure_at": null,
            "code": null,
            "message": null
        },
        "identity": {
            "instance_id": "953fe0d6-2a5f-43db-81ec-e94e3c3a20df",
            "version": "0.1.0",
            "boot_id": "d65d7f43-9b8f-4490-bab5-7ef2ef8b87f8"
        },
        "status": {
            "received_at": "2026-07-10T12:00:00.100Z",
            "stale_at": "2026-07-10T12:00:30.100Z",
            "freshness": "fresh",
            "stale_reason": null,
            "report": {
                "observed_at": "2026-07-10T12:00:00Z",
                "state": "ready",
                "code": null,
                "message": null,
                "system": null,
                "boot": null,
                "provisioning": null
            }
        }
    }
}
```

All listed fields are required. `agent.connection`, `agent.identity`, and
`agent.status` are nullable. When `agent.mode` is `disabled`, all three are
null:

```json
{
    "mode": "disabled",
    "connection": null,
    "identity": null,
    "status": null
}
```

When `agent.mode` is `enabled`, `agent.connection` is required and contains
enum `state` (`connecting`, `responsive`, or `unresponsive`), nullable host
timestamps `last_success_at` and `last_failure_at`, and nullable bounded strings
`code` and `message`. Identity and status remain nullable until observed.

For enabled mode, before the first valid status, connection state is
`connecting` and identity and status are null. A failed attempt changes it to
`unresponsive`, records a bounded monitor-generated failure, and retains
identity and status if present. A valid status changes it to `responsive`,
clears failure fields, and replaces identity and status. Disabled mode has no
agent poller or connection state.

The status wrapper has host timestamps `received_at` and `stale_at`, freshness
`fresh` or `stale`, nullable stale reason `receipt_age` or
`monitor_stopping`, and the guest report without repeated identity fields.

Machine, monitor, VM, readiness, connection, receipt, and freshness values are
host facts. Identity and everything under `report` are guest assertions. The
document does not expose disks, host paths, backend details, or network policy.

### Host Metrics

Host `GET /v1/metrics` always returns `200 OK` when a document can be encoded:

```json
{
    "machine_id": "018ff6f2-7b2a-7697-9b32-778ecdfc5f2c",
    "name": "dev",
    "monitor": {
        "instance_id": "3bbbd891-0fd5-4a13-9737-8ac91db245b5",
        "observed_at": "2026-07-10T12:00:05.000Z"
    },
    "metrics": {
        "agent_instance_id": "953fe0d6-2a5f-43db-81ec-e94e3c3a20df",
        "received_at": "2026-07-10T12:00:00.200Z",
        "stale_at": "2026-07-10T12:01:00.200Z",
        "freshness": "fresh",
        "stale_reason": null,
        "report": {
            "observed_at": "2026-07-10T12:00:00Z",
            "snapshot": {
                "memory": null,
                "cpu": null,
                "load_average": null,
                "uptime_seconds": null,
                "filesystems": [],
                "network_interfaces": [],
                "block_devices": []
            }
        }
    }
}
```

Before the first accepted metric response, `metrics` is null. Otherwise it
contains guest UUID `agent_instance_id`, host timestamps `received_at` and
`stale_at`, freshness `fresh` or `stale`, nullable stale reason `receipt_age`
or `monitor_stopping`, and the complete guest report.

Freshness depends only on host receipt age and monitor lifecycle. A status
identity change clears metrics before the new status becomes visible. Guest
timestamps never control freshness.

## Working With The Guest Filesystem

Filesystem operations are for the common host-side experience: inspect a guest
path, upload an input before networking exists, retrieve an output, create a
directory, or remove an entry. They are not a shell and do not depend on SSH.
The host API accepts the caller's validated intent, then `vmmon` performs the
matching agent operation while preserving bounded streaming and backpressure.
The following sections make that experience precise, including the cases where
guest paths race, agents fail, or an operation cannot complete atomically.

### Paths

Every filesystem route requires exactly one `path` query parameter. It is a
bounded, percent-decoded UTF-8 absolute guest path. `/` is valid except for
file creation and deletion. Other paths must be lexically canonical: no empty,
`.` or `..` component, repeated separator, NUL, or trailing separator.

Parent path resolution follows normal guest filesystem semantics. Operations
never follow the final symlink when deciding the target entry. Recursive
deletion never traverses a symlink.

The API supports only UTF-8 path names. Encountering a non-UTF-8 directory
entry returns `422 unsupported_filename`.

### Entry Attributes

`GET /v1/fs/entry?path=/etc/hosts` uses `lstat` semantics and returns:

```json
{
    "path": "/etc/hosts",
    "name": "hosts",
    "kind": "file",
    "size_bytes": 391,
    "mode": "0644",
    "uid": 0,
    "gid": 0,
    "modified_at": {
        "seconds": 1783684800,
        "nanoseconds": 0
    }
}
```

Every field is required. `kind` is `file`, `directory`, `symlink`, `fifo`,
`socket`, `block_device`, or `character_device`. `mode` is exactly four octal
digits and contains permission and special bits without file-type bits.
`size_bytes` is a nonnegative JSON-safe integer. Timestamp seconds are a signed
JSON-safe Unix value and nanoseconds are in `0..999999999`.

For the root entry, `path` and `name` are both `/`. For every other entry,
`name` is the non-empty final UTF-8 path component.

Missing paths return `404 path_not_found`; inaccessible paths return
`403 permission_denied`.

### File Download

`GET /v1/fs/file?path=/tmp/result.bin` returns a regular file as
`application/octet-stream`. The agent opens without following the final
symlink, verifies the opened handle is regular, and streams from that handle.
Known size produces `Content-Length`.

Directories, symlinks, devices, sockets, and FIFOs return
`409 not_regular_file`. Errors before response headers use the JSON envelope.
An error after headers closes the stream. The route does not support `Range`.

### File Upload

`PUT /v1/fs/file` accepts these query parameters:

| Parameter | Required | Meaning                   |
| --------- | -------- | ------------------------- |
| `path`    | yes      | Target regular file.      |
| `mode`    | no       | Four octal digits.        |
| `uid`     | no       | Unsigned 32-bit owner ID. |
| `gid`     | no       | Unsigned 32-bit group ID. |

The body is `application/octet-stream`. The agent writes a unique temporary
regular file in the destination directory, enforces the configured byte limit,
applies requested attributes, closes it successfully, and atomically renames
it over the target. Disconnect, timeout, size overflow, write failure, or
attribute failure removes the temporary file.

The final target is never followed. An existing directory or non-regular entry
returns `409 not_regular_file`. On create, omitted mode defaults to `0644` and
omitted ownership uses the agent service's effective IDs. On replace, omitted
mode and ownership preserve the existing regular file's values.

An inaccessible parent, denied create or replacement, or rejected attribute
change returns `403 permission_denied`. A required parent that is absent or
disappears during the operation returns `404 parent_not_found`. An intermediate
component that is not a directory returns `409 not_directory`.

Creation returns `201 Created`; replacement returns `204 No Content`. Atomic
visibility is guaranteed only within the destination filesystem. V1 does not
promise crash durability or parent-directory `fsync`.

### Directory Listing

`GET /v1/fs/directory` accepts required `path`, optional positive `limit`, and
optional opaque `cursor`. Defaults and maxima are implementation settings. It
returns:

```json
{
    "entries": [],
    "next_cursor": null
}
```

Each entry has the exact attributes shape above with its full canonical path.
Entries are ordered by UTF-8 filename bytes. `next_cursor` is null at end.
Directory mutation between pages may cause entries to be skipped or repeated;
pagination is not a snapshot. Invalid or expired cursors return
`409 invalid_cursor`.

A non-directory final entry returns `409 not_directory`.

### Directory Creation

`PUT /v1/fs/directory` accepts:

| Parameter | Required | Meaning                                    |
| --------- | -------- | ------------------------------------------ |
| `path`    | yes      | Target directory.                          |
| `parents` | no       | Create missing parents; defaults to false. |
| `mode`    | no       | Target mode; defaults to `0755` on create. |
| `uid`     | no       | Target unsigned 32-bit owner ID.           |
| `gid`     | no       | Target unsigned 32-bit group ID.           |

The route has no request body. A newly created target returns `201 Created`.
An existing directory returns `204 No Content` without changing attributes.
An existing non-directory returns `409 not_directory`. Missing parents created
under `parents=true` use mode `0755` and the agent's effective IDs.

Denied traversal or creation returns `403 permission_denied`. A required parent
that is absent with `parents=false`, or disappears during creation, returns
`404 parent_not_found`. An intermediate component that is not a directory also
returns `409 not_directory`.

### Entry Removal

`DELETE /v1/fs/entry` accepts required `path` and optional boolean `recursive`,
which defaults to false. A file or symlink is unlinked. A directory requires
empty contents unless `recursive=true`. Recursive traversal never follows
symlinks.

Success returns `204 No Content`. Missing paths return `404 path_not_found`.
Denied traversal or removal returns `403 permission_denied`. Removing a
non-empty directory with `recursive=false` returns
`409 directory_not_empty`. Removing `/` is always `400 invalid_path`.
Recursive deletion is not atomic; an error may leave a partially removed tree
and returns the first bounded failure observed.

### Crossing The Trust Boundary

Host filesystem handlers validate host requests before opening the agent
operation. `vmmon` forwards only validated intent and streams data with fixed
buffers and backpressure. It independently enforces transfer, response, entry,
connection, and deadline limits even when the agent claims success.

Agent application errors preserve their documented HTTP status and stable code.
Connection failure maps to `503 agent_unavailable`, deadline expiry to
`504 agent_timeout`, and malformed or contradictory agent responses to
`502 agent_protocol_error`. Mid-download failures close the host response.
`vmmon` does not retry an operation after request delivery becomes ambiguous.

Filesystem operations have a concurrency domain independent from polling,
host finite requests, readiness waiters, SSH relays, and serial ownership.
Control polling retains reserved capacity while transfers are active.

## HTTP And Resource Limits

Hyper owns RFC 9110 and RFC 9112 parsing and framing. Axum owns static route and
method dispatch. Serde owns typed JSON decoding. Silo configures relevant Hyper
HTTP/1.1 settings rather than relying on unstable defaults.

Both servers obey these rules:

- only HTTP/1.1 is served;
- `Host` is syntactically required but is neither authority nor routing input;
- unknown paths return `404`, and known paths with other methods return `405`
  with `Allow`;
- `HEAD` and `OPTIONS` are not implicit;
- JSON requests require `Content-Type: application/json`;
- file uploads require `Content-Type: application/octet-stream`;
- content encoding is unsupported;
- routes without bodies reject non-empty bodies;
- malformed framing, incomplete requests, unsafe unread rejected bodies, and
  deadline expiry close the connection;
- finite responses have unambiguous Hyper-generated framing; and
- normal HTTP/1.1 persistence and pipelining behavior is retained.

Head bytes, header count, request-target bytes, body bytes, decoded
cardinality, header read time, body read time, total request time, and idle HTTP
lifetime are bounded. File streams additionally have transfer byte and idle
progress limits. Deadlines are absolute monotonic deadlines and do not reset on
progress.

Host traffic enters independent operation domains after routing: finite API
requests, readiness waiters, filesystem operations, SSH relays, and serial
ownership. Agent status and metric polling have reserved independent capacity.
There is no one global count in which raw or file streams consume lifecycle or
polling capacity.

## Preserving Native SSH And Serial

SSH and serial use these requests:

```http
GET /v1/ssh HTTP/1.1
Host: vmmon
Connection: Upgrade
Upgrade: silo-ssh
```

```http
GET /v1/serial HTTP/1.1
Host: vmmon
Connection: Upgrade
Upgrade: silo-serial
```

The request must have exactly the applicable Upgrade token, nominate `upgrade`
in `Connection`, and contain no body or `Expect`. Invalid or rejected Upgrade
requests close the HTTP connection after the finite error. Missing or incorrect
headers return `426 upgrade_required`; serial contention returns
`409 serial_in_use`.

The client sends only request headers and waits for the complete validated
`101 Switching Protocols` before sending raw bytes. Optimistic bytes are
forbidden.

Before sending `101`, `vmmon` acquires the raw resource and connects the
backend under an absolute deadline. Failure returns `503 backend_unavailable`
and releases ownership. A successful response is:

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: silo-ssh
```

After Hyper yields the upgraded transport, the handler inspects parser
read-ahead. If bytes were buffered beyond the HTTP headers, it closes both
sides without forwarding those bytes. Hyper may expose this only after `101`,
so the contract promises closure rather than a retroactive error.

Only after the complete `101` and empty-read-ahead check do bytes become the
opaque SSH or serial protocol. `vmmon` adds no framing and never parses,
authenticates, logs, or modifies them. Fixed per-direction buffers,
backpressure, EOF, and half-close propagation govern the relay. One cleanup
guard releases slots and serial ownership on every exit path.

SSH is available independently of guest status and readiness. The host SSH
client owns server-key acceptance and continuity. Serial is independently
exclusive.

## What Happens When The VM Stops

Shutdown and spontaneous backend exit use the same serialized lifecycle rules.
Entering `stopping`:

1. rejects new filesystem operations and raw opens;
2. cancels agent polling and active agent filesystem operations;
3. revokes readiness and marks fresh status and metrics stale with
   `monitor_stopping`;
4. wakes readiness waiters with the latest full status;
5. immediately cancels active SSH and serial relays and releases ownership;
6. requests backend stop under one absolute deadline;
7. linearizes backend exit as `stopped` or `failed`;
8. permits only a bounded drain of already materialized finite host responses;
9. closes the host listener; and
10. exits without unlinking the manager-owned socket path.

Forced shutdown is never delayed by draining or guest I/O. Racing operations
are accepted or rejected according to their serialized admission order. A
process kill or host failure can still prevent final responses.

## Access Records And Logging

Existing structured monitor logs provide best-effort attributable access
records, not a tamper-proof or guaranteed-durable audit sink. Allowlisted
content-free records cover:

- host raw open, deny, and close;
- serial ownership conflicts;
- agent connection and polling outcomes;
- filesystem operation type, path hash, outcome, duration, and byte count;
- backend connection outcome; and
- shutdown cancellation.

Useful fields include `monitor_instance_id`, route, request correlation ID,
available peer credentials, outcome, duration, and optional byte counts. Raw
guest paths are not logged by default. Logs never contain bodies, guest report
messages, file contents, SSH or serial bytes, or terminal content.

The kernel can deny an unauthorized Unix connection before `vmmon` sees it;
host OS auditing is responsible for those events.

## From ADR To Implementation

Before handlers are implemented, the embedded OpenAPI appendices are checked
against implementation-time extracted YAML and generated or shared Rust models:

1. extracted YAML for the eleven host and nine agent operations;
2. shared JSON Schemas or generated Rust models for structured resources; and
3. a compact normative transport specification for Unix/vsock authority,
   Hyper configuration, polling, streaming, Upgrade, read-ahead rejection, raw
   relay behavior, and cleanup that OpenAPI cannot express.

The embedded appendices are the complete initial structured reference. Prose
remains normative for Unix/vsock authority, strict HTTP behavior,
polling/freshness, streaming, Upgrade/read-ahead, backpressure, shutdown, and
resource isolation that OpenAPI cannot express. Extracted artifacts and models
must be generated from or checked against the appendices.

Conformance tests exercise real HTTP bytes over Unix sockets and
vsock-equivalent transports. Required coverage includes:

- exact eleven-operation host and nine-operation agent route inventories;
- owner/group Unix authorization and fail-closed socket binding;
- machine-scoped host-to-agent admission and port collision rejection;
- strict queries and JSON, media types, body bounds, malformed framing,
  deadlines, keep-alive, and pipelining;
- delayed agent startup, capped backoff, hanging and malformed services, and
  clean cancellation;
- agent identity replacement and contradictory identity rejection;
- independent status and metric polling, receipt freshness, and every
  readiness state;
- disabled-agent status with null connection, identity, and status, no agent
  polling, and enabled-agent rejection of a null connection;
- whole-device diskstats filtering, 512-byte-sector byte normalization,
  cumulative-counter reset handling, in-flight gauges, and bounded device
  cardinality;
- many concurrent SSH and filesystem streams while status and lifecycle work
  remains responsive;
- canonical path validation, canonical root entry naming, and every filesystem
  entry kind;
- symlink, race, permission, missing-parent, non-directory, non-empty-directory,
  pagination, cursor, and non-UTF-8 behavior;
- interrupted and oversized uploads, sibling cleanup, atomic visibility, and
  ownership preservation;
- download backpressure, midstream failure, and bounded memory;
- no optimistic raw bytes, parser read-ahead, backend timeout, serial
  contention, both half-close directions, and cleanup;
- shutdown raced against waits, polling, transfers, backend connect, and raw
  relays; and
- zero guest report, file, or raw-content leakage in logs.

Coverage-guided fuzzing targets both Hyper boundaries, typed JSON models,
filesystem query decoding, agent response validation, identity and freshness
state transitions, and Upgrade handling. Resource tests vary implementation
limits rather than assuming default tuning values are wire promises.

## Consequences

### Benefits

- Agent configuration and post-boot control have independent owners.
- Guest code cannot initiate HTTP work in `vmmon`; the monitor controls poll
  cadence and concurrency.
- One stable host socket exposes finite state, file transfer, and raw access.
- Agent identity replacement and host receipt times give deterministic
  readiness and freshness without guest-controlled deadlines.
- Resource-oriented filesystem operations avoid shell execution and utility
  dependencies.
- Independent domains keep SSH and large transfers from consuming lifecycle or
  polling capacity.
- One process per boot removes VM generation and in-process restart ambiguity.
- Manager-owned namespace cleanup cannot race late monitor unlinking.

### Tradeoffs

- Readiness and metric updates are observed no faster than their polling
  intervals.
- `vmmon` now owns an active agent connection supervisor and response parser.
- Status, metrics, and diagnostics disappear when `vmmon` exits.
- Guest readiness, telemetry, and filesystem results remain untrusted.
- Recursive deletion can partially succeed.
- Atomic upload visibility does not imply crash durability.
- Strict request schemas require `/v2` for incompatible changes.
- Custom Upgrade handling still requires careful read-ahead detection and
  cleanup.
- Active Unix socket authorization survives later group removal.

## Alternatives Considered

### One Host Socket Per Capability

Separate observer, file, SSH, or serial sockets can create role and resource
boundaries but add discovery and permission complexity. The optional group is
a full administrator role, so one host socket with internal operation domains
is simpler.

### Synchronous Host Status Proxying

Calling the agent for each host status or metric request would expose guest
latency directly and multiply guest work by the number of host clients. A
single monitor poller and cached current snapshots provide bounded load and
consistent readiness.

### SSH-Backed Filesystem Operations

Using SSH exec or SFTP would require `vmmon` to terminate SSH, own credentials,
choose a guest user, and map weaker protocol errors. It would also contradict
the opaque relay boundary. The agent HTTP service already owns guest
filesystem access and provides exact typed semantics.

### Archive Transfer

Tar upload and download require archive-root, overwrite, traversal, link,
device, expanded-size, partial-failure, and ownership rules. V1 provides
regular-file streaming and explicit directory operations instead.

### Guest Events And Host Streams

No current consumer requires retained guest events. Current status contains
boot and provisioning diagnostics, and logs provide history. Removing event
retention and fan-out keeps the per-VM monitor bounded.

### Generic Telemetry

Arbitrary metric names, labels, and history would turn the per-VM supervisor
into a telemetry service. V1 retains only one typed current guest snapshot.

## Accepted Limitations

- Guest root or the guest kernel can impersonate the agent and fabricate every
  guest assertion and filesystem result.
- No status, metric, or diagnostic history survives monitor exit.
- Polling can miss intermediate guest state changes.
- Raw guest output and file contents may contain hostile control sequences or
  payloads. Clients own safe display and storage.
- Filesystem operations support only UTF-8 guest path names.
- Recursive removal is non-atomic and may leave a partial result.
- Deliberate same-UID runtime-path tampering and disruption by a
  socket-authorized VM administrator are outside the protected boundary.
- `vmmon`, Hyper, Axum, Serde, the host kernel, `virt`, and the selected VMM
  backend remain trusted computing-base components for the host service.

## What This Does Not Decide

This ADR does not define:

- A public, remote, fleet, or manager API.
- Authentication or attestation of one process against guest root.
- Confidential delivery of data to a guest workload.
- Durable telemetry, event history, an audit database, or a Prometheus adapter.
- Parsing, authenticating, or terminating SSH in `vmmon`.
- The SSH client's server-key policy.
- Sanitizing hostile terminal or file content for clients.
- In-process VM restart or multiple VM boots in one `vmmon` invocation.
- Per-route host roles, read-only observer access, or active revocation of an
  already accepted host connection.
- Archive creation or extraction, resumable transfer, or filesystem
  transaction semantics.

Those concerns require separate decisions and trust models.

## API Reference

These are two complete standalone OpenAPI 3.1.1 documents because their shared
method-path pairs have different schemas. They use JSON Schema 2020-12. The
documents describe finite HTTP messages, not Unix DAC authorization, machine-
scoped host-initiated vsock authority, strict HTTP/1.1 parsing, polling and
freshness, stream backpressure, Upgrade read-ahead rejection, or shutdown.
Every finite successful and JSON error response uses `Cache-Control: no-store`
where shown. Clients must ignore additive response fields as specified above.
The host API is authorized by Unix DAC, not bearer tokens. The agent API is
host-initiated over the current machine's vsock port 1027, not a public callback
service. See [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html) and
[Linux I/O statistics](https://www.kernel.org/doc/html/latest/admin-guide/iostats.html).

### Host API OpenAPI

```yaml
openapi: 3.1.1
jsonSchemaDialect: https://json-schema.org/draft/2020-12/schema
info:
    title: Silo vmmon host API
    version: v1
    description: >-
        Exactly one vmmon process, VM, and boot. Machine identity is response data, never routing.
        Unix socket authorization is Unix DAC; no bearer authentication.
servers:
    - url: http://vmmon.invalid
      description: Placeholder for HTTP/1.1 over the manager-supplied Unix socket.
      x-silo-transport: unix-socket
security: []
paths:
    "/healthz":
        get:
            operationId: hostHealthz
            responses:
                "200":
                    "$ref": "#/components/responses/Health"
                "500":
                    "$ref": "#/components/responses/Error"
    "/v1/status":
        get:
            operationId: hostStatus
            parameters:
                - "$ref": "#/components/parameters/Wait"
                - "$ref": "#/components/parameters/TimeoutMs"
            responses:
                "200":
                    "$ref": "#/components/responses/HostStatus"
                "400":
                    "$ref": "#/components/responses/Error"
                "408":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/metrics":
        get:
            operationId: hostMetrics
            responses:
                "200":
                    "$ref": "#/components/responses/HostMetrics"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/ssh":
        get:
            operationId: hostSshUpgrade
            x-silo-upgrade-protocol: silo-ssh
            parameters:
                - "$ref": "#/components/parameters/Connection"
                - "$ref": "#/components/parameters/UpgradeSsh"
            responses:
                "101":
                    "$ref": "#/components/responses/SshUpgrade"
                "426":
                    "$ref": "#/components/responses/SshUpgradeRequired"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/serial":
        get:
            operationId: hostSerialUpgrade
            x-silo-upgrade-protocol: silo-serial
            parameters:
                - "$ref": "#/components/parameters/Connection"
                - "$ref": "#/components/parameters/UpgradeSerial"
            responses:
                "101":
                    "$ref": "#/components/responses/SerialUpgrade"
                "409":
                    "$ref": "#/components/responses/Error"
                "426":
                    "$ref": "#/components/responses/SerialUpgradeRequired"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/fs/entry":
        get:
            operationId: hostGetEntry
            parameters:
                - "$ref": "#/components/parameters/Path"
            responses:
                "200":
                    "$ref": "#/components/responses/Entry"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/Error"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
        delete:
            operationId: hostDeleteEntry
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Recursive"
            responses:
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/DirectoryNotEmpty"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
    "/v1/fs/file":
        get:
            operationId: hostGetFile
            parameters:
                - "$ref": "#/components/parameters/Path"
            responses:
                "200":
                    "$ref": "#/components/responses/Binary"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/Error"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/Error"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
        put:
            operationId: hostPutFile
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Mode"
                - "$ref": "#/components/parameters/Uid"
                - "$ref": "#/components/parameters/Gid"
            requestBody:
                "$ref": "#/components/requestBodies/Binary"
            responses:
                "201":
                    "$ref": "#/components/responses/NoContent"
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/ParentNotFound"
                "409":
                    "$ref": "#/components/responses/Error"
                "413":
                    "$ref": "#/components/responses/Error"
                "415":
                    "$ref": "#/components/responses/Error"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
    "/v1/fs/directory":
        get:
            operationId: hostGetDirectory
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Limit"
                - "$ref": "#/components/parameters/Cursor"
            responses:
                "200":
                    "$ref": "#/components/responses/Directory"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/Error"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/Error"
                "422":
                    "$ref": "#/components/responses/Error"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
        put:
            operationId: hostPutDirectory
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Parents"
                - "$ref": "#/components/parameters/Mode"
                - "$ref": "#/components/parameters/Uid"
                - "$ref": "#/components/parameters/Gid"
            responses:
                "201":
                    "$ref": "#/components/responses/NoContent"
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/ParentNotFound"
                "409":
                    "$ref": "#/components/responses/Error"
                "502":
                    "$ref": "#/components/responses/Error"
                "503":
                    "$ref": "#/components/responses/Error"
                "504":
                    "$ref": "#/components/responses/Error"
components:
    parameters:
        Path:
            name: path
            in: query
            required: true
            schema:
                "$ref": "#/components/schemas/Path"
        Wait:
            name: wait
            in: query
            schema:
                type: string
                enum:
                    - ready
        TimeoutMs:
            name: timeout_ms
            in: query
            description: Valid only with wait=ready.
            schema:
                type: integer
                minimum: 1
        Mode:
            name: mode
            in: query
            schema:
                type: string
                pattern: "^[0-7]{4}$"
        Uid:
            name: uid
            in: query
            schema:
                type: integer
                minimum: 0
                maximum: 4294967295
        Gid:
            name: gid
            in: query
            schema:
                type: integer
                minimum: 0
                maximum: 4294967295
        Limit:
            name: limit
            in: query
            schema:
                type: integer
                minimum: 1
        Cursor:
            name: cursor
            in: query
            schema:
                type: string
                minLength: 1
        Parents:
            name: parents
            in: query
            schema:
                type: boolean
                default: false
        Recursive:
            name: recursive
            in: query
            schema:
                type: boolean
                default: false
        Connection:
            name: Connection
            in: header
            required: true
            description: >-
                Must nominate the `upgrade` token (case-insensitively) and contain no body or Expect
                header.
            schema:
                type: string
            example: Upgrade
        UpgradeSsh:
            name: Upgrade
            in: header
            required: true
            schema:
                type: string
                const: silo-ssh
        UpgradeSerial:
            name: Upgrade
            in: header
            required: true
            schema:
                type: string
                const: silo-serial
    headers:
        NoStore:
            schema:
                type: string
                const: no-store
        UpgradeSsh:
            schema:
                type: string
                const: silo-ssh
        UpgradeSerial:
            schema:
                type: string
                const: silo-serial
    requestBodies:
        Binary:
            required: true
            content:
                application/octet-stream:
                    schema: {}
    responses:
        Health:
            description: Listener answered.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Health"
                    example:
                        ok: true
        HostStatus:
            description: Current host status or completed readiness wait.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/HostStatus"
                    example:
                        machine_id: "018ff6f2-7b2a-7697-9b32-778ecdfc5f2c"
                        name: dev
                        monitor:
                            instance_id: 3bbbd891-0fd5-4a13-9737-8ac91db245b5
                            observed_at: "2026-07-10T12:00:05.000Z"
                        vm:
                            state: running
                            state_changed_at: "2026-07-10T11:59:30.000Z"
                            running_since: "2026-07-10T11:59:30.000Z"
                            code:
                            message:
                        readiness:
                            ready: true
                            reason: guest_reported_ready
                        agent:
                            mode: enabled
                            connection:
                                state: responsive
                                last_success_at: "2026-07-10T12:00:00.100Z"
                                last_failure_at:
                                code:
                                message:
                            identity:
                                instance_id: 953fe0d6-2a5f-43db-81ec-e94e3c3a20df
                                version: 0.1.0
                                boot_id: d65d7f43-9b8f-4490-bab5-7ef2ef8b87f8
                            status:
                                received_at: "2026-07-10T12:00:00.100Z"
                                stale_at: "2026-07-10T12:00:30.100Z"
                                freshness: fresh
                                stale_reason:
                                report:
                                    observed_at: "2026-07-10T12:00:00Z"
                                    state: ready
                                    code:
                                    message:
                                    system:
                                    boot:
                                    provisioning:
        HostMetrics:
            description: Latest cached metric snapshot.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/HostMetrics"
                    example:
                        machine_id: "018ff6f2-7b2a-7697-9b32-778ecdfc5f2c"
                        name: dev
                        monitor:
                            instance_id: 3bbbd891-0fd5-4a13-9737-8ac91db245b5
                            observed_at: "2026-07-10T12:00:05.000Z"
                        metrics:
                            agent_instance_id: 953fe0d6-2a5f-43db-81ec-e94e3c3a20df
                            received_at: "2026-07-10T12:00:00.200Z"
                            stale_at: "2026-07-10T12:01:00.200Z"
                            freshness: fresh
                            stale_reason:
                            report:
                                observed_at: "2026-07-10T12:00:00Z"
                                snapshot:
                                    memory:
                                    cpu:
                                    load_average:
                                    uptime_seconds:
                                    filesystems: []
                                    network_interfaces: []
                                    block_devices: []
        Entry:
            description: lstat entry attributes.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Entry"
                    example:
                        path: "/etc/hosts"
                        name: hosts
                        kind: file
                        size_bytes: 391
                        mode: "0644"
                        uid: 0
                        gid: 0
                        modified_at:
                            seconds: 1783684800
                            nanoseconds: 0
        Directory:
            description: Ordered, non-snapshot directory page.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Directory"
                    example:
                        entries: []
                        next_cursor:
        Binary:
            description: Regular-file stream. Post-header errors close the stream.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/octet-stream:
                    schema: {}
        NoContent:
            description: Operation completed.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
        Error:
            description: Bounded JSON error.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: path_not_found
                        message: the requested guest path does not exist
        PermissionDenied:
            description: Guest filesystem permissions denied the operation.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: permission_denied
                        message: guest filesystem permissions denied the operation
        ParentNotFound:
            description: A required guest parent directory does not exist.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: parent_not_found
                        message: a required guest parent directory does not exist
        DirectoryNotEmpty:
            description: A non-empty guest directory requires recursive removal.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: directory_not_empty
                        message: the guest directory is not empty
        SshUpgradeRequired:
            description: Required silo-ssh Upgrade headers are absent or invalid.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
                Upgrade:
                    "$ref": "#/components/headers/UpgradeSsh"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
        SerialUpgradeRequired:
            description: Required silo-serial Upgrade headers are absent or invalid.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
                Upgrade:
                    "$ref": "#/components/headers/UpgradeSerial"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
        SshUpgrade:
            description: HTTP ends at 101; post-101 opaque bytes are not modeled.
            headers:
                Connection:
                    schema:
                        type: string
                        const: Upgrade
                Upgrade:
                    "$ref": "#/components/headers/UpgradeSsh"
        SerialUpgrade:
            description: HTTP ends at 101; post-101 opaque bytes are not modeled.
            headers:
                Connection:
                    schema:
                        type: string
                        const: Upgrade
                Upgrade:
                    "$ref": "#/components/headers/UpgradeSerial"
    schemas:
        JsonInt:
            type: integer
            minimum: 0
            maximum: 9007199254740991
        Path:
            type: string
            minLength: 1
            description: >-
                Bounded absolute UTF-8 guest path. Prose enforces lexical canonicality, no NUL, repeated
                slash, `.` or `..` component, or trailing slash; `/` is accepted only where the operation
                permits it. Dot-prefixed names are valid.
        Health:
            type: object
            additionalProperties: false
            required:
                - ok
            properties:
                ok:
                    type: boolean
                    const: true
        Error:
            type: object
            additionalProperties: false
            required:
                - code
                - message
            description: Code and message are bounded by implementation settings.
            properties:
                code:
                    type: string
                    minLength: 1
                message:
                    type: string
        Uuid:
            type: string
            format: uuid
            pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        HostTimestamp:
            type: string
            format: date-time
            pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
            description: RFC 3339 UTC timestamp with exactly millisecond precision.
        GuestTimestamp:
            type: string
            format: date-time
            pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$"
            description: RFC 3339 UTC timestamp with optional fractional seconds.
        Entry:
            type: object
            additionalProperties: false
            required:
                - path
                - name
                - kind
                - size_bytes
                - mode
                - uid
                - gid
                - modified_at
            properties:
                path:
                    "$ref": "#/components/schemas/Path"
                name:
                    type: string
                    minLength: 1
                    description: >-
                        "/" for the root entry; otherwise the final UTF-8 component of path.
                kind:
                    type: string
                    enum:
                        - file
                        - directory
                        - symlink
                        - fifo
                        - socket
                        - block_device
                        - character_device
                size_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                mode:
                    type: string
                    pattern: "^[0-7]{4}$"
                uid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                gid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                modified_at:
                    type: object
                    additionalProperties: false
                    required:
                        - seconds
                        - nanoseconds
                    properties:
                        seconds:
                            type: integer
                            minimum: -9007199254740991
                            maximum: 9007199254740991
                        nanoseconds:
                            type: integer
                            minimum: 0
                            maximum: 999999999
        Directory:
            type: object
            additionalProperties: false
            required:
                - entries
                - next_cursor
            properties:
                entries:
                    type: array
                    items:
                        "$ref": "#/components/schemas/Entry"
                next_cursor:
                    type:
                        - string
                        - "null"
        HostStatus:
            type: object
            additionalProperties: false
            required:
                - machine_id
                - name
                - monitor
                - vm
                - readiness
                - agent
            properties:
                machine_id:
                    "$ref": "#/components/schemas/Uuid"
                name:
                    type: string
                monitor:
                    type: object
                    additionalProperties: false
                    required:
                        - instance_id
                        - observed_at
                    properties:
                        instance_id:
                            "$ref": "#/components/schemas/Uuid"
                        observed_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                vm:
                    type: object
                    additionalProperties: false
                    required:
                        - state
                        - state_changed_at
                        - running_since
                        - code
                        - message
                    properties:
                        state:
                            type: string
                            enum:
                                - starting
                                - running
                                - stopping
                                - stopped
                                - failed
                        state_changed_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                        running_since:
                            oneOf:
                                - "$ref": "#/components/schemas/HostTimestamp"
                                - type: "null"
                        code:
                            type:
                                - string
                                - "null"
                        message:
                            type:
                                - string
                                - "null"
                readiness:
                    type: object
                    additionalProperties: false
                    required:
                        - ready
                        - reason
                    properties:
                        ready:
                            type: boolean
                        reason:
                            type: string
                            enum:
                                - vm_starting
                                - vm_stopping
                                - vm_stopped
                                - vm_failed
                                - agent_not_required
                                - agent_unavailable
                                - agent_status_stale
                                - guest_starting
                                - guest_failed
                                - guest_reported_ready
                agent:
                    "$ref": "#/components/schemas/Agent"
        Agent:
            type: object
            additionalProperties: false
            required:
                - mode
                - connection
                - identity
                - status
            properties:
                mode:
                    type: string
                    enum:
                        - enabled
                        - disabled
                connection:
                    oneOf:
                        - "$ref": "#/components/schemas/AgentConnection"
                        - type: "null"
                identity:
                    type:
                        - object
                        - "null"
                    additionalProperties: false
                    properties:
                        instance_id:
                            "$ref": "#/components/schemas/Uuid"
                        version:
                            type: string
                        boot_id:
                            "$ref": "#/components/schemas/Uuid"
                    required:
                        - instance_id
                        - version
                        - boot_id
                status:
                    type:
                        - object
                        - "null"
                    additionalProperties: false
                    properties:
                        received_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                        stale_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                        freshness:
                            type: string
                            enum:
                                - fresh
                                - stale
                        stale_reason:
                            type:
                                - string
                                - "null"
                            enum:
                                - receipt_age
                                - monitor_stopping
                                - null
                        report:
                            "$ref": "#/components/schemas/AgentStatusReport"
                    required:
                        - received_at
                        - stale_at
                        - freshness
                        - stale_reason
                        - report
            allOf:
                - if:
                      required:
                          - mode
                      properties:
                          mode:
                              const: disabled
                  then:
                      properties:
                          connection:
                              type: "null"
                          identity:
                              type: "null"
                          status:
                              type: "null"
                - if:
                      required:
                          - mode
                      properties:
                          mode:
                              const: enabled
                  then:
                      properties:
                          connection:
                              "$ref": "#/components/schemas/AgentConnection"
            examples:
                - mode: disabled
                  connection: null
                  identity: null
                  status: null
        AgentConnection:
            type: object
            additionalProperties: false
            required:
                - state
                - last_success_at
                - last_failure_at
                - code
                - message
            properties:
                state:
                    type: string
                    enum:
                        - connecting
                        - responsive
                        - unresponsive
                last_success_at:
                    oneOf:
                        - "$ref": "#/components/schemas/HostTimestamp"
                        - type: "null"
                last_failure_at:
                    oneOf:
                        - "$ref": "#/components/schemas/HostTimestamp"
                        - type: "null"
                code:
                    type:
                        - string
                        - "null"
                message:
                    type:
                        - string
                        - "null"
        AgentStatusReport:
            type: object
            additionalProperties: false
            required:
                - observed_at
                - state
                - code
                - message
                - system
                - boot
                - provisioning
            properties:
                observed_at:
                    "$ref": "#/components/schemas/GuestTimestamp"
                state:
                    type: string
                    enum:
                        - starting
                        - ready
                        - failed
                code:
                    type:
                        - string
                        - "null"
                message:
                    type:
                        - string
                        - "null"
                system:
                    oneOf:
                        - "$ref": "#/components/schemas/System"
                        - type: "null"
                boot:
                    oneOf:
                        - "$ref": "#/components/schemas/Boot"
                        - type: "null"
                provisioning:
                    oneOf:
                        - "$ref": "#/components/schemas/Provisioning"
                        - type: "null"
            allOf:
                - if:
                      properties:
                          state:
                              const: ready
                  then:
                      properties:
                          code:
                              type: "null"
                          message:
                              type: "null"
                - if:
                      properties:
                          state:
                              const: failed
                  then:
                      properties:
                          code:
                              type: string
                              minLength: 1
                          message:
                              type: string
                              minLength: 1
                - if:
                      properties:
                          state:
                              const: starting
                  then:
                      oneOf:
                          - properties:
                                code:
                                    type: "null"
                                message:
                                    type: "null"
                          - properties:
                                code:
                                    type: string
                                    minLength: 1
                                message:
                                    type: string
                                    minLength: 1
        HostMetrics:
            type: object
            additionalProperties: false
            required:
                - machine_id
                - name
                - monitor
                - metrics
            properties:
                machine_id:
                    "$ref": "#/components/schemas/Uuid"
                name:
                    type: string
                monitor:
                    type: object
                    additionalProperties: false
                    required:
                        - instance_id
                        - observed_at
                    properties:
                        instance_id:
                            "$ref": "#/components/schemas/Uuid"
                        observed_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                metrics:
                    type:
                        - object
                        - "null"
                    additionalProperties: false
                    properties:
                        agent_instance_id:
                            "$ref": "#/components/schemas/Uuid"
                        received_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                        stale_at:
                            "$ref": "#/components/schemas/HostTimestamp"
                        freshness:
                            type: string
                            enum:
                                - fresh
                                - stale
                        stale_reason:
                            type:
                                - string
                                - "null"
                            enum:
                                - receipt_age
                                - monitor_stopping
                                - null
                        report:
                            type: object
                            additionalProperties: false
                            required:
                                - observed_at
                                - snapshot
                            properties:
                                observed_at:
                                    "$ref": "#/components/schemas/GuestTimestamp"
                                snapshot:
                                    "$ref": "#/components/schemas/MetricSnapshot"
                    required:
                        - agent_instance_id
                        - received_at
                        - stale_at
                        - freshness
                        - stale_reason
                        - report
        MetricSnapshot:
            type: object
            additionalProperties: false
            required:
                - memory
                - cpu
                - load_average
                - uptime_seconds
                - filesystems
                - network_interfaces
                - block_devices
            properties:
                memory:
                    oneOf:
                        - "$ref": "#/components/schemas/Memory"
                        - type: "null"
                cpu:
                    oneOf:
                        - "$ref": "#/components/schemas/Cpu"
                        - type: "null"
                load_average:
                    oneOf:
                        - "$ref": "#/components/schemas/LoadAverage"
                        - type: "null"
                uptime_seconds:
                    type:
                        - number
                        - "null"
                    minimum: 0
                filesystems:
                    type: array
                    items:
                        "$ref": "#/components/schemas/Filesystem"
                    description: Bounded; mount_point values are unique.
                network_interfaces:
                    type: array
                    items:
                        "$ref": "#/components/schemas/NetworkInterface"
                    description: Bounded; name values are unique.
                block_devices:
                    type: array
                    items:
                        "$ref": "#/components/schemas/BlockDevice"
                    description: >-
                        Bounded; name values are unique. Entries are whole block devices only, never partitions.
        BlockDevice:
            type: object
            additionalProperties: false
            description: >-
                Whole devices only, derived from Linux /proc/diskstats. Kernel 512-byte sector counts are
                normalized to bytes. Read and write fields are cumulative and may decrease when a guest-side
                reset occurs. in_flight_operations is a current gauge.
            required:
                - name
                - read_bytes
                - read_operations
                - write_bytes
                - write_operations
                - in_flight_operations
            properties:
                name:
                    type: string
                    minLength: 1
                read_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                read_operations:
                    "$ref": "#/components/schemas/JsonInt"
                write_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                write_operations:
                    "$ref": "#/components/schemas/JsonInt"
                in_flight_operations:
                    "$ref": "#/components/schemas/JsonInt"
        Memory:
            type: object
            additionalProperties: false
            required:
                - total_bytes
                - available_bytes
            properties:
                total_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                available_bytes:
                    "$ref": "#/components/schemas/JsonInt"
            description: available_bytes cannot exceed total_bytes.
        Cpu:
            type: object
            additionalProperties: false
            required:
                - logical_cpu_count
                - user_seconds
                - nice_seconds
                - system_seconds
                - idle_seconds
                - iowait_seconds
                - irq_seconds
                - softirq_seconds
                - steal_seconds
            properties:
                logical_cpu_count:
                    type: integer
                    minimum: 1
                    maximum: 65535
                user_seconds:
                    type: number
                    minimum: 0
                nice_seconds:
                    type: number
                    minimum: 0
                system_seconds:
                    type: number
                    minimum: 0
                idle_seconds:
                    type: number
                    minimum: 0
                iowait_seconds:
                    type: number
                    minimum: 0
                irq_seconds:
                    type: number
                    minimum: 0
                softirq_seconds:
                    type: number
                    minimum: 0
                steal_seconds:
                    type: number
                    minimum: 0
        LoadAverage:
            type: object
            additionalProperties: false
            required:
                - one_minute
                - five_minutes
                - fifteen_minutes
            properties:
                one_minute:
                    type: number
                    minimum: 0
                five_minutes:
                    type: number
                    minimum: 0
                fifteen_minutes:
                    type: number
                    minimum: 0
        Filesystem:
            type: object
            additionalProperties: false
            required:
                - mount_point
                - filesystem_type
                - total_bytes
                - used_bytes
                - available_bytes
            properties:
                mount_point:
                    type: string
                filesystem_type:
                    type: string
                total_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                used_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                available_bytes:
                    "$ref": "#/components/schemas/JsonInt"
            description: >-
                used_bytes and available_bytes cannot exceed total_bytes.
        NetworkInterface:
            type: object
            additionalProperties: false
            required:
                - name
                - mac
                - receive_bytes
                - transmit_bytes
            properties:
                name:
                    type: string
                    minLength: 1
                mac:
                    type:
                        - string
                        - "null"
                    pattern: "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
                receive_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                transmit_bytes:
                    "$ref": "#/components/schemas/JsonInt"
        System:
            type: object
            additionalProperties: false
            required:
                - kernel_version
                - os_name
                - os_version
                - architecture
                - hostname
                - ip_addresses
            properties:
                kernel_version:
                    type: string
                os_name:
                    type: string
                os_version:
                    type: string
                architecture:
                    type: string
                hostname:
                    type: string
                ip_addresses:
                    type: array
                    items:
                        type: string
        Boot:
            type: object
            additionalProperties: false
            description: >-
                Observed guest diagnostics only. This schema does not define target-init selection,
                PID 1 ownership, probing policy, fork or exec behavior, or process arguments.
            required:
                - mode
                - requested_init
                - handoff_init_path
                - probed_init_paths
                - agent_path
                - agent_pid
                - agent_is_pid1
                - message
            properties:
                mode:
                    type: string
                    enum:
                        - standard
                        - agent_pid1
                        - init_child
                requested_init:
                    type: string
                handoff_init_path:
                    type: string
                probed_init_paths:
                    type: array
                    items:
                        type: string
                agent_path:
                    type: string
                agent_pid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                agent_is_pid1:
                    type: boolean
                message:
                    type: string
        Provisioning:
            type: object
            additionalProperties: false
            required:
                - status
                - started_at
                - finished_at
                - duration_ms
                - message
                - steps
            properties:
                status:
                    type: string
                    enum:
                        - succeeded
                        - degraded
                        - skipped
                        - failed_boot
                started_at:
                    oneOf:
                        - "$ref": "#/components/schemas/GuestTimestamp"
                        - type: "null"
                finished_at:
                    oneOf:
                        - "$ref": "#/components/schemas/GuestTimestamp"
                        - type: "null"
                duration_ms:
                    "$ref": "#/components/schemas/JsonInt"
                message:
                    type: string
                steps:
                    type: array
                    items:
                        "$ref": "#/components/schemas/ProvisioningStep"
        ProvisioningStep:
            type: object
            additionalProperties: false
            required:
                - id
                - status
                - failure_policy
                - changed
                - backend
                - message
                - error_chain
                - duration_ms
            properties:
                id:
                    type: string
                status:
                    type: string
                    enum:
                        - succeeded
                        - failed
                        - skipped
                        - unsupported
                failure_policy:
                    type: string
                    enum:
                        - best_effort
                        - fail_boot
                changed:
                    type: boolean
                backend:
                    type: string
                message:
                    type: string
                error_chain:
                    type: string
                duration_ms:
                    "$ref": "#/components/schemas/JsonInt"
```

### Guest Agent API OpenAPI

```yaml
openapi: 3.1.1
jsonSchemaDialect: https://json-schema.org/draft/2020-12/schema
info:
    title: Silo guest agent API
    version: v1
    description: >-
        Host-initiated HTTP/1.1 over the current machine's vsock port 1027. The transport scopes
        a machine but does not authenticate the guest process. No bearer authentication.
servers:
    - url: http://guest-agent.invalid
      description: Placeholder for host-initiated HTTP/1.1 over machine-scoped vsock port 1027.
      x-silo-transport: vsock:1027
security: []
paths:
    "/healthz":
        get:
            operationId: agentHealthz
            responses:
                "200":
                    "$ref": "#/components/responses/Health"
                "500":
                    "$ref": "#/components/responses/Error"
    "/v1/status":
        get:
            operationId: agentStatus
            responses:
                "200":
                    "$ref": "#/components/responses/Status"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/metrics":
        get:
            operationId: agentMetrics
            responses:
                "200":
                    "$ref": "#/components/responses/Metrics"
                "503":
                    "$ref": "#/components/responses/Error"
    "/v1/fs/entry":
        get:
            operationId: agentGetEntry
            parameters:
                - "$ref": "#/components/parameters/Path"
            responses:
                "200":
                    "$ref": "#/components/responses/Entry"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/Error"
        delete:
            operationId: agentDeleteEntry
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Recursive"
            responses:
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/DirectoryNotEmpty"
    "/v1/fs/file":
        get:
            operationId: agentGetFile
            parameters:
                - "$ref": "#/components/parameters/Path"
            responses:
                "200":
                    "$ref": "#/components/responses/Binary"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/Error"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/Error"
        put:
            operationId: agentPutFile
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Mode"
                - "$ref": "#/components/parameters/Uid"
                - "$ref": "#/components/parameters/Gid"
            requestBody:
                "$ref": "#/components/requestBodies/Binary"
            responses:
                "201":
                    "$ref": "#/components/responses/NoContent"
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/ParentNotFound"
                "409":
                    "$ref": "#/components/responses/Error"
                "413":
                    "$ref": "#/components/responses/Error"
                "415":
                    "$ref": "#/components/responses/Error"
    "/v1/fs/directory":
        get:
            operationId: agentGetDirectory
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Limit"
                - "$ref": "#/components/parameters/Cursor"
            responses:
                "200":
                    "$ref": "#/components/responses/Directory"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/Error"
                "404":
                    "$ref": "#/components/responses/Error"
                "409":
                    "$ref": "#/components/responses/Error"
                "422":
                    "$ref": "#/components/responses/Error"
        put:
            operationId: agentPutDirectory
            parameters:
                - "$ref": "#/components/parameters/Path"
                - "$ref": "#/components/parameters/Parents"
                - "$ref": "#/components/parameters/Mode"
                - "$ref": "#/components/parameters/Uid"
                - "$ref": "#/components/parameters/Gid"
            responses:
                "201":
                    "$ref": "#/components/responses/NoContent"
                "204":
                    "$ref": "#/components/responses/NoContent"
                "400":
                    "$ref": "#/components/responses/Error"
                "403":
                    "$ref": "#/components/responses/PermissionDenied"
                "404":
                    "$ref": "#/components/responses/ParentNotFound"
                "409":
                    "$ref": "#/components/responses/Error"
components:
    parameters:
        Path:
            name: path
            in: query
            required: true
            schema:
                "$ref": "#/components/schemas/Path"
        Mode:
            name: mode
            in: query
            schema:
                type: string
                pattern: "^[0-7]{4}$"
        Uid:
            name: uid
            in: query
            schema:
                type: integer
                minimum: 0
                maximum: 4294967295
        Gid:
            name: gid
            in: query
            schema:
                type: integer
                minimum: 0
                maximum: 4294967295
        Limit:
            name: limit
            in: query
            schema:
                type: integer
                minimum: 1
        Cursor:
            name: cursor
            in: query
            schema:
                type: string
                minLength: 1
        Parents:
            name: parents
            in: query
            schema:
                type: boolean
                default: false
        Recursive:
            name: recursive
            in: query
            schema:
                type: boolean
                default: false
    headers:
        NoStore:
            schema:
                type: string
                const: no-store
    requestBodies:
        Binary:
            required: true
            content:
                application/octet-stream:
                    schema: {}
    responses:
        Health:
            description: Listener answered.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Health"
                    example:
                        ok: true
        Status:
            description: Complete current agent report.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Status"
                    example:
                        agent_instance_id: 953fe0d6-2a5f-43db-81ec-e94e3c3a20df
                        agent_version: 0.1.0
                        boot_id: d65d7f43-9b8f-4490-bab5-7ef2ef8b87f8
                        observed_at: "2026-07-10T12:00:00Z"
                        state: ready
                        code:
                        message:
                        system:
                            kernel_version: 6.12.0
                            os_name: Alpine Linux
                            os_version: "3.22"
                            architecture: aarch64
                            hostname: dev
                            ip_addresses:
                                - 192.168.105.2
                        boot:
                            mode: agent_pid1
                            requested_init: "/sbin/init"
                            handoff_init_path: "/sbin/init"
                            probed_init_paths:
                                - "/sbin/init"
                            agent_path: "/run/agent/silo-agent"
                            agent_pid: 1
                            agent_is_pid1: true
                            message: ""
                        provisioning:
                            status: succeeded
                            started_at: "2026-07-10T11:59:31Z"
                            finished_at: "2026-07-10T11:59:39Z"
                            duration_ms: 8000
                            message: ""
                            steps: []
        Metrics:
            description: >-
                Complete current metric snapshot, including bounded whole-device disk I/O assertions.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Metrics"
                    example:
                        agent_instance_id: 953fe0d6-2a5f-43db-81ec-e94e3c3a20df
                        observed_at: "2026-07-10T12:00:00Z"
                        snapshot:
                            memory:
                            cpu:
                            load_average:
                            uptime_seconds:
                            filesystems: []
                            network_interfaces: []
                            block_devices: []
        Entry:
            description: lstat entry attributes.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Entry"
                    example:
                        path: "/etc/hosts"
                        name: hosts
                        kind: file
                        size_bytes: 391
                        mode: "0644"
                        uid: 0
                        gid: 0
                        modified_at:
                            seconds: 1783684800
                            nanoseconds: 0
        Directory:
            description: Ordered, non-snapshot directory page.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Directory"
                    example:
                        entries: []
                        next_cursor:
        Binary:
            description: Regular-file stream. Post-header errors close the stream.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/octet-stream:
                    schema: {}
        NoContent:
            description: Operation completed.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
        Error:
            description: Bounded JSON error.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: path_not_found
                        message: the requested guest path does not exist
        PermissionDenied:
            description: Guest filesystem permissions denied the operation.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: permission_denied
                        message: guest filesystem permissions denied the operation
        ParentNotFound:
            description: A required guest parent directory does not exist.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: parent_not_found
                        message: a required guest parent directory does not exist
        DirectoryNotEmpty:
            description: A non-empty guest directory requires recursive removal.
            headers:
                Cache-Control:
                    "$ref": "#/components/headers/NoStore"
            content:
                application/json:
                    schema:
                        "$ref": "#/components/schemas/Error"
                    example:
                        code: directory_not_empty
                        message: the guest directory is not empty
    schemas:
        JsonInt:
            type: integer
            minimum: 0
            maximum: 9007199254740991
        Path:
            type: string
            minLength: 1
            description: >-
                Bounded absolute UTF-8 guest path. Prose enforces lexical canonicality, no NUL, repeated
                slash, `.` or `..` component, or trailing slash; `/` is accepted only where the operation
                permits it. Dot-prefixed names are valid.
        Health:
            type: object
            additionalProperties: false
            required:
                - ok
            properties:
                ok:
                    type: boolean
                    const: true
        Error:
            type: object
            additionalProperties: false
            required:
                - code
                - message
            description: Code and message are bounded by implementation settings.
            properties:
                code:
                    type: string
                    minLength: 1
                message:
                    type: string
        Uuid:
            type: string
            format: uuid
            pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        GuestTimestamp:
            type: string
            format: date-time
            pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$"
            description: RFC 3339 UTC timestamp with optional fractional seconds.
        Entry:
            type: object
            additionalProperties: false
            required:
                - path
                - name
                - kind
                - size_bytes
                - mode
                - uid
                - gid
                - modified_at
            properties:
                path:
                    "$ref": "#/components/schemas/Path"
                name:
                    type: string
                    minLength: 1
                    description: >-
                        "/" for the root entry; otherwise the final UTF-8 component of path.
                kind:
                    type: string
                    enum:
                        - file
                        - directory
                        - symlink
                        - fifo
                        - socket
                        - block_device
                        - character_device
                size_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                mode:
                    type: string
                    pattern: "^[0-7]{4}$"
                uid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                gid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                modified_at:
                    type: object
                    additionalProperties: false
                    required:
                        - seconds
                        - nanoseconds
                    properties:
                        seconds:
                            type: integer
                            minimum: -9007199254740991
                            maximum: 9007199254740991
                        nanoseconds:
                            type: integer
                            minimum: 0
                            maximum: 999999999
        Directory:
            type: object
            additionalProperties: false
            required:
                - entries
                - next_cursor
            properties:
                entries:
                    type: array
                    items:
                        "$ref": "#/components/schemas/Entry"
                next_cursor:
                    type:
                        - string
                        - "null"
        Status:
            type: object
            additionalProperties: false
            required:
                - agent_instance_id
                - agent_version
                - boot_id
                - observed_at
                - state
                - code
                - message
                - system
                - boot
                - provisioning
            properties:
                agent_instance_id:
                    "$ref": "#/components/schemas/Uuid"
                agent_version:
                    type: string
                boot_id:
                    "$ref": "#/components/schemas/Uuid"
                observed_at:
                    "$ref": "#/components/schemas/GuestTimestamp"
                state:
                    type: string
                    enum:
                        - starting
                        - ready
                        - failed
                code:
                    type:
                        - string
                        - "null"
                message:
                    type:
                        - string
                        - "null"
                system:
                    oneOf:
                        - "$ref": "#/components/schemas/System"
                        - type: "null"
                boot:
                    oneOf:
                        - "$ref": "#/components/schemas/Boot"
                        - type: "null"
                provisioning:
                    oneOf:
                        - "$ref": "#/components/schemas/Provisioning"
                        - type: "null"
            allOf:
                - if:
                      properties:
                          state:
                              const: ready
                  then:
                      properties:
                          code:
                              type: "null"
                          message:
                              type: "null"
                - if:
                      properties:
                          state:
                              const: failed
                  then:
                      properties:
                          code:
                              type: string
                              minLength: 1
                          message:
                              type: string
                              minLength: 1
                - if:
                      properties:
                          state:
                              const: starting
                  then:
                      oneOf:
                          - properties:
                                code:
                                    type: "null"
                                message:
                                    type: "null"
                          - properties:
                                code:
                                    type: string
                                    minLength: 1
                                message:
                                    type: string
                                    minLength: 1
        Metrics:
            type: object
            additionalProperties: false
            required:
                - agent_instance_id
                - observed_at
                - snapshot
            properties:
                agent_instance_id:
                    "$ref": "#/components/schemas/Uuid"
                observed_at:
                    "$ref": "#/components/schemas/GuestTimestamp"
                snapshot:
                    "$ref": "#/components/schemas/Snapshot"
        Snapshot:
            type: object
            additionalProperties: false
            required:
                - memory
                - cpu
                - load_average
                - uptime_seconds
                - filesystems
                - network_interfaces
                - block_devices
            properties:
                memory:
                    oneOf:
                        - "$ref": "#/components/schemas/Memory"
                        - type: "null"
                cpu:
                    oneOf:
                        - "$ref": "#/components/schemas/Cpu"
                        - type: "null"
                load_average:
                    oneOf:
                        - "$ref": "#/components/schemas/LoadAverage"
                        - type: "null"
                uptime_seconds:
                    type:
                        - number
                        - "null"
                    minimum: 0
                filesystems:
                    type: array
                    items:
                        "$ref": "#/components/schemas/Filesystem"
                    description: Bounded; mount_point values are unique.
                network_interfaces:
                    type: array
                    items:
                        "$ref": "#/components/schemas/NetworkInterface"
                    description: Bounded; name values are unique.
                block_devices:
                    type: array
                    items:
                        "$ref": "#/components/schemas/BlockDevice"
                    description: >-
                        Bounded; name values are unique. Entries are whole block devices only, never partitions.
        Filesystem:
            type: object
            additionalProperties: false
            required:
                - mount_point
                - filesystem_type
                - total_bytes
                - used_bytes
                - available_bytes
            properties:
                mount_point:
                    type: string
                filesystem_type:
                    type: string
                total_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                used_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                available_bytes:
                    "$ref": "#/components/schemas/JsonInt"
            description: >-
                used_bytes and available_bytes cannot exceed total_bytes.
        NetworkInterface:
            type: object
            additionalProperties: false
            required:
                - name
                - mac
                - receive_bytes
                - transmit_bytes
            properties:
                name:
                    type: string
                    minLength: 1
                mac:
                    type:
                        - string
                        - "null"
                    pattern: "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
                receive_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                transmit_bytes:
                    "$ref": "#/components/schemas/JsonInt"
        BlockDevice:
            type: object
            additionalProperties: false
            description: >-
                Whole devices only, derived from Linux /proc/diskstats. Kernel 512-byte sector counts are
                normalized to bytes. Read and write fields are cumulative and may decrease when a guest-side
                reset occurs. in_flight_operations is a current gauge.
            required:
                - name
                - read_bytes
                - read_operations
                - write_bytes
                - write_operations
                - in_flight_operations
            properties:
                name:
                    type: string
                    minLength: 1
                read_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                read_operations:
                    "$ref": "#/components/schemas/JsonInt"
                write_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                write_operations:
                    "$ref": "#/components/schemas/JsonInt"
                in_flight_operations:
                    "$ref": "#/components/schemas/JsonInt"
        Memory:
            type: object
            additionalProperties: false
            required:
                - total_bytes
                - available_bytes
            properties:
                total_bytes:
                    "$ref": "#/components/schemas/JsonInt"
                available_bytes:
                    "$ref": "#/components/schemas/JsonInt"
            description: available_bytes cannot exceed total_bytes.
        Cpu:
            type: object
            additionalProperties: false
            required:
                - logical_cpu_count
                - user_seconds
                - nice_seconds
                - system_seconds
                - idle_seconds
                - iowait_seconds
                - irq_seconds
                - softirq_seconds
                - steal_seconds
            properties:
                logical_cpu_count:
                    type: integer
                    minimum: 1
                    maximum: 65535
                user_seconds:
                    type: number
                    minimum: 0
                nice_seconds:
                    type: number
                    minimum: 0
                system_seconds:
                    type: number
                    minimum: 0
                idle_seconds:
                    type: number
                    minimum: 0
                iowait_seconds:
                    type: number
                    minimum: 0
                irq_seconds:
                    type: number
                    minimum: 0
                softirq_seconds:
                    type: number
                    minimum: 0
                steal_seconds:
                    type: number
                    minimum: 0
        LoadAverage:
            type: object
            additionalProperties: false
            required:
                - one_minute
                - five_minutes
                - fifteen_minutes
            properties:
                one_minute:
                    type: number
                    minimum: 0
                five_minutes:
                    type: number
                    minimum: 0
                fifteen_minutes:
                    type: number
                    minimum: 0
        System:
            type: object
            additionalProperties: false
            required:
                - kernel_version
                - os_name
                - os_version
                - architecture
                - hostname
                - ip_addresses
            properties:
                kernel_version:
                    type: string
                os_name:
                    type: string
                os_version:
                    type: string
                architecture:
                    type: string
                hostname:
                    type: string
                ip_addresses:
                    type: array
                    items:
                        type: string
        Boot:
            type: object
            additionalProperties: false
            description: >-
                Observed guest diagnostics only. This schema does not define target-init selection,
                PID 1 ownership, probing policy, fork or exec behavior, or process arguments.
            required:
                - mode
                - requested_init
                - handoff_init_path
                - probed_init_paths
                - agent_path
                - agent_pid
                - agent_is_pid1
                - message
            properties:
                mode:
                    type: string
                    enum:
                        - standard
                        - agent_pid1
                        - init_child
                requested_init:
                    type: string
                handoff_init_path:
                    type: string
                probed_init_paths:
                    type: array
                    items:
                        type: string
                agent_path:
                    type: string
                agent_pid:
                    type: integer
                    minimum: 0
                    maximum: 4294967295
                agent_is_pid1:
                    type: boolean
                message:
                    type: string
        Provisioning:
            type: object
            additionalProperties: false
            required:
                - status
                - started_at
                - finished_at
                - duration_ms
                - message
                - steps
            properties:
                status:
                    type: string
                    enum:
                        - succeeded
                        - degraded
                        - skipped
                        - failed_boot
                started_at:
                    oneOf:
                        - "$ref": "#/components/schemas/GuestTimestamp"
                        - type: "null"
                finished_at:
                    oneOf:
                        - "$ref": "#/components/schemas/GuestTimestamp"
                        - type: "null"
                duration_ms:
                    "$ref": "#/components/schemas/JsonInt"
                message:
                    type: string
                steps:
                    type: array
                    items:
                        "$ref": "#/components/schemas/ProvisioningStep"
        ProvisioningStep:
            type: object
            additionalProperties: false
            required:
                - id
                - status
                - failure_policy
                - changed
                - backend
                - message
                - error_chain
                - duration_ms
            properties:
                id:
                    type: string
                status:
                    type: string
                    enum:
                        - succeeded
                        - failed
                        - skipped
                        - unsupported
                failure_policy:
                    type: string
                    enum:
                        - best_effort
                        - fail_boot
                changed:
                    type: boolean
                backend:
                    type: string
                message:
                    type: string
                error_chain:
                    type: string
                duration_ms:
                    "$ref": "#/components/schemas/JsonInt"
```
