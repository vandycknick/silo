# 8. Vmmon Host and Guest Agent gRPC APIs

Date: 2026-07-08

Updated: 2026-07-14

## Status

Implemented

## The Problem

Managing a VM requires a stable way to interact with the process that owns it.
Silo needs to read lifecycle state and metrics, wait for readiness, establish
SSH and serial sessions, and transfer files without depending on a particular
VMM backend or on guest networking.

That interface spans two processes. `vmmon` owns the VMM, lifecycle policy,
host-side access, and the host control socket. The guest agent observes the
guest, reports provisioning and metrics, and performs guest filesystem
operations. Neither surface is sufficient by itself: local callers use the
`vmmon` API, while `vmmon` uses the guest agent API.

The protocol must support finite requests and long-lived streams without
inventing separate framing for SSH, serial, file transfer, status updates, or
metrics. It must also preserve the trust boundary between authoritative host
state and untrusted guest reports.

## Decision

Silo uses gRPC with Protocol Buffers for both control surfaces.

- Each `vmmon` serves a host gRPC API on its machine-scoped Unix socket.
- The guest agent serves a guest gRPC API on machine-scoped vsock port 1027.
- `vmmon` initiates all guest API connections. The guest never calls back into
  the host API.
- Unary, client-streaming, server-streaming, and bidirectional-streaming RPCs
  are used according to the operation's data flow.
- Tonic owns gRPC and HTTP/2 behavior. Prost owns protobuf encoding and
  generated Rust types.
- Standard gRPC health and reflection services are available on both surfaces.
- The `.proto` files in `specs/protocol/proto` are the normative structured
  wire contract. This ADR defines transport, policy, trust, lifecycle, and
  operational semantics around that contract.

The APIs use plaintext gRPC over kernel-provided local transports. Unix socket
permissions protect the host surface. The machine-scoped vsock connection and
host-CID check constrain the guest surface. TLS is not added inside either
transport.

```text
CLI, libvm, or local administrative tool
                  |
                  | gRPC over machine vm.sock (Unix socket)
                  v
               vmmon ------------------> VMM lifecycle
                  |  \
                  |   +----------------> SSH and serial backends
                  |
                  | host-initiated gRPC over machine vsock:1027
                  v
             guest agent
                  |
                  +--------------------> guest status and metrics
                  +--------------------> guest filesystem
```

There is no HTTP/1.1 REST API, JSON wire model, OpenAPI contract, HTTP Upgrade
handshake, guest registration RPC, or in-band protocol negotiation.

## Two Control Surfaces

### Host Surface

The host endpoint admits these Silo services:

| Service | RPC | Shape | Purpose |
| --- | --- | --- | --- |
| `VmMonitorService` | `GetStatus` | unary | Return the current host-owned status snapshot. |
| `VmMonitorService` | `WaitReady` | unary | Wait for ready, terminal state, or a bounded timeout. |
| `VmMonitorService` | `GetMetrics` | unary | Return the latest host-retained guest metrics. |
| `VmAccessService` | `OpenSsh` | bidirectional stream | Relay an opaque SSH byte stream. |
| `VmAccessService` | `OpenSerial` | bidirectional stream | Relay an opaque serial byte stream. |
| `GuestFilesystemService` | `GetEntry` | unary | Read guest entry attributes. |
| `GuestFilesystemService` | `RemoveEntry` | unary | Remove a guest entry. |
| `GuestFilesystemService` | `DownloadFile` | server stream | Stream a regular file from the guest. |
| `GuestFilesystemService` | `UploadFile` | client stream | Atomically create or replace a regular file. |
| `GuestFilesystemService` | `ListDirectory` | unary | Return one ordered directory page. |
| `GuestFilesystemService` | `CreateDirectory` | unary | Create a guest directory. |

The host also serves `grpc.health.v1.Health` and
`grpc.reflection.v1.ServerReflection`.

`GetStatus` and `GetMetrics` read monitor-owned state. A host request never
synchronously fetches status or metrics from the guest. Filesystem requests are
validated by `vmmon`, forwarded to the guest service, and independently
validated again before a response is exposed to the host caller.

### Guest Surface

The guest endpoint admits these Silo services:

| Service | RPC | Shape | Purpose |
| --- | --- | --- | --- |
| `GuestAgentService` | `GetStatus` | unary | Return the current complete agent status. |
| `GuestAgentService` | `WatchStatus` | server stream | Return current status, changes, and heartbeats. |
| `GuestAgentService` | `GetMetrics` | unary | Collect one complete metrics snapshot. |
| `GuestAgentService` | `WatchMetrics` | server stream | Collect and stream metrics at a requested interval. |
| `GuestFilesystemService` | `GetEntry` | unary | Read entry attributes. |
| `GuestFilesystemService` | `RemoveEntry` | unary | Remove an entry. |
| `GuestFilesystemService` | `DownloadFile` | server stream | Stream a regular file to the host. |
| `GuestFilesystemService` | `UploadFile` | client stream | Atomically create or replace a regular file. |
| `GuestFilesystemService` | `ListDirectory` | unary | Return one ordered directory page. |
| `GuestFilesystemService` | `CreateDirectory` | unary | Create a directory. |

The guest also serves `grpc.health.v1.Health` and
`grpc.reflection.v1.ServerReflection`.

`vmmon` uses `WatchStatus` and `WatchMetrics` during normal supervision. The
unary guest methods remain useful for direct diagnostics and independent
clients, but they do not drive host readiness.

### Reflection Boundaries

Each endpoint publishes only the services admitted on that endpoint. The host
reflection inventory excludes `GuestAgentService`. The guest reflection
inventory excludes `VmMonitorService` and `VmAccessService`. Shared message
descriptors may still appear when referenced by an admitted service.

Filtering prevents reflection from advertising a generated service merely
because its descriptor was compiled into the same binary.

## Protocol Contract And Evolution

The `silo.v1` protobuf package is the first major API version. Its source is
split by concern:

- `common.proto` defines shared status, identity, metrics, provisioning, and
  byte-chunk messages.
- `vm_monitor.proto` defines host status, readiness, metrics, and access RPCs.
- `guest.proto` defines guest status and metrics RPCs.
- `filesystem.proto` defines the filesystem service shared by both surfaces.
- `errors.proto` defines stable Silo application error details.

The build produces generated clients and servers plus a source-free serialized
descriptor set. Reflection is built from a service-filtered view of that
descriptor set. Generated Rust code is not a separate hand-maintained contract.

### Presence And Validation

Proto3 scalar fields that need presence use `optional`. Message fields have
message presence, and mutually exclusive states use `oneof`. Enum value zero is
always an `UNSPECIFIED` sentinel rather than a valid domain value.

Wire-level optionality does not imply semantic optionality. Receivers validate
fields required by an operation and reject absent values, unspecified enums,
unknown enum values where no forward behavior is defined, malformed UUIDs,
invalid timestamps or durations, oversized text, non-finite metrics, and
contradictory combinations.

This lets decoders distinguish omission from a legitimate scalar default while
still producing useful application errors instead of silently accepting an
incomplete message.

### Compatibility

Compatible v1 evolution follows protobuf compatibility rules:

- Existing field numbers and meanings do not change.
- Removed fields reserve their numbers and names before reuse can occur.
- Additive fields must have behavior that is safe when an older peer omits or
  ignores them.
- New enum values are added only when older consumers have defined behavior for
  an unknown value. Otherwise the change requires a new version.
- Existing RPC request and response cardinality does not change.
- Incompatible service or message changes use a new versioned package rather
  than in-band feature negotiation.

Operational tuning such as concurrency, retry delays, and collection intervals
may change without defining a new wire version unless a protobuf field gives
the caller explicit control over that value.

## One Monitor Per Boot

One `vmmon` invocation owns exactly one VMM instance and one VM boot. It creates
one random monitor instance ID and one in-memory state store. A terminal VM
state ends that process; restarting a machine creates a new `vmmon`, monitor
identity, state store, control listener, and set of guest streams.

There is no separate in-process VM generation. Host status cannot cross a boot
without also crossing a monitor process boundary.

The state store serializes VM lifecycle, guest connection state, guest
identity, accepted observations, freshness, and readiness. Network, VMM, file,
and stream I/O happen outside that state boundary. Freshness deadlines use the
host monotonic clock; protobuf timestamps are explanatory wall-clock values.

## Discovering And Supervising The Guest

When managed guest services are enabled, port 1027 is added to the VMM in host
connect mode and `silo.guest.port=1027` is added to the guest kernel command
line. The guest agent reads that argument and binds its listener before
long-running provisioning completes, allowing it to publish `starting` while
boot work continues.

After the VM reaches the VMM's running state, `vmmon` starts independent status
and metrics supervisors.

### Status Stream

`vmmon` opens `WatchStatus` with a five-second heartbeat interval. The guest
sends the current status immediately, sends a new message when status changes,
and repeats the latest status on each heartbeat. The guest retains only the
latest status, so a slow watcher does not build an unbounded queue of obsolete
states.

Watch setup and the first status message each have a five-second deadline.
After that, three missed heartbeats, currently fifteen seconds of silence,
terminate the stream. Each accepted heartbeat is a fresh host observation even
if the status content did not change.

Before the first valid snapshot, failed connection attempts retry every 25 ms
for the first two seconds. Discovery then changes to full-jitter exponential
backoff starting at 100 ms and capped at five seconds. Once any valid snapshot
has been received, future reconnects use the backoff schedule immediately. A
valid snapshot resets the backoff.

### Metrics Stream

The metrics supervisor waits until status has established a current agent
identity. It then opens `WatchMetrics` with a five-second interval. The guest
collects one snapshot immediately and continues at that interval. Fifteen
seconds without a metric message terminates the stream and triggers a
reconnect.

Status and metrics have separate gRPC channels, retry state, and stream
capacity. A slow metric collection cannot prevent a status heartbeat from
refreshing readiness.

Individual Linux collectors may leave an optional metric section absent when
that section cannot be collected. Metric arrays are bounded. Counters are
cumulative guest observations and may decrease after reset, reattachment,
reinitialization, or overflow.

## Agent Identity And Freshness

Each agent process creates a random `agent_instance_id`. Status also reports the
agent version and the guest's claimed boot ID. These values establish an
untrusted process identity for consistency checks, not authentication.

The first valid status establishes the current identity. If a later status has
a different instance ID, `vmmon` clears status and metrics from the previous
agent before accepting the replacement. Reusing one instance ID with a
different version or boot ID is a protocol violation.

Every metric message carries an agent instance ID. Metrics are not accepted
before status has established identity. A mismatched metric identity clears the
retained identity and observations, interrupts the status stream, and requires
status to establish the replacement before metrics resume.

For every accepted status or metric message, `vmmon` records:

- the host receipt time;
- the host-computed stale time;
- a monotonic freshness deadline; and
- the validated guest report.

Guest timestamps never control ordering or freshness. Status and metric
freshness are independent. A failed stream retains the latest observation for
diagnostics until its deadline. Only an accepted status message refreshes
readiness.

Status watches retain only the latest value. Rapid intermediate guest states
may therefore be coalesced before a watcher consumes them. The API provides
current state, not event history.

## Readiness

Readiness is monitor policy, not a guest fact and not gRPC channel readiness.
The VM must first be running according to the VMM. If managed guest services
are disabled, that condition is sufficient. If they are enabled, `vmmon` also
requires a fresh guest status whose state is `ready`.

The monitor chooses exactly one readiness reason in this order:

| Condition | Ready | Reason |
| --- | --- | --- |
| VM is starting | false | `VM_STARTING` |
| VM is stopping | false | `VM_STOPPING` |
| VM is stopped | false | `VM_STOPPED` |
| VM failed | false | `VM_FAILED` |
| Agent is disabled and VM is running | true | `AGENT_NOT_REQUIRED` |
| No valid status is retained | false | `AGENT_UNAVAILABLE` |
| Retained status is stale | false | `AGENT_STATUS_STALE` |
| Guest reports starting | false | `GUEST_STARTING` |
| Guest reports failed | false | `GUEST_FAILED` |
| Guest reports ready | true | `GUEST_REPORTED_READY` |

`GUEST_REPORTED_READY` deliberately identifies the untrusted assertion on
which host readiness depends. A transient stream failure does not revoke
readiness until the retained observation becomes stale.

`GetStatus` returns immediately. `WaitReady` accepts a positive `max_wait` no
greater than five minutes and returns the latest complete host status when one
of these outcomes occurs:

- `READY`: readiness became true;
- `TERMINAL`: the VM reached a terminal state; or
- `TIMED_OUT`: the requested wait elapsed.

Client cancellation removes only that waiter. The caller's gRPC deadline is
separate from the requested wait and should include enough margin to receive
the final response.

## Host Status And Metrics

`HostStatus` separates host facts from guest assertions.

Host facts include machine identity and name, monitor identity and observation
time, VM state and transition times, readiness, connection state, receipt
times, stale times, and freshness. Guest assertions include agent identity,
guest observation times, system information, boot diagnostics, provisioning
reports, status detail, and metrics.

Agent mode is a protobuf `oneof`:

- Disabled mode contains no connection, identity, or guest status.
- Enabled mode always exposes connection state and may lack identity or status
  until a valid status message has been accepted.

Connection state is `CONNECTING`, `RESPONSIVE`, or `UNRESPONSIVE`. A valid
status changes it to responsive. A failed status stream records a bounded
failure and changes it to unresponsive once the initial fast-discovery window
has passed. Retained identity and status remain visible until replacement or
staleness.

`HostMetrics.metrics` is absent before the first accepted metric observation.
Afterward it includes the guest instance ID, host freshness metadata, and the
validated guest report. An agent identity replacement clears metrics.

## Health And Reflection

Both servers implement standard gRPC health `Check` and `Watch`. Health answers
whether a named gRPC service is serving requests. It does not mean that the VM
is ready, guest status is fresh, SSH authentication will succeed, or a
particular filesystem operation is permitted.

On the host, overall health, the admitted Silo services, and reflection start as
`SERVING`. When shutdown begins, access, filesystem, and reflection become
`NOT_SERVING`, while the monitor service remains available long enough to
expose stopping or terminal state. Before the server closes, the monitor and
overall health also become `NOT_SERVING`.

On the guest, overall health, `GuestAgentService`, `GuestFilesystemService`, and
reflection become `NOT_SERVING` before the gRPC server is shut down.

Reflection exists for local inspection and tools such as `grpcurl`. It is not a
second source of service definitions; it publishes the compiled protobuf
descriptors admitted on that endpoint.

## Guest Filesystem

The same `GuestFilesystemService` contract is implemented by the guest and
proxied by `vmmon`. This gives callers typed filesystem operations before guest
networking or SSH is available, without exposing arbitrary command execution.

### Paths

Paths are bounded UTF-8 absolute guest paths. They must use one lexical spelling:

- maximum encoded path length is 4095 bytes;
- every non-root component is at most 255 bytes;
- empty, `.`, and `..` components are rejected;
- repeated separators, NUL, and a trailing separator are rejected; and
- `/` is valid only for operations that explicitly allow the root.

Intermediate components follow normal guest filesystem resolution. Operations
do not follow the final symlink when identifying the target. Recursive removal
does not traverse symlinks. Non-UTF-8 directory entry names cannot be represented
by v1 and produce `UNSUPPORTED_FILENAME`.

`vmmon` validates host requests before connecting to the guest. The guest
validates the request again before touching the filesystem. For reads, `vmmon`
also validates returned paths, names, kinds, attributes, ordering, cardinality,
timestamps, cursors, and dispositions before exposing the result.

### Entry And Directory Operations

`GetEntry` uses `lstat` semantics. It reports the canonical path, final name,
entry kind, size, permission and special mode bits, numeric UID and GID, and
modification time. Supported kinds are regular file, directory, symlink, FIFO,
socket, block device, and character device.

`ListDirectory` returns entries ordered by UTF-8 filename bytes. The default
page size is 256 and the maximum is 1024. Cursors are opaque byte strings,
bounded to 8 KiB, and tied to the agent instance and directory path. Pagination
is not a snapshot; concurrent mutation may cause entries to be skipped or
repeated.

`CreateDirectory` optionally creates missing parents. Mode is a numeric value
containing at most `07777`; optional UID and GID request ownership. Existing
directories return `ALREADY_EXISTS` as a successful disposition rather than
changing their attributes. An existing non-directory is a failed precondition.

`RemoveEntry` unlinks files and symlinks. Directories must be empty unless
`recursive` is true. Removing `/` is forbidden. Recursive removal is not atomic
and may leave a partially removed tree when an error occurs.

### Download

`DownloadFile` opens the final entry without following a symlink, verifies the
opened handle is a regular file, and returns a stream of `ByteChunk` messages.
Devices, sockets, FIFOs, directories, and symlinks are rejected.

The stream uses bounded channels and gRPC flow control. Empty chunks are
ignored by the host proxy. A failure after streaming starts terminates the RPC
with its final status; already delivered chunks cannot be rolled back.

### Upload

`UploadFile` requires the first request message to contain `UploadFileHeader`.
Every subsequent message must contain a `ByteChunk`. The header supplies the
target path and optional mode, UID, and GID.

The guest creates a unique temporary regular file in the destination directory,
writes the bounded stream, applies requested or preserved attributes, closes it,
and atomically renames it over the target. Failure or cancellation removes the
temporary file. Omitted attributes default on create and preserve the existing
regular file's values on replacement.

Atomic visibility is guaranteed only within the destination filesystem. V1
does not promise crash durability, parent-directory `fsync`, resumable upload,
or transactional behavior across operations.

### Filesystem Limits

Current enforced limits are:

| Limit | Value |
| --- | --- |
| Structured gRPC message | 16 MiB |
| Byte chunk | 64 KiB |
| File transfer | 8 GiB |
| Transfer idle progress | 30 seconds |
| Transfer total duration | 30 minutes |
| Proxied metadata RPC | 30 seconds |
| Concurrent filesystem operations per host proxy | 8 |
| Concurrent filesystem operations in the guest | 8 |

Concurrency values and timing are operational policy rather than compatibility
promises. Size and shape limits that protect cross-version decoding are shared
by the protocol crate and enforced on both sides.

`vmmon` does not retry a filesystem mutation after delivery becomes ambiguous.
Callers must treat a deadline or connection loss during a mutating RPC as an
unknown outcome and inspect the target before deciding whether to retry.

## SSH And Serial Access

`OpenSsh` and `OpenSerial` are bidirectional streams of `ByteChunk`. They use
gRPC framing and flow control only; `vmmon` does not parse, authenticate, log,
or modify the relayed SSH or terminal protocol.

Before returning a successful RPC response, `vmmon` acquires stream capacity
and opens the backend under a five-second setup deadline. A successful response
therefore means the requested backend was acquired, not merely that the host
gRPC method exists.

Client chunks are limited to 64 KiB. Backend output is emitted in chunks no
larger than 32 KiB. Bounded channels apply backpressure in both directions.

For SSH, request half-close shuts down the backend write half and continues
draining backend output until EOF. For serial, request half-close stops further
input while output continues. Client cancellation, backend EOF, monitor
shutdown, or output receiver closure ends the relay and releases ownership.

SSH has an independent capacity of 32 streams. Serial interactive access is
exclusive through the serial backend. SSH and serial are available regardless
of guest readiness; readiness is not an access-control gate.

The host SSH client, not `vmmon`, owns SSH server-key acceptance and continuity.

## Errors

Every gRPC RPC completes with a canonical gRPC status. Application-generated
errors also carry serialized `silo.v1.ErrorDetail` bytes in the status details.
The detail contains a stable Silo `ErrorCode` and optional retry delay.
Transport-generated gRPC failures may not contain a Silo detail.

The canonical status communicates broad behavior:

| gRPC status | Representative Silo errors |
| --- | --- |
| `INVALID_ARGUMENT` | Invalid request, path, mode, interval, or cursor. |
| `NOT_FOUND` | Missing target or parent. |
| `PERMISSION_DENIED` | Guest filesystem permission failure. |
| `RESOURCE_EXHAUSTED` | Admission capacity, size limit, or serial ownership. |
| `FAILED_PRECONDITION` | Wrong entry kind, non-empty directory, expired cursor, or unsupported filename. |
| `UNAVAILABLE` | Guest, backend, or monitor is unavailable. |
| `DEADLINE_EXCEEDED` | Setup, operation, or progress deadline expired. |
| `DATA_LOSS` | Guest response violated the protocol contract. |
| `CANCELLED` | The operation was cancelled. |
| `UNIMPLEMENTED` | The requested behavior is unsupported. |
| `INTERNAL` | A trusted component invariant failed. |

Diagnostic messages are bounded to 4096 UTF-8 bytes. They are not stable
machine interfaces; callers branch on canonical status and `ErrorCode`.

When proxying filesystem operations, `vmmon` ensures a detail-free guest status
receives the stable detail implied by its canonical code, then verifies that
the gRPC status, Silo detail, and retry metadata are mutually consistent.
Malformed, oversized, unknown, or contradictory guest details become
`DATA_LOSS` with `AGENT_PROTOCOL_ERROR` rather than passing through unchecked.

Silo's generated-client wrappers do not configure automatic RPC retries. The
monitor supervisors explicitly reconnect status and metrics watches, but
callers must not automatically retry non-idempotent operations merely because
gRPC returned `UNAVAILABLE` or `DEADLINE_EXCEEDED`.

## Trust Boundaries

### Host Caller

The machine directory is mode `0700` before the host socket is bound, and the
socket is created with mode `0600`. `vmmon` also requires each accepted peer UID
to match the socket owner and rejects connections when peer credentials are not
available. Access is therefore an owner-only, full-administrator capability for
that VM. The API has no read-only role, per-RPC authorization, configured
administrator group, or active revocation of an already accepted connection.

The manager supplies a machine-scoped socket path and serializes machine
lifecycle operations. At startup, `vmmon` tightens the machine directory,
removes the expected stale socket entry, binds the socket, and sets its
permissions. `vmmon` does not unlink the path during late process exit, avoiding
removal of a successor's listener. Managed path reconciliation remains a
`libvm` responsibility.

### Guest Agent

The guest accepts RPC connections only from the host vsock CID. `vmmon` opens
those connections through the current `VirtualMachine`, so another host process
still needs access to that machine object or backend transport.

This identifies the host and VM transport, not the intended guest process.
Guest root or a compromised guest kernel can replace the agent, fabricate
identity and readiness, return malicious filesystem data, or deliberately
consume resources. Every guest report and filesystem result is an untrusted
assertion.

`vmmon` therefore validates guest messages after protobuf decoding, bounds all
retained text and collections, applies stream silence deadlines, sanitizes
errors, and keeps lifecycle, status, metrics, filesystem, SSH, and serial in
separate admission domains.

Neither surface provides guest-agent attestation, end-to-end confidentiality
from the host, or protection from a compromised host kernel.

## Resource Isolation And Deadlines

Tonic and HTTP/2 provide message framing and per-stream flow control. Silo adds
application limits because transport flow control alone does not bound decoded
objects, retained state, task count, or total transfer size.

The host currently separates these capacities:

- 64 finite monitor RPCs;
- 64 readiness waiters;
- 32 SSH streams;
- exclusive serial interactive ownership; and
- 8 proxied filesystem operations.

The guest separately admits eight status watches, four metric watches, and
eight filesystem operations. Its accepted vsock connection queue is bounded.

Status and metric supervisors retain their own capacity and channels. Large
file or access streams cannot consume their stream slots. All internal queues
are bounded, and producers await capacity rather than buffering unbounded data.

Finite `libvm` calls use gRPC deadlines. File operations use longer deadlines,
and access setup uses a short explicit timeout before the caller receives the
stream. Filesystem transfer idle and total deadlines are monotonic. Progress
refreshes only the idle deadline, never the total deadline.

## Shutdown

Signal-driven shutdown and spontaneous VMM exit converge on the same lifecycle
state and server cleanup.

On requested shutdown, `vmmon`:

1. changes VM state to `STOPPING`, revoking readiness and waking waiters;
2. marks access, filesystem, and reflection health `NOT_SERVING`;
3. cancels guest supervisors, endpoint work, and active access relays;
4. requests VMM stop with a 45-second deadline;
5. records the resulting terminal VM state;
6. marks monitor and overall health `NOT_SERVING`;
7. stops accepting host gRPC connections;
8. permits each supervised service task at most one second to drain before
   aborting it;
9. stops serial log attachment; and
10. exits without late socket unlinking.

While state is stopping, retained status and metrics project as stale with
`MONITOR_STOPPING`. New access and filesystem work is rejected once shutdown is
observed. gRPC cancellation, channel closure, bounded server drain, and VMM
teardown terminate remaining in-flight work. A second signal may force an
earlier exit.

A host crash or process kill can prevent final health transitions and RPC
statuses. Callers must treat connection loss as authoritative evidence that the
monitor API is gone, not as proof of one final VM state.

## Logging

Structured logs are operational diagnostics, not a tamper-proof audit trail.
Current records cover monitor startup, VM transitions, host RPC method names and
available peer credentials, guest stream connection and retry state, agent
identity and status transitions, readiness, backend access, and shutdown.

File content, SSH bytes, serial input, and terminal output are not logged by the
gRPC relays. Bounded guest status codes and diagnostic messages may appear in
lifecycle logs and must be treated as untrusted text. Reflection does not expose
runtime state or request content.

## Consequences

### Benefits

- One protobuf contract generates clients, servers, and reflection descriptors.
- RPC cardinality directly models finite calls, watches, transfers, and opaque
  duplex access.
- HTTP/2 multiplexing and gRPC flow control remove custom HTTP Upgrade and
  framing behavior.
- Standard health and reflection make local diagnosis possible with common
  tooling.
- Host-initiated status and metrics streams observe changes quickly without
  guest callbacks or repeated polling setup.
- Cached host snapshots isolate administrative callers from guest latency and
  multiplicative guest work.
- Host receipt time and agent identity make freshness and replacement
  deterministic without trusting guest clocks.
- The shared filesystem service gives host callers the same typed semantics the
  guest implements while preserving an independent validation boundary.
- Separate admission domains keep large transfers and access streams from
  starving readiness supervision.

### Tradeoffs

- Every implementation must support protobuf and the required gRPC streaming
  forms.
- API evolution requires protobuf field-number and enum discipline.
- Binary protobuf is less convenient to inspect manually than JSON; reflection
  and `grpcurl` become important development tools.
- Guest readiness, telemetry, and filesystem results remain untrusted despite
  being strongly typed.
- Long-lived watches require reconnect, silence detection, cancellation, and
  identity-reset logic in `vmmon`.
- Current status retains no event history and may coalesce rapid transitions.
- Recursive deletion can partially succeed, and atomic upload visibility does
  not imply crash durability.
- Unix socket authorization has one full-administrator role and no active
  revocation for accepted connections.

## Alternatives Considered

### HTTP/1.1, JSON, And OpenAPI

The original proposal used resource-oriented HTTP/1.1 routes, strict JSON
models, OpenAPI documents, and HTTP Upgrade for SSH and serial. It was not
implemented.

That design would require Silo-specific rules for Upgrade validation,
read-ahead, content types, JSON closure, body framing, and route evolution.
gRPC already provides typed unary and streaming operations, generated code,
flow control, deadlines, health, and reflection. Using one protocol for finite
and streaming operations removes an unnecessary second contract.

### Guest Registration Or Callback

An agent-initiated registration call gives the guest control over host work and
requires a host listener reachable from the guest. Host-initiated watches keep
connection cadence, retry, capacity, and shutdown under monitor control. The
first valid status message establishes identity without a separate registration
protocol.

### Repeated Unary Polling

Polling `GetStatus` and `GetMetrics` would repeatedly establish application
work, add observation latency, and make fast readiness depend on poll cadence.
Server streams provide an immediate snapshot, updates or intervals, and
heartbeats on one supervised RPC. Unary guest methods remain available for
diagnostics, not routine supervision.

### Synchronous Host Status Proxying

Calling the guest for every host status or metrics request would expose guest
latency directly and multiply work by the number of local clients. Monitor-owned
snapshots provide bounded guest load and a single readiness decision.

### One Host Socket Per Capability

Separate status, filesystem, SSH, and serial sockets could provide distinct
Unix permission roles, but would add path discovery, cleanup, and authorization
complexity. V1 intentionally grants one full VM-administrator capability and
uses internal admission domains for resource isolation.

### SSH-Backed Filesystem Operations

SFTP or SSH exec would require `vmmon` to terminate SSH, own guest credentials,
choose a guest user, and map less precise errors. It would also violate the
opaque SSH relay boundary. The guest agent already has direct filesystem access
and can implement exact typed semantics.

### Archive Transfer

Archive upload and download require traversal, link, device, overwrite,
expanded-size, ownership, and partial-failure rules. V1 offers explicit regular
file and directory operations instead.

### Retained Guest Events And Generic Telemetry

No current caller requires durable guest events, arbitrary metric names,
labels, or history. The per-VM monitor retains one current typed status and
metric observation. Durable telemetry and event storage belong in a separate
service with a different lifecycle and resource model.

## Accepted Limitations

- Guest root or the guest kernel can impersonate the agent and fabricate every
  guest assertion and filesystem result.
- Status, metrics, and diagnostics are not retained after `vmmon` exits.
- A latest-value status watch can coalesce intermediate guest changes.
- Raw guest and file output may contain hostile control sequences or payloads;
  clients own safe display and storage.
- Filesystem operations support only UTF-8 guest path names.
- Recursive removal is non-atomic and may leave a partial result.
- Mutating RPC cancellation or deadline expiry may leave an unknown outcome.
- Host socket access grants every API capability; there is no observer role.
- Deliberate same-UID runtime-path tampering is outside the protected boundary.
- Tonic, Prost, Tokio, the host kernel, `virt`, and the selected VMM backend are
  trusted computing-base components for the host service.

## What This Does Not Decide

This ADR does not define:

- a public, remote, fleet, or manager API;
- guest-agent authentication against guest root or cryptographic attestation;
- confidential delivery of data from the host to a guest workload;
- durable telemetry, event history, audit storage, or a Prometheus adapter;
- SSH parsing, termination, authentication, or server-key policy in `vmmon`;
- sanitization of terminal or file content for client display;
- in-process VM restart or multiple VM boots in one `vmmon` process;
- per-RPC host roles, read-only access, or active revocation;
- archive extraction, resumable transfer, or filesystem transactions; or
- automatic application-level retries for mutating RPCs.

Those concerns require separate decisions and trust models.

## Implementation References

- [Common protobuf messages](../../specs/protocol/proto/common.proto)
- [Host monitor and access services](../../specs/protocol/proto/vm_monitor.proto)
- [Guest status and metrics service](../../specs/protocol/proto/guest.proto)
- [Guest filesystem service](../../specs/protocol/proto/filesystem.proto)
- [Stable Silo error details](../../specs/protocol/proto/errors.proto)
- [Host gRPC testing with `grpcurl`](../host-grpc-testing.md)
- `runtime/vmmon/src/services.rs` for host service admission, access streams,
  health, and reflection
- `runtime/vmmon/src/guest.rs` for guest watches, discovery, and reconnects
- `runtime/vmmon/src/state.rs` for identity, validation, freshness, and
  readiness
- `runtime/vmmon/src/filesystem.rs` for the host filesystem proxy
- `guest/agent/src/rpc.rs` for guest status, metrics, health, and reflection
- `guest/agent/src/filesystem.rs` for guest filesystem semantics
- `runtime/libvm/src/vmmon/client.rs` for the host client

## External References

- [gRPC core concepts and RPC cardinality](https://grpc.io/docs/what-is-grpc/core-concepts/)
- [gRPC status codes](https://grpc.io/docs/guides/status-codes/)
- [gRPC health checking](https://grpc.io/docs/guides/health-checking/)
- [gRPC reflection](https://grpc.io/docs/guides/reflection/)
- [Protocol Buffers language guide](https://protobuf.dev/programming-guides/proto3/)
