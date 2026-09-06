# 15. Firecracker-Compatible Hybrid Vsock Host Surface

Date: 2026-08-25

## Status

Accepted

Supersedes [ADR 0005](0005-vmmon-vsock-endpoint-plugins.md)

Amended by [ADR 0016](0016-vsock-forwards-and-netd-publications.md): port
1028 is reserved in both namespaces, `vmmon` binds host listeners for machine-
and session-scoped forwards, and 16 of the 1023 connection slots are reserved for
internal traffic.

## The Problem

Silo needs a generic way for host software to exchange byte streams with guest
services over vsock, in both directions, without baking every integration into
`vmmon`.

[ADR 0005](0005-vmmon-vsock-endpoint-plugins.md) answered this with endpoint
plugins: `vmmon` supervised external plugin processes and brokered connected
stream file descriptors to them over a `SCM_RIGHTS` control socket. That model
was implemented, and its use revealed structural problems:

- The plugin contract required a client library per language to hide fd
  passing, the control-message framing, and the stdout event protocol. Every
  supported language multiplied that maintenance cost.
- A plugin received an abstract nonblocking stream fd rather than a socket it
  could name. Standard tooling (`curl`, HTTP frameworks, gRPC clients, `socat`)
  could not participate without custom adapters.
- Delivering and starting the guest half of a plugin was never solved. The
  plugin model specified the host half in detail while leaving the harder
  deployment question open.
- On Linux, libkrun's built-in vsock support mapped each port to a Unix socket
  that had to be declared before boot and was owned by the `krun` child process.
  A `vmmon`-level plugin surface on top of that meant relaying between two
  Unix sockets per stream and prevented connections to ports that were not
  known at boot.

Two external facts changed what was possible. libkrun v2 added support for
vhost-user devices
([libkrun PR #642](https://github.com/libkrun/libkrun/pull/642)), allowing the
virtio-vsock device to be terminated by an external process instead of libkrun
itself. Firecracker had also documented a convention for representing vsock as
Unix sockets on the host, the
[hybrid vsock design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md),
which `vhost-device-vsock` also implements.

This ADR replaces the plugin model with that convention.

## Terminology

| Term | Meaning |
| --- | --- |
| CID | Vsock context identifier. CID 2 is always the host from the guest's perspective. Each guest has one CID, assigned by the VMM. |
| Port | 32-bit vsock port. Each CID has an independent port namespace. |
| Host-initiated | A connection dialed by host software toward a guest port. |
| Guest-initiated | A connection dialed by the guest toward a host port on CID 2. |
| Mux socket | The single Unix socket through which all host-initiated connections enter, using the `CONNECT` command. |
| Listener socket | A Unix socket at `<uds>_<port>` that receives guest-initiated connections for one host port. |
| Vhost-user frontend | The `krun`/libkrun component that exposes the VM's virtqueues and interrupt plumbing to another userspace process. |
| Vhost-user backend | The embedded `vmmon` component that consumes the shared virtqueues and implements the virtio-vsock device behavior. |
| Vhost-user control socket | The private, persistent Unix socket between the vhost-user frontend and backend. It carries protocol negotiation, configuration, and file descriptors, not normal vsock stream payloads. |
| libkrun built-in vsock port-path API | Libkrun's own virtio-vsock backend configured with `krun_add_vsock` and predeclared port-to-Unix-socket mappings through `krun_add_vsock_port2`. |

## Decision

`vmmon` always attaches a vsock device for its internal SSH and guest-agent
traffic. When explicitly enabled, it also exposes that device through a
Firecracker-compatible hybrid Unix-socket surface in the machine runtime
directory. The public surface uses Firecracker's host-initiated wire protocol
and guest-initiated socket naming convention, subject to Silo's reserved port
and asynchronous listener discovery described below. There are no endpoint
plugins, no plugin supervisor, and no per-endpoint configuration.

Core invariants:

- The `VmSpec` `vsock` section configures only whether the public hybrid surface
  is enabled and the filename of its mux socket. It does not control attachment
  of the internal device and contains no routes, endpoints, or process
  definitions.
- The device and vmmon's ability to dial guest ports 22 and 1027 exist whether
  or not the public surface is enabled. A dial may still be refused when the
  corresponding managed guest service is disabled or not running.
- Host-initiated connections use one mux socket and the textual
  `CONNECT <port>\n` / `OK <port>\n` handshake for any guest port after boot.
  No guest port is declared before boot.
- A host process publishes a guest-initiated user port `N` by binding and
  listening on `<uds>_N`. `vmmon` discovers published listeners through an
  initial directory scan and subsequent directory-change notifications. The
  port becomes reachable after backend registration completes.
- Guest-initiated destination port 1027 belongs exclusively to Silo and never
  routes to a user listener socket. Guest services reserve the same port for
  Silo, but a host client with access to the mux may connect to that guest
  service.
- Linux uses an embedded vhost-user-vsock backend inside `vmmon`. macOS uses
  `VZVirtioSocketDevice`. Both backends implement the same observable contract,
  including reset behavior while a newly published listener awaits discovery;
  discovery latency need not be identical.
- `vmmon` neither launches nor supervises consumers of this surface. The
  process hosting `libvm` owns extension lifecycles. Whoever controls the guest
  image owns delivery and startup of guest-side services.

## Representative Flows

Host-initiated, guest service on port 8080:

```text
host process                     vmmon                        guest
    |  connect(<dir>/vsock.sock)   |                            |
    |------------------------------>                            |
    |  "CONNECT 8080\n"            |                            |
    |------------------------------>  vsock dial (guest, 8080)  |
    |                               |--------------------------->
    |  "OK 1073741824\n"           |         accepted           |
    <------------------------------|                            |
    |  <== raw byte stream, spliced by vmmon in both ways ==>   |
```

Guest-initiated, host service on port 5000:

```text
host process                     vmmon                        guest
    | bind/listen(vsock.sock_5000) |                            |
    |                              |                            |
    |      directory change        |                            |
    |----------------------------->| register backend port 5000 |
    |                              |                            |
    |                              |   guest dials (2, 5000)    |
    |                              <----------------------------|
    |        accept()              | connect(vsock.sock_5000)   |
    <------------------------------|                            |
    |  <== raw byte stream, spliced by vmmon in both ways ==>   |
```

A guest connection made before backend registration completes receives a reset.
Guest software that depends on a dynamically published listener must retry.

## VmSpec Contract

`VmSpec` replaces the ADR 0005 `vsock` section with an explicit public-surface
section:

```yaml
vsock:
  enabled: true
  uds: vsock.sock   # optional, defaults to "vsock.sock"
```

Rust shape:

```rust
/// Public hybrid vsock host surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vsock {
    /// Expose the user-facing hybrid vsock Unix-socket surface.
    #[serde(default)]
    pub enabled: bool,

    /// Mux socket filename within the machine runtime directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uds: Option<PathBuf>,
}
```

Semantics:

- The virtio-vsock device is always attached because vmmon uses it for internal
  traffic. Omitting `vsock`, or setting `enabled: false`, disables the public
  mux and user-listener discovery without disabling the device or vmmon's
  internal connection API.
- `enabled` defaults to `false`. When it is `true`, `uds` defaults to
  `vsock.sock`. Configuring `uds` while `enabled` is `false` is rejected because
  the path would otherwise be silently ignored.
- `uds` must contain exactly one normal path
  component. `vmmon` rejects absolute paths, empty paths, `.` and `..`, and
  paths containing directory separators. The resolved mux and listener paths
  therefore remain inside the machine runtime directory. The runtime-owned
  names `vm.sock`, `vm.pid`, `vm.lock`, and `krun.vsock` are also rejected to
  prevent collisions with vmmon control, lifecycle, and backend artifacts. At
  startup, `vmmon` verifies that the resolved mux path and the longest possible
  listener path fit the platform's Unix-socket path limit. A failure identifies
  the invalid path and platform limit in the user-facing diagnostic.
- Listener sockets derive from the mux path by suffixing `_<port>`, where
  `<port>` is the canonical decimal representation of a `u32`. Discovery
  ignores non-canonical names, non-socket filesystem entries, and symbolic
  links.
- The guest CID is not configurable. Hosts address the guest through one
  machine's mux by port; guests address the host as CID 2. The Linux backend
  fixes the guest CID at 3, Firecracker's conventional default.
  Virtualization.framework provides no CID configuration or query API, and
  Apple does not document its assigned value. Silo validated the assumption on
  both backends by verifying that Linux and macOS guests report CID 3 through
  `IOCTL_VM_SOCKETS_GET_LOCAL_CID`.
- The `VsockEndpoint`, `VsockEndpointMode`, `Plugin`, `Lifecycle`,
  `RestartPolicy`, and `Backoff` types from ADR 0005 are removed from
  `vm-spec`. The schema rejects configurations containing those fields.
- This intentional schema break does not change the existing VM spec version.
  Removed fields are rejected with diagnostics rather than migrated or ignored.

## Listener Discovery And Registration

The socket filename is the complete registration surface; there is no Silo
registration API. `vmmon` implements registration as directory reconciliation:

1. Before starting the VM, `vmmon` opens the machine runtime directory and
   attempts to install a directory-change watcher.
2. Once the backend can accept listener registrations, `vmmon` scans the
   directory and registers every canonical non-reserved listener socket.
3. Each directory-change notification causes a complete rescan. Notifications
   are invalidation signals, not a lossless event log.
4. A successfully discovered port remains registered until the machine stops.
   Removal or replacement of its Unix socket does not unregister the backend
   port.
5. For every guest connection, `vmmon` performs a fresh Unix `connect()` to the
   current `<uds>_<port>` path. A missing, stale, or non-listening socket causes
   that connection to reset.

The watcher is installed before the initial scan so a socket created during VM
startup cannot be missed. `vmmon` registers the initial listener set as soon as
the backend socket device is available and completes the initial scan before
reporting VM startup success. On macOS, the guest may already be executing and
can attempt a connection before registration completes. Guest software must
treat that reset like any other transiently unavailable host service and retry.

Failure to install or operate the watcher does not terminate the machine.
`vmmon` continues serving registered ports, logs that dynamic discovery is
unavailable, and retries watcher installation. After restoring the watcher, it
performs a complete rescan before resuming notification-driven reconciliation.

`vmmon` registers at most 1024 non-reserved listener ports per machine. Each
scan processes new canonical ports in ascending order until the remaining slots
are full; an existing registration is never evicted in favor of a lower port.
`vmmon` logs each ignored port with its path and the limit. Silo port 1027 does
not consume this allowance.

## Compatibility And Migration

This ADR intentionally breaks the ADR 0005 configuration and plugin protocols.
There is no compatibility adapter because the old configuration describes
process supervision and fd delivery that have no equivalent in this surface.

Before upgrading, users must replace an ADR 0005 `vsock` configuration with the
public-surface section above and arrange extension-process lifecycles outside
`vmmon`. On the next launch, `vm-spec` rejects removed plugin fields and names
each unsupported field in the diagnostic. An upgrade does not rewrite stored
machine definitions or silently discard endpoint configuration.

## Wire Protocol

### Host-Initiated Connections

When the public surface is enabled, `vmmon` owns the mux socket at the resolved
`uds` path. The machine-runtime owner ensures that only one `vmmon` instance may
start a machine. After that exclusion is established, `vmmon` removes a stale
socket inode, binds the mux before VM start, sets its mode to `0600`, and removes
it during shutdown. The lifecycle exclusion remains held until socket cleanup
completes. `vmmon` never replaces a non-socket entry or follows a symbolic link.

`vmmon` accepts mux connections for the lifetime of the machine. Per
connection:

1. The client sends `CONNECT <port>\n`, where `<port>` is the decimal vsock
   port and the terminator is one `\n` byte (0x0A). The complete command,
   including the terminator, must fit in 32 bytes.
2. `vmmon` dials the guest on that port.
3. On success, `vmmon` replies `OK <hostside_port>\n`, where
   `<hostside_port>` is the decimal source port assigned to the host end.
   Every byte after that newline in either direction belongs to the stream.
4. On a malformed or oversized command or a guest refusal, `vmmon` closes the
   Unix connection without a reply.

The command, acknowledgement, and 32-byte command bound match Firecracker.
Like Firecracker, `vmmon` does not apply an application-level count or timeout
while an accepted mux client has not yet supplied a complete command. After a
valid command, connection establishment has Firecracker's two-second request
timeout.

`vmmon` accepts `CONNECT` for guest port 1027. Reservation of that guest port
governs service allocation, not access control. Silo's host tooling reaches the
Silo guest service through the same mux as other authorized clients.

### Guest-Initiated Connections

When the guest dials CID 2 on port `N`, `vmmon` routes the connection in this
order:

1. If `N` is 1027, `vmmon` delivers the connection to the Silo-internal
   service or sends `VIRTIO_VSOCK_OP_RST` when no handler exists. It never
   dials a user socket for that reserved host port.
2. Otherwise, if `N` has been discovered and registered, `vmmon` dials
   `<uds>_N`. On success it splices the streams. If the path is absent, stale,
   or not listening, `vmmon` resets the guest connection.
3. Otherwise, `vmmon` resets the guest connection. This includes a connection
   attempted before listener discovery completes.

`vmmon` never creates, removes, or accepts ownership of listener sockets. One
Unix connection is dialed per guest connection.

### Resource Limits

Matching Firecracker's single device connection map, `vmmon` permits at most
1023 active vsock connections per machine. This is one device-wide allowance
shared by every port, both connection directions, the public surface, and
vmmon's internal SSH and guest-agent traffic. A connection becomes active after
a mux client supplies a valid `CONNECT` command or when a guest connection
request reaches the backend. A raw mux client awaiting its command is not an
active vsock connection and consumes no slot.

When all 1023 slots are active, `vmmon` closes a newly accepted mux connection
without a reply, rejects a valid command that raced with another connection,
and resets a new guest connection. Closing or failing a connection releases its
slot. The 1024-port discovery limit is independent of this active-connection
limit; listener registration does not consume a connection slot.

## Responsibilities

| Concern | Owner |
| --- | --- |
| Internal vsock device, mux socket, listener discovery, backend registration, `_<port>` routing, stream splicing | `vmmon` |
| Path accessors for the mux and listener sockets | `libvm` |
| Lifecycle of host processes that consume the surface | the process hosting `libvm` (CLI, SDK consumer, or user tooling) |
| Guest-side services, their delivery into the image, and their startup | whoever controls the guest image |

`libvm` exposes the resolved mux socket path and the derived listener socket
path for any port except 1027. The accessors return `None` when the public
surface is omitted or disabled; the listener accessor also returns `None` for
port 1027. `libvm` does not proxy streams, speak the `CONNECT` protocol on a
caller's behalf, or supervise extension processes. This is a non-normative
sketch of the accessor surface:

```rust
impl Machine {
    /// Path to the hybrid vsock mux socket.
    pub async fn vsock_socket(&self) -> Result<Option<PathBuf>>;
    /// Path a host listener must bind to receive guest dials to `port`.
    pub async fn vsock_listener_socket(&self, port: u32) -> Result<Option<PathBuf>>;
}
```

Guest-side examples are documentation, not contract. A guest service listens
with any AF_VSOCK-capable tool, and a guest client dials CID 2:

```sh
# guest: accept host-initiated connections on port 8080
socat VSOCK-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:80

# guest: dial a host listener on port 5000
socat - VSOCK-CONNECT:2:5000
```

## Backend Architecture

The `VirtBackend` primitives (`connect_vsock`, `listen_vsock`) are the internal
seam. The mux accept loop, directory reconciliation, per-port accept loops,
`_<port>` dialing, and stream splice loops are backend-agnostic `vmmon` code
above that seam. Discovery calls `listen_vsock(N)` once for each new port and
retains the returned registration until machine shutdown. On macOS that
registration owns a framework listener; on Linux it authorizes the embedded
backend to accept requests for the port.

### Linux: Embedded vhost-user-vsock Backend

`vmmon` implements the vhost-user-vsock device backend in process, using the
`vhost-user-backend` crate family, with `vhost-device-vsock` as the reference
implementation. `vmmon` listens on a private vhost-user socket in the machine
runtime directory; the `krun` helper attaches it with
`krun_add_vhost_user_device`. It does not add libkrun's built-in vsock device,
so the guest receives exactly one explicitly configured vsock device. Guest RAM
uses memfd-backed regions so the backend can map the virtqueues.

The private `krun.vsock/vhost.sock` is the vhost-user control socket, not the
public hybrid mux and not a per-port stream endpoint. It remains connected for
the lifetime of the device. The `krun`/libkrun frontend uses it to negotiate
features, read device configuration, describe and enable the three virtqueues,
and pass guest-memory memfds plus queue kick and call eventfds to `vmmon` with
`SCM_RIGHTS`. Closing it means that the frontend or backend has disconnected;
it cannot be removed after initialization while leaving the device operational.

Initialization separates the persistent control channel from the resources it
establishes:

```text
vmmon (vhost-user backend)                 krun/libkrun (vhost-user frontend)
        |                                                   |
        |  bind/listen krun.vsock/vhost.sock                |
        |<------------------- connect ----------------------|
        |                                                   |
        |<-------- feature and protocol negotiation ------->|
        |<--------- device configuration requests --------->|
        |                                                   |
        |<--- SET_MEM_TABLE + guest-memory memfd FDs -------|
        |<--- SET_VRING_* + kick/call eventfd FDs ----------|
        |<--- SET_VRING_ENABLE ------------------------------|
        |                                                   |
        |==== shared memfd-backed guest RAM and vrings =====|
        |<--- guest queue kicks through eventfds ------------|
        |---- used-queue calls through eventfds ------------>|
```

Normal `VIRTIO_VSOCK_OP_REQUEST`, `VIRTIO_VSOCK_OP_RESPONSE`, and
`VIRTIO_VSOCK_OP_RW` packets do not traverse the control socket. `vmmon` reads
and writes them in the shared virtqueues and uses the passed eventfds for queue
notifications. The control socket may still carry device lifecycle or
configuration messages, but it is not in the steady-state byte-stream path.

The runtime paths are:

```text
Host-initiated

vmmon caller or public mux
        |
        | endpoint stream (an unnamed socket pair for the internal seam)
        v
vmmon vhost-user-vsock backend
        |
        | write RX descriptors in shared guest RAM
        | signal call eventfd
        v
krun virtio interrupt delivery
        |
        v
guest AF_VSOCK service
```

```text
Guest-initiated

guest AF_VSOCK client
        |
        | write TX descriptors and signal kick eventfd
        v
vmmon vhost-user-vsock backend
        |
        | route by destination port through an unnamed socket pair
        v
vmmon internal consumer
        or
vmmon stream splice <----> public <uds>_<port> listener
```

Terminating the device inside `vmmon` removes the constraints that motivated
ADR 0005's indirection: no per-port Unix sockets owned by the `krun` child, no
ports declared before boot, and no mandatory relay through a krun-owned
per-port socket. It does not make the host stream path socketless. The internal
`VirtBackend` stream seam uses unnamed Unix socket pairs, and the public surface
splices those streams to the mux or listener socket. `vmmon` sees the
destination port in each guest
`VIRTIO_VSOCK_OP_REQUEST`. It accepts requests for ports registered by the
common discovery loop, dials the corresponding listener socket, and sends
`VIRTIO_VSOCK_OP_RST` for other user ports.

The selected Linux implementation compares with libkrun's built-in port-path
API as follows:

| Concern | Vhost-user-vsock (`krun_add_vhost_user_device`) | Libkrun built-in vsock port-path API (`krun_add_vsock` and `krun_add_vsock_port2`) |
| --- | --- | --- |
| Vsock protocol backend owner | `vmmon` | `krun`/libkrun |
| VM-facing device model | Generic vhost-user frontend in `krun`/libkrun, backed by `vmmon` | Built-in virtio-vsock device and backend in `krun`/libkrun |
| Backend attachment | One vhost-user device for the VM | One built-in libkrun vsock device |
| Unix-socket topology | One private control socket per VM; no krun-owned per-port listeners | One predeclared path mapping per configured port; krun listens for host-initiated mappings |
| Port lifecycle | Host and guest ports are registered or dialed dynamically after boot | Every usable port and direction must be declared before boot |
| Guest memory access | Memfd-backed guest regions are mapped into both processes | The backend accesses guest memory directly inside krun |
| Queue notification | Kick and call eventfds cross the process boundary | Queue handling and interrupt delivery stay inside krun |
| Host stream dataplane | Endpoint stream bytes are copied between a host stream and shared virtqueues in `vmmon`; the control socket is not the payload path | Endpoint stream bytes are copied between a configured per-port Unix socket and virtqueues in libkrun |
| Public hybrid surface | One mux supports arbitrary host-initiated ports; listener discovery supports runtime guest-initiated publication | Requires an additional adaptation layer over fixed port-path mappings |
| krun-owned UDS listeners | None for vsock | One for each host-initiated port mapping |

#### Performance Characteristics

This decision does not assume that vhost-user-vsock is unconditionally faster
than libkrun's built-in port-path API. Its primary benefits are dynamic routing,
ownership, and a cross-platform host contract. The relevant performance effects
are:

- Vhost-user negotiation, descriptor passing, and guest-memory mapping add
  one-time startup work. They replace per-port startup configuration rather
  than adding a per-connection control exchange.
- Mapping a guest-memory memfd into `vmmon` does not duplicate the guest RAM.
  It does add another virtual mapping and its page-table and address-space
  bookkeeping.
- Normal stream bytes bypass the vhost-user control socket. The backend copies
  bytes directly between endpoint streams and shared guest-memory descriptors.
- Compared with a backend inside krun, queue processing crosses a process
  boundary through kick and call eventfds. Scheduler wakeups, context switches,
  cache migration, and interrupt-delivery handoffs can increase small-message
  latency and CPU cost.
- Internal `connect_vsock` and `listen_vsock` streams use unnamed Unix socket
  pairs to preserve the common `VsockStream` abstraction. This still incurs a
  kernel socket-buffer copy; vhost-user does not make the host endpoint path
  zero-copy.
- Public host-initiated and guest-initiated streams are spliced with
  `copy_bidirectional` between the public Unix socket and the backend stream.
  That extra relay can cost additional syscalls and copies compared with an
  internal vmmon consumer.
- The vhost-user backend negotiates `VIRTIO_RING_F_EVENT_IDX`, allowing the
  guest and backend to suppress unnecessary notifications under load.
- The selected vhost-user device uses three queues of depth 128. Libkrun's
  built-in vsock device uses depth 256. The smaller depth reduces queue metadata
  but may reduce burst tolerance or in-flight work under high concurrency.

These are architectural expectations, not benchmark results. Changes that
target throughput or latency must measure connection setup, bidirectional
small-message latency, bulk throughput, CPU time, context switches, and
concurrency against both implementations on the same host and guest kernel.

This requires a libkrun version that includes vhost-user device support. The
`krun` crate drops its `VsockPort` plumbing in favor of one vhost-user device
attachment. The embedded backend is attached even when the public surface is
disabled because vmmon's internal ports use it.

### macOS: Virtualization.framework

`VZVirtioSocketDeviceConfiguration` is always attached for vmmon's internal
traffic. `connect_vsock` maps to `VZVirtioSocketDevice.connect(toPort:)`.
`listen_vsock(N)` installs a `VZVirtioSocketListener` for that specific port;
Virtualization.framework exposes no wildcard listener. The directory discovery
loop supplies the required port numbers and may add listeners while the VM
runs. Dropping the machine unregisters all VZ listeners.

`vmmon` installs the initial listener set as soon as the runtime socket device
is available and installs newly discovered listeners while the VM runs.

## Security And Trust

- The vsock protocol itself carries no authentication or encryption. The
  trust boundary is the owner-only machine runtime directory. The mux socket is
  mode `0600`; directory search permission also protects user-created listener
  sockets when their modes are broader. This is consistent with `vm.sock` from
  [ADR 0008](0008-vmmon-host-and-guest-grpc-api.md).
- For every accepted mux connection, `vmmon` requires platform peer
  credentials and verifies that the peer UID matches the machine-runtime owner.
  A missing credential or UID mismatch causes `vmmon` to close the connection
  before reading a command. Any authorized process can reach every guest port,
  including port 1027. That matches the control-socket authorization model, in
  which the same user controls the machine and its control socket.
- `vmmon` never exposes vsock on TCP. Bridging a guest port to localhost or
  beyond is a deliberate act performed by a host process the user runs and
  owns, outside `vmmon`.
- The guest is untrusted. Guest-initiated connections reach only the fixed
  `_<port>` path selected by the destination port, or the Silo-internal handler
  on port 1027. The machine-runtime owner is trusted and may replace or redirect
  listener paths; the guest cannot choose a path independently of that owner.

## Failure Semantics And Diagnostics

- A malformed or oversized mux command or a guest refusal causes `vmmon` to
  close the mux connection without an `OK` line.
- A guest dial to an undiscovered, missing, stale, or non-listening user socket
  receives a reset. A guest dial to port 1027 without an internal handler also
  receives a reset.
- Failure to install or operate the directory watcher logs that dynamic
  listener discovery is unavailable. Existing registrations continue to work.
  `vmmon` retries installation and performs a complete rescan after recovery.
- Failure to register a listener found during the initial scan prevents VM
  startup. A runtime registration failure logs the machine, port, path, and
  backend error; later rescans retry it. Guest attempts reset until registration
  succeeds.
- Reaching a listener-registration or active-connection limit logs the machine,
  rejected port when known, and applicable limit.
- Either half of a spliced stream reaching EOF or error causes `vmmon` to shut
  down the opposite half and release both ends.
- Vsock activity and discovery progress do not change instance readiness.
  `HostStatus.readiness` remains defined by
  [ADR 0008](0008-vmmon-host-and-guest-grpc-api.md).

## Consequences

### Benefits

- Firecracker's wire format and socket naming convention replace a
  Silo-proprietary plugin contract. Existing hybrid-vsock host-initiated clients
  work unchanged. Guest-initiated host services use the same `<uds>_<port>`
  paths and require no Silo registration call.
- Extensions are ordinary processes speaking Unix sockets in any language,
  with no Silo client library required.
- Host-initiated connections need no up-front port declaration on either
  backend.
- A guest-initiated listener bound before VM start is included in the initial
  scan. New listeners may also be published while the VM runs.
- `vmmon` loses process supervision, fd brokering, restart policy, and the
  stdout event protocol. `vm-spec` loses six plugin-related types.
- Both backends expose the same paths, wire format, port policy, limits, and
  failure outcomes despite using different discovery mechanisms internally.

### Tradeoffs

- `vmmon` relays every vsock byte in userspace. This is inherent to both
  backends (Virtualization.framework hands connections to the host process;
  the embedded vhost-user backend terminates the device in `vmmon`) and
  matches the cost `vmmon` already pays for serial and SSH streams.
- The `CONNECT`/`OK` preamble means a byte relay cannot front the mux without
  first sending the command and consuming the acknowledgement line. A
  convenience proxy can be layered later without changing this surface.
- macOS listener publication is eventually consistent because
  Virtualization.framework requires per-port registration. A guest that races
  discovery receives a reset and must retry. Linux follows the same public
  failure contract but may discover a listener sooner.
- `vmmon` must run a platform-specific directory watcher for every machine with
  the public surface enabled. The watcher and monotonic VZ registrations consume
  resources even when no stream is active.
- Guest-initiated availability is discoverable only through the filesystem.
  There is no runtime inventory of bound `_<port>` sockets.
- Extension processes have no supervisor unless their owner provides one. A
  crashed forwarder stays crashed until its owner restarts it.
- Linux gains a dependency on libkrun's vhost-user support and on `vmmon`
  implementing a virtio device backend correctly, including memfd guest
  memory.

## Alternatives Considered

### Keep Endpoint Plugins (ADR 0005)

The plugin model kept `vmmon` out of the data path and isolated integrations
in supervised child processes. It loses because the contract cost lands on
every consumer: a per-language client library, fd-passing conventions, an
opaque stream type incompatible with standard tooling, and an unsolved
guest-delivery story. The model this ADR adopts serves the same use cases
with sockets every language already speaks.

### Explicit Listener Registration API

An RPC or SDK method could register each guest-initiated port with `vmmon` and
acknowledge exactly when the VZ listener is ready. This would eliminate the
filesystem discovery race and provide precise errors. It loses because it adds
a Silo control-plane protocol to an otherwise standard socket convention,
requires every host integration to perform an extra operation, and makes
registration cleanup part of that API's lifecycle contract. Directory
discovery preserves ordinary Firecracker-style host processes at the accepted
cost of eventual registration.

### Initial Directory Scan Without Runtime Watching

A startup-only scan would support services published before VM start without a
control API. It loses because Firecracker resolves `<uds>_<port>` on every guest
connection and therefore permits a new listener after boot. Continuous watching
retains that capability, except for the documented discovery interval, without
adding endpoint configuration.

### Sidecar vhost-device-vsock Process On Linux

Running the upstream `vhost-device-vsock` binary as a supervised sidecar
implements the same protocol with less code in `vmmon`. It loses because it
adds a packaged runtime dependency and a second process to supervise, and
because `vmmon` still needs the in-process `connect_vsock`/`listen_vsock`
primitives for its own agent traffic, which the embedded backend provides
directly.

## Accepted Limitations

- No per-connection or per-port metrics, health, or inventory. Diagnostics are
  `vmmon` logs.
- The `_<port>` suffix convention is name-based coupling with no discovery
  mechanism beyond the filesystem.
- A newly published listener is not reachable until directory reconciliation
  and backend registration complete. A guest connection during that interval
  resets, including during the initial macOS scan if listeners cannot be
  installed before VM start.
- Port registrations are monotonic for a machine lifetime. Publishing many
  distinct listener names can exhaust the 1024-port limit even after those
  socket files are removed.
- Port 1027 is allocated to Silo in both namespaces. Guest dials to host port
  1027 reach a Silo-internal handler or receive a reset and never reach a user
  socket. Host-initiated `CONNECT` to guest port 1027 remains allowed. Host port
  22 is not reserved and may be published as a user listener.

## External References

- [Firecracker: Using the Virtio-vsock Device](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
- [Firecracker Unix vsock muxer](https://github.com/firecracker-microvm/firecracker/blob/main/src/vmm/src/devices/virtio/vsock/unix/muxer.rs)
- [Apple: `VZVirtioSocketDevice`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice)
- [Apple: registering a `VZVirtioSocketListener`](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice/setsocketlistener(_:forport:))
- [libkrun PR #642: vhost-user device support](https://github.com/libkrun/libkrun/pull/642)
- [vhost-device-vsock reference implementation](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md)
- [QEMU: vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
