# 0022. Lobby in silod with a Go tailnet gateway

Date: 2026-11-11

## Status

Accepted

Supersedes [ADR 0019](0019-optional-tailnet-service.md) and amends the SDK
packaging requirements of
[ADR 0012](0012-cross-platform-runtime-and-sdk-packaging.md) and the service
state layout of [ADR 0017](0017-single-host-state-root.md). This ADR records
the target architecture, not functionality already delivered.

## Context

Taild is a Go service whose VM operations need the Go SDK's cgo bridge to
libvm. That bridge adds native-library packaging, ABI qualification and
process-signal ownership to a service whose Go requirement is Tailscale.
Libvm must remain the only VM-monitor client; moving monitor calls into Go
is not an alternative.

A pure Rust tailnet is not currently possible. tailscale-rs 0.7.1 lacks
WhoIs ([#478](https://github.com/tailscale/tailscale-rs/issues/478)), app
capabilities ([#161](https://github.com/tailscale/tailscale-rs/issues/161),
[#411](https://github.com/tailscale/tailscale-rs/issues/411)), TLS certificates
and an SSH server
([#285](https://github.com/tailscale/tailscale-rs/issues/285)). The tailnet
transport still needs Go, but VM management does not.

## Decision

Delete the Go and Node SDKs, the `silo-go-ffi` / `libsilo_go_ffi` cgo bridge,
the Go protocol bindings, the vendored signal-hook-registry and taild. Split
the remote service at the transport boundary:

| Component | Responsibility |
| --- | --- |
| `tsgate` | Separate Go module at `app/tsgate`, built with `CGO_ENABLED=0`. Owns tsnet, lobby-node enrollment, raw tailnet TCP on :22, TLS termination on :443 and stream forwarding. No VM-management interface. |
| silod `lobby` | Rust module at `app/cli/lib/lobby/`. Owns the russh SSH server, command grammar, authorization, jobs, documents, consent and HTTP, including `/health` and `/metrics` on :443. Calls management functions and libvm in-process. |
| libvm | Remains the only client of the VM monitor. |
| netd | Remains Go and owns each VM's tailnet node. |

The lobby command set is ported one to one. Caller identity is an interface
separate from the incoming stream source. The tailnet identity implementation
uses WhoIs; grammar, jobs and service code do not depend on the tailnet
interface. A plain SSH listener with another identity source is outside this
decision.

### Process Seam

Silod spawns tsgate with one inherited `AF_UNIX` `SOCK_STREAM` socket. Frames
are a 4-byte big-endian length followed by one JSON object, limited to
64 KiB. Descriptors travel through `SCM_RIGHTS`. `SOCK_SEQPACKET` is not used
because macOS does not support it for Unix sockets.

| Direction | Message | Purpose |
| --- | --- | --- |
| silod to tsgate | `bootstrap` | First frame: hostname, tag, control URL, state directory, capability key and optional client secret. Secrets never appear in argv or environment variables. |
| silod to tsgate | `whois {id, remote}` | Resolve a remote `ip:port`. |
| silod to tsgate | `status {id}` | Request current node status. |
| silod to tsgate | `shutdown` | Stop accepting; exit after streams drain or a deadline. |
| tsgate to silod | `state` | Push enrollment, approval, node identity and error state on every change. |
| tsgate to silod | `conn {listener, remote}` | Identify an SSH or HTTP connection and pass one socketpair endpoint. Tsgate copies the tailnet stream through the other endpoint. |
| tsgate to silod | `reply {id, ...}` | Answer a WhoIs or status request. |

The WhoIs reply is a repository-owned, versioned identity shape: node ID,
node name, tags, user ID, login name, display name and raw JSON values for the
requested capability key. The Rust tailnet interface exposes incoming SSH
and already-decrypted HTTP streams, WhoIs, status and state notifications.
Silod closing the control socket means owner loss; tsgate exits within five
seconds.

### Names And State

`<Home>` is the Silo home defined by ADR 0017.

| What | Value |
| --- | --- |
| Go gateway | `tsgate` |
| Rust service in silod | `lobby` |
| Lobby state | `<Home>/lobby/` |
| tsnet state | `<Home>/tsgate/` |
| VM labels | `io.silo.lobby.*` |
| Tailnet capability key | `github.com/vandycknick/silo` |
| Configuration | `daemon.tailscale.*`, unchanged |
| Secrets | `tailscale.lobby.*`, unchanged |

Session caps, ceilings, disk reserve and file-transfer limits remain under
`daemon.tailscale.*`; there is no `daemon.lobby.*` configuration section.

### Shutdown And Compatibility

Host-shutdown protection is dropped, not ported. There is no logind delay
inhibitor, `silo daemon run --host-shutdown`, `taild --shutdown-only`,
shutdown `ExecStop=`, `DrainMutations` or `ShutdownProtection` contract.
Ordinary service stop or restart drops lobby sessions without becoming a VM
stop operation.

This is a hard break. There are no SDK or taild compatibility shims, aliases,
state migrations or old/new runtime switches. Users reinstall and wipe
existing Silo state, consistent with ADR 0014's breaking release.

## Consequences

The remote service uses the same in-process lifecycle implementation as
other Rust frontends without a cgo bridge or separate management RPC layer.
Tsgate has no native Rust dependency. Tailnet transport and caller identity
remain replaceable: tailscale-rs can later replace tsgate behind the tailnet
trait when it supplies the required capabilities.

The remote-facing parser and SSH server now run inside silod. Session caps,
bounded buffers, contained session-task panics and tokenizer/frame-codec
fuzzing are required defenses. Session bytes pass through silod, and the
socketpair relay must preserve half-close and backpressure. The Go helper
and its private framing protocol remain an operational cost.

There is no guaranteed guest shutdown window at host poweroff. Silo-vmm
still attempts orderly guest shutdown on SIGTERM, but no inhibitor holds the
host open for it. SDK consumers and existing taild installations must accept
the hard break.

## Alternatives Considered

**Keep taild and the cgo SDK** preserves the existing Go service but retains
the native bridge, packaging matrix and signal-ownership boundary that this
decision removes.

**Move monitor access into Go** avoids cgo but creates a second VM-monitor
client and duplicates libvm's lifecycle responsibilities.

**Use tailscale-rs now** removes the Go gateway but cannot supply the identity,
capability, TLS and SSH facilities required by the service today.

## References

- [Optional tailnet service](0019-optional-tailnet-service.md)
- [Runtime packaging](0012-cross-platform-runtime-and-sdk-packaging.md)
- [Single host state root](0017-single-host-state-root.md)
- [VM tailnet identity](0020-netd-tailnet-identity.md)
- [tsnet](https://tailscale.com/kb/1244/tsnet)
