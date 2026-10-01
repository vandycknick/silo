# 0019. Optional tailnet service through the public Go SDK

Date: 2026-10-01

## Status

Accepted

## Context

A remote user needs VM lifecycle access without a host login. The daemonless CLI
and optional system daemon already share a host runtime and machine store. A new
remote service must preserve that model and prevent service restart from becoming
a VM stop operation.

## Decision

Taild is an optional Go service with an in-process tsnet lobby and the public Go
SDK as its sole VM interface. It uses the existing machine store and labels for
ownership; it must not maintain a parallel VM database. WhoIs supplies connection
identity and a freshly checked capability supplies authority. V1 accepts only
`own` scope. Operator-approved templates, policies and ceilings bound requests;
the remote surface must not accept host paths or arbitrary host mounts.

Exact user-requested names are globally collision-checked locally and on the
tailnet. Taild must reject collisions rather than adding an owner prefix. Enrollment
requires explicit consent or approved tag provisioning and verifies exact assigned
DNS and principal ownership before state promotion. Readiness is established by
an actual guest connection attempt, not solely an agent RPC.

Linux systemd uses a dedicated private home and `KillMode=process`. Ordinary
restart/stop drops lobby sessions but leaves VM workers running. Host shutdown
uses a bounded logind delay inhibitor and a stopping-only ExecStop fallback to
stop managed VMs through the SDK. Unmanaged machines remain untouched.

The native CGO build embeds an exact target-local bridge, verifies its digest and
ABI/product version, and installs the runtime explicitly with a pinned archive
digest. Runtime roots carry exact-version inventory manifests. Build order is
runtime stage/archive → native bridge/hash → isolated target-local SDK assembly →
taild → portable archive. No all-target SDK dependency may create a release cycle.

In the embedded Go attachment path, Go owns each scoped process-signal
subscription and sends typed controls through the native token. Return restores
inherited ignored/default behavior and preserves independent application
subscribers. The SDK must not rely on Tokio's cached process handlers being
reinstalled after Go restores SIG_IGN. The current ABI3 includes this control
export as well as cancellation and node-state leases.

## Consequences

The CLI, local daemon and remote service keep one lifecycle implementation. A
service restart can reconcile existing labelled machines without adopting others.
The in-process bridge avoids an additional RPC daemon but a fatal native crash
terminates taild and loses transport; it cannot promise an SSH exit status.
CGO and per-host qualification increase packaging cost. macOS service operation
and cross-owner sharing remain outside v1. G1/G2/G3 and real logind/KVM drills
remain required qualification, not inferred from offline tests.

## Alternatives Considered

**Shelling out to the CLI** would reuse commands but introduce text/error parsing,
host environment leakage and weaker lifecycle ownership. The public typed SDK
provides the needed operations directly.

**A persistent service database** would simplify service queries, but duplicate
machine state and require reconciliation after every out-of-band CLI operation.
Labels and native inventory retain one source of truth.

**Stopping VMs on service shutdown** would simplify cgroup cleanup, but make an
ordinary deployment interrupt independent sessions. Host shutdown is the explicit
stop boundary instead.

## References

- [Single host root](0017-single-host-state-root.md)
- [Runtime packaging](0012-cross-platform-runtime-and-sdk-packaging.md)
- [Operator guide](../taild/operator.md)
- [systemd kill modes](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
- [logind inhibitors](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html)
