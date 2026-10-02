# 0020. Netd owns the VM tailnet node and relays guest SSH

Date: 2026-10-01

## Status

Accepted

## Context

A VM needs a stable tailnet identity across start/stop and a guest SSH connection
without a host listener or user SSH keys. Putting Tailscale in every guest would
couple guest images and credentials to host network enrollment.

## Decision

Netd owns the VM's tsnet node, whose identity persists in tsnet's own machine state.
Taild reads validated public IPN profile/node state; it must not write a second
identity record. Missing/empty state means pending, while corrupt or mismatched
state is unreadable and must not be treated as permission for fresh registration.

Enrollment runs while the VM is stopped under the SDK's per-machine node-state
lease. Native Start/Remove/Update fail busy while replacement is active. A pending
directory, validated identity-free digest receipt and recoverable backup promotion
preserve the prior node state after failure. Reauthentication fences stable node ID
and exact name, rather than creating a duplicate registration.

Netd terminates tailnet SSH and relays to guest SSH using a per-machine SSH CA and
short-lived certificate for the requested guest login. Taild shell/exec defaults
to root unless an account was explicitly provisioned at VM creation; that selection
is persisted per machine. Direct SSH uses the username requested by the client.
The guest agent does
not own tailnet identity. OpenSSH is used when present; the native fallback serves
images without it and does not promise the complete OpenSSH SFTP/forwarding feature
set. SSH CA and HTTPS/TLS CA remain separate authorities.

Published guest ports are discovery hints. They create no host listener and do
not constrain inbound access: tailnet policy governs all guest ports. Secrets are
delivered through the explicit store/provider contract and bounded spawn pipe,
never ambient Tailscale credential environment variables.

## Consequences

Guest images remain independent of Tailscale and persistent node identity survives
VM restart. The host must enforce principal/name validation and recover replacement
transactions before admitting sessions. Tailnet control-plane interoperability,
key expiry, client forwarding and fallback-server behavior require real tests.
The exact guest connection attempt is the readiness proof.

## Alternatives Considered

**Tailscale inside the guest** would expose native tailnet interfaces to the guest,
but require image-specific installation and move enrollment secrets into every VM.
Netd keeps this responsibility at the existing network boundary.

**A new service-owned identity database** could speed queries but diverge from
tsnet's authoritative node state. Public persisted profile/state plus native leases
avoid duplicating identity ownership.

**User SSH keys** offer familiar administration but require separate key lifecycle
and revocation. Short-lived per-machine certificates bind relay sessions to the
requested guest user and limit credential lifetime.

## References

- [Optional service](0019-optional-tailnet-service.md)
- [Netd publication semantics](0016-vsock-forwards-and-netd-publications.md)
- [User quick start](../taild/user-quickstart.md)
- [tsnet](https://tailscale.com/kb/1244/tsnet)
