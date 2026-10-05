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
Taild observes a private, atomic, versioned status file bound to the current VM run.
The file reports connectivity, verified identity and required browser-login actions;
it is not a command queue or a second source of identity truth. Historical observations
retain their own timestamps for stopped-node expiry display. The configured hostname
remains visible while stopped, without inspecting private authentication state.

Netd consumes initial credentials through the secret-store transport and uses its
persisted node state thereafter. Registration, reconnects and required browser
reauthentication do not block guest boot or require VM restarts. Taild retains the
OAuth-app browser callback solely to acquire the initial auth key before creating
the VM. Human requests use that delegated key or native browser identity rather
than a privileged shared client. Tagged nodes and management ownership are modeled
separately, with tag assignment decided by Tailscale's permissions.

Legacy pending/backup transactions remain recoverable under the stopped-node lease.
New onboarding does not create those transactions. There is no dedicated `reauth`
command: netd handles required authentication and `show` exposes its current action.

VM removal deletes local resources only, including credentials and node state.
It does not log out or contact the device-deletion API. Abandoned node transactions
do not block explicit deletion; active process and lease checks still apply.

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
VM restart. The host must enforce management-owner and node-identity validation,
and recover any legacy replacement transactions. Tailnet control-plane interoperability,
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
