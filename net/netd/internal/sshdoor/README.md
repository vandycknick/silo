# Tailnet SSH front door

`session` starts this door through the phase-8 node's `Listen("tcp", ":22")`
adapter. Fallback TCP routing always reserves port 22, even if the door cannot
start. There is no host-side production listener or identity-bypass mode.

Every authentication method uses bounded WhoIs on the accepted socket's actual
remote address. Untagged self requires an untagged peer with the same nonzero
user ID. Tagged self requires tag intersection, never the creator's user ID.
Permissions retain the authorized identity. Authorization is rechecked every
30 seconds, and any denial, error or identity change closes both SSH legs.

The machine directory is the parent of libvm's supplied `--tailscale-state-dir`.
Its sibling `ssh/` holds the persistent `tailnet_host_ed25519_key` and libvm's
immutable `known_host`. Files are owner-owned 0600, the directory is 0700 and
has its parent's owner. Descriptor-relative accesses reject symlinks. Pin reads
share `known_host.lock` with `common/utils/src/ssh.rs`; netd never creates or
replaces a pin. Missing pins fail until libvm has established one.

Setup has one 30-second budget covering downstream authentication, pin access,
Unix mux `CONNECT 22\n` and certificate-authenticated guest SSH. Read-ahead after
`OK <port>\n` is retained. Successful setup clears both deadlines. Certificates
use fresh Ed25519 keys, the requested login principal, now-60s to now+300s and
PTY/agent/port-forwarding extensions, without X11. The machine CA is parsed once.

The raw SSH connections relay channel opens in both directions, ordered channel
and global requests (including reply payloads), data and stderr. Both output
pumps finish before EOF; exit requests drain before close. `SILO_PEER` is injected
once immediately before shell/exec/subsystem, and client attempts to set it are
rejected before or after execution. Each leg receives a keepalive every 30s;
an unanswered keepalive closes the connection after 10s. Shutdown closes and
joins all relay workers.

Per-door admission limits are 16 simultaneous setups, 128 connections, 32 active
session channels across all connections, and 256 forwarding reservations/channels.
Pending channel opens reserve capacity too. TCP and Unix remote listeners retain
their reservations until successful cancellation or connection close. Requests
without replies conservatively retain reservations until connection close.

## Verification and backend support

Offline tests use real current-UID `sshd -i` with CA-only authentication, PAM off,
internal SFTP and a Unix framing endpoint. Their TCP front listener and explicit
already-authorized identity exist only in `_test.go`. They do not qualify WhoIs.
`SILO_TEST_SSH_200MB=1` enables the actual 200MB scp/SFTP/hash exercise; defaults
use smaller binary transfers. Missing rsync/other client binaries skip explicitly.

`TestNativeKVMRelayCore` requires `SILO_E2E_KVM=1`,
`SILO_TEST_SSH_MACHINE_DIR` and `SILO_TEST_SSH_MUX` for an already-running native
fixture. It uses the actual machine CA, existing pin and VMM mux.

Native guest SSH currently supports shell, exec, PTY and agent forwarding.
**It does not support SFTP or port forwarding.** Modern scp requires SFTP;
these operations require an OpenSSH guest. OpenSSH's authoritative guest config
includes `Subsystem sftp internal-sftp`. No native SFTP subsystem is introduced.

`TestRealTailnetSSHFrontDoor` is separately gated on the KVM flag, test tailnet,
peer OAuth secret, `SILO_E2E_TS_SSH_TARGET` (actual running netd VM IP), and machine
directory for its host key. Optional `SILO_TEST_SSH_USER` defaults to `silo`.
It enrolls actual matching/nonmatching tagged peers and exercises the production
door plus a 200MB cat/hash relay. Both peers must have TCP22 packet access, so
the negative test checks SSH authorization rather than packet-filter denial.
Local throughput does not establish tailnet throughput or macOS/vz behavior.
