# silo-agent

Guest-side agent for Silo VMs.

`silo-agent` runs inside the Linux guest and connects back to Silo's guest control plane over vsock. It is responsible for registration, SSH access, and optional guest provisioning.

## Overview

`silo-agent` currently does three main jobs inside the guest:

- registers with the host-side control service over vsock
- serves SSH on guest `vsock::22` when that port is free
- runs optional guest provisioning tasks

The control RPC port is selected from the kernel command line via `silo.guest.port`. If that kernel arg is missing or invalid, the agent falls back to Silo's default control port.

At startup the agent:

1. initializes tracing
2. loads guest config from disk
3. reads the control port from `/proc/cmdline`
4. runs provisioning if enabled, with loopback and optional static networking first
5. attempts to bind guest `vsock::22` for SSH, unless another listener already owns it
6. registers with the host-side control service

## Config

The default guest config path is:

```text
/etc/silo/agent.yaml
```

If the file is missing, the agent falls back to its built-in defaults.

Current config shape:

```yaml
provision:
  enabled: false
```

Example with all supported sections populated:

```yaml
provision:
  enabled: true
  network:
    interfaces:
      - mac_address: "02:00:00:00:00:02"
        ipv4:
          address: 192.168.105.2
          prefix_length: 24
          gateway: 192.168.105.1
        dns:
          servers: [192.168.105.1]
          search: []
  hostname: silo-dev
  resize_rootfs:
    enabled: true
```

Notes:

- SSH is not configured here. The agent attempts to bind guest `vsock::22`; if another listener already owns `vsock::22`, the agent leaves it alone.
- `provision` controls optional guest provisioning work such as static networking, hostname, and root filesystem resizing.
- `provision.network` is omitted for a machine without a network attachment. When provisioning is enabled, the network provisioner still brings up loopback but leaves non-loopback links, routes, and `/etc/resolv.conf` untouched.
- Networking is the first provisioner. It brings up loopback, then matches and configures the optional static interface through Linux rtnetlink without invoking DHCP, `ip`, or a network manager.
- The host only configures a guest certificate authority when its network policy contains a TLS-terminating endpoint (HTTPS or registries). It resolves the Home SecretStore pair once, sends its certificate to guest trust, and delivers that same pair to netd through the secrets pipe. VMs without interception do not generate, transfer, or install TLS CA material. The private key never enters guest configuration.
- CA trust installation uses `update-ca-certificates` when available, otherwise p11-kit `trust`. A configured CA is required launch state, so a missing or failed trust backend fails managed boot.
- Ext4 root filesystems grow through the kernel's online resize ioctl. Guest images do not need `findmnt`, `resize2fs`, or e2fsprogs.
- A configured root filesystem resize is required launch state. Discovery or resize failures fail managed boot instead of exposing less capacity than requested.
- The agent does not read its control RPC port from this file. That comes from the kernel arg owned by the host side.

## SSH

When `silo-agent` owns guest `vsock::22`, it prepares OpenSSH's `/run/sshd` runtime directory before registering with the host. Each incoming connection then starts `/usr/sbin/sshd -i` and passes the accepted vsock stream as the child process stdin/stdout. This matches the inetd-style shape used by systemd socket activation for `sshd-vsock.socket`, while keeping the child stderr attached to the agent logs instead of the SSH byte stream.

Some systemd guests can automatically bind SSH sockets such as `vsock::22` before the agent starts. To disable those automatic systemd SSH bindings and let `silo-agent` own the port, add this kernel command line argument:

```text
systemd.ssh_auto=0
```

Explicit systemd SSH listeners configured with `systemd.ssh_listen=` or the `ssh.listen` system credential still apply even when automatic bindings are disabled.

## Logging

`silo-agent` writes its runtime logs to stderr.

In the default systemd boot path, logs are captured by the service manager, for example through `journalctl -u silo-agent.service`.

## Bootstrap

Silo distributes an agent-free base initramfs and a standalone agent. At each
managed launch, `libvm` appends `/agent/silo-agent` and `/agent/config.json` in a
raw CPIO overlay. `silo-init` validates and copies both files to `/run/agent`,
then invokes the agent with `--config=/run/agent/config.json`.

The agent supports ordinary process startup and the managed PID 1 handoff mode.
Custom agents and initramfs implementations must honor the same explicit config
path and guest API contract when managed readiness is enabled.

### Live workload containment

The initial live profile is **Silo-managed AgentPid1**. Init mounts cgroup v2,
creates `/sys/fs/cgroup/silo/{control,workloads,activation}`, and enters
`control` before executing the agent. Every Silo-created workload process,
including native exec, userdata and both OpenSSH spawn paths, enters
`workloads` in an async-signal-safe pre-exec operation. The selected activation
hook alone uses the `activation` sibling. An image-init handoff moves the PID 1
parent into `workloads`; the agent child remains in `control`.

`Standard` and `InitChild` are still cold-boot profiles, but live operations
explicitly reject them before changing admission or freezer state. The
AgentPid1 contract assumes Silo-owned process spawning and cgroup management;
it does not claim to contain arbitrary privileged workload code which moves
itself out of the subtree, or an image-owned cgroup manager. Kernel/driver and
host-lane qualification remain separate mandatory admission gates. Missing
cgroup support preserves cold boot, never produces a successful fake freeze.

The agent retains descriptors and verifies their directory/file identities
before using them. It never recreates a missing freeze target during an
operation. Closing reversible spawn admission stops new launches immediately;
Freeze asynchronously drains each parent's complete spawn/exec acknowledgement
before writing the freezer, avoiding a frozen pre-exec child that would
otherwise deadlock its parent without blocking the agent runtime. Admission
does not wait for the lifetime of a running workload or forward listener.

Freezer writes only request a transition. Completion is the actual
`cgroup.events` `frozen` value, observed through a subscribed descriptor and
bounded monotonic deadline. The lifecycle coordinator owns failed-freeze
rollback, checks actual thaw completion before reopening admission, and keeps
failed rollback fenced. Disconnecting or dropping the controller never thaws
workloads. Freeze does not call `sync` or `fsfreeze`.

Activation retires captured native/OpenSSH sessions and drains their real
process, input/output and forwarding workers. Retired session children receive
SIGKILL and are reaped, so cleanup does not wait indefinitely for SIGTERM
delivery to a frozen process. Native SSH input mutations retain admission
through queued data's actual kernel writes, not just through enqueueing.

### Managed overlay root and mount ordering

The `linux-erofs-overlay-v1` root is assembled and grown by trusted init,
before the agent starts. Its immutable lower is EROFS and its private writable
upper is ext4. Init authenticates the lower serial, read-only access, exact
length, sector size, EROFS UUID, CRC32C, fixed superblock and contiguous mapped
pack geometry before mounting it read-only. The agent reads the bounded shared-codec observation at
`/run/silo/rootfs/observation.json` through root-only, no-follow directories and
checks the retained lower/upper mount devices. A missing or malformed observation
on an overlay root fails boot. The agent never sends a resize ioctl to overlay
`/`; ordinary raw ext4 and btrfs root resizing remains separate.
Init requires the explicit `silo.rootfs=linux-erofs-overlay-v1` boot contract and
never falls back to raw boot or a rescue shell after managed assembly failure.
The root-owned maintenance mounts `/run/silo/rootfs/lower` and
`/run/silo/rootfs/upperfs`, plus their observation, survive a checked `/run`
mount move. The observation carries validated device UUIDs, geometry, fixed
persistence profiles, filesystem span, unusable tail and temporary-directory
policy, not a shutdown certificate. `/tmp` remains merged-disk backed by
default; an explicitly sized tmpfs is mounted before handoff and is
nonpersistent and memory-charged.

The independent `specs/rootfs-spec/fixtures/overlay.json` bootstrap and
`observation.json` retained record encode `lower.filesystem` as `erofs` and
`upper.filesystem` as `ext4`; the device expectation type is unchanged.
Negative UUID and tail fixtures retain that same current profile so they fail
for their intended identity/accounting violation. Codec regressions separately
refuse retired `linux-flat-overlay-v1` kind/marker bytes, swapped filesystem
roles, malformed or truncated inputs and non-block-aligned lowers. The init
unit regressions construct fixed-format superblocks and device slots, covering
checksums, unsupported features, nil/out-of-range geometry, missing/repeated
occurrences, truncated records and wrong UUIDs without mounting a host filesystem.

All requested mounts are required early boot state, including when optional
provisioning is disabled. The complete plan is normalized and validated before
final user-mount effects: targets must be absolute, traversal and normalized duplicate
targets are rejected, and `/`, `/run`, `/run/silo` and its maintenance descendants
are protected. Mount targets are directories; existing file or symlink ancestors
are rejected, including aliases into maintenance state. Parents mount before
children. Every required mount completes before image-owned PID 1 is exec'd or
managed workload admission starts; mount failures stop boot rather than becoming
best-effort provisioning failures.
Required mounts are verified against `/proc/self/mountinfo` after the mount
command, so `nofail`, a missing `findmnt` executable or a successful command exit
cannot disguise an absent mount or wrong source/filesystem/access mode.
The public mount plan supports directory `virtiofs` shares only. Accepted options
are `ro`, `rw`, `nofail`, `nosuid`, `nodev` and `noexec`; duplicate or conflicting
access options and bind/move/remount operations are rejected. Nested targets are
checked against their nearest configured parent share's actual source view:
before publishing final mounts, a child-only mount namespace stages read-only
parent shares on a private `/run` tmpfs, checks file/symlink ancestors, then exits
and is reaped. Neither the original mount namespace nor host-share contents are
modified by that preflight.

Agent-PID1 shutdown uses the private bidirectional `OrderlyShutdown` RPC. The
injected launch context binds the exact machine/run and complete block/share
manifest; the request must also match the current agent instance, boot and
shutdown-attempt identity. The sequence is `BEGIN`, `ACCEPTED` (AgentPid1),
sticky `COMPLETED` (Succeeded, Failed or Unsupported), `ALLOW_POWEROFF`, then
poweroff. Image-owned PID 1 remains supported, but the child agent rejects
shutdown authority with `Unimplemented` before acceptance.

The same PID1 shutdown path handles host requests and autonomous guest stop.
It closes process/file/listener admission, cancels idle uploads and backpressured
downloads/forwarders, drains the actual filesystem and process-dependent
reader/writer/logger owners, joins the cache reclaimer, and stops workloads.
The internal RPC connection stays alive throughout these drains, without being
included in its own drain barrier. Retained filesystem descriptors receive
checked `syncfs`; overlay `/` is frozen first, underlying writable storage is
unmounted or remounted read-only, the resulting state is verified, and final
`syncfs` is checked. The first failure stays sticky through later successful
cleanup.

Certification additionally compares every manifest block serial, geometry and
access mode against sysfs and retained mount identities. Partition filesystems
are covered only through actual children of that exact parent attachment, with
kernel slot/range/device/access facts checked against the shared GPT/MBR parser
and held block-device measurements (including expanded-disk GPT policy).
Whole-disk ext4, partition ext4 and mounted vfat ESP/data filesystems each need
their own retained mount error cursor; covering the root does not cover its ESP.
Writable Data must still be mounted and covered. Every retained mount is synced
and unmounted or verified read-only before completion can succeed.
Writable virtiofs, unknown mount namespaces, raw block-device workload access,
unqualified external/concurrent writers, unmounted writable Data and unsupported
filesystem/device stacks are explicitly noncertifying, not removed VM features.
Namespace ownership is classified per task using the kernel's `PF_KTHREAD` flag,
not PID or process name. Kernel workers may retain the boot mount namespace;
their writeback is covered by checked filesystem synchronization. A foreign
userspace mount namespace remains noncertifying.
The synchronous tracing sink drains, flushes and permanently closes before the
final filesystem synchronization; even failure-path logging cannot write later.

Completion is memory-only, never a success file or filesystem log. After
completion the PID1 worker waits at most five seconds for the exact matching
host receipt; disconnect or expiry allows poweroff but does not manufacture a
receipt. Autonomous poweroff without an admitted exchange cannot certify guest
protocol completion. The guest result is not host-flush or attachment-closure
proof; the monitor establishes those facts independently.
Writeback-error cursors are retained before agent provisioning or SSH trust/key
writes; newly mounted early filesystems are registered before writes are admitted.
A filesystem discovered only at shutdown, even if currently read-only, makes
historical error coverage incomplete and cannot produce internal completion.
Cleanup resolves each retained mount ID to
its current target and checks the opened target's mount ID before any path-based
unmount/remount, so moved or replaced paths cannot redirect cleanup.
Actual blocking workers retain admission through output disposal (including
abandoned upload unlink cleanup), and child I/O leases cover guest-process and
native/OpenSSH reader/writer/logger workers beyond async-handler cancellation.
The same lifecycle leases cover process RPC first-message, rejected-input,
control-reader and pre-spawn orchestration tasks, plus SSH agent-forwarding
accept/proxy tasks. Shutdown explicitly wakes idle reads, backpressured control
sends, forwarding accepts, channel opens and bidirectional copies before waiting
for leases to drain; peer FIN is not a prerequisite for those cancellation paths.

## Live guest lifecycle protocol

`FreezeWorkloads`, `Activate`, and `Thaw` use the existing host-only guest
control service. The current admitted containment profile is Silo-managed
`AgentPid1`, not arbitrary privileged image-owned cgroup management. Cold boot
still supports `Standard` and `InitChild`; their live requests reject before
effects with the named unsupported profile. Kernel/driver and whole-machine
qualification remain host-owned and are not inferred from guest RPC success.

Every freeze names canonical machine/run/operation UUIDs and a nonzero,
monotonic per-run epoch. Exact in-flight retries join owned operations even if
the original RPC disconnects. A cached frozen response rechecks actual
`cgroup.events`. A completed thaw cannot be undone by replaying its old freeze
epoch: lost-thaw recovery must send the exact next epoch and observe a real
freeze. A delayed old thaw cannot release that newer epoch. The control service
and read-only filesystem/metrics requests remain responsive; workload spawn,
filesystem mutation and forward registration admission is reversibly closed
and real admitted workers drain before freeze completion. Disconnect never
automatically thaws. Failed freezes record observed roots and rollback outcome;
failed rollback remains faulted and fenced.

The trusted monitor sends activation only after the exact kernel generation
acknowledgement. Activation preserves Linux boot provenance, rotates the shared
agent-instance identity once, rebinds machine/run and shutdown inventory,
retires inherited sessions and forwards, replaces networking on its retained
ifindex, installs only named destination listeners with monitor-issued tokens,
and runs only the explicitly selected bounded hook. A networkless capture may
remain networkless; adding or removing the managed attachment is refused.
Activation wall time only steps forward, including positive subsecond offsets.
Hooks run in the activation sibling cgroup, with null bounded output, a deadline,
and actual descendant kill/reap cleanup; background descendants are a failure.

Identical activation retries return the recorded in-memory result and never
repeat network, hook or listener effects. Any admitted activation failure is
sticky; no normal thaw or in-place retry is allowed. Success remains
`ActivatedFrozen`; only an explicit exact destination-bound thaw releases the
workload. These guest states do not authorize public Running or release host
network/mux fences. Host orchestration and real restore/generation conformance
remain later-phase gates, not claims made by these guest implementations.

## Cross-Compilation

The current repo-level helper is:

```bash
make build-guest-agent
```

That target builds the guest agent binary and copies it into Silo's runtime assets directory:

```text
target/resources/assets/agent
```

The helper selects a statically linked musl target matching the host architecture:

- x86_64: `x86_64-unknown-linux-musl`
- arm64: `aarch64-unknown-linux-musl`

Override `GUEST_TARGET` when intentionally cross-building for another architecture.

For example:

```bash
make build-guest-agent GUEST_TARGET=x86_64-unknown-linux-musl
```

## Status

This crate is Linux-guest-only. Host-side validation can be done from macOS, but full agent compilation and runtime verification still depend on having the Linux target toolchain available.
