# Silo system daemon

The optional Silo system daemon runs a persistent Docker Engine inside one
per-user microVM. Docker and containerd data live on an installation-owned ext4
disk, separate from the replaceable appliance root disk. The host endpoint is
`<Home>/run/docker.sock`. The daemon resolves the same `SILO_HOME` and
`XDG_CONFIG_HOME` paths as the CLI; `silod` has no `--home` or `--state` argument.

The Docker socket grants its callers administrative control of the guest and
read/write access to every configured host share. Treat access to it like
membership in a Docker administration group. Silo does not expose it globally
or replace `/var/run/docker.sock`.

## Process boundary

`silod` (`app/silod`) is the daemon; `silo daemon up/down/status/logs` is its
controller. Both read normal configuration through `silo-config`. Their published
daemon contract is the `silod-spec` crate, which holds data and encodings only:

The typed management schema is
`specs/silod-spec/proto/daemon.proto` (`silo.daemon.v1`). It separates daemon
status/runtime selection, machine lifecycle, network definitions and runtime
image/policy operations. Rust adapters in `common/vm-control` preserve native
snapshots, run identities, errors, byte-valued host paths and absent-versus-empty
updates. Local creation uses the same normalized builder application.

Committed Go clients live in `specs/protocol/go`; regenerate with
`make protocol-go` and verify drift with `make protocol-go-check`. Both commands
use pinned Go generators and vendored protoc. Guest execution and secret reads
are deliberately absent from this management protocol. Session transport stays
in libvm and its SDK bindings.

The foreground daemon serves management on
`<HostPaths::run_root()>/silod/control.sock`, with a private 0700 directory,
0600 socket, same-UID peer admission, and one active daemon per UID. Core status
does not open the VM store. Ordinary runtime initialization is lazy and retryable;
its exact six-component selection is shared with native SDK sessions.

Accepted native mutations remain tracked after a client disconnects. Admission
is bounded to 64 active mutations; shutdown seals admission and drains actual
work, not merely RPC waiters. A disconnected mutation must not be replayed
automatically. Log tails and following share native snapshot descriptors to avoid
duplicating or losing bytes between history and live output.


```text
 silo ── --system-* argv ─────────────────────────────► silod
 silo ◄─ ~/.silo/daemon/status.json, logs/daemon/ ───── silod
 both ── io.silo.system.* machine labels ────────────── libvm
```

- The CLI owns service registration (launchd/systemd), Docker context integration
  and the status display. It never reads silod's installation record or performs
  appliance provisioning.
- `silod` reads the shared configuration and owns installation records,
  provisioning, supervision and image upgrades. Appliance networking remains
  separate from ordinary VM networking.

`silod` has no subcommands: running it starts the foreground daemon. The CLI
registers the native service without copying default-filled configuration into
arguments. The service reads configuration on every launch and persists only
the resolved `HOME`, `SILO_HOME` and `XDG_CONFIG_HOME` environment identities.
Before registering, `up` runs `silod --check`, so invalid configuration does not
replace the service. `up --foreground` applies process-only overrides without
persisting feature choices.
Every `--system-*` argument configures the system appliance, not defaults for
ordinary VMs. Silod implements the local management API through libvm; guest
execution remains a direct libvm/SDK session, not a daemon stream relay.

Build both executables with `make cli silod` (or the full build). Portable
installations keep `silod` beside `silo`; macOS bundles install it under
`Contents/Helpers/silod`. Existing services must be stopped before upgrading
from the embedded daemon, then started with the new CLI so its service
definition points at `silod`. Rebuilding alone does not replace a running process.

## Prerequisites

- Linux amd64/arm64 with KVM, or supported Apple Silicon macOS with
  Hypervisor.framework. Apple Virtualization.framework remains available as an
  explicit backend.
- A non-root login session with a systemd user manager on Linux or GUI launchd
  domain on macOS. Silo does not install a system service, enable lingering, or
  use a privileged helper.
- A native host Docker CLI for automatic context setup and normal Docker use.
  Docker Compose and Buildx remain separately installed host plugins. A host
  Docker Engine is not required.
- Access to the configured appliance registry and enough space for the root
  image, persistent data disk, and an offline upgrade backup.

## Configuration

No configuration file is required: run `silo daemon up` to use the built-in
system image and defaults (4 CPUs, 8 GiB memory, a sparse 20 GiB root disk and
500 GiB data disk, and a read/write home share). `silod` generates
`~/.silo/daemon/daemon.json` as internal installation state; do not create or
edit it yourself. An omitted option always means its default, so removing a key
from `config.yaml` reverts it on the next `up`. The exceptions are settings
fixed when the installation was created: the backend and the root and data disk
sizes keep their recorded values unless set explicitly.

Release builds use the qualified image digest embedded via `SILO_SYSTEM_IMAGE`.
Development builds otherwise use `ghcr.io/vandycknick/silo/system:dev`. A release
built without an embedded image requires an explicit image override.

To override defaults, optionally add a strict version-1 `daemon` section to
`~/.config/silo/config.yaml` (or the equivalent `XDG_CONFIG_HOME` path).
Only specify settings you want to change. Both executables use the shared strict
parser; explicit foreground arguments take precedence over stored values.

```yaml
daemon:
  version: "1"
  backend: krun                  # optional; krun (default) | vz (macOS)
  system:
    # image: ghcr.io/vandycknick/silo/system@sha256:<qualified-digest>
    resources:
      cpus: 4
      memory: 8GiB
    storage:
      root-size: 20GiB
      data-size: 500GiB
    mounts:
      home: true
      additional: []
    networking:
      publish-bind: any
    # rosetta: true
```

Feature selection is stored in `daemon.system.enabled` and
`daemon.tailscale.enabled`. `silo daemon up --system[=true|false]` and
`--tailscale[=true|false]` update these selections; omission preserves stored
choices. An omitted initial system selection resolves to enabled on macOS or
for an existing appliance installation, otherwise disabled. Tailscale defaults
to disabled. Feature and default-machine writes share a sidecar transaction
lock and atomic replacement, preserving unrelated configuration. Invalid
configuration is never overwritten.

There is one native service registration per UID. A live service bound to
another Home must be stopped with its original Home before reconfiguration.
Configuration leaves and transaction locks must be owned regular files, not
symlinks or FIFOs; group/world-writable configuration is rejected.


The equivalent direct daemon interface is:

```text
silod [--system-backend krun|vz] [--system-image REFERENCE]
      [--system-cpus COUNT] [--system-memory SIZE]
      [--system-root-size SIZE] [--system-data-size SIZE]
      [--system-rosetta true|false] [--system-home-share true|false]
      [--system-share PATH] [--system-share-read-only PATH]
      [--system-clear-shares] [--system-publish-bind loopback|any]
```

Shares are repeatable. Explicit empty `additional: []` maps to
`--system-clear-shares`. Existing installation restrictions still apply. For
example, `silod --system-cpus 10` overrides only appliance CPUs. Bare `silod`
requires no configuration or arguments. `silod --check [options]` validates the
options against the installation and exits without changing anything.
`silod --stop` stops the installation's VMs when no daemon is running.

VMs silod creates carry the `io.silo.system.role=system` and
`io.silo.system.installation` labels so they can be tracked. Ordinary `silo`
commands (`stop`, `rm`, `set`, ...) work on them like on any other VM.

Global `networking.drivers.netd` settings apply only to direct CLI/libvm operations,
not the system appliance. Its networking uses the runtime defaults plus the
explicit system publication setting.

`memory` is the ceiling the VM can use. A Linux guest fills spare memory with
page cache, and without host reclaim the host can retain backing for pages the
guest has touched, so a busy engine's host footprint can grow toward `memory`
while idle.

Memory reclamation is automatic, with no daemon policy knobs. silo-vmm enables a
balloon; libkrun advertises free-page reporting only when the backend supports
it and its qualification succeeds. Otherwise the basic balloon remains.
`HostMemoryRemapper` maintains compatible private RAM mappings independently of
the balloon and its reporting capability.

The managed agent's `GuestCacheReclaimer` detects negotiated reporting and
writable cgroup v2 reclaim interfaces. After two idle minutes it requests
bounded file-cache reclaim, with no global cache-drop fallback. Unsupported
guests retain their cache. `daemon status` reports the last guest reclaim run
and host qualification/cumulative advised bytes, not current physical savings.

Remove the retired `memory-reclaim`, `memory-reclaim-after`, and
`host-memory-reclaim` YAML keys when upgrading. See
[Memory Reclaim](architecture/memory-reclaim.md) for the four components,
capability checks, safety policies, and upgrade behavior.

`backend` explicitly selects `krun` or Apple Virtualization.framework (`vz`).
The first-start default is `krun` on Linux and macOS. An existing installation
keeps its backend unless overridden. `SILO_VIRT_BACKEND` continues to select the
backend for direct CLI machine starts, but does not configure the daemon's system
appliance; use `daemon.backend` in CLI configuration or `--system-backend`.

`rosetta` enables x86_64 container execution through Rosetta. Left unset, it is
on for `vz` when the host is Apple silicon with Rosetta installed
(`softwareupdate --install-rosetta`) and off otherwise. It defaults off for
`krun`. Explicitly enabling it with krun selects the experimental
`CapturedCompatibilityV1` path, currently restricted to host build `25G83` and
a pinned unmodified translator digest. The captured baseline is not
TSO-qualified and does not promise compatibility with later Apple releases.
The setting is applied to the system VM the next time the daemon starts it from
stopped.

The home share is enabled read/write by default and appears at the same absolute
path in the guest. Disable it if the engine must not access the host home.
Additional shares must be absolute, non-overlapping directories. Both disks are
sparse files, so their sizes only cap what the guest may use and cost host space
as data is written. Unset sizes follow the existing installation even if the
defaults change. Data-disk resizing, share changes, and publish-bind changes are
rejected after installation (`up` reports this before registering anything).
CPU, memory, and Rosetta changes are applied the next time the daemon starts the
VM from stopped (`silo daemon down`, then `up`). Image changes are applied by
the daemon itself; see [Image upgrades](#image-upgrades).

The Docker context points directly to `~/.silo/run/docker.sock`. Silo does not
create or modify Docker's own sockets (`/var/run/docker.sock`, or a Docker
Desktop socket under `~/.docker/run`), including any existing symlink.

Silo never removes a foreign file, symlink, socket, Docker context, systemd unit,
or LaunchAgent. A dead socket is not assumed to be owned merely because it does
not answer.

## Lifecycle

```bash
silo daemon up
silo daemon status
silo daemon logs --follow
silo daemon down
```

`up` installs/enables the per-user native service and waits for guest, engine,
and host-socket readiness. It creates or validates the `silo` Docker context and
selects it unless `--no-switch-context` is passed. Native service restarts never
change the active Docker context. Silo invokes `docker context create` and
`docker context use`; Docker itself writes the context metadata and updates
`config.json`. Silo does not edit those files directly.

`DOCKER_CONFIG` selects where the Docker CLI stores context metadata and must be
absolute. `DOCKER_HOST` and `DOCKER_CONTEXT` override the active context; Silo
reports those overrides and does not claim that `context use` changed the
effective endpoint. The endpoint is always usable explicitly:

```bash
docker --host unix://$HOME/.silo/run/docker.sock version
docker --context silo info
```

`down` disables automatic startup and waits for `silod` to detach and exit.
It then runs `silod --stop`, which explicitly stops the installation's VMs,
so the system VM is stopped when `down` returns. A service-manager restart or
SIGINT/SIGTERM to silod alone leaves the VM running for the next manager to adopt. It preserves the machine, images, containers, networks, volumes, build cache, and
both disks. It does not select another Docker context. Repeated `down` remains
disabled across the next login or service-manager activation cycle.

For development without native registration, run:

```bash
silo daemon up --foreground
```

Foreground mode uses the same supervisor and persistent installation. It does
not background itself or install a service. SIGINT or SIGTERM stops only the
manager, leaving an established VM and its network helper running. Run `silod
--stop` after the manager exits to explicitly stop the system appliance, or use
`silo daemon down` for the complete stop operation.

## Daemon State

The CLI's `config.yaml` holds optional user overrides. `silod` keeps its internal installation record at
`~/.silo/daemon/daemon.json`. It contains:

- Installation and persistent data-disk identities.
- The active VM ID, or no ID while initial setup is unfinished.
- One resolved system-appliance configuration snapshot, including the image
  reference the active VM was created or upgraded from.
- While an upgrade is in flight: the previous VM ID and configuration, the
  candidate VM ID, and the data backup. It is cleared once the upgraded VM has
  been Ready.

There is no persisted VM lifecycle or duplicate image digest. Silo inspects the
recorded VM for those facts. A missing recorded VM is an error, not permission to
create a replacement. Ownership-label discovery is only used to recover creation
that finished before its VM ID could be saved.

The record is replaced atomically, and only `silod` reads or writes it. The
lifetime lock prevents two daemons from owning the installation, and the CLI
waits on it in `down`. `status.json` is only a live-status cache, checked
against the daemon process, not installation state.

Records written while the CLI embedded the daemon also held its service
registration; `silod` drops that field when it loads such a record. There is no
migration for the older multi-file daemon state.

An interrupted first setup with no VM resumes with whatever image is configured
now; a VM created before its ID was recorded is adopted and upgraded normally.

## Image upgrades

`silod` follows the configured image reference (`daemon.system.image`, else the
built-in default) and replaces the system VM in place, without restarting
itself. Shortly after the engine first becomes Ready, and then every hour, it
asks the registry which manifest the reference names. A digest reference never
changes, so a release build only upgrades when a new release embeds a new
digest, or when the configured image changes.

When the manifest differs from the one the VM runs, silod:

1. Qualifies the image by booting it against a throwaway data disk. Docker keeps
   serving meanwhile, and a failure only reports `update_error` in the status.
2. Stops Docker and the VM (phase `upgrading`), backs up the data disk sparsely,
   and boots a candidate VM against the original data disk.
3. Commits the candidate once its guest manifest, activation, and Docker socket
   validate, then brings it up like any start. After it reaches Ready, silod
   removes the previous VM and the backup.

Any failure after the old VM stopped restores the previous VM, its
configuration, and the data backup, then starts it again. So does a crash, at the
next start, and a committed candidate that cannot reach Ready. Recovery discards
engine writes made after the backup; the engine is down from the backup until the
candidate's validation, so only writes made during that validation are at risk.
A manifest that fails qualification, validation, or its first boot is not
retried until silod restarts.

## Diagnostics

`daemon status` reports the summary state, whether the service autostarts at
login, the Docker endpoint, and, while a daemon runs, its PID, machine, image
reference and digest, the last image update check, last status update, and a
one-line summary of the last failure. The full cause chain
is in `daemon logs`.

```
State:      starting (retrying; 3 attempts so far)
Autostart:  enabled
Endpoint:   unix:///Users/me/.silo/run/docker.sock
PID:        80954
Memory:     8 GiB; last idle cache reclaim used bounded cgroup reclaim 12 minutes ago, observed guest cache delta 5.2 GiB
Updated:    2026-09-11 10:37:29 UTC (12 seconds ago)
Error:      could not fetch the system image: registry denied anonymous access to image "ghcr.io/example/system:dev"; it may not exist or may be private
```

`--format json` returns the same view with the raw supervisor record under
`daemon`.

The appliance ships no OpenSSH server. `silo shell silo-system` and
`silo exec silo-system` go through the injected Silo agent's built-in SSH
service over vsock, so they need no guest configuration or host keys.

`daemon status` and `daemon logs` do not initialize libvm or start the engine.
The live status is corroborated with native service PID, daemon generation, and
process-start identity rather than trusting an old `ready` file. Logs are
bounded and rotated under `~/.silo/logs/daemon`.

If the engine cannot be brought up, for example because the system image is
not available yet, the daemon stays running: it records the failure in
`daemon status` and its log and retries with exponential backoff, at most every
60 seconds. These attempts use the `retrying` phase, not terminal `failed`.
`up` reports retry errors as progress and keeps waiting within its 120-second
startup deadline. Once the engine is ready, the same invocation finishes Docker
context integration. If the deadline expires, `up` exits non-zero with the last
startup error without stopping the service; inspect `status` and `logs`, then
rerun `up` when ready.

Guest activation waits up to 30 seconds for systemd's control interface before
starting Docker units. Guest-agent readiness alone does not imply systemd is
ready. This wait probes the manager directly, so unrelated degraded units do
not prevent activation.

If the daemon process itself exits during startup (a fatal condition such as a
configuration the installation cannot accept, or a foreign lock), `up` reports the recorded failure at once
instead of waiting for the readiness timeout, and stops the native service so
the service manager does not relaunch it in a loop. The service stays enabled;
the next `up` or login starts it again. On macOS the process's stdout/stderr
are captured in `~/.silo/logs/daemon/native.log`, which is where
panics and failures that happen before the supervisor publishes a status record
appear; on Linux use `journalctl --user -u silo-system.service`.

The launchd agent restarts only after an unsuccessful exit, allows 90 seconds
for the manager to detach before SIGKILL, uses `AbandonProcessGroup`, and runs
with the `Standard` process type. The systemd unit uses `KillMode=process`:
restarting the management service must not kill the surviving VMM/netd processes.
Explicit `down` still stops the VM through the separate `silod --stop` operation. The VM inherits this scheduling policy: `Background` throttles its CPU and
I/O work even when a user is actively building or running containers. Standard
uses normal service scheduling, without requesting the `Interactive` class or
pinning host cores. See [build performance](architecture/build-performance.md)
for the controlled comparison.

This scheduling class is separate from permission to run without an open app.
macOS still lists Silo under System Settings > General > Login Items & Extensions
as an item allowed to run in the background; a debug build shows the bare
executable name because it is not signed with a Developer ID.

After upgrading an existing installation, stop and start the daemon to regenerate
and reload its launchd definition. Rebuilding the executable or editing the plist
alone does not change the policy of an already-running VM.

Common failures are actionable:

- Missing Linux user bus or macOS GUI domain: use a normal login session, or use
  explicit foreground mode for development.
- macOS refuses to load the agent (`Domain does not support specified action`):
  background execution of `silo` was turned off in Login Items & Extensions;
  allow it and rerun `up`.
- Missing KVM/helper/runtime assets: inspect `daemon logs` and the machine's
  semantic monitor/network logs.
- Missing Docker CLI: install the native CLI/plugins, then use the explicit
  endpoint or create the printed context. Guest Linux tools are never copied to
  the host.
- Failed upgrade: `daemon status` shows the reason under Updates and the
  previous VM keeps running; `daemon logs` has the full cause. Do not delete
  lock or recovery records.
- Wrong/missing data disk or share: activation fails before Docker starts. Silo
  never formats a replacement disk during guest activation.

## Deliberate Limits

- TCP publication is supported. UDP, privileged ports requiring host elevation,
  and binding a specific host interface are not v1 features.
- Docker `--network host` means the guest's network namespace, not the physical
  host network.
- Native-architecture containers are the baseline. On Apple silicon, x86_64
  containers run through Rosetta when it is installed; other cross-architecture
  combinations need a separately installed binfmt/emulation path.
- Unix socket bind mounts and filesystem notifications across shared paths do
  not have native-host filesystem semantics in every tool.
- No root daemon, global socket takeover, automatic host-tool installation,
  Kubernetes service, or manager RPC API is included in v1. Image upgrades are
  always automatic; there is no switch to pin the running image yet.
## Optional tailnet service

`taild` is a separate optional Linux service using the public Go SDK, not a remote
host-login interface to silod. Its dedicated home is `/var/lib/silo-taild`.
See the [operator guide](taild/operator.md) for the shipped systemd unit, private
secret directories, logind shutdown inhibitor, stopping-only fallback and manual
restart/shutdown drills. Both service shapes require `KillMode=process` so ordinary
restart leaves VM workers running. Real logind/systemd survival and a one-week soak
remain explicit qualification gates; daemonless Linux results do not qualify macOS.
