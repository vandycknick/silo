# Silo daemon

Silod is an optional per-user VM-management daemon. Its independently enabled
system integration runs a persistent Docker Engine in one microVM. Docker and
containerd data live on an installation-owned ext4 disk, separate from the
replaceable appliance root disk. Its endpoint is `<Home>/run/docker.sock`.
The daemon resolves the same `SILO_HOME` and `XDG_CONFIG_HOME` as the CLI;
`silod` has no `--home` or `--state` argument.

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

Each CLI command selects management once. A matching ready silod receives its
management calls; proven absence uses local libvm. Selection has a two-second
deadline. A live owner without a usable API, incompatible identity, unsafe socket,
or different Home/config root is an error, never permission to fall back.
The admitted connection is pinned: losing it cannot retarget an in-flight command
to a replacement daemon or replay a mutation locally.

CLI SSH shell, structured exec, forwarding, serial, and logs remain native.
Their lazy session runtime adopts the selected daemon's exact runtime components
and immutable machine ID. An established independent CLI session survives silod
shutdown. Foreground cleanup still requires its selected management backend and
original run ID; detached cleanup runs locally in the monitor's trusted hook.
`create/run --dry-run` remain local, metadata-only planning without probing silod
or opening a mutable runtime. CLI creation and updates normalize host paths before
dispatch, so the daemon's working directory cannot change their meaning.


```text
 CLI management, daemon absent  -> libvm
 CLI management, daemon ready   -> gRPC -> silod -> libvm
 CLI shell/exec                 -> libvm -> silo-vmm -> guest
 CLI service control            -> native user service -> silod
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

`make build` produces the CLI, silod, taild and native bridge together. Portable
installations keep them in `bin/`; macOS bundles place silod, taild and the bridge
under `Contents/Helpers/`. Existing services must be stopped before upgrading
from the embedded daemon, then started with the new CLI so its service
definition points at `silod`. Rebuilding alone does not replace a running process.

## Prerequisites

- Linux amd64/arm64 with KVM, or supported Apple Silicon macOS with
  Hypervisor.framework. Apple Virtualization.framework remains available as an
  explicit backend.
- A non-root login session with a systemd user manager on Linux or GUI launchd
  domain on macOS for native service registration. Foreground operation does
  not require a service manager.
- When system integration is enabled, a native host Docker CLI for context
  integration, access to the appliance registry, and space for the root image,
  persistent data disk, and offline upgrade backup. Docker Compose/Buildx remain
  separate host plugins. Core-only operation needs none of these Docker inputs.

## Configuration

No configuration file is required. A fresh Linux `silo daemon up` starts core
management only; macOS and existing appliance installations default to system
integration enabled. Use `silo daemon up --system` to enable the built-in system
image (4 CPUs, 8 GiB memory, a sparse 20 GiB root disk, 500 GiB data disk, and a
read/write home share). For that integration, silod generates
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

`up` installs/enables the per-user native service and waits for the core API.
When system integration is enabled, it also waits for guest, engine, and
host-socket readiness, then validates/selects the `silo` Docker context unless
`--no-switch-context` is passed. System-disabled startup performs no Docker
preflight or context work. Tailscale startup or pending authentication is
reported separately and does not claim lobby readiness.

Repeating `up` with the same configuration is idempotent. Changed daemon settings
restart the owned service without the explicit appliance-stop operation; ordinary
and system VM runs survive. The service reads normal configuration on each launch.
Deterministic configuration/usage errors exit 2 and are not restart-looped by
systemd; transient runtime failures remain restartable.

On Linux, `up --linger` asks `loginctl enable-linger <current-user>` to enable
account-wide boot-before-login and logout persistence, without sudo. Authorization
failure is explicit. Omitted selection offers consent only on a terminal, after
the configuration-check spinner finishes and normal input echo is restored.
Enter declines; invalid answers ask again; EOF or Ctrl-C cancels before service
registration. Declining leaves account linger unchanged and continues startup
with a persistence note, not a warning. Noninteractive operation does not read
input and prints the same note and explicit enable command. A fresh startup
spinner starts after the linger decision, so its elapsed time excludes answering.
`--linger=false` suppresses the offer, never disables existing lingering.
Foreground/macOS reject `--linger`; `down` never changes account linger.

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

`daemon status` reports core readiness, optional system/Tailscale state,
native service enablement, and account linger separately. Appliance diagnostics
include its VM/run identity, Docker endpoint, configured image, update failures,
and guest/host memory-reclaim observations. A system retry does not change a
working core API into a failed daemon.


`--format json` returns the view with the schema-2 record under `daemon`.
`daemon.core` is independent of optional `daemon.system` and `daemon.tailscale`.
One publisher merges component updates for the status file and gRPC API.

The appliance ships no OpenSSH server. `silo shell silo-system` and
`silo exec silo-system` go through the injected Silo agent's built-in SSH
service over vsock, so they need no guest configuration or host keys.

`daemon status` and `daemon logs` do not initialize libvm or start the engine.
Foreground daemons are visible without a native service MainPID. Kernel PID
birth-time identity rejects stale status, including PID reuse; a live old-schema
record requires a daemon restart rather than being interpreted as ready.
Status reports account linger independently of native service enablement.
Logs remain bounded and rotated under `<Home>/logs/daemon`.

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
Explicit `down` still stops the system appliance through the separate `silod --stop` operation. The VM inherits this scheduling policy: `Background` throttles its CPU and
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
- No root daemon, global socket takeover, automatic host-tool installation or
  Kubernetes service is included. Management RPC is private and same-user only.
  Image upgrades are automatic; there is no switch to pin the running image yet.
## Optional tailnet helper

`silo daemon up --tailscale` enables the same-user `taild` child. It is not a
remote host-login interface. The existing user service owns silod, and silod owns
the helper through a private bootstrap/lifetime pipe. Core readiness remains
independent of tailnet enrollment and reports pending authentication separately.

The helper uses normal Silo Home/config paths and exact manager-selected native
assets. Its stable identity, pins and audit remain under `<Home>/taild`; optional
frontend credentials come from plain Home-scope secrets. See the
[operator guide](taild/operator.md) for setup and authorization.

Helper crashes get bounded restart backoff. Normal silod termination drains and
reaps the helper; owner-pipe EOF after an unexpected parent death cancels it
within five seconds. Neither event stops VMs. `KillMode=process` preserves VM
descendants while silod explicitly owns helper cleanup.

Linux `ExecStop` uses `silod --host-shutdown`, not a VM-stop request on ordinary
service termination. The adjacent shutdown-only helper authorizes stops only
after real `systemctl` state is `stopping`, existing ownership is read and the
helper lease is held. A live manager remains authoritative; proven absence
permits a temporary, doubly locked API restricted to inspection, draining and
run-fenced stops. No SDK/bridge/assets or frontend enrollment are required.
Actual native drain and a fresh final inventory protect against late creations.
macOS reports shutdown protection as unsupported.

Linux service executable paths may contain spaces, dollar signs and percent
signs; quotes, backslashes and control characters are rejected before installing
an invalid unit. Executable and argument escaping differ under
[systemd command-line rules](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20Lines).

Real logind/systemd survival, live tailnet authentication, native macOS/HVF and
soak qualification require their corresponding hosts/credentials; Linux fixture
results do not establish those gates.
