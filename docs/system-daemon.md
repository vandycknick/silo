# Silo system daemon

The optional Silo system daemon runs a persistent Docker Engine inside one
per-user microVM. Docker and containerd data live on an installation-owned ext4
disk, separate from the replaceable appliance root disk. The host endpoint is
`~/.docker/run/silo.sock`.

The Docker socket grants its callers administrative control of the guest and
read/write access to every configured host share. Treat access to it like
membership in a Docker administration group. Silo does not expose it globally
or replace `/var/run/docker.sock`.

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

Add a strict version-1 `daemon` section to `~/.config/silo/config.yaml` (or the
equivalent `XDG_CONFIG_HOME` path):

```yaml
daemon:
  version: "1"
  backend: krun                  # optional; krun (default) | vz (macOS)
  system:
    image: ghcr.io/vandycknick/silo/system@sha256:<qualified-digest>
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

`memory` is the ceiling the VM can use. A Linux guest fills spare memory with
page cache, and without host reclaim the host can retain backing for pages the
guest has touched, so a busy engine's host footprint can grow toward `memory`
while idle.

Memory reclamation is automatic, with no daemon policy knobs. vmmon enables a
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
The default is `krun` on Linux and macOS. If the key is omitted,
`SILO_VIRT_BACKEND=krun` or `SILO_VIRT_BACKEND=vz` on `silo daemon up` is copied
into the resolved daemon registration, including login-item starts. An explicit
`backend` key wins over that environment variable. The environment variable
also selects the backend for direct CLI machine starts.

`rosetta` enables x86_64 container execution through Rosetta. Left unset, it is
on for `vz` when the host is Apple silicon with Rosetta installed
(`softwareupdate --install-rosetta`) and off otherwise. It defaults off for
`krun`. Explicitly enabling it with krun selects the experimental
`CapturedCompatibilityV1` path, currently restricted to host build `25G83` and
a pinned unmodified translator digest. The captured baseline is not
TSO-qualified and does not promise compatibility with later Apple releases.
The setting is applied to the system VM the next time the daemon starts it from
stopped. Existing schema-1 resolved records that predate the persisted
`backend` field retain their historical platform selection; create a new
registration to adopt the current default.

The home share is enabled read/write by default and appears at the same absolute
path in the guest. Disable it if the engine must not access the host home.
Additional shares must be absolute, non-overlapping directories. Both disks are
sparse files, so their sizes only cap what the guest may use and cost host space
as data is written. Sizes are fixed at creation: unset sizes follow the existing
installation even if the defaults change, and setting a different size for an
existing installation is rejected. Share changes and data-disk growth are not
supported after installation. CPU, memory, and Rosetta changes are applied
the next time the daemon starts the VM from stopped (`silo daemon down`, then
`up`). Image changes use the explicit upgrade command.

The Docker context points directly to `~/.docker/run/silo.sock`. Silo does not
create or modify `~/.docker/run/docker.sock`, including any existing symlink.

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
docker --host unix://$HOME/.docker/run/silo.sock version
docker --context silo info
```

`down` disables automatic startup and gracefully stops Docker and the VM. It
preserves the machine, images, containers, networks, volumes, build cache, and
both disks. It does not select another Docker context. Repeated `down` remains
disabled across the next login or service-manager activation cycle.

For development without native registration, run:

```bash
silo daemon up --foreground
```

Foreground mode uses the same supervisor and persistent installation. It does
not background itself or install a service. Stop it with SIGINT or SIGTERM.

## Upgrade And Recovery

```bash
silo daemon upgrade --image ghcr.io/vandycknick/silo/system@sha256:<digest>
silo daemon upgrade --recover
```

Upgrade first resolves compatibility metadata and boots the candidate against a
disposable data disk. It then stops the native service, proves the old monitor
has exited, creates a sparse offline backup, and boots the replacement against
the original data disk. Only one recorded VM can write that disk through the
supported CLI path.

If cutover fails or is interrupted, ordinary startup refuses the ambiguous
record. Run `--recover` after reviewing daemon logs. Recovery stops every
recorded candidate and restores the pre-upgrade backup. It discards engine
writes made after that backup, so it is intentionally never automatic.

## Diagnostics

`daemon status` reports the summary state, whether the service autostarts at
login, the Docker endpoint, and, while a daemon runs, its PID, machine, image,
last update, and a one-line summary of the last failure. The full cause chain
is in `daemon logs`.

```
State:      failed (retrying; 3 attempts so far)
Autostart:  enabled
Endpoint:   unix:///Users/me/.docker/run/silo.sock
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
bounded and rotated under `XDG_STATE_HOME/silo/logs/daemon`.

If the engine cannot be brought up, for example because the system image is
not available yet, the daemon stays running: it records the failure in
`daemon status` and its log and retries with exponential backoff, at most every
60 seconds. `up` reports the first such failure it observes and exits non-zero
without stopping the service; rerun `up` once the daemon is ready to finish
Docker integration.

If the daemon process itself exits during startup (a fatal condition such as a
pending upgrade or a foreign lock), `up` reports the recorded failure at once
instead of waiting for the readiness timeout, and stops the native service so
the service manager does not relaunch it in a loop. The service stays enabled;
the next `up` or login starts it again. On macOS the process's stdout/stderr
are captured in `XDG_STATE_HOME/silo/logs/daemon/native.log`, which is where
panics and failures that happen before the supervisor publishes a status record
appear; on Linux use `journalctl --user -u silo-system.service`.

The launchd agent restarts only after an unsuccessful exit, waits 90 seconds for
a graceful VM shutdown before SIGKILL, and runs with the `Standard` process
type. The VM inherits this scheduling policy: `Background` throttles its CPU and
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
- Pending upgrade: run `silo daemon upgrade --recover`; do not delete lock or
  recovery records.
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
  unattended image migration, Kubernetes service, or manager RPC API is
  included in v1.
