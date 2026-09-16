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
      memory-reclaim: off         # experimental: auto | off
      host-memory-reclaim: off    # experimental: auto | off
      memory-reclaim-after: 2m
    storage:
      root-size: 20GiB
      data-size: 500GiB
    mounts:
      home: true
      additional: []
    networking:
      publish-bind: any
    docker:
      compatibility-socket: auto
    # rosetta: true
```

`memory` is the ceiling the VM can use. A Linux guest fills spare memory with
page cache, and the host keeps every page the guest has touched, so a busy
engine's host footprint grows toward `memory` and stays there while idle.

`memory-reclaim: auto` enables guest cache reclaim modelled on WSL2's
`autoMemoryReclaim`. The daemon ships the policy to the guest agent in the
machine's guest config at launch, and a low-priority thread in the agent does
the work: once CPU has stayed idle for `memory-reclaim-after` it asks the
cgroup v2 root `memory.reclaim` for one bounded step of file cache per ten
seconds, then compacts free memory so the freed pages can be reported to the
host. It falls back to a cache drop only on kernels without `memory.reclaim`.
`daemon status` shows the last run's mode, outcome, and how far the guest's
cached memory fell. It is off by default and changes take effect on the next
VM start. This setting controls guest cache cleanup only; freed guest pages
reach the host through the balloon's free-page reporting when
`host-memory-reclaim` is effective. See
[Memory Reclaim](architecture/memory-reclaim.md).

See [Memory Reclaim](architecture/memory-reclaim.md) for how the two
memory settings relate.

`host-memory-reclaim: auto` separately asks the krun helper to attach a balloon
and run its per-VM host-reclaim qualification probe. A passing probe enables
host reclaim for that VM; failed or inconclusive probes leave ordinary guest
memory active. Releases remap the range immediately so guest refaults stay
in-kernel; it still defaults to `off` while that path is validated in the field.
The krun helper reports the probe outcome, the effective state, and the bytes
released so far over a status pipe, and `daemon status` shows them on the
`Host memory reclaim` row. This setting does not change backend selection, vsock, native
execution, or Rosetta intent. `daemon status` reports requested and observed
effective state separately and never treats `auto` as proof that reclaim became
effective.

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

`compatibility-socket` accepts:

- `auto`: create `~/.docker/run/docker.sock -> silo.sock` when that path is free;
  warn and continue through the dedicated context on conflict.
- `disabled`: never create the compatibility alias.
- `required`: fail `up` if the alias is foreign or unavailable.

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
change the active Docker context.

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
a graceful VM shutdown before SIGKILL, and runs with the `Background` process
type. macOS lists it under System Settings > General > Login Items & Extensions
as an item allowed to run in the background; a debug build shows the bare
executable name because it is not signed with a Developer ID.

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
