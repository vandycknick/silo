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
  Virtualization.framework.
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
  system:
    image: ghcr.io/vandycknick/system@sha256:<qualified-digest>
    resources:
      cpus: 4
      memory: 4GiB
    storage:
      root-size: 8GiB
      data-size: 64GiB
    mounts:
      home: true
      additional: []
    networking:
      publish-bind: any
    docker:
      compatibility-socket: auto
```

The home share is enabled read/write by default and appears at the same absolute
path in the guest. Disable it if the engine must not access the host home.
Additional shares must be absolute, non-overlapping directories. Share changes
and data-disk growth are not supported after installation. Resource changes are
supported only while stopped. Image changes use the explicit upgrade command.

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
silo daemon upgrade --image ghcr.io/vandycknick/system@sha256:<digest>
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

`daemon status` and `daemon logs` do not initialize libvm or start the engine.
The live status is corroborated with native service PID, daemon generation, and
process-start identity rather than trusting an old `ready` file. Logs are
bounded and rotated under `XDG_STATE_HOME/silo/logs/daemon`.

Common failures are actionable:

- Missing Linux user bus or macOS GUI domain: use a normal login session, or use
  explicit foreground mode for development.
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
- Native-architecture containers are the baseline. Cross-architecture execution
  needs a separately installed and qualified binfmt/emulation path.
- Unix socket bind mounts and filesystem notifications across shared paths do
  not have native-host filesystem semantics in every tool.
- No root daemon, global socket takeover, automatic host-tool installation,
  unattended image migration, Kubernetes service, or manager RPC API is
  included in v1.
