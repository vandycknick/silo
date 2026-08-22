# Run Lifecycle

`silo run` creates a machine for one workload. The machine starts before the
workload launches and stops when that workload exits. `--detach` backgrounds the
workload, but it does not make the VM independent of it.

Use `silo create` followed by `silo start` when you want an idle VM that remains
running without an owning application workload.

## Behavior

Attachment and retention are separate choices:

| Command | CLI behavior | After the workload exits |
| --- | --- | --- |
| `silo run IMAGE -- COMMAND` | Attaches to the workload | Stops and removes the ephemeral VM |
| `silo run --name NAME IMAGE -- COMMAND` | Attaches to the workload | Stops and retains the named VM |
| `silo run --detach IMAGE -- COMMAND` | Returns after workload launch | Stops and removes the ephemeral VM |
| `silo run --detach --name NAME IMAGE -- COMMAND` | Returns after workload launch | Stops and retains the named VM |
| `silo create --name NAME IMAGE` then `silo start NAME` | Boots without an application workload | Runs until explicitly stopped |

Every machine has a name. Without `--name`, `run` generates one and marks the
machine ephemeral. Ephemeral removal is best effort, so a cleanup failure can
leave a stopped machine that you can remove with `silo rm`.

## Default Workload

A command after `--` replaces the image command while preserving the effective
entrypoint:

```bash
silo run ubuntu:26.04 -- uname -a
```

Without a command after `--`, Silo runs the workload resolved from the CLI and
image process settings. `--entrypoint` replaces the image entrypoint; when it is
used without a trailing command, Silo runs that program alone and omits the
image command. Otherwise, Silo uses the image's OCI `ENTRYPOINT` and `CMD`.

For a foreground interactive run with no resolved workload, Silo falls back to
`/bin/sh`, or the path supplied through `--shell`. Detached runs require a
resolved workload because they do not have an interactive shell fallback.

Some images use an interactive shell as their default command. For example:

```bash
silo run --detach ubuntu:26.04
```

The shell has no attached terminal or input, so it may exit immediately. The VM
then stops because its workload ended. Supply a long-running command when you
want a detached workload:

```bash
silo run --detach ubuntu:26.04 -- sleep 300
```

## Retention

Use `--name` when you need to inspect or restart the machine after its workload
exits:

```bash
silo run --detach --name worker ubuntu:26.04 -- sleep 300
silo logs worker --stream exec --follow
silo show worker
```

When `sleep` exits, `worker` becomes stopped and remains available. You can then
inspect it, remove it, or start it as an idle VM:

```bash
silo start worker
silo stop worker
silo rm worker
```

Without `--name`, the generated machine is removed after exit. Use a named run
when post-exit logs or filesystem inspection matter.

## Idle VMs

`run --detach` is for a background workload. It is not the idle-VM command. To
boot a persistent machine without starting its image workload:

```bash
silo create --name dev ubuntu:26.04
silo start dev
silo shell dev
```

`create` stores the image process settings but leaves the VM stopped. `start`
boots it in idle mode, and `exec` or `shell` starts work inside it later.

## Output

Detached `run` writes progress and lifecycle guidance to stderr, then writes
only the machine name to stdout. This keeps command substitution reliable:

```bash
machine=$(silo run --detach ubuntu:26.04 -- sleep 300)
silo show "$machine"
```
