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
silo info worker
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
silo info "$machine"
```

`silo info NAME --format json` reports private-copy persistence separately from
execution state and readiness in `durability`: `constructed` means the child
is startable but its persistence barrier has not completed, while `durable`
means that barrier completed. The plain-output row is **Durability**, next to
**Ready**. Ordinary created machines are durable; restore and fork join their
child barriers before returning, so healthy completed children are durable.
In-progress or barrier-failed live children can still be constructed even when
running. This field is not a guest-filesystem cleanliness certificate.

Readiness uses the same prerequisites after restore and live-capture resume:
fresh guest `ready` status and, when SSH is configured, a successful listener
key exchange checked against the machine's immutable host-key pin. Capture
temporarily revokes that evidence while it freezes workloads, so
`WORKLOAD_NOT_READY` during `guest-freeze` is expected even when the source was
ready at admission. After thaw, public readiness stays false until those
prerequisites are re-established and the monitor returns to `Running`.

An SSH pin-check timeout immediately reports `SSH_NOT_READY`. The monitor
still drains the filesystem operation, which cannot be canceled, and consumes
its eventual result only if the verification target remains current and
supervision has not been canceled. A delayed successful pin check can thus
restore readiness without waiting for the next periodic SSH check; a changed
listener, stopped machine, mismatched pin or canceled supervisor cannot.

## Storage shutdown and recovery

Lifecycle `stopped` is not a storage-consistency certificate. `silo stop`
first attempts the bounded, run-bound guest orderly-shutdown protocol.
Storage-clean additionally requires all three independent facts: successful
guest writer/filesystem shutdown, checked host synchronization after native
owners terminate, and closure of every qualified attachment handle.

`silo info NAME --format json` exposes the observed terminal
`storage_stop_outcome` (`clean`, `forced`, `unknown`, or null when storage
metadata is unavailable). The human-readable view labels it **Last storage
stop**. This is not a statement that a currently running VM is safe to copy.
Inspection is read-only: it may classify a current terminal exit before that
result is committed to the catalog. An explicit lifecycle command such as
`silo stop NAME` performs durable reconciliation, including for an already
terminal run, and retires its operation pins only after ownership is settled.
`vm.exit.json` in the machine log directory retains exact-run evidence and
diagnostics. A manager-written forced fence can omit `storageShutdown`
because the killed monitor did not establish finalizer facts; absence does
not imply either clean storage or observed attachment closure.

Force-stop and native errors cannot certify clean. Missing or incomplete
current-run shutdown evidence becomes unknown only after attachment holders
are ruled out. Writable host directory shares, externally writable Data
disks, unsupported guest authority and unqualified backends remain usable
but do not receive an all-storage certificate.

Killing a monitor does not authorize deleting or replacing its disks: the
actual worker may still own attachments and its inherited generation lease.
Silo retains durable holder identities and operation dependencies until all
holders are terminal and an independent nonblocking lease probe permits
reconciliation. Start, removal, replacement and collection fail closed while
that ownership is unresolved. Do not manually remove lease/holder files to
clear a busy error. Inspect logs and let the owned worker terminate.

This release is a hard state-format cutover. Reinstall and explicitly reset
all prior Silo state; no automatic wipe, migration or old-record reader is
provided. Keep any needed data outside the old Silo state before resetting it.
