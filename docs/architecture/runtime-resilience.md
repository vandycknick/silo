# Runtime validation, VM observations, and netd lifetime

## Failure boundaries

Opening libvm validates the installation and global storage. Missing/invalid
runtime components, incompatible state databases, and database-wide I/O failures
remain fatal. Opening the runtime does not reconcile every VM.

`Runtime::inventory()` and `Runtime::inspect_inventory()` return indexed identity
plus best-effort machine details. An individually undecodable configuration is an
entry with `data: None` and configuration issues, not a failed fleet inventory.
`Machine::inspect()` returns details when configuration is available. Machine
mutations still validate the selected machine strictly.

Inspection does not repair or delete network attachments and does not write back
observed lifecycle changes. Explicit lifecycle operations reconcile under their
normal locks. A busy mutation lock can cause inspection to return last-known state
rather than treating an in-progress transition as definitive. Monitor inspection
has a two-second deadline covering connection setup and the status RPC.

The read model distinguishes:

- `observation: observed`: lifecycle was observed locally; optional telemetry may
  still have an issue.
- `observation: last-known`: lifecycle comes from durable state, not a verified
  current process observation.
- `observation: unavailable`: no reliable lifecycle state is available.
- `issues`: typed component diagnostics (`lifecycle`, `telemetry`, `network`,
  `rootfs`, or `configuration`).

The CLI renders non-observed lifecycle as `unknown`, preserving `last_known_state`
where available. `running` describes VM execution, not end-to-end connectivity.
A dead netd does not clear VM/guest readiness or stop the VM. Failed telemetry can
make readiness unavailable without implying that the VM stopped.

```sh
silo ls
silo ls --format json
silo info <VM>
silo info <VM> --format json
silo system info --format json
silo logs <VM>
silo logs <VM> --stream network
```

`silo info` reports exact running-monitor live evidence (`scope: machine`),
including its backend and lane. A stopped machine reports separately labelled
prospective next-start host evidence, not a fabricated run report.
`silo system info` reports prospective manager capabilities and, when enabled,
the separately configured system appliance host capabilities. Each vector has
`pause`, `capture`, `restore`, `fork`, and `incremental`, with `native` and
tagged `supported`/`unsupported` availability and a closed reason code.
The native implementation bit is diagnostic, not product admission.

The explicit execution-state command grammar is:

```sh
silo pause <VM>
silo snapshot create <VM> --live [--name <NAME>]
silo fork <VM> --live --name <CHILD> [--name <CHILD>...] [--preserve]
          [--max-children <N>] [--private-write-percent <P>] [--memory-overcommit]
          [--operation-id <UUID>]
silo fork <VM> --live --children-json '<JSON array>'
silo fork --operation <UUID> [--cancel]
silo restore <CHECKPOINT> --execution [--name <CHILD>]
```

These endpoints refuse unsupported operations with typed capability errors.
They never stop a machine, capture only its disks, or cold boot as a fallback.
For VZ the ordinary alternative is to use `silo stop`, then the stopped-storage
snapshot workflow, not an execution checkpoint.

A live fork is one durable operation: one capture of the source, one restored
running child per `--name` (or `--children-json` entry of `name`,
`activationHook` and `destination`). Children receive no host forwards or guest
publication unless that entry's `destination` grants them. Sixteen is the
default fan-out bound, never an implied child count; more children require an
explicit `--max-children`. The CLI selects the operation UUID before submission
unless `--operation-id` supplies it; repeating identical options replays that
operation, while changed options conflict. Every accepted operation prints one
complete JSON result naming each child with its reserved machine and run IDs,
the capture and the independent source outcome. The exit status is zero only
when the operation finished uncancelled with every child running and the source
resumed (or preserved with `--preserve`); otherwise it is nonzero after the
JSON is printed. A failed child never rolls back its siblings, and a nonzero
status or an interrupted client never stops running children or cancels the
operation. `silo fork --operation` observes the operation by ID even after its
source is removed; `--cancel` records durable cancellation intent, so
unsubmitted children never start while submitted children settle normally.

Stopped-storage operations are separate mutations, never a live fallback:

```sh
silo fork <VM> --name <CHILD>
silo snapshot create <VM> [--name <NAME>]
silo snapshot inspect image:<NAME>
silo snapshot list
silo restore image:<NAME> --name <CHILD>
silo snapshot remove image:<NAME>
silo image remove image:<NAME>
```

Fork supports admitted stopped opaque raw and development flat-overlay roots.
Snapshots and stopped restoration support opaque raw only. Both alias and
immutable `image:sha256:HEX` references resolve through the library artifact
collection. An unnamed snapshot is still explicitly retained. `snapshot remove`
releases only that explicit retention; `image remove` removes only an alias.
Other aliases, machines and in-flight operations continue rooting shared bytes.

Exact copies preserve credentials, guest keys, dirty journals and deleted-data
remnants. They do not sanitize, repair or replay source storage, nor implicitly
start or stop a machine. Managed writable disks are included by default.
External resources default to refusal. `--external-requirements` explicitly
omits them while recording required destination mappings. Snapshot creation
accepts only default refusal or required declarations, never destination host
paths. On fork and restore, `--map-disk ORDER=PATH` and `--map-share TAG=PATH`
explicitly select absolute destination paths.
Unresolved requirements block start, and shared external mappings do not imply
self-contained or independently writable storage.

Admission has two explicit intervals: read-only catalog lookup and monitor
status observation may happen first; the actual operation consumes that exact
run-bound observation and refuses before new operational locks, mutation
permits, leases, budgets, workspace allocation, or lifecycle RPCs. Cold discovery
does not initialize writable runtime state. A running monitor's backend takes
precedence over the current prospective backend override.
Live-refusal commands and `system info` can use an authenticated normal daemon
whose core is stopping; ordinary management still requires a ready core.
Stopped fork, snapshot creation, restore and retention/alias removal require
normal mutation readiness and drain admission, including when live refusal
would be permitted. Read-only preflight rejects unsupported root, boot,
resource or artifact kinds before writable initialization where possible;
the library repeats authoritative checks under its runtime locks.
The separate shutdown-only service retains its restrictive RPC allowlist.
Daemon capability reports and typed refusals are validated before encoding.
Invalid outbound evidence is a protocol failure, never a substitute
`unsupported` reason or a successful response.
At durable-machine boundaries, compact stored machine IDs and canonical live
machine IDs are matched by UUID value. Live reports and monitor outer identities
retain their strict canonical representation; run and monitor fences remain exact.

The replacement commands do not retain top-level `show`/`status` aliases.
`silo daemon status` remains the separate daemon lifecycle/status command.

Inventory/partial inspection succeeds with explicit issues. Missing requested
VMs, global runtime failures, and failed mutations return nonzero. Use `-v` to
expand a global initialization error. Historical logs remain accessible when the
machine configuration is corrupt; reading logs does not require a runtime lock.

## Process ownership

A managed netd launch uses two modes of the same executable:

```text
silo (CLI or `silo daemon run`) / embedded libvm
  `- netd --daemonize             short-lived launcher, waited on by caller
       `- netd worker             new session; adopted when launcher exits

After launcher exit:
  OS orphan reaper
    |- silo-vmm
    `- netd worker
```

`setsid()` alone is not daemonization for reaping purposes. The launcher's exit
is essential. The worker inherits an explicit allowlist of directory/startup/
lifetime descriptors through Go's re-exec mechanism. Standard streams are detached;
service diagnostics go to the per-machine network log.

The OS orphan reaper is ordinarily launchd on macOS or PID 1 on Linux. Linux
subreapers can intercept adoption: an embedding environment that installs a
subreaper is responsible for reaping adopted descendants. Silo does not install a
process-global SIGCHLD handler or steal unrelated child exit statuses.

The worker reports startup success only after initializing and binding the
network endpoint. Its report contains worker PID and VM/run/network identity.
libvm validates the report, records the worker's OS birth identity, and reaps the
launcher. Launcher exit or a socket pathname alone is not readiness.

Foreground netd remains available without managed startup/exit descriptors.
Managed mode requires distinct, valid descriptors above stderr; pipe direction
and type are validated. Startup reports and startup waits are bounded.

## One-way lifetime handoff

```text
netd worker                           final silo-vmm
  exit-pipe READ  <-------------------- exit-pipe WRITE

CLI, daemon, temporary launchers, backend workers and exit hooks:
  no writer copies retained after handoff
```

libvm initially holds the writer while preparing the VM. It passes that writer
through VMM daemonization and releases its copy after startup. The final VMM
holds it through backend shutdown/finalization, with close-on-exec restored so
backend/command processes cannot extend its lifetime. The exit-runner fork closes
unrelated inherited descriptors explicitly.

When the final writer closes, netd receives EOF and runs its bounded shutdown
path. This also works if the VMM crashes. If launch fails before handoff, closing
the caller's writer shuts down the unneeded worker. Once the VMM inherits the
writer, startup rollback must also terminate/finalize that VMM.

There is deliberately **no reverse pipe**:

- VMM exits -> netd shuts down and the OS reaps it.
- netd exits -> VMM continues running, potentially without networking.
- CLI exit or daemon restart after handoff -> neither is stopped.

Daemon SIGINT/SIGTERM detaches the manager. Explicit `silo daemon down` stops the
service and then stops the installation (`silo daemon run --stop`). Regenerate
existing native service definitions after upgrading to obtain the new process-
preservation settings. See [system daemon](../system-daemon.md).

## Legacy state and safe cleanup

Existing running helpers cannot retroactively receive a new exit pipe; they gain
the new lifetime contract on their next normal launch. No database reset or
forced restart is required to open or inspect their state.

Process probing distinguishes dead/zombie processes from live identities. An
unavailable identity is an error, not evidence that a PID was reused. Inspection
reports stale attachments without deleting them. During explicit teardown, a
missing/dead or conclusively replaced helper generation needs no signal. A
replacement process is never intentionally signalled. Invalid PID records,
permission errors, or uncertain identity refuse cleanup and retain evidence.
Shared attachment counts and generation-owned runtime paths still constrain
teardown; logs remain durable across runs.

Socket path checks are not connectivity tests. Crashes can leave paths behind;
unlinking a path does not prove that its owner exited. Datagram sockets do not
provide stream-style EOF. No watchdog, packet probe, or universal network-health
policy is part of this design.

## Verification

The storage-holder reconciliation test waits for a real child process to report
userspace readiness before dropping the launch lease and asserting a free flock.
This establishes that inherited close-on-exec descriptors have finished teardown;
an exec-status notification alone is not the fixture's readiness boundary. The
same live-holder fence is exercised with clean, missing, and malformed exit
records, and the child is killed and reaped before terminal reconciliation.

Focused process tests use the real netd binary and actual child processes. The
real-host smoke tests require built/signed runtime components and disposable VMs:

```sh
make stage && make smoke SMOKE_ARGS="-k 'netd_lifetime or daemon'"
```

The suite isolates HOME/config/state and generated sockets, stops its test VMs,
and retains evidence on failure. See [smoke/README.md](../../smoke/README.md)
for prerequisites, image configuration, and evidence paths. It covers real
helper reaping, normal/VMM-crash EOF shutdown, netd-crash survival, suspended
monitor timeouts, partial plain/JSON inventory, historical logs, strict runtime
validation, and adoption of the same VMM/netd generation across daemon restart
(pulls `ghcr.io/vandycknick/silo/system:dev` unless `SILO_SMOKE_SYSTEM_IMAGE`
overrides it).
Run on each supported host platform; success on macOS is not Linux verification.
