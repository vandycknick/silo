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
silo show <VM>                  # alias: silo status <VM>
silo show <VM> --format json
silo logs <VM>
silo logs <VM> --stream network
```

Inventory/partial inspection succeeds with explicit issues. Missing requested
VMs, global runtime failures, and failed mutations return nonzero. Use `-v` to
expand a global initialization error. Historical logs remain accessible when the
machine configuration is corrupt; reading logs does not require a runtime lock.

## Process ownership

A managed netd launch uses two modes of the same executable:

```text
silo / silod / embedded libvm
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

CLI, silod, temporary launchers, backend workers and exit hooks:
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
- CLI exit or silod restart after handoff -> neither is stopped.

silod SIGINT/SIGTERM detaches the manager. Explicit `silo daemon down` stops the
service and then invokes `silod --stop` to stop the installation. Regenerate
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

Focused process tests use the real netd binary and actual child processes. The
real-host smoke tests require built/signed runtime components and disposable VMs:

```sh
make cli silod silo-vmm netd

# Use an immutable cached root disk; create clones, never boot the source.
SILO_SMOKE_DISK=/path/to/cached/rootfs.img \
  python3 scripts/smoke/netd_lifetime.py

# Requires a compatible system image; an existing image cache may be COW-cloned.
SILO_SMOKE_SYSTEM_IMAGE=registry/system@sha256:... \
SILO_SMOKE_CACHE=/path/to/images \
  python3 scripts/smoke/silod_restart.py
```

These are dependency-free Python scripts. Both isolate HOME/config/state and stop
their test VMs on completion; failed runs retain evidence under `/tmp`. They cover
real helper reaping, normal/VMM-crash EOF shutdown, netd-crash survival, suspended
monitor timeouts, partial plain/JSON inventory, historical logs, strict runtime
validation, and adoption of the same VMM/netd generation across silod restart.
Run on each supported host platform; success on macOS is not Linux verification.
