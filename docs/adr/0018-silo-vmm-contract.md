# 18. silo-vmm Contract

Date: 2026-09-24

Updated: 2026-11-01

## Status

Accepted

The storage lease and shutdown-evidence additions below are planned contract
extensions admitted with [ADR 0014](0014-layered-oci-image-storage.md), and
the live-command and restore additions are planned extensions admitted with
[ADR 0021](0021-live-snapshots-and-forks.md). Neither is a claim about the
currently delivered monitor or backends.

The 2026-11-01 owner decision makes the combined ADR 0014/0021 implementation
a **hard breaking release** requiring reinstall and a full state wipe.
Its monitor/launch callers cut over together without old-contract decoders,
compatibility bridges or state-upgrade scripts. The earlier naming decisions
below describe the existing surface, not a requirement to preserve old state.

Supersedes the "`vmm` Process Model" and "Startup and Shutdown Semantics"
sections of [ADR 0004](0004-daemonless-architecture.md). The daemonless
decision itself stands.

## The Problem

`silo-vmm` is Silo's virtual machine monitor. It supervises one running VM:
it starts the virtualization backend,
serves the machine's control API, runs guest services, and records how the
generation ended. libvm launches it, hands it inputs, and later reconciles its
results into the state database.

That boundary was defined by code on both sides and by fragments of [ADR 0004](0004-daemonless-architecture.md).
It had grown to include argv flags, four inherited descriptors, a JSON start
request, a line protocol, files the monitor writes, and an exit command. None of
it was written down in one place, so changing either side safely meant reading
both.

The monitor is modelled on conmon: a small per-instance supervisor with a
narrow, file-based contract that a manager drives. The same reuse goal applies.
Anything that implements this contract can manage a Silo VM, and a different
monitor implementation should be buildable from this document alone.

## Decision

The contract between libvm (the manager) and `silo-vmm` (the monitor) is the
normative interface below. It is file- and descriptor-based. The monitor never
opens the state database; libvm is its only writer.

### Process

- One `silo-vmm` process supervises exactly one VM generation, identified by
  `--id` (machine) and `--run-id` (generation). A restart is a new process with
  a new run ID.
- Unless `--foreground` is given, the monitor daemonizes: the process libvm
  spawned exits once the detached monitor exists, and the detached process
  starts a new session with stdin, stdout and stderr on `/dev/null`. libvm
  treats the launcher's exit (within 5 seconds) as the daemonize handshake.
- The libkrun backend runs guest execution and devices in a child process: the same executable
  started with argv[0] `krun` and no arguments. The VZ backend runs the VM
  through Apple's Virtualization.framework helper. The monitor owns, signals
  and reaps its child; the child is an implementation detail of the backend.

### Naming and Compatibility

The executable and Cargo package are `silo-vmm`, the source lives under
`virt/vmm`, and the component override is `SILO_VMM_PATH`. Install the CLI,
SDK runtime, and helpers as one co-versioned set; old executable paths and
`SILO_VMMON_PATH` are not aliases.

The private libkrun worker uses argv[0] `krun`; its executable is still
`silo-vmm`. macOS Activity Monitor may therefore label both processes
`silo-vmm`, while command-line views distinguish the worker.

Public SDK error identifiers (`VmMonExecutableNotFound`,
`VmMonExecutableInvalid`) and execution-loss identifiers (`VmmonExited`,
`LOST_REASON_VMMON_EXITED`, `vmmon_exited`, and Go's
`ExecutionLostVMMonExited`) refer to `silo-vmm`. The current gRPC service is
`VmMonitorService` and the serialized runtime-state key is `vmmonPid`.
The ADR 0014/0021 hard cutover does not retain aliases or decoding paths solely
for older clients or persisted state; affected callers are updated together.

### Inputs

Arguments:

| Flag | Meaning |
| --- | --- |
| `--id <machine-id>` | Machine identifier. |
| `--name <name>` | Human-readable machine name. |
| `--run-id <run-id>` | Generation identifier, echoed in every output. |
| `--data-dir <dir>` | Machine data directory: `config.json`, disks, initramfs, `apple-machine-id`. |
| `--runtime-dir <dir>` | Machine run directory for generated sockets. |
| `--pidfile <path>` | Where to write the monitor pid. |
| `--exit-status <path>` | Where to write `vm.exit.json`. |
| `--config <path>` | The machine's `VmSpec` (`config.json`). |
| `--socket <path>` | Where to bind the control API socket. |
| `--serial-log <path>` | Serial console log, appended. |
| `--trace-log <path>` | Monitor trace log, appended. |
| `--network <spec>` | `none` or `unixdg,<path>,mac=<mac>`. |
| `--agent-enabled` | Whether guest agent services are expected. |
| `--exit-command <program>` | Optional program to run after the generation ends. |
| `--exit-command-arg <arg>` | Repeated arguments for the exit command, passed opaquely. |
| `--foreground` | Do not daemonize (tests and embedding). |

The `--config` disk schema is exclusively VM spec `0.2.0`. Each disk requires
path, semantic role, explicit raw/VMDK format, exact virtual geometry, validated
block identity and read-only access. Missing fields and old spec versions
reject, with no ordered-role inference or filename-based format detection.
Opaque raw uses one writable raw root; the opt-in development overlay uses a
read-only generated VMDK lower (`silo-root-lower`) and writable raw upper
(`silo-root-upper`), followed by typed Data disks. Both public config and private
worker boundaries enforce the same combinations, unique printable ASCII
identities (1 through 20 bytes, no whitespace), and at most 16 attachments.
VZ rejects VMDK/managed overlay before attachment. The worker preserves supplied
geometry/identity/access rather than reconstructing them from device positions.

Every Silo direct launch, raw or managed overlay, carries an independently
injected root bootstrap `silo/rootfs.json` in the initramfs, uid/gid 0, mode
0600, at most 64 KiB, regardless of agent injection. A single core-only
`rootfs-spec` codec serves host and init and accepts only `schemaVersion: 2`
with a mandatory `rosetta` mode (`disabled`, `optional`, `required`). An
`opaque-raw-v1` root names the `silo-root` attachment (effective length,
512-byte sectors, access), a concrete `whole-disk`, unique `gpt-partition`
GUID or `mbr-partition` slot 1 through 4 selector, and `ext4`; an overlay root
names its two fixed device expectations and profiles. Neither contains host
paths or caller mount flags. The root attachment's block identity therefore
must reach the guest as its virtio-blk serial on every backend; kernel
`root=`, `rootfstype=`, `rootflags=` and `rdinit=` arguments, in any spelling
Linux `next_arg` recognizes (including double quotes), are rejected rather
than honored, so the trusted `/init` is always the initial executable.
Missing/invalid bootstrap fails closed. Schema support never grants
production boot qualification.

Inherited descriptors are named by environment variables. Scalar roles hold a
descriptor number; the generation lease uses the bounded JSON array below:

| Variable | Descriptor | Contract |
| --- | --- | --- |
| `_VM_STARTPIPE` | read end of a pipe | One JSON start request followed by EOF (below). |
| `_VM_SYNCPIPE` | write end of a pipe | The monitor reports startup on it (below). Its closure by the manager means the manager is gone during startup. |
| `_VM_MACHINE_LOG_DIR` | directory | The machine log directory, used for `exec.log` rotation. |
| `_VM_MACHINE_LOCK` | regular file | `vm.lock`, already `flock`ed by libvm. The monitor holds it for its lifetime so the machine cannot be started twice. |
| `_VM_STORAGE_LEASES` | Exactly one descriptor in JSON array syntax, `[N]` | Shared `flock` open file description protecting one resolved generation closure, acquired by libvm and retained through terminal backend attachment closure and exit publication. |

Every managed launch, including foreground launch, requires a current start
request and exactly one generation lease, not one lease per backing or chunk.
The environment value is at most 64 bytes and contains one integer in
`3..=i32::MAX`. Capabilities-only queries do not require or create a lease.
Before adopting any inherited descriptor, the monitor validates the entire
set: distinct numbers/resources, role type and access, and an euid-owned
regular lease inode with exact mode 0600, one link, and read/write access.
The required request metadata binds that inode. Inheritance never validates by
acquiring, converting or unlocking a flock: continuity follows the trusted
producer's duplicate/exec chain.

All parent descriptors remain CLOEXEC, including during concurrent launches;
only the intended child's bounded allowlist changes in pre-exec. Adoption
restores CLOEXEC before starting threads or unrelated children. A retained
qualified ELF descriptor stays open and CLOEXEC until exec resolves it, then
is absent from the loaded monitor. The Linux worker re-execs `/proc/self/exe`.
Manager lease ownership includes complete startup or actual failure cleanup.
Monitor/worker lease ownership includes attachment terminality; the monitor
also retains its lease through checked finalization and durable exit publication.
The fork-only exit runner closes all storage descriptors before waiting,
fails closed if sanitation fails, and strips `_VM_STORAGE_LEASES` from its
executed environment. The monitor never opens the manager database.

Start request (version 1, camelCase JSON, unknown fields rejected, 16 MiB
limit): required `version`, `machineId`, `machineRunId` (matching the
arguments), `storageLease` and `storageShutdown`; optional `startupCommand`,
`virtBackend`, `rosettaIntent`, `assetDirectory` and `startupBudgetMs`.
`storageLease` contains required `operationId` (canonical nonnil UUID),
`fileDevice` and `fileInode`, matching the inherited lease's actual inode.
`storageShutdown` is the exact trusted launch context also injected into the
guest agent, bound to the enclosing machine/run and covering the complete
storage manifest. Missing metadata is an invalid current request, not an idle
or old-format launch path.

### Outputs

| Output | Contract |
| --- | --- |
| syncpipe | Exactly one line: `started\n` once the VM runs, the control API is serving and any required guest readiness is met; otherwise `failed\t<message>\n` or `startup-command-launch-failed\t<json>\n`. |
| `--pidfile` | The monitor pid and a newline, mode 0600, removed at the end of the generation. |
| `--socket` | The control API ([ADR 0008](0008-vmm-host-and-guest-grpc-api.md)), mode 0600, bound for the life of the generation. |
| `--trace-log`, `--serial-log` | Appended, with a generation boundary line naming the machine and run IDs. |
| `exec.log` | In the inherited log directory; rotated at 10 MiB into `exec.log.1..3`. |
| `--exit-status` | `vm.exit.json`, written once per generation, atomically (temporary file plus `renameat`), mode 0600, in a 0700 directory owned by the caller. |

`vm.exit.json` fields: `machineId`, `runId`, `pid` (the monitor), `exitedAt`
(Unix seconds), `outcome` (`clean`, `error` or `forced`), `error` (string or
null), and an optional `backend` object:

```json
{
  "kind": "krun",
  "stage": "started",
  "forceReason": "stop",
  "process": { "pid": 4242, "rawStatus": 9, "code": null, "signal": 9, "coreDumped": false },
  "diagnostic": { "tail": "...", "truncated": false }
}
```

`backend` is absent when no machine was constructed (for example a signal or
manager loss during startup). `process` and `diagnostic` are present only when
the backend ran the VMM in a child process. The manager stores `backend` for
diagnosis and must not interpret it for reconciliation. The record is versioned
by addition only.

### Storage shutdown evidence (ADR 0014)

The existing `outcome` semantics are unchanged: `clean` describes a non-forced
terminal result without a reported error, not proof of storage consistency.
An additive, optional top-level `storageShutdown` object supplies the stronger
evidence required by [ADR 0014](0014-layered-oci-image-storage.md). Version 1 has this shape:

```json
{
  "version": 1,
  "guestProtocolCompleted": true,
  "hostFlushCompleted": true,
  "attachmentsClosed": true
}
```

This object belongs to the enclosing exit record's `machineId` and `runId`;
there is no separate storage generation identifier. The manager accepts it only
for the generation being reconciled. Each boolean records a positively observed
fact for **all** storage covered by that generation:

- `guestProtocolCompleted`: the admitted guest shutdown protocol acknowledged
  successful writer quiescence and filesystem synchronization, including the
  read-only/unmount steps required by the guest storage profile. Requesting
  shutdown, observing poweroff/reboot, or a zero backend exit status is not proof.
- `hostFlushCompleted`: the backend completed the required host-side storage
  flushes successfully after guest quiescence; guest acknowledgement alone
  cannot establish this.
- `attachmentsClosed`: all backend storage attachments and handles are closed,
  including those held by workers/helpers; monitor exit alone is insufficient.

The monitor emits this evidence only after terminal backend closure and before
writing the exit record. A false field means completion was not established
(failure, unsupported protocol, or missing observation), never success by
default. Missing evidence, an unsupported version, or an incomplete/malformed
object cannot qualify as [ADR 0014](0014-layered-oci-image-storage.md) storage-clean. That classification requires
`outcome: "clean"` **and** all three version-1 fields to be true;
diagnostic `backend` fields cannot substitute for this evidence.
The normal CLI/libvm stop path begins a bounded bidirectional
`OrderlyShutdown` exchange before cancelling the ordinary services or forcing
the backend: host `BEGIN` with the complete launch manifest, guest
`ACCEPTED/AGENT_PID1`, guest `COMPLETED/SUCCEEDED|FAILED|UNSUPPORTED`, host
`ALLOW_POWEROFF`, then poweroff. Every frame binds protocol version 1, the
exact machine/run/shutdown attempt, agent instance and boot ID. The guest
compares against trusted injected launch context, not an echoed host request.
The transport survives writer admission closure and actual writer drains;
`ACCEPTED`, disconnect and a timeout cannot establish completion. No persistent
success file or filesystem logging follows guest completion.

For the qualified Linux Raw attachment profile, the monitor retains each
actual backing inode before native writes and supplies checked FD-derived
paths to the worker. After actual native owners are terminal/reaped, its
blocking finalizer checks synchronization of every writable retained Raw
handle and explicitly closes every retained handle. The finalizer owns the
generation lease through actual completion even if its async waiter is
cancelled. Only then does the monitor freeze evidence, durably publish the
exit record and release its lease copy. A sync failure remains a failure even
if later cleanup succeeds. Recovery sync without valid guest completion is
not the normative host-flush fact.

The immutable manifest includes all block attachments and directory shares.
Writable shares, unknown namespaces, unqualified raw-device/unmounted Data
writers, external concurrent writers, image-owned PID1 without admitted
shutdown authority and unqualified framework-owned attachment closure remain
noncertifying; these VM shapes are not removed. Linux Raw proof does not
qualify Darwin full-sync, `/dev/fd` behavior or VZ closure by analogy.

The manager alone reconciles lifecycle and storage outcome atomically for
the expected run. A valid current forced/error outcome remains forced even
when storage evidence is malformed. Missing, unsupported, incomplete or
malformed evidence otherwise yields unknown once liveness is ruled out.
Previously observed true facts are not erased merely because a later action
forces termination. A malformed outer record or wrong-run record cannot
authorize clean classification.

Every managed generation has one durable storage operation and one shared
OFD lease, inherited through the monitor and actual worker. Before releasing
worker configuration or constructing attachments, the monitor durably
publishes the strict current `vm.storage-holder.json` in its runtime directory:
exact machine/run/operation plus monitor and optional worker PID/start
identity. Reuse and GC require terminal registered identities, an independent
nonblocking exclusive lease probe and operation reconciliation. Monitor death
or a free lease alone is not closure. Missing/malformed holder evidence after
an admitted launch fails closed; stable lease inodes are never unlinked.

These are implementation contracts, not claims that every native platform
has passed qualification. Real native smoke/standalone gates separately
observe healthy completion, forced/crash refusal, retained-inode sync failure
and a stopped worker surviving monitor death. Injected syscall EIO is labelled
as such, never as physical-media failure.

### Live commands, restore inputs and capture evidence (planned, ADR 0021)

[ADR 0021](0021-live-snapshots-and-forks.md) adds a nonterminal lifecycle to the monitor. Its additions keep every
promise above: the monitor still never opens the database, still writes only
inside its named directories, and still ends every generation through the one
finalization path.

**Capabilities.** `silo-vmm capabilities --backend <kind> [--scenario
<path>] --json` runs without a machine, socket or data directory and prints
the selected backend's live capability vector for this host: `pause`,
`capture`, `restore`, `fork` and `incremental`, each `supported` or
`unsupported` with one reason from the closed set
[ADR 0021](0021-live-snapshots-and-forks.md) defines (`backend-excluded`,
`host-os-below-floor`, `lane-not-qualified`, `hypervisor-unavailable`,
`build-excluded`, `not-delivered`), plus a diagnostic `native` field per
operation reporting whether the embedded libkrun primitive exists on this
lane. The backend argument follows the same selection the manager uses for a
start request (explicit override, else host default); VZ reports every bit
`backend-excluded`; the mock backend reports what its scenario declares. The
status API of a running machine carries the same vector as a `live` object,
narrowed by the attached devices and guest profile (`device-profile-rejected`
names the device). The manager refuses an unsupported live operation before
it sends a command; a command that arrives anyway is rejected with the
vector's reason.

The manager may first perform explicit read-only machine lookup and run-fenced
status observation. This phase may coordinate catalog reads and send `GetStatus`.
Read-only means unchanged logical database contents and persisted machine/runtime
state, not unchanged SQLite WAL/SHM coordination files. Ordinary SQLite-native
coordination is allowed through the SQLx read-only/query-only/no-create-main
boundary, retaining the native shared catalog guard and close barrier. Observation
must not initialize a writable Runtime, invoke application write recovery or
migrations, mutate logical records, or reserve operation resources.
The operation consumes that exact immutable
machine/run/monitor/topology observation and rejects before acquiring any new
operational locks, leases or budgets, allocating workspace or children, or sending
a lifecycle command. A cold name-based invocation is therefore not a promise of
zero read locks or zero status RPCs. Missing or malformed live evidence is a
protocol/observation error, never an implicit unsupported/default vector.

Host and machine reports carry distinct mandatory scopes. A running report names
the backend that actually constructed the run, regardless of the manager's
current prospective backend override. Production qualification is compiled into
the monitor and bound to its resolved libkrun revision and build profile; mutable
home files, database rows and environment variables cannot grant support.

**Live commands** are additions to `VmMonitorService` on `--socket`, for the
current run only: `Pause`, `Resume`, `Capture`, `GetOperation`,
`CancelOperation` and `ReleaseCapture`. Every command carries `machineId`,
`runId` and `requestId`; a repeated request ID with identical inputs returns
the earlier result and with different inputs is a conflict. `Pause` and
`Capture` create an operation whose ID is the request ID (a `Capture`'s
operation ID is its capture ID); `Resume`, `GetOperation`, `CancelOperation`
and `ReleaseCapture` additionally name the target `operationId` and are
idempotent. Every operation has one status, `in-progress`, `succeeded` or
`failed` with a typed error, kept for the life of the run; a succeeded
`Pause` carries its token, a succeeded `Capture` the sealed capture ID.
`CancelOperation` on a pause while the machine is `Pausing` (in progress or
failed) rolls back the worker's partial pause, thaws, lifts the fences and
returns the machine to `Running` or `Error`; on a capture before the seal it
abandons the capture; on any other finished operation it returns the
status unchanged. A pause token carries its owner: `user` for a public
pause, the capture while a capture is in progress, and `user` again after a
`preserve` capture seals. `Resume` names the token; it is rejected while a
capture is in progress. A command for another run or a stale or foreign
token is rejected. Admission per state is the single table in
[ADR 0021](0021-live-snapshots-and-forks.md). The status API reports the
`live` vector and, for a paused machine, the current token and owner. Bulk
data never crosses the socket.

After the seal, the sealed inventory and `vm.capture.json` are immutable;
`vm.capture-source.json` is the only file added to the capture directory
afterwards.

**Capture staging** lives under `--data-dir/captures/<capture-id>/`, 0700,
with the files [ADR 0021](0021-live-snapshots-and-forks.md) names (`request.json`, `memory.ram`,
`memory-layout.json`, `execution.state`, `devices.state`, `disks/<role>.raw`,
`vm.capture.json`, `vm.capture-source.json`). libvm registers the operation and
hands its storage leases to the monitor before submitting `Capture`. The
monitor closes every writer before publishing the result.

`vm.capture.json` is written once per capture, mode 0600, by writing a
temporary file in the capture directory, synchronizing it, renaming it into
place and synchronizing the directory. Version 1 carries `machineId`,
`runId`, `captureId`, the pause token, the configuration and attachment
digest, RAM geometry, the staged output inventory with sizes and digests,
timestamps, `captureOutcome` (`coherent` or `failed`), `error`, and the
booleans `workloadsFrozen`, `vcpusPaused`, `devicesQuiesced`,
`hostWritersDrained`, `hostFlushCompleted`, `diskCopiesSealed` and
`memoryStateSealed`. Each boolean records a positively observed fact; a
false, missing or malformed field cannot yield `coherent`. A capture is
**sealed** when this durable record exists with `captureOutcome: coherent`
and all seven facts true; a `failed` record is diagnostic, not a seal. The
file is immutable once written. It is versioned by addition only. It does not
replace `vm.exit.json`, and `captureOutcome` is not a stop outcome.

`vm.capture-source.json` is written the same way, after the source's
continuation step, with `version`, `machineId`, `runId`, `captureId`, the
pause token and `sourceOutcome` (`resumed`, `preserved` or `resume-failed`
with `error`). While the run is alive its absence means the continuation is
unfinished and `GetOperation` is authoritative; after the run has ended its
absence means `unknown`. The manager never issues a resume because the file
is absent.

**Restore inputs** extend the start request with an optional, capability-gated
`restore` object: `checkpointId`; `memory` (RAM file and layout), `execution`
and `devices` state, each as an inherited read-only descriptor named by an
environment variable in the same way as the descriptors above; the private
disk roles as paths under `--data-dir`; `compatibilityProfile`; `activation`
(the new identity, network configuration, guest-side listeners for the
machine-scoped forwards the monitor will open, and optional hook); and
`startPaused: true`. Unknown fields remain rejected. A reader that does not
implement the extension rejects a request carrying it.

On a restore launch the backend constructs the VM, installs memory, execution
and device state before the first guest instruction and reports
`restorePrepared` to the monitor internally. The syncpipe line `started`
keeps its meaning: it is written only after [ADR 0021](0021-live-snapshots-and-forks.md)'s activation and thaw
have completed and the control API serves. A restore that fails before
`started` reports `failed\t<message>\n` as today.

**States.** The monitor exposes `Pausing`, `Paused`, `Capturing`,
`Restoring`, `Activating` and `ActivationFailed` through its status API;
readiness is false in every state but `Running`. Stop is serialized with
capture: before the capture is sealed it cancels the capture and finalizes;
afterwards it preserves the sealed result and finalizes. Loss of the manager
never resumes a paused machine; an operation-owned capture completes and
continues the source under its recorded policy without a live manager.
Monitor or worker death produces no positive capture evidence.

### Monitor promises

- Every controlled end of a generation (startup failure, signal, guest exit,
  forced stop) runs one finalization path, in order: stop the VM if it is still
  live, wait for the backend's terminal status, write `vm.exit.json` (the
  primary error first, cleanup errors appended), report failure on the
  syncpipe if startup had not succeeded, remove the pidfile, then trigger the
  exit command.
- The exit command runs at most once per generation, after `vm.exit.json`
  exists, with `SILO_MACHINE_ID` and `SILO_MACHINE_RUN_ID` set and stdio on
  `/dev/null`. If the monitor dies without finalizing, the exit command still
  runs; `vm.exit.json` may then be missing.
- The monitor writes only inside `--data-dir`, `--runtime-dir`, the log
  directory and the files named by its arguments. It never opens the state
  database or any other manager state.
- The monitor's backend-independent contract includes the `backend` diagnostic
  block and, when the [ADR 0014](0014-layered-oci-image-storage.md) extension is admitted, storage shutdown evidence.

### Manager promises

- libvm creates the machine data, run and log directories (0700, owned by the
  user) and `flock`s `vm.lock` before launching.
- libvm writes exactly one start request and closes the startpipe.
- libvm reads `vm.pid` to find a running monitor and `vm.exit.json` to learn
  how a generation ended, then reconciles the machine state into the database.
  A missing or foreign pid means the monitor is gone; a missing exit record
  after the monitor is gone means the generation ended uncontrolled.

## Exit Runner

The exit command is not spawned by the monitor at the end. Right after
daemonizing and taking the machine lock, while still single-threaded, the
monitor forks an idle runner that holds only the read end of a pipe (all other
descriptors, including `vm.lock`, are closed and stdio points at `/dev/null`).
Finalization writes one byte to the pipe; if the monitor dies, EOF has the same
effect. The runner then execs the command and is reparented. Without
`--exit-command` nothing is forked.

This is an implementation detail, but it is what lets the contract promise an
exit command even after a crash, and it keeps the command out of the monitor's
own process so a future sandbox for the monitor does not need access to the
database or `$HOME`.

## Backend Behavior Covered By This Contract

- krun on x86_64 appends `krun.poweroff=i8042` to the guest kernel command
  line. The Silo x86_64 workload kernel carries a patch that turns guest
  `poweroff` into a terminal libkrun exit through the i8042 device when that
  argument is present. Guest poweroff and reboot both end the generation with a
  clean outcome. This alone does not prove the admitted guest shutdown protocol
  completed or qualify as [ADR 0014](0014-layered-oci-image-storage.md) storage-clean. aarch64 and VZ do not receive
  the argument.

## Properties

- **No database.** The monitor's state is files and descriptors. The manager
  reconciles.
- **Backend independent.** krun and VZ satisfy the same contract; a Firecracker
  or other backend would too.
- **Implementable from this document.** No field of the contract requires
  reading libvm or silo-vmm source.
- **Confinable.** Everything the monitor touches is named by its inputs, so a
  sandbox profile can be derived from its arguments. Confinement (Seatbelt on
  macOS, Landlock on Linux) is future work; this contract keeps it possible.

## Consequences

- Changing an input or output is a contract change and belongs in this ADR.
- libvm's launcher and reader are the reference manager implementation; the
  mock backend lets libvm's integration tests drive a real monitor process
  without a hypervisor.
- The monitor can evolve internally (process topology, backends, confinement)
  without touching libvm, as long as the contract holds.

## Alternatives Considered

### Monitor writes machine state to the database

Removes a reconciliation step, but makes two processes write one SQLite file
and ties every monitor to the manager's schema. Keeping the database with libvm
keeps the monitor reusable and the write path single.

### Pass configuration through the environment

Environment variables leak into every child and are awkward for structured,
private data. The start request is typed, bounded and closed after reading.

### Run libkrun inside the monitor

Would remove a process, but libkrun terminates its process with `_exit` on
normal shutdown and leaves detached threads, so the monitor could not finalize.
The child process keeps the monitor's lifetime independent of the VMM's.
