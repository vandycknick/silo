# 18. silo-vmmon Contract

Date: 2026-09-24

## Status

Accepted

Supersedes the "`vmmon` Process Model" and "Startup and Shutdown Semantics"
sections of [ADR 0004](0004-daemonless-architecture.md). The daemonless
decision itself stands.

## The Problem

`silo-vmmon` supervises one running VM: it starts the virtualization backend,
serves the machine's control API, runs guest services, and records how the
generation ended. libvm launches it, hands it inputs, and later reconciles its
results into the state database.

That boundary was defined by code on both sides and by fragments of ADR 0004.
It had grown to include argv flags, four inherited descriptors, a JSON start
request, a line protocol, files the monitor writes, and an exit command. None of
it was written down in one place, so changing either side safely meant reading
both.

The monitor is modelled on conmon: a small per-instance supervisor with a
narrow, file-based contract that a manager drives. The same reuse goal applies.
Anything that implements this contract can manage a Silo VM, and a different
monitor implementation should be buildable from this document alone.

## Decision

The contract between libvm (the manager) and `silo-vmmon` (the monitor) is the
normative interface below. It is file- and descriptor-based. The monitor never
opens the state database; libvm is its only writer.

### Process

- One `silo-vmmon` process supervises exactly one VM generation, identified by
  `--id` (machine) and `--run-id` (generation). A restart is a new process with
  a new run ID.
- Unless `--foreground` is given, the monitor daemonizes: the process libvm
  spawned exits once the detached monitor exists, and the detached process
  starts a new session with stdin, stdout and stderr on `/dev/null`. libvm
  treats the launcher's exit (within 5 seconds) as the daemonize handshake.
- The libkrun backend runs the VMM in a child process: the same executable
  started with argv[0] `silo-krun` and no arguments. The VZ backend runs the VM
  through Apple's Virtualization.framework helper. The monitor owns, signals
  and reaps its child; the child is an implementation detail of the backend.

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

Inherited descriptors, each named by an environment variable holding the
descriptor number:

| Variable | Descriptor | Contract |
| --- | --- | --- |
| `_VM_STARTPIPE` | read end of a pipe | One JSON start request followed by EOF (below). |
| `_VM_SYNCPIPE` | write end of a pipe | The monitor reports startup on it (below). Its closure by the manager means the manager is gone during startup. |
| `_VM_MACHINE_LOG_DIR` | directory | The machine log directory, used for `exec.log` rotation. |
| `_VM_MACHINE_LOCK` | regular file | `vm.lock`, already `flock`ed by libvm. The monitor holds it for its lifetime so the machine cannot be started twice. |

Start request (version 1, camelCase JSON, unknown fields rejected, 16 MiB
limit): `version`, `machineId`, `machineRunId` (both must match the
arguments), and optional `startupCommand`, `virtBackend`, `rosettaIntent`,
`assetDirectory` and `startupBudgetMs`. Fields are added, never repurposed.

### Outputs

| Output | Contract |
| --- | --- |
| syncpipe | Exactly one line: `started\n` once the VM runs, the control API is serving and any required guest readiness is met; otherwise `failed\t<message>\n` or `startup-command-launch-failed\t<json>\n`. |
| `--pidfile` | The monitor pid and a newline, mode 0600, removed at the end of the generation. |
| `--socket` | The control API (ADR 0008), mode 0600, bound for the life of the generation. |
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
- The monitor's behavior does not depend on the backend beyond the `backend`
  block of the exit record.

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
  clean outcome. aarch64 and VZ do not receive the argument.

## Properties

- **No database.** The monitor's state is files and descriptors. The manager
  reconciles.
- **Backend independent.** krun and VZ satisfy the same contract; a Firecracker
  or other backend would too.
- **Implementable from this document.** No field of the contract requires
  reading libvm or silo-vmmon source.
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
