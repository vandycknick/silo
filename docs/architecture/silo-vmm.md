# silo-vmm

`silo-vmm` is Silo's virtual machine monitor (VMM), responsible for VM
configuration, execution, and lifecycle across virtualization backends. One
supervisor process owns each running VM generation. It delegates guest execution
and virtual devices to libkrun or Apple's Virtualization.framework, serves the
machine's control API and guest services, and records how the generation ended.
It is not the host hypervisor. Its interface with libvm is
[ADR 0018](../adr/0018-silo-vmm-contract.md); this document describes how it
is built.

## Process Model

```text
libvm / CLI / SDK
  -> silo-vmm                      daemonized, one per generation
       Tokio, control API, guest services, forwards, finalization
       |
       +-> krun                    krun backend: same executable, argv[0] "krun"
       |     descriptor adoption, watchdog, host admission
       |     synchronous engine -> libkrun -> process exit
       |   or Virtualization.framework (vz backend, in the monitor process)
       |
       +-> exit runner             only with --exit-command; idle until triggered
```

`main()` checks argv[0] before anything else. When its basename is
`krun` it runs the worker (`virt/vmm/src/krun/worker`) and never touches
supervisor code: no argument parsing, daemonization, tracing or Tokio. On Linux
the worker also sets its thread name, so `/proc/<pid>/comm` reads `krun`.
Command-line views in `ps` and htop show `krun`. The executable remains
`silo-vmm`: macOS Activity Monitor can show that name for both the supervisor
and worker, because overriding argv[0] does not rename the executable. There
is no separate `krun` binary or executable alias.

libkrun is linked into silo-vmm, but VM construction and execution happen
only in the worker. libkrun may call `_exit()` during normal shutdown and leaves
detached threads, so it must never run on a monitor thread.

`virt::VirtualMachine` is the backend-neutral handle the monitor uses. VZ runs
in process on its own dispatch queue. On macOS silo-vmm is signed with both
`com.apple.security.hypervisor` and `com.apple.security.virtualization`
(`virt/vmm/silo-vmm.entitlements`).

## Worker Handoff

The monitor spawns its own executable with argv[0] `krun` and no
arguments. A `pre_exec` step marks every descriptor close-on-exec, parks the
handoff descriptors above the target range (a source may already sit on
another role's number), and `dup2`s them onto a fixed table:

| fd | Role | Checked as |
| --- | --- | --- |
| 0 | `/dev/null` | |
| 1, 2 | diagnostics pipe, drained into a 64 KiB tail | |
| 3 | config: one `KrunConfig` JSON, read to EOF | FIFO, read-only |
| 4 | events: length-prefixed JSON events | FIFO, write-only |
| 5 | watchdog: POLLHUP means the monitor is gone | FIFO, read-only |
| 6 | console | TTY (PTY slave), read-write |
| 7 | vsock mux, present iff `config.vsock_mux` | connected `SOCK_STREAM` |

The worker validates every role, direction and type, rejects descriptors that
alias the same resource (on macOS also the two ends of one pipe, through
`proc_pidfdinfo`), and fails closed if anything above the table is open. Only
then does it adopt the descriptors and restore close-on-exec on them. No
configuration travels through argv or the environment.

`KrunConfig` is the single wire type. The monitor validates and serializes it
and closes fd 3, which marks the end of the config. The worker reads to EOF
under a 16 MiB cap, decodes with `deny_unknown_fields`, and never echoes decode
errors (they could contain private values). The engine validates the config
once at entry. Rosetta launch data is a typed field with a redacted `Debug`.

| Resource | Bound |
| --- | --- |
| Config, read to EOF | 16 MiB |
| One event | 16 KiB |
| Error diagnostic in an event | 8 KiB |
| Retained worker diagnostic tail | 64 KiB |
| Event and diagnostic final drain | 1 s |
| Serial final drain | 1 s |

The watchdog thread starts before the config is read and before any native
initialization. Loss of its only write end terminates the worker with
`_exit(125)`, even when another channel is blocked.

Worker events are `startup_stage`, `backend_started`, `startup_failed` and
`host_memory_reclaim`. Stages advance `spawned -> admission -> build ->
started`; a config failure reports `spawned`. `backend_started` acknowledges
construction, not guest readiness.

## Ownership and Stopping

One owner task alone signals, waits for and reaps the worker, and publishes its
lifecycle (`Starting`, `Started`, `Reaped`, `Exited`). Callers subscribe to the
cached exit. A deadline is never proof of death: if SIGKILL is not observed, the
owner keeps its reap responsibility instead of inventing a status.

| Timeout | Value |
| --- | --- |
| Worker startup | 300 s |
| Graceful stop (macOS) | 30 s |
| Force observation | 5 s |
| VM stop before escalation (monitor) | 65 s |
| Service drain | 1 s |

On macOS a stop sends SIGTERM to the worker, which asks libkrun to shut the
guest down. On Linux a stop is SIGKILL. A second signal to the monitor escalates
to a forced stop.

## Terminal Outcome

The backend reports a neutral `VmExit`: an outcome (clean, forced or failed),
the startup stage reached, the force reason, the worker's wait status when it
had a process, and the diagnostic tail.

- A zero worker exit is clean unless an earlier startup or cleanup error exists.
- Unexpected signals and non-zero statuses are errors, even after a stop request.
- A supervisor-issued SIGKILL that was actually observed is `forced`, including
  Linux's normal stop. Force intent alone never rewrites another signal.
- An earlier startup error stays the primary error.

`finalize.rs` is the only code that ends a generation. It stops a failed live
machine, reads the cached exit, writes `vm.exit.json` (with the `backend`
block described in ADR 0018), reports failure on the syncpipe, removes the
pidfile and triggers the exit runner, in that order.

## Exit Runner

When `--exit-command` is given, `main()` forks an idle runner immediately after
daemonizing and taking the machine lock. At that point the process is still
single-threaded: the tracing appender, which starts the first thread, is set up
afterwards. The runner points stdio at `/dev/null`, closes every other
descriptor (so it never holds `vm.lock`, whose flock state belongs to the open
file description, nor the log directory or supervisor pipes) and blocks on a
pipe. Finalization writes one byte; if the monitor dies first, EOF releases the
runner. It then execs the command with `SILO_MACHINE_ID` and
`SILO_MACHINE_RUN_ID`. The monitor exits without reaping it; it is reparented.

## Confinement

The monitor is not sandboxed yet. Confinement is a goal (Seatbelt on macOS,
Landlock on Linux), and the design keeps it within reach:

- the monitor never opens the state database or other manager state;
- every path it touches is named by its arguments or start request;
- the exit command runs in the early runner, outside any future profile.

A profile would allow the machine data and run directories, the log directory,
the asset directory, virtio-fs mount sources, the attached network's run
directory, the executable (to start `krun`), and the Mach services and
sysctls Virtualization.framework and Hypervisor.framework need.

## x86-64 Poweroff

The x86_64 workload kernel has neither ACPI nor an i8042 driver, so a plain
`poweroff` halts the vCPUs and the VM never exits. The workload patch
`resources/kernels/patches/x86_64/0001-x86-krun-i8042-poweroff.patch` adds a
lowest-priority poweroff handler that writes `0xfe` to port `0x64` when the
kernel command line carries `krun.poweroff=i8042`. libkrun's i8042 device
treats that byte as a terminal exit. The krun backend adds the argument on
x86_64 only. aarch64 guests power off through PSCI. Guest poweroff and reboot
both end the generation cleanly.

## Code Map

| Path | Contents |
| --- | --- |
| `virt/vmm/src/main.rs` | argv[0] dispatch, argument parsing, daemonization, exit runner fork, tracing, runtime. |
| `virt/vmm/src/startup.rs`, `services.rs`, `shutdown.rs` | Start request, backend construction, guest services, shutdown triggers. |
| `virt/vmm/src/finalize.rs` | The single terminal path. |
| `virt/vmm/src/exit_command.rs`, `exit_status.rs` | Exit runner and `vm.exit.json`. |
| `virt/vmm/src/virt/` | Backend-neutral facade, `VmExit`, krun owner and mux, VZ backend. |
| `virt/vmm/src/krun/` | `KrunConfig`, engine, host checks, Rosetta data. |
| `virt/vmm/src/krun/worker/` | Worker entry, descriptor adoption (`fds.rs`), wire format (`wire.rs`), HVF admission. |

See [process and native test instructions](../../virt/vmm/tests/README.md),
[packaging](../../PACKAGING.md) and [native dependencies](../libkrun-deps.md).

## Qualification

| Check | Result |
| --- | --- |
| Real-process worker boundary: fixed descriptors, bad roles, aliasing, fd above the table, config EOF read and limits, watchdog, full event pipe | Passed on macOS |
| Exit runner: once after the record, on monitor SIGKILL, absent without the flag, holds only its trigger | Passed on macOS |
| Signed macOS HVF native gate: devices, serial RPC, block and virtio-fs, stop, worker SIGKILL, reboot, poweroff, new generation | Passed before the executable and worker rename; rerun required |
| Linux KVM native gate, including x86-64 poweroff with a kernel built from this tree | Not yet run |
| Linux `/proc/<pid>/comm` is `krun` | Not yet run |
| VZ backend under the renamed binary | Not yet run |
