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

### Idle listener discovery

The public vsock surface watches the runtime directory for listener changes.
Ordinary filesystem access events are ignored: on Linux, scanning the watched
directory itself generates open/read/close notifications, which must not trigger
another scan. Rescan-required events and watcher errors still trigger
reconciliation. The bounded notification queue coalesces changes; it does not
prevent a self-triggering event loop.

Periodic reconciliation remains necessary because a session can release a vsock
port without a filesystem event. It also retries watcher installation after a
failure. Idle CPU qualification should measure the supervisor separately from
its `krun` worker and include a real socket publication and guest round trip.

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
| 8 | generation lease | euid-owned regular file, mode 0600, nlink 1, read-write, exact device/inode binding |
| 9..24 | retained Raw backing handles, in manifest order | at most 16, exact config binding and access |

The worker validates the entire set before taking ownership, restores CLOEXEC,
and rejects unexpected descriptors, including fd 7 when the mux is absent.
Protocol/lease roles must not alias a resource (on macOS, neither end of one
pipe may fill another role, checked through `proc_pidfdinfo`). Raw disks may
share a backing inode when the existing disk contract permits it; each still
has a distinct descriptor and manifest binding. No configuration travels
through argv or the environment. FD 8 is required even while config is withheld,
and the worker retains its storage descriptors through actual process exit.

The manager likewise changes only its child's inheritance flags. The
qualified executable FD stays open but CLOEXEC during pre-exec cleanup so
Linux can resolve its retained ELF; it does not survive into the monitor.
Native Linux worker re-exec uses `/proc/self/exe`, never the restaged pathname.

`KrunConfig` is the single wire type. The monitor validates and serializes it
and closes fd 3, which marks the end of the config. The worker reads to EOF
under a 16 MiB cap, decodes with `deny_unknown_fields`, and validates before host
admission or native logging. Decode and validation errors do not echo private
request values. The engine independently validates at entry. Rosetta launch
data is a typed field with a redacted `Debug`.

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

## Typed Storage Attachments

The current VM spec is `0.2.0`. The monitor, backend-neutral configuration and
private `KrunConfig` all carry `vm_spec::Disk` directly: required path, role,
format, exact virtual geometry, validated block ID and read-only access.
There is no private ordered-only disk decoder or defaulted attachment metadata.
Both monitor backend validation and the worker use
`vm_spec::Storage::validate_disks` for the same root-pair, ordering, uniqueness
and geometry rules. User data attachments follow the explicitly typed roots.

For the opt-in development flat-overlay profile, libvm supplies a generated
VMDK `RootLower` with serial `silo-root-lower` and read-only access, followed by
a raw writable `RootUpper` with serial `silo-root-upper`. Its VMDK geometry is
the virtual lower length, not the descriptor's host file size. The engine maps
only the closed `Raw` and `Vmdk` types to libkrun and passes the supplied serial
unchanged. It never infers a format from a filename or a role from an index.
VZ rejects VMDK and either managed overlay role before framework attachment
construction. Opaque raw roots retain their existing explicit boot contract.

Guest flush behavior remains libkrun `SyncMode::Relaxed`, not `None`. Native
libkrun diagnostics still flow through the worker's stdout/stderr pipe into the
bounded monitor diagnostic tail, including actual host I/O errors. The pinned
native request-error log preserves the host errno but does not identify the
attachment role; a bounded host-exhaustion qualification must establish which
backing was exhausted rather than relabeling a guest `EIO` as host `ENOSPC`.
The worker diagnostic tail is not a lossless audit channel.

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

The lifecycle outcome named `clean` is not a storage shutdown certificate.
Neither a zero worker exit, device drop nor observed process reap proves the
future `storageShutdown`, `hostFlushCompleted` or `attachmentsClosed` facts.

`finalize.rs` is the only code that ends a generation. It stops a failed live
machine, reads the cached exit, writes `vm.exit.json` (with the `backend`
block described in ADR 0018), reports failure on the syncpipe, removes the
pidfile and triggers the exit runner, in that order.

## Live Pause Ownership

`live/coordinator.rs` owns the run's Pause/Resume/Cancel journal and fences.
The manager persists each exact request before sending it over `vm.sock`;
reconnection observes the same operation and current pause authority, rather
than creating another pause. Historical success does not authorize a consumed
token. A new `CancelOperation` is rejected while `Paused`; cancellation is
the recovery exit from an unfinished or failed `Pausing`.
Manager journal and authority updates acquire the SQLite writer reservation
before reading current state, so concurrent checkpoint publication cannot
invalidate a deferred read-to-write upgrade.

The monitor drains new session, mutation and forward-connection setup before
freezing the workload. Existing streams remain attached. The worker's dedicated
lifecycle socket owns native tokens; only a positive native barrier publishes
`Paused`. Stop terminates a paused worker without resuming it.
Host forward arrivals are refused while fenced even when guest transport is
unavailable; they cannot be parked for admission after resume.

On Linux x86_64, the guest reports actual same-boot clock evidence, refreshed
after Freeze: TSC, every online CPU's deadline clockevent, a non-PIT broadcast
device (including a completed empty read), and absence of speaker consumers.
When `/proc/modules` is absent, the agent verifies `CONFIG_MODULES` in a bounded
decode of the running kernel's `/proc/config.gz`. Missing or contradictory
evidence fails closed. The coordinator checks the boot identity; the worker
installs the observed retired-PIT profile before native pause.

Resume retains parked-status freshness until native positively releases the
pause. After the ClockOnly generation acknowledgement, it requires a same-identity
status receipt observed after native release, then exact guest Thaw and readiness,
before reporting `Running`. A lost Thaw acknowledgement requires
a new freeze and native pause, with a new token; failed recovery stays fenced.
Operation deadlines are never extended by parked freshness or transport retries.

## Live Capture Ownership

`live/capture.rs` coordinates workload freeze, native pause and provider drain,
disk flush/copy, execution/device state and RAM sealing. The worker receives
owned output descriptors over its lifecycle socket. Capture staging is private
(`0700` directories, `0600` files); the write-once `vm.capture.json` publishes
the seven cut facts only after the outputs are sealed and synchronized.

libvm reserves staging space before freeze. Admission validates the held source
identities and lengths, not a second allocation sample while the guest can still
write. Before sealing, the monitor checks actual staged allocation against that
reservation. Exceeding it fails capture with `staging-budget-exceeded` and applies
the recorded continuation policy. This accounting is not a filesystem quota.

A running source acquires capture-owned pause authority. `resume-if-acquired`
continues that source; `preserve` transfers authority to the user. Capturing an
already user-paused source requires `preserve` and borrows its exact token,
never resumes it. Cancellation before sealing abandons the cut and applies
the continuation policy; cancellation after sealing cannot discard the cut.
`vm.capture-source.json` records continuation separately from capture success.

libvm verifies the sealed closure and native envelope bindings before publishing
a `live-execution` snapshot. Publication serializes concurrent consumers and
retains independent pool RAM, dependency roots and native baseline leases.
Reconciliation can publish a durable cut even when source continuation is
unknown; uncertainty does not authorize releasing a live owner's storage.
Terminal staging reclamation preserves the capture evidence separately.

## Exit Runner

When `--exit-command` is given, `main()` forks an idle runner immediately after
daemonizing and taking the machine lock. At that point the process is still
single-threaded: the tracing appender, which starts the first thread, is set up
afterwards. The runner points stdio at `/dev/null`, closes every other
descriptor (including machine/storage locks, retained backing handles, log
directories and supervisor pipes), and blocks on a pipe only if sanitation
succeeds. Cleanup failure immediately exits the runner instead of retaining
storage ownership while waiting. Finalization writes one byte; if the monitor
dies first, EOF releases the runner. It removes `_VM_STORAGE_LEASES` from the
environment before execing the command with `SILO_MACHINE_ID` and
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

See [process and native test instructions](../../virt/vmm/tests/README.md)
and [packaging](../../PACKAGING.md).

## Qualification

| Check | Result |
| --- | --- |
| Real-process worker boundary: fixed descriptors, bad roles, aliasing, fd above the table, config EOF read and limits, watchdog, full event pipe | Passed on macOS |
| Exit runner: once after the record, on monitor SIGKILL, absent without the flag, holds only its trigger | Passed on macOS |
| Signed macOS HVF native gate: devices, serial RPC, block and virtio-fs, stop, worker SIGKILL, reboot, poweroff, new generation | Passed before the executable and worker rename; rerun required |
| Linux KVM native gate, including x86-64 poweroff with a kernel built from this tree | Not yet run |
| Linux `/proc/<pid>/comm` is `krun` | Not yet run |
| VZ backend under the renamed binary | Not yet run |
