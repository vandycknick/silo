# Vmmon and the private krun worker

## One executable, two processes

```text
libvm / CLI / SDK
  -> vmmon supervisor
       Tokio, API, guest services, lifecycle, exit metadata
       |
       +-> current_exe() worker
             descriptor validation, watchdog, host admission
             synchronous krun engine -> libkrun -> process exit
```

Libkrun is linked into vmmon, but VM construction and execution happen only in
the worker. Libkrun may call `_exit()` during normal shutdown. It must not run
on a supervisor thread. The `virt/krun` crate is a process-owning engine facade,
not a process launcher or reusable VM teardown API.

Clap dispatches the `vmmon worker` subcommand before Tokio, daemonization, or
supervisor logging. The worker has its own descriptor arguments and does not
initialize supervisor services or spawn another worker.

`virt::VirtualMachine` remains the common application boundary. VZ remains in
process on its existing dispatch queue. On macOS, vmmon needs both
`com.apple.security.hypervisor` and `com.apple.security.virtualization`; checking
the entitlement plist is not a substitute for signed execution of both modes.

## Ownership and startup

One supervisor generation reserves one primary launch attempt. Preparation,
spawn, transmission, admission, build, and acknowledgement failures are terminal.
Stop-before-start is terminal too. Restart means a new supervisor, run ID, and
worker, never another attempt on the same object. The temporary macOS Rosetta
acquisition probe is preparation, not a replacement primary worker.

One owner task alone signals, waits for, and reaps the worker. Callers subscribe
to cached completion. Cancelling a start requests cleanup without cancelling the
owner; cancelling a waiter has no lifecycle effect. Force-stop escalates through
the same owner. A deadline is not proof of death: an unconfirmed termination
retains its reap owner rather than synthesizing a terminal status.

The supervisor registers the serial reader before native startup and captures
worker stdout/stderr on a separate diagnostic pipe. Guest serial output does not
share that pipe. Vsock listeners may be registered before native execution and
belong to the same single-use session. Termination fences that session.

`BackendStarted` acknowledges construction and worker setup, not guest readiness.
Libkrun can execute vCPUs during construction. The supervisor observes completion
during later startup gates and fences readiness as soon as reaping is observed,
even while terminal diagnostics are draining. Primary ownership is retained even
when startup fails before a full daemon context exists.

## Private transport

Only numeric bootstrap FD roles appear in worker argv. Launch configuration is
not passed through argv or environment variables. The supervisor's exec policy
closes unrelated descriptors and opposite channel endpoints. The worker validates
numbers, directions, types, connected mux sockets, and underlying-resource aliases
before adopting ownership. Adopted descriptors regain `FD_CLOEXEC`.

The request/event protocol uses a four-byte big-endian length prefix:

| Resource | Bound |
| --- | --- |
| One launch request, followed by EOF | 16 MiB |
| One event | 16 KiB |
| Error diagnostic in an event | 8 KiB |
| Retained worker diagnostic tail | 64 KiB |
| Worker event/diagnostic final drain | 1 second |
| Serial final drain | 1 second |

Malformed request values are not echoed by parser diagnostics. Native diagnostic
output is drained independently and retained with an explicit truncation flag.
This captures worker output, not automatic native backtraces or OS crash reports.
The mandatory watchdog starts before request reading and native initialization.
Loss of its sole supervisor write endpoint terminates the worker with `_exit(125)`,
including while another channel is blocked.

## Terminal outcomes

Exit metadata keeps the supervisor PID at the top level. Optional worker details
include its distinct PID, raw wait status, code/signal, core-dump bit, last stage,
shutdown intent, force reason, and bounded diagnostics.

- Natural worker status zero is clean unless a separate startup/cleanup error exists.
- Unexpected signals and nonzero statuses remain errors, even after a stop request.
- An intentional supervisor-issued worker SIGKILL is `Forced`, including Linux's
  normal krun stop mechanism. Force intent alone does not rewrite another signal.
- An earlier startup/cleanup error remains `Error`; worker details retain any
  intentional cleanup SIGKILL instead of losing its context.

Normal finalization attempts all teardown, writes the terminal record, and invokes
the exit command once. Second signals escalate the backend stop and continue
waiting for owned cleanup. Libvm failed-start cleanup first interrupts vmmon and
allows an independent 75-second cleanup budget before emergency termination.

`Machine::kill()`, supervisor SIGKILL/crash, and emergency process-group termination
retain weaker guarantees. They cannot promise final metadata or an exit command.
The watchdog prevents a persistently running worker, but cannot resurrect a dead
supervisor to finalize it.

## Packaging and qualification

Runtime/application payloads contain vmmon and netd plus the usual guest assets.
Both supervisor and worker processes execute vmmon; the worker uses the `worker`
subcommand. The krun engine is a library, not an installed executable.

See [process and native test instructions](../../runtime/vmmon/tests/README.md),
[packaging](../../PACKAGING.md), and [native dependencies](../libkrun-deps.md).

### Evidence from this refactor

| Check | Result |
| --- | --- |
| Linux real worker protocol, FD policy, cancellation, watchdog, bounded diagnostics | Passed |
| Full host-aware `make test`, including existing lifecycle regressions and netd tests | Passed |
| Linux x86-64 KVM boot and bidirectional serial RPC | Passed |
| Block ordering/read-only flags, virtio-fs read and read-only enforcement | Passed |
| Balloon and vsock device enumeration | Passed |
| Linux supervised stop / unexpected worker SIGKILL | `Forced` / `Error`, both reaped and finalized |
| Guest reboot using libkrun's normal init mechanism | Clean worker exit, supervisor finalized |
| New generation on the same machine directory | New supervisor, worker, and run ID; no replacement within a run |
| Active worker after supervisor SIGKILL | Watchdog status 125, reaped by isolated qualification subreaper; no final metadata, as documented |
| Debug staged runtime with only vmmon/netd | Booted and stopped successfully |
| Linux debug vmmon dynamic dependencies | No libkrun, libkrunfw, or libbz2 sidecar |
| Guest `RB_POWER_OFF` with the available x86-64 kernel | Did not terminate the worker; not qualified |
| Linux arm64, native guest networking and bidirectional vsock traffic | Not qualified in this run |
| Signed macOS HVF/VZ execution, Rosetta and reclaim | Unavailable on this Linux host |
| Release archives, macOS app/DMG/signing | Inventory tests passed; release artifacts not qualified |

The x86-64 direct-boot kernel deliberately omits ACPI. Guest reboot is the path
used by [upstream libkrun's init](https://github.com/libkrun/libkrun/commit/5cfd94dafd739a880f67da13d1483880c8d86027).
The separate power-off result is a remaining acceptance gap, not evidence that
the supervisor observed an exit. Do not claim full cross-platform release
qualification from the successful Linux checks above.
