# krun

Silo's typed configuration and synchronous, process-owning libkrun engine.
There is no standalone krun executable or process launcher in this crate.

## Execution boundary

The supervisor launches its own vmmon executable with argv[0] `krun` and the
first private argument `__krun`. The worker dispatches before supervisor
argument parsing, logging, Tokio, or services. It receives private configuration
through an inherited pipe, not argv or environment variables.

`engine::run_process(config, resources, on_built)` must run only in that dedicated
worker process. Libkrun normally terminates the **entire calling process** using
`_exit()`. A thread is not sufficient isolation. Returning errors do not make a
partially built VM reusable, and restart always needs a new supervisor generation.

`VmmBuilder::build()` can start guest execution before `on_built`. The callback
finishes process-control setup and acknowledges backend startup, not guest-agent
readiness. Unexpected event-loop return is an error.

## Ownership

- The engine validates configuration and constructs devices in stable order:
  console, disks, mounts, Rosetta, vsock, network, RNG, optional balloon.
- Console descriptors and explicitly protected streams are borrowed for the
  entire call. The mux descriptor is moved into the native device.
- `engine::Control` offers supported guest shutdown and host-reclaim snapshots.
  Clones share the handle; there is no restart, returning teardown, or child API.
- The worker owns admission, global native logging, signal masks, mandatory
  watchdog setup, bounded startup events, and periodic reclaim reporting.
- Vmmon owns child launch, early console/diagnostic consumption, cancellation,
  termination, reaping, mux/session fencing, and finalization.

Raw block format, read-only flags, relaxed disk sync, external kernel formats,
network feature bits and buffer policy remain unchanged. The engine supports
Unix datagram, Unix stream and TAP configuration; the common production backend
continues to expose only its supported network modes. Standalone native vsock is
restricted to CID 3 and cannot coexist with the mux.

Rosetta configuration remains typed and validated, including immutable source
verification, translator digest, ioctl result and captured-response size. Debug
output redacts its content. The selected worker receives it through the bounded
private request. The signed qualification harness also uses the vmmon worker;
its executable option is `--vmmon`, not `--krun`.

## Features and host support

The optional `engine` feature links the pinned libkrun fork. Configuration-only
consumers need not enable it. On x86-64 it retains static bzip2 support.

The dependency revision and native dependency policy are documented in
[`docs/libkrun-deps.md`](../../docs/libkrun-deps.md). Silo enables only native
`blk` and `net` features, without libkrun's default features or C `ffi` exports.
GPU, input, timesync, confidential-compute, Nitro and other unused APIs stay
disabled. Do not enable features speculatively.

Linux admission checks KVM access, API version and required capabilities inside
the actual worker. The reusable library host-check APIs remain available; there
is no extra krun host-check process. macOS workers perform the empty HVF admission
probe and require vmmon's hypervisor entitlement. The vmmon entitlement set also
retains virtualization support for its VZ backend.

## Termination semantics

A supervisor-issued worker SIGKILL is `Forced`, including Linux's normal stop
mechanism. A nonzero worker exit or an unexpected signal is an error. Shutdown
intent does not turn an unrelated crash into an expected stop. Raw process status,
startup progress, force reason and primary startup errors are retained separately.

`Machine::kill()` is still an emergency operation: killing the supervisor may
bypass diagnostics, metadata and the configured exit command. The worker watchdog
terminates on loss of its supervisor keepalive without running Rust destructors
or waiting on logging locks.
