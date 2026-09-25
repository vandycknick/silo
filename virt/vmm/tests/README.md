# silo-vmm process tests

Run the real executable boundary tests without a working hypervisor:

```sh
cargo test --locked -p silo-vmm --test krun_worker -- --nocapture
cargo test --locked -p silo-vmm --all-features --bin silo-vmm krun::worker::
cargo test --locked -p silo-vmm --all-features --bin silo-vmm virt::backend::krun::
cargo test --locked -p silo-vmm --all-features --bin silo-vmm exit_command::
cargo test --locked -p silo-vmm --all-features --bin silo-vmm virt::serial::tests::
cargo test --locked -p libvm machine::lifecycle::tests::
```

`make test` discovers these integration tests on the Linux and macOS CI lanes.
`CARGO_BIN_EXE_silo-vmm` identifies the actual executable, never the Rust
unit-test harness. The worker is that same executable spawned with argv[0]
`krun`, no arguments, and the fixed descriptor table described in
[silo-vmm architecture](../../../docs/architecture/silo-vmm.md):

| fd | role |
| --- | --- |
| 0 | `/dev/null` |
| 1, 2 | diagnostics pipe |
| 3 | config FIFO (one `KrunConfig` JSON document, read to EOF) |
| 4 | event FIFO |
| 5 | watchdog FIFO |
| 6 | console PTY slave |
| 7 | vsock mux stream, only when the config enables it |

The tests cover:

- The fixed descriptor mapping: wrong access modes, repeated or aliased
  resources, opposite ends of one pipe, a pipe where a TTY is required, a
  missing role, a datagram or unconnected vsock mux, and any inherited
  descriptor above fd 7 all fail closed before the worker emits an event.
- The config read: empty, truncated, trailing, and oversized (above 16 MiB)
  documents are rejected, and decode errors are redacted.
- Bounded event framing, watchdog closure while the config is still incomplete
  and while the event channel is full, partial-request signal and parent-loss
  cancellation, and native startup-failure finalization. The latter uses an
  invalid kernel and may fail host admission instead, so it proves cleanup, not
  successful virtualization.
- The exit runner: it exists only when `--exit-command` is given, holds only its
  trigger descriptor, and still runs the command when the supervisor is killed.

Every launched fixture has a deadline and a separate owned process group for
failure cleanup. Tests never kill system-wide processes. Tests that use a generic
OS child are labeled as signal/output-collection unit tests, not VM tests. The
diagnostic collector test emits more than a pipe capacity without newlines using
real child output. No production fake-VMM mode or successful worker stub exists.

The default suite does **not** qualify successful guest boot, macOS entitlements,
graceful HVF/VZ shutdown, or Rosetta. Native qualification is explicitly ignored
unless requested, rather than silently passing when assets or a hypervisor are absent.

## Native guest acceptance

Build matching kernel/initramfs assets with the normal `make build` or `make stage`
workflow. On x86_64 the workload kernel must be built from this tree: guest
poweroff depends on the i8042 poweroff patch in
`resources/kernels/patches/x86_64/` together with the `krun.poweroff=i8042`
kernel argument that the krun backend adds on x86_64. aarch64 guests power off
through PSCI and need neither.

Compile the dependency-free guest-only shutdown utility for the guest
architecture (never execute this utility on the host):

```sh
GUEST_TARGET=x86_64-unknown-linux-musl # aarch64-unknown-linux-musl for arm64 guests
RUST_HOST=$(rustc -vV | awk '/host:/{print $2}')
rustc --edition=2024 --target "$GUEST_TARGET" \
  -C linker="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin/rust-lld" \
  -C link-self-contained=yes \
  virt/vmm/tests/guest/shutdown.rs -o target/krun-guest-shutdown

SILO_TEST_KERNEL="$PWD/target/debug/assets/kernel-default" \
SILO_TEST_INITRAMFS="$PWD/target/debug/assets/initramfs" \
SILO_TEST_SHUTDOWN="$PWD/target/krun-guest-shutdown" \
  cargo test --locked -p silo-vmm --test krun_worker \
  native_guest_devices_shutdown_crash_and_new_generation -- --ignored --nocapture
```

The utility requires an exact qualification marker in `/proc/cmdline`, supplied
by the fixture, before it can invoke reboot or poweroff. Its host-safe parser
test does not execute the utility's main function:

```sh
rustc --edition=2024 --test virt/vmm/tests/guest/shutdown.rs -o target/krun-guest-shutdown-tests
target/krun-guest-shutdown-tests
```

The musl Rust target must already be available. On macOS, build the test executable
first with `cargo test --locked -p silo-vmm --test krun_worker --no-run`, sign
`target/debug/silo-vmm` with `virt/vmm/silo-vmm.entitlements`, and run
without changing build inputs. Native macOS execution remains a separate required
qualification; Linux success does not establish it.

The test boots the real Silo initramfs into its rescue shell, without a guest-agent
stub, and runs these scenarios as consecutive generations in the same machine
directory: two intentional stops, an unexpected SIGKILL of the worker, a guest
reboot, and a guest poweroff. Each generation exercises bidirectional serial RPC,
block ordering/read-only flags, virtio-fs reads and read-only enforcement,
vsock/balloon device enumeration, a single `krun` child whose argv is exactly
`krun` (and whose executable is `silo-vmm` on Linux), the `backend` block
of `vm.exit.json`, and reap. Guest reboot and poweroff follow libkrun's init
convention and must end the worker cleanly, not restart it. A bare rescue guest
may also require macOS's forced fallback rather than acknowledging a graceful
power-button request.

Networking, bidirectional guest vsock traffic, filesystem writeback, Rosetta,
reclaim savings, and explicit VZ operation need their separate real-host scenarios.
See [silo-vmm architecture](../../../docs/architecture/silo-vmm.md) for
results and remaining limitations. A debug stage is not release-archive or
macOS-signature qualification.
