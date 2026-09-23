# Vmmon process tests

Run the real executable boundary tests without a working hypervisor:

```sh
cargo test --locked -p vmmon --test krun_worker -- --nocapture
cargo test --locked -p vmmon --all-features --bin vmmon virt::backend::krun::
cargo test --locked -p vmmon --all-features --bin vmmon virt::serial::tests::
cargo test --locked -p libvm machine::lifecycle::tests::
```

`make test` discovers these integration tests on the Linux and macOS CI lanes.
`CARGO_BIN_EXE_vmmon` identifies the actual executable, never the Rust unit-test
harness. The tests exercise the production inheritance policy and private parser,
invalid/aliased descriptors, bounded framing, watchdog closure with deliberately
inheritable opposite pipe endpoints, event backpressure, partial-request signal
and parent-loss cancellation, and native startup-failure finalization. The latter
uses an invalid kernel and may fail host admission instead, so it proves cleanup,
not successful virtualization.

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
workflow. Compile the dependency-free guest-only shutdown utility for the guest
architecture (never execute this utility on the host):

```sh
GUEST_TARGET=x86_64-unknown-linux-musl # aarch64-unknown-linux-musl for arm64 guests
RUST_HOST=$(rustc -vV | awk '/host:/{print $2}')
rustc --edition=2024 --target "$GUEST_TARGET" \
  -C linker="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin/rust-lld" \
  -C link-self-contained=yes \
  runtime/vmmon/tests/guest/shutdown.rs -o target/krun-guest-shutdown

SILO_TEST_KERNEL="$PWD/target/debug/assets/kernel-default" \
SILO_TEST_INITRAMFS="$PWD/target/debug/assets/initramfs" \
SILO_TEST_SHUTDOWN="$PWD/target/krun-guest-shutdown" \
  cargo test --locked -p vmmon --test krun_worker \
  native_guest_devices_shutdown_crash_and_new_generation -- --ignored --nocapture
```

The utility requires an exact qualification marker in `/proc/cmdline`, supplied
by the fixture, before it can invoke reboot. Its host-safe parser test does not
execute the utility's main function:

```sh
rustc --edition=2024 --test runtime/vmmon/tests/guest/shutdown.rs -o target/krun-guest-shutdown-tests
target/krun-guest-shutdown-tests
```

The musl Rust target must already be available. On macOS, build the test executable
first with `cargo test --locked -p vmmon --test krun_worker --no-run`, sign
`target/debug/vmmon` with `runtime/vmmon/vmmon.entitlements`, and run without changing
build inputs. Native macOS execution remains a separate required qualification;
Linux success does not establish it.

The test boots the real Silo initramfs into its rescue shell, without a guest-agent
stub. It exercises bidirectional serial RPC, block ordering/read-only flags,
virtio-fs reads and read-only enforcement, vsock/balloon device enumeration, worker
argv/executable identity on Linux, intentional stop, unexpected SIGKILL, guest
reboot, final metadata, reap, and repeated generations in the same machine directory.
Guest reboot follows libkrun's init convention and must end the worker, not restart
it. The utility's optional `poweroff` argument is available for separate diagnosis;
`RB_POWER_OFF` did not end the worker with the x86-64 kernel used in this refactor.
Reproduce that separate, currently blocked gate by using the same environment with
the `native_guest_poweroff` test filter and `-- --ignored --nocapture`. It remains
an explicit ignored acceptance test, not a silently skipped assertion. A bare
rescue guest may also require macOS's forced fallback rather than acknowledging a
graceful power-button request.

Networking, bidirectional guest vsock traffic, filesystem writeback, Rosetta,
reclaim savings, and explicit VZ operation need their separate real-host scenarios.
See the [acceptance matrix](../../../docs/architecture/krun-worker.md#evidence-from-this-refactor)
for results and remaining limitations. A debug stage is not release-archive or
macOS-signature qualification.
