# silo-vmm process tests

Run the real executable boundary tests without a working hypervisor:

```sh
cargo test --locked -p silo-vmm --test krun_worker -- --nocapture
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm krun::worker::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm virt::backend::krun::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm exit_command::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm virt::serial::tests::
cargo test --locked -p libvm machine::lifecycle::tests::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm machine::tests::vm_spec_machine_config_attaches_spec_disks_in_order
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm virt::config::tests::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm krun::engine::tests::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm capabilities::
cargo test --locked -p silo-vmm --features mock-backend --test capabilities
```

The ordinary host suite excludes diagnostic native probe features. Build and
exercise `restore-irq-probe` separately. Diagnostic instrumentation is not a
separate state format and cannot substitute for native decoder validation.

Capability Cargo tests use pure lane/format constants or the VZ/scenario backend,
never native host discovery. Real `--backend krun` queries consume the
dependency's read-only system KVM/HVF observations and live in
`smoke/tests/test_native_capabilities.py`, even though they create no VM.

Phase 11 linked-fact tests expect native pause on all three recognized lanes.
KVM x86_64 also supports native capture, restore, fork and incremental; those
four primitives remain unsupported and pending on KVM arm64 and HVF arm64.
Excluded lanes support none of the five primitives. Public pause, capture,
restore, fork and incremental are delivered and supported wherever the native
primitive exists and host checks pass. Tests distinguish native support, public
delivery and host admission. Capture receipts carry `liveStateSchema` and
`architecture`, not build fingerprints. Each native decoder checks its own magic
and schema. Restore inspection rejects mismatched schema or architecture before
activation, while the complete device inventory remains required:

```sh
cargo test --locked -p vm-spec inspection_requires_complete_exact_devices_without_imposing_envelope_order
```


To query the actual monitor, build its binary (not only the unit-test harness)
in the repository development shell with the configured libkrun dependency
available:

```sh
cargo build --locked -p silo-vmm --bin silo-vmm
target/debug/silo-vmm capabilities --backend krun --json
```

The development shell supplies the native compiler and libclang prerequisites.
Use the corresponding output path if `CARGO_TARGET_DIR` or an explicit target is
set. The krun query performs read-only host discovery, not a VM run. Its
`native: true` fields follow the lane matrix above. Delivered native operations
are supported subject to host checks; attached devices and guest profiles may
narrow the running machine's vector. Runtime suites use the staged monitor
directly.

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
| 8 | one generation lease, required even before config arrives |
| 9..24 | retained Raw handles in manifest order, at most 16 |
| 25..28 | restore-only RAM, layout, execution and devices objects |
| 29..31 | forbidden in normal workers (standalone-native endpoints only) |
| 32 | monitor lifecycle stream, required in every normal worker |
| 33 | restore-only complete canonical RAM map |
| 34+ | restore-only VMDK descriptors and inherited extents, at most 16 + 1536 |

The tests cover:

- The fixed descriptor mapping: wrong access modes, repeated or aliased
  resources, opposite ends of one pipe, a pipe where a TTY is required, a
  missing role, a datagram or unconnected vsock mux, and unexpected inherited
  descriptors (including optional-role holes) all fail closed before events.
- The config read: empty, truncated, trailing, and oversized (above 16 MiB)
  documents are rejected, and decode errors are redacted.
- Typed storage private-boundary checks: required role, format, geometry,
  identity and access; complete lower/upper pairs; exact managed serials;
  duplicate identities; roots preceding Data; malformed, unknown and old
  ordered-only disk shapes. These tests execute parsers and projections only.
- Bounded event framing, watchdog closure while the config is still incomplete
  and while the event channel is full, partial-request signal and parent-loss
  cancellation, and native startup-failure finalization. The latter uses an
  invalid kernel and may fail host admission instead, so it proves cleanup, not
  successful virtualization.
- The exit runner: it exists only when `--exit-command` is given, holds only its
  trigger descriptor, and still runs the command when the supervisor is killed.
- Real Linux child descriptor enumeration, CLOEXEC restoration, a shared-flock
  OFD held through exec and watchdog exit, and an unrelated child remaining
  alive without delaying lease release. Colliding source/target mappings run
  through the production pre-exec installer, not a synthetic FD mapper.
- Restore bootstrap admits the exact state and lower table, restores CLOEXEC
  before reading configuration, and rejects partial state, writable objects,
  orphaned lowers and cross-role aliases before emitting any worker event.
  Pure worker journal tests cover activation authority, serialized admission,
  replay conflicts, exposure gating and private stop-only parking. Descriptor
  tests preserve a generated read-only VMDK rather than flattening it, and keep
  reading the inherited extent inode after its pathname is replaced. These are
  descriptor/journal unit tests, not proof of native guest restore execution.
- Manager launch unit tests execute a retained ELF through `/proc/self/fd/N`
  after child cleanup and check that its CLOEXEC executable FD is absent after
  exec. These tests need no guest or hypervisor.
- The loaded-monitor replacement test creates executable copies in its child,
  then replaces the pathname and re-execs `/proc/self/exe`. This preserves the
  real ELF ownership check without letting other test threads' forks inherit
  writable fixture descriptors and race exec with `ETXTBSY`.

Every launched fixture has a deadline and a separate owned process group for
failure cleanup. Tests never kill system-wide processes. Tests that use a generic
OS child are labeled as signal/output-collection unit tests, not VM tests. The
diagnostic collector test emits more than a pipe capacity without newlines using
real child output. No production fake-VMM mode or successful worker stub exists.

The default suite does **not** qualify successful guest boot, macOS entitlements,
graceful HVF/VZ shutdown, or Rosetta. Native qualification is explicitly ignored
unless requested, rather than silently passing when assets or a hypervisor are absent.

## Capture verification ownership

At `CaptureVerify`, native execution/RAM completion must already have closed
all four output writers. RAM is never read back: the monitor resolves the
worker's chunk digests and affected-chunk bitmap against the exact retained
baseline map, then checks the prepared inode, layout and length. Full capture
requires every chunk to be authoritative; incremental zero receipts replace
dirty baseline chunks, including a short final chunk.

Sparse disk copies hash each 8 MiB logical chunk while copying, skip complete
holes without reading, and publish `disks/<name>.map.json`. Clones retain a
single chunk-authentication scan because no copy bytes traverse the monitor.
RAM and disk inventory entries carry stream `identity`, never byte `sha256`;
small state and complete map entries retain whole-file SHA-256.

Capture writes and closes files, maps and the coherent `vm.capture.json` record
without file or directory durability barriers. There is no `cut` field or
durability mode. Coherence still requires all seven observed cut facts.
Checkpoint pool publication owns durability; fork children retain their
independent background barriers.

The complete `memory.map.json` (wire role `ram-map`) and disk maps use ADR
0014's canonical stream schema. The evidence bound includes a complete 1 TiB
RAM chunk receipt in addition to its control metadata. Maps and bounded
evidence remain charged against the pre-freeze staging reservation and the
64 MiB state allowance. Retained and candidate maps have operation/run
lifetimes, not a TTL; result release never discards the source's baseline.

Real-file module regressions cover stream identities independently recomputed
from sparse disk source bytes, full/incremental RAM receipt assembly, private
inodes, cancellation, layout/length failures, staged allocation accounting,
canonical map inventory and write-once publication:

```sh
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm live::coordinator::capture::tests::
cargo test --locked -p silo-vmm --features mock-backend --bin silo-vmm live::staging::tests::
```

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
SILO_TEST_INIT="$PWD/target/$GUEST_TARGET/debug/init" \
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

The test formats a whole-disk ext4 root carrying the multicall Silo binary
(`SILO_TEST_INIT`) as `/bin/sh`, attaches it as `silo-root`, and appends a
schema-2 whole-disk launch bootstrap to the real base initramfs, as libvm
composes it. The real Silo init resolves that root only through the bootstrap,
then hands off to `init=/bin/sh`; there is no kernel `root=` argument and no
rescue-shell path. Without a guest-agent stub, it runs these scenarios as
consecutive generations in the same machine
directory: two intentional stops, an unexpected SIGKILL of the worker, a guest
reboot, and a guest poweroff. Each generation exercises bidirectional serial RPC,
block ordering/read-only flags, virtio-fs reads and read-only enforcement,
vsock/balloon device enumeration, a single `krun` child whose argv is exactly
`krun` (and whose executable is `silo-vmm` on Linux), the `backend` block
of `vm.exit.json`, and reap. Guest reboot and poweroff follow libkrun's init
convention and must end the worker cleanly, not restart it. A bare shell guest
may also require macOS's forced fallback rather than acknowledging a graceful
power-button request.

Networking, bidirectional guest vsock traffic, filesystem writeback, Rosetta,
reclaim savings, and explicit VZ operation need their separate real-host scenarios.
See [silo-vmm architecture](../../../docs/architecture/silo-vmm.md) for
results and remaining limitations. A debug stage is not release-archive or
macOS-signature qualification.

Flat-overlay/VMDK runtime qualification uses `smoke/tests/`, through the real
libvm, monitor and worker path, not additional native Cargo tests. In particular,
read-only handle evidence must inspect the actual worker's descriptor and every
lower backing handle, not the monitor. Serial fault fixtures are isolated
source-copy builds, never a shipped validation bypass. Private wire-contract
and VZ rejection unit tests do not qualify a native host lane.
