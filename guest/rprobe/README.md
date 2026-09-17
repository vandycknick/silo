# Rosetta acquisition appliance

`rprobe` is one ARM64 Linux kernel containing this crate's static Rust PID1 as
`/init` in a built-in initramfs. The runtime installs only `assets/rprobe`.
There is no external probe initramfs or runtime JSON manifest.

The guest mounts Apple's Rosetta directory share, issues ioctl `0x80456122`,
transmits a versioned frame with the 1024-byte response on `hvc1`, and powers
off. `hvc0` carries diagnostic text only. The bytes are acquired on the current
Mac at launch, never captured on the builder or published inside the image.

## Build on native ARM64 Linux

From the repository root:

```sh
make rprobe PROFILE=release
```

Prerequisites are the repository's pinned Rust toolchain, its
`aarch64-unknown-linux-musl` target, and native Linux kernel tools (C compiler,
binutils, make, flex, bison, Perl, bc, OpenSSL/libelf development files, curl,
and archive utilities). ORAS and jq are needed only for OCI packaging/tests,
not the single-file build. No privileged build or nested virtualization is needed.

xtask builds `silo-rprobe`, validates its static ELF, generates the same archive
twice to check reproducibility, then invokes the shared kernel builder. The
probe-owned miniconfigs live in `kernel/`. Linux embeds the generated archive
using `CONFIG_INITRAMFS_SOURCE`; boot-critical drivers are built in.

Outputs:

- `target/release/assets/rprobe`: the only runtime asset.
- `target/release/rprobe-build/initramfs.cpio.gz`: build intermediate.
- `$HOME/.cache/silo/kernels/`: verified sources and isolated kernel build trees.

`CARGO_TARGET_DIR` changes the first two locations. For a shared macOS/Linux
checkout, use a Linux-local target directory to avoid mixing host outputs:

```sh
silo exec --workdir "$PWD" builder -- sh -c '
  export HOME=/root CARGO_HOME=/root/.cargo RUSTUP_HOME=/root/.rustup
  export RUSTUP_TOOLCHAIN=1.96.1 CARGO_TARGET_DIR=/var/cache/silo-rprobe/cargo
  make rprobe PROFILE=release
'
```

The complete kernel build identity includes the archive content hash, not its
source pathname. A probe change cannot reuse an old embedded image. Unchanged
inputs reuse their build tree. Output publication uses a temporary file and
rename. Final OCI publication through CI is separate future work.

To assemble a macOS runtime, provide a directory containing just the built
`rprobe` file with xtask's existing `--rprobe-assets DIRECTORY` option. Do not
reuse a legacy three-file probe asset directory. The workload's own kernel and
initramfs remain separate and unchanged.

## Kernel size and configuration policy

The appliance profile produces a 3,590,152-byte ARM64 Image (3.42 MiB with
Linux 7.2.2 and GCC 16.1.1), including a 13,566-byte compressed initramfs.
This is 29% smaller than the initial 5,068,808-byte image. Exact sizes depend
on source and toolchain versions; this is a measured baseline, not a limit.

The probe-owned fragments deliberately disable unused initramfs decompressors,
block support, swap/compaction, suspend, CPU hotplug, core dumps, notification
APIs, legacy PTYs and FUSE passthrough. `BASE_SMALL` and `SLUB_TINY` favor a
small appliance over general-purpose throughput. ARM64 requires SMP and a
minimum `NR_CPUS=2`, even though the probe runs with one virtual CPU. Some
infrastructure, including the power-supply core and sysctl support, remains
selected by Kconfig; disabling a parent feature does not remove every core.
The build validates the resolved configuration against every explicit setting.

Kernel printk and guest serial diagnostics remain available, with a 16 KiB
printk ring. In-image symbol/config tables, SLUB debugging and verbose BUG
locations are omitted. Keep the build-side `.config`, `System.map` and
`vmlinux` when investigating crashes: symbolic in-guest backtraces and long
retained kernel-log history are no longer available. KASLR, stack protection,
strict kernel RWX, CPU mitigations and architecture errata remain enabled.
Both PCI and MMIO virtio transports remain; an experimental PCI/IOMMU-disabled
image failed acquisition on the qualification host.

The production image has passed acquisition, translated x86-64 execution and
startup-cancellation cleanup on the qualification Mac. Other supported hosts
still need qualification. Workload kernel configuration is unchanged.

Further size experiments should use separate build trees and the hardware
harness before changing these fragments. Clang ThinLTO requires the full LLVM
build tools, not just clang/lld. ARM64 does not enable the kernel's standalone
`LD_DEAD_CODE_DATA_ELIMINATION` option in this source version; adding generic
linker garbage-collection flags is not a supported substitute. `tinyconfig`
is only a starting point and does not preserve our device or hardening needs.
A bare-metal replacement would need its own ARM64 boot/platform handling,
virtio queues, virtiofs/FUSE protocol and console/shutdown implementation.

## Runtime ownership

libvm forwards only enabled/disabled Rosetta intent and the generic runtime
asset directory. vmmon resolves the implementation for its selected backend:
VZ uses Apple's native share; krun first acquires compatibility data through the
VZ probe and then supplies the typed response to krun. Probe assets and capture
profiles do not appear in the libvm launch contract.

There is no macOS build or translator hash allowlist. Actual Rosetta availability,
frame validity, timeouts, cleanup, and translator/file consistency are checked.
Host build and translator hashes are diagnostic context, not admission criteria.
Runtime components must be upgraded together; old backend-specific start
requests are deliberately rejected by the strict reader.

## Hardware harness (Apple Silicon macOS)

```sh
cargo build --locked -p vmmon --bin silo-rprobe-vz-harness
codesign -f --entitlements runtime/vmmon/vmmon.entitlements \
  -s - target/debug/silo-rprobe-vz-harness

target/debug/silo-rprobe-vz-harness --kernel /absolute/path/to/rprobe
```

Embedded-kernel runs execute the same acquisition implementation as vmmon.
The harness retains `--initramfs` for explicit external-archive experiments and
`--cancel-while-starting` for the specialized VZ lifecycle test.

For actual translated execution, also supply `--krun`, `--guest-kernel`,
`--guest-initramfs`, and `--translated-workload`. Those guest assets belong to
the krun qualification VM, not the probe. Build the current exerciser with
xtask's `rosetta-exerciser-initramfs` command and this crate's x86-64 fixture.
The exerciser checks the translated program's stdout and exit status, not just
successful acquisition. `--cancel-helper-after-spawn` tests helper cleanup.

## Diagnostics

vmmon reads `RUST_LOG` at launch and writes into its existing trace log:

```sh
RUST_LOG=info,vmmon::rosetta=debug
RUST_LOG=info,vmmon::rosetta=debug,rosetta_wire=trace
```

For the standalone harness, use its module target and redirect stderr:

```sh
RUST_LOG=info,silo_rprobe_vz_harness::rosetta=debug,rosetta_wire=trace \
  target/debug/silo-rprobe-vz-harness --kernel /absolute/path/to/rprobe \
  2>rosetta-trace.log
```

Debug records identities, state transitions, bounded guest diagnostics, decoded
headers, payload hashes and elapsed time. It also enables kernel loglevel 7.
The dedicated `rosetta_wire` trace target records bounded raw bytes before
validation, with offsets, including malformed/trailing data. Treat those logs
as potentially sensitive. Ordinary debug logs never include the capture payload.
Use scoped targets to avoid enabling unrelated backend logging.

Both streams are drained regardless of logging level. Diagnostic retention is
bounded to 64 KiB, with a 4 KiB excerpt in errors. Cleanup failures retain the
original acquisition error and available guest diagnostics. Changing the filter
takes effect on the next vmmon launch, not in an already running process.
