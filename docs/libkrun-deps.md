# Embedded libkrun Dependency

Silo compiles its pinned libkrun fork into `vmmon` through the `krun` engine
crate. Vmmon executes it only in a separate private worker process, launched
from the same executable with argv[0] `krun` and the first argument `__krun`.
There is no standalone krun executable, `libkrun.so`, `libkrun.dylib`, or
`libkrunfw` sidecar.

## Source Pin

The workspace dependency is pinned by full Git commit in the root
`Cargo.toml`:

```text
repository: https://github.com/vandycknick/libkrun.git
tracked revision: 11dbc7863a6ca6176939d48147e67f03d34eeda0
public branch: silo/v2
previous tracked revision: 6c26f56863317971cd61a1b7bc51c05470077c65
previous tip backup: backup/silo-v2-before-four-commit-cleanup-20260917 @ 6c26f56863317971cd61a1b7bc51c05470077c65
earlier cleanup backup: backup/silo-v2-before-cleanup-20260916-202550 @ b892b1974e34a48b857c4562bc41f2e541b30ea5
older tip backup: backup/silo-v2-2026-09-15 @ 10b6f752ba8ea735c3d9edaa549599dcf3f98d18
pre-split backup: backup/silo-v2-before-feature-split-2026-09-15 @ ea84066ff3c8499a4aac5cdd3ec326aee0667e9b
fetchable: yes
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

The tracked revision is published on `silo/v2` and fetchable directly from
GitHub, with no path override or URL rewrite. The local libkrun worktree at
`/Users/nickvd/Projects/worktrees/libkrun/v2-cleanup` remains on `silo/v2`.

The downstream series contains four commits above `24d714b5dce8e8dd91afb9e0f64ebf6f3e1e846e`:

1. `ac4b8578e4a323723490077fd188492d43f9a7bf`: balloon host reclaim, including
   page-wise advice, fault recovery, automatic reporting qualification, and an
   independent `HostMemoryRemapper`. Periodic passes run every 30 seconds;
   report preparation is throttled to 250 ms. Incompatible providers retain
   basic balloon functionality. Tests cover real HVF qualification, remapping
   without a balloon, nested EL2 reporting suppression, and live-data preservation.
2. `346f2822f7aad1807e7752b5d8f1d7bf45184d0e`: owned native vsock control-channel
   mux, including quiet expected Unix-vsock teardown. Shutdown accepts `ENOTCONN`
   while preserving other errors, and routine proxy removals log at debug level.
   Real-socket tests cover half-close, repeated shutdown, disconnected sockets,
   and unexpected errors. Unexpected datagram packet errors remain visible.
3. `d0d0e277f26ac663769c5d6d848cb5fe7dc4e51b`: immutable captured Rosetta compatibility data.
4. `11dbc7863a6ca6176939d48147e67f03d34eeda0`: direct external initramfs streaming.

This history cleanup folds the follow-up balloon and vsock fixes into their
respective feature commits. The final tree is byte-identical to the previous
six-commit tip. The original commits remain published on
`backup/silo-v2-before-four-commit-cleanup-20260917`.

The fork reclaims reported guest RAM on macOS as follows.
Each coalesced report uses `hv_vm_unmap`, one `madvise(MADV_FREE)` call per
native host page, and immediate `hv_vm_map`. Page-wise advice avoids XNU's
bulk host-PTE path, which can leave guest-written backing dirty. There is no
`MAP_FIXED` backing replacement. Later guest refaults remain in-kernel, and host
devices retain passthrough memory access.
One atomic per 2 MiB extent lets a vCPU faulting inside the unmap window retry
once the mapping is restored, including after new reclaim has been disabled.

The scratch probe checks page state without first reading host payload pages;
it no longer qualifies on footprint deltas. A passing probe verifies clean,
unreferenced, uncompressed backing and guest reuse, not a pressure soak.
Real-HVF tests also verified release of already-compressed backing, while the
report-before-pressure test remained inconclusive at its bounded 1 GiB budget.
Nested EL2 guests remain unqualified. The external initramfs is streamed into
guest RAM instead of staged in a large heap buffer.

The native VMM event loop now also performs content-preserving, same-address
Mach self-remapping every 30 seconds for compatible private RAM, independently
of balloon attachment and reporting qualification. Report-driven preparation
can bring that deadline forward, with a 250-ms throttle. This removes
host translations whose footprint charge survives page-wise advice, including
translations populated by virtio block I/O. It keeps the existing backing and
guest mappings, never replays old free-page reports, and runs only while the
VMM owns the RAM. No maintenance thread is attached to the status handle.
A remapping failure stops the event loop. This maintenance changes mapping
accounting; it does not prove physical discard or immediate compressor relief.

A matched 512 MiB Linux VM experiment reading and freeing 128 MiB through
virtio-block stayed near 210 MiB footprint without maintenance and fell to
62 MiB with it. VM-object accounting stayed near 179 MiB in both cases.

The fork also merges adjacent descriptors of one free-page report into a
single release cycle and exposes `VmmHandle::host_reclaim_status()`. The krun
helper samples that every five seconds and writes a `host-memory-reclaim`
record on a dedicated status pipe (`SILO_KRUN_STATUS_FD`) whenever it changes.
vmmon reads the pipe, stores the latest record, and returns it in `GetMetrics`
as `HostMetrics.host_memory_reclaim`, which is how `silo daemon status` learns
whether the probe passed, whether reclaim is effective, and how many bytes were
successfully advised free. The cumulative counter includes repeat reports and
is not a measurement of physical memory returned.

The previous fork tip carried an x86_64 initrd placement patch and immediate
Unix-vsock endpoint release. Upstream now contains its own initrd placement fix
and 3330/4096 MiB regression tests, but Silo's x86_64 runtime verification is
deferred, so no x86 boot claim is made here. The old endpoint-release behavior
belonged to the unused port-path API and is not part of the native control-
channel transport. Silo does not retain duplicate patch files or generated C
bindings.

## Cargo Features

Silo disables libkrun's default features and enables only:

```text
blk
net
```

`blk` provides the raw virtio-block path used by Silo disks. `net` provides
the Unix datagram, Unix stream, and Linux TAP networking paths. The helper's
private adapter calls the safe native Rust block, network, and vsock device
constructors directly. Libkrun's `ffi` and `vhost-user` features are disabled.
The former Silo-side nix `uio` feature carrier for libkrun's vhost-user graph
has been removed. The updated fork enables `uio` in its own devices manifest;
Silo's own control-channel implementation enables the nix
socket and `uio` APIs directly where it uses `sendmsg` and `SCM_RIGHTS`.

The resynced graph uses `kvm-bindings 0.14.1`, `imago 0.2.4`, and
`vm-memory 0.18`. This removes the old `vm-memory 0.17` duplicate from the
lockfile and aligns libkrun's devices with imago's memory types. Review these
transitive versions on every libkrun update.

Libkrun's native builder has no implicit console, vsock, balloon, or RNG device
and no longer injects a default init binary. Silo supplies an explicit kernel
and optional initramfs, adds its console when requested, always adds RNG and
balloon devices, and attaches one native vsock device when vmmon supplies the
inherited control descriptor. TSI and per-port mappings remain disabled.
Consequently, Silo neither builds nor packages `libkrunfw`.

## Build

Build the combined supervisor/worker executable with:

```bash
make vmmon PROFILE=debug
```

For a release build:

```bash
make vmmon PROFILE=release
```

The plain `krun` library does not activate the optional libkrun dependency.
The `engine` feature links libkrun into vmmon, which executes it only in a separate private worker process.

On x86-64, `engine` also activates bzip2's `static` feature. Libkrun uses
bzip2 to load `Image.bz2` kernels, and the helper must not depend on a host
`libbz2.so` that is absent from the portable runtime.

On Linux, `ldd` and `readelf -d` must not report `libkrun.so` or `libbz2.so`.
On macOS,
`otool -L` must not report `libkrun.dylib`. The macOS helper still uses
Hypervisor.framework and must be signed with the
`com.apple.security.hypervisor` entitlement before distribution, alongside
`com.apple.security.virtualization` for VZ. The xtask component build invoked
by `make vmmon` signs and verifies this union automatically.

The macOS krun Rosetta path is experimental. Its current
`CapturedCompatibilityV1` profile accepts only host build `25G83` and the
pinned unmodified translator digest, then captures the host response through a
bounded VZ acquisition probe. This baseline is not TSO-qualified and makes no
compatibility promise for later Apple releases. New Linux and macOS
configurations default to krun; VZ remains an explicit macOS override. Legacy
resolved records that predate persisted backend selection retain their
historical VZ selection on macOS.

## Updating libkrun

For each upstream update:

1. Back up the existing `silo/v2` tip, then move the same branch to the exact upstream revision.
2. Check whether each downstream fix has landed upstream.
3. Apply only the fixes that remain necessary as focused commits.
4. Run the fork's targeted regression tests on x86_64 Linux and arm64 macOS.
5. Build the fork with default features disabled and `blk,net` enabled.
6. Update the full Git revision in the root `Cargo.toml`.
7. Regenerate and commit `Cargo.lock`.
8. Review the helper adapter against the native Rust API signatures.
9. Run Silo's krun unit, integration, lint, and VM boot tests.
10. Inspect the final binary for unexpected dynamic dependencies and compare
    its compressed size with the prior release.

The helper uses typed native API variants for disk format, disk synchronization,
kernel format, and network flags. It retains only the virtio-net feature mask,
which is a guest protocol compatibility policy rather than a C API mirror.

libkrun is Apache-2.0 licensed. Keep the fork's license and required
third-party attribution in Silo release materials.
