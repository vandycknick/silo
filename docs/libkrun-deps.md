# Embedded libkrun Dependency

Silo compiles its pinned libkrun fork directly into the `krun` helper. The
launcher library remains process-backed, so `vmmon` and other Rust callers do
not link libkrun. The distributed runtime contains one self-contained `krun`
executable and no `libkrun.so`, `libkrun.dylib`, or `libkrunfw` sidecar.

## Source Pin

The workspace dependency is pinned by full Git commit in the root
`Cargo.toml`:

```text
repository: https://github.com/vandycknick/libkrun.git
tracked revision: d54c7e9088687098ded67245efc7cb63a68d5223
public branch: silo/v2
previous tracked revision: 3ab6249a1ff4cb4945d216ce74f9feecbf4def7d
previous tip backup: backup/silo-v2-2026-09-15 @ 10b6f752ba8ea735c3d9edaa549599dcf3f98d18
pre-split backup: backup/silo-v2-before-feature-split-2026-09-15 @ ea84066ff3c8499a4aac5cdd3ec326aee0667e9b
fetchable: yes
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

The committed revision is reachable through the fork URL: a direct
`git fetch https://github.com/vandycknick/libkrun.git d54c7e9088687098ded67245efc7cb63a68d5223`
succeeds. Cargo therefore resolves the tracked pin directly from GitHub with no
local checkout, path patch, URL rewrite, or alternate lockfile. The public
`silo/v2` branch names the reviewable tip, while release reproducibility comes
from the immutable revision in `Cargo.toml` and `Cargo.lock`. The force update
preserved the former public tip on `backup/silo-v2-2026-09-15`.

The tracked revision changes how the balloon advises guest RAM free on macOS.
Each coalesced report uses `hv_vm_unmap`, one `madvise(MADV_FREE)` call per
native host page, and immediate `hv_vm_map`. Page-wise advice avoids XNU's
bulk host-PTE path, which can leave guest-written backing dirty. There is no
`MAP_FIXED` backing replacement or periodic whole-RAM remap. Later guest
refaults remain in-kernel, and host devices retain passthrough memory access.
One atomic per 2 MiB extent lets a vCPU faulting inside the unmap window retry
once the mapping is restored, including after new reclaim has been disabled.

The scratch probe checks page state without first reading host payload pages;
it no longer qualifies on footprint deltas. A passing probe verifies clean,
unreferenced, uncompressed backing and guest reuse, not a pressure soak.
Real-HVF tests also verified release of already-compressed backing, while the
report-before-pressure test remained inconclusive at its bounded 1 GiB budget.
Nested EL2 guests remain unqualified. The external initramfs is streamed into
guest RAM instead of staged in a large heap buffer.

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

Build the self-contained helper with:

```bash
make krun PROFILE=debug
```

For a release build:

```bash
make krun PROFILE=release
```

The plain `krun` library does not activate the optional libkrun dependency.
Only the `krun-bin` feature used by the helper does so.

On x86-64, `krun-bin` also activates bzip2's `static` feature. Libkrun uses
bzip2 to load `Image.bz2` kernels, and the helper must not depend on a host
`libbz2.so` that is absent from the portable runtime.

On Linux, `ldd` and `readelf -d` must not report `libkrun.so` or `libbz2.so`.
On macOS,
`otool -L` must not report `libkrun.dylib`. The macOS helper still uses
Hypervisor.framework and must be signed with the
`com.apple.security.hypervisor` entitlement before distribution. The xtask
component build invoked by `make krun` signs and verifies it automatically.

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
