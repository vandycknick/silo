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
tracked revision: d34748e32bf3169a81ab16a7c2ba3dcb93716a31
public branch: silo/v2-reclaim-fast
previous tracked revision: ff25952c0d94090add6f06d73737a37247cac18f @ silo/v2
previous tip backup: backup/silo-v2-2026-09-15 @ 10b6f752ba8ea735c3d9edaa549599dcf3f98d18
pre-split backup: backup/silo-v2-before-feature-split-2026-09-15 @ ea84066ff3c8499a4aac5cdd3ec326aee0667e9b
fetchable: yes
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

The committed revision is reachable through the fork URL: a direct
`git fetch https://github.com/vandycknick/libkrun.git d34748e32bf3169a81ab16a7c2ba3dcb93716a31`
succeeds. Cargo therefore resolves the tracked pin directly from GitHub with no
local checkout, path patch, URL rewrite, or alternate lockfile. The public
`silo/v2-reclaim-fast` branch names the reviewable tip, while release reproducibility comes
from the immutable revision in `Cargo.toml` and `Cargo.lock`. The force update
preserved the former public tip on `backup/silo-v2-2026-09-15`.

The tracked revision changes how the balloon releases guest RAM on macOS.
Each free-page report is released as `hv_vm_unmap`, `madvise(MADV_FREE_REUSABLE)`,
`hv_vm_map` with the range remapped immediately, so the host footprint drops
while later guest refaults are handled in-kernel without a VM exit. Host device
access to guest memory is no longer guarded by a lease ledger; devices use
passthrough guest memory the way KVM-based VMMs do. The only shared state is
one atomic per 2 MiB extent so a vCPU that faults inside the unmap window
retries after the remap. This removed the throughput collapse that
`host-memory-reclaim: auto` previously caused on virtio-net and vsock.

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
cargo build --locked -p krun --features krun-bin --bin krun
```

For a release build:

```bash
cargo build --locked --release -p krun --features krun-bin --bin krun
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
`com.apple.security.hypervisor` entitlement before distribution.

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
