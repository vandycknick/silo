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
local branch:      silo/v2 @ 24d714b5dce8e8dd91afb9e0f64ebf6f3e1e846e
remote silo/v2:    10b6f752ba8ea735c3d9edaa549599dcf3f98d18
upstream:   24d714b5dce8e8dd91afb9e0f64ebf6f3e1e846e (main)
revision:   24d714b5dce8e8dd91afb9e0f64ebf6f3e1e846e
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

The pinned upstream revision is reachable through the fork URL: a direct
`git fetch https://github.com/vandycknick/libkrun.git 24d714b5dce8e8dd91afb9e0f64ebf6f3e1e846e`
succeeds. Cargo therefore resolves it directly from GitHub with no local
checkout, URL rewrite, path patch, or development-only lockfile. The local
`silo/v2` branch was moved to this revision after preserving
`10b6f752ba8ea735c3d9edaa549599dcf3f98d18` as
`backup/silo-v2-2026-09-13`; the remote branch has not been rewritten or pushed.

The previous fork tip carried an x86_64 initrd placement patch and immediate
Unix-vsock endpoint release. Upstream now contains its own initrd placement fix
and 3330/4096 MiB regression tests, but Silo's x86_64 runtime verification is
deferred, so no x86 boot claim is made here. The immediate-release behavior is
not present at this upstream revision; it remains a pending fork fix before the
interim Linux vhost-user phase can be accepted. Silo does not retain duplicate
patch files or generated C bindings.

## Cargo Features

Silo disables libkrun's default features and enables only:

```text
blk
net
vhost-user (Linux only)
```

`blk` provides the raw virtio-block path used by Silo disks. `net` provides
the Unix datagram, Unix stream, and Linux TAP networking paths. `vhost-user`
provides the explicit device API used to attach vmmon's embedded
vhost-user-vsock backend. The helper's private adapter calls the safe native
Rust block, network, and vhost-user device constructors directly. Libkrun's
`ffi` feature is disabled.

The `krun-bin` feature also unifies nix 0.30's `uio` feature into libkrun's
device graph. The pinned v2 `krun-devices` manifest enables `socket` for its
vhost-user frontend but omits the `uio` feature required by `sendmsg` and
`ControlMessage`. This private feature carrier can be removed when that
dependency edge is fixed in the pinned fork or upstream.

The resynced graph uses `kvm-bindings 0.14.1`, `imago 0.2.4`, and
`vm-memory 0.18`. This removes the old `vm-memory 0.17` duplicate from the
lockfile and aligns libkrun's devices with imago's memory types. Review these
transitive versions on every libkrun update.

Libkrun's native builder has no implicit console, vsock, balloon, or RNG device
and no longer injects a default init binary. Silo supplies an explicit kernel
and optional initramfs, adds its console when requested, always adds an RNG, and
on Linux attaches one explicit vhost-user-vsock device. It does not configure
the native vsock/TSI path or use fallback firmware. Consequently, Silo neither
builds nor packages `libkrunfw`.

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

## Updating libkrun

For each upstream update:

1. Back up the existing `silo/v2` tip, then move the same branch to the exact upstream revision.
2. Check whether each downstream fix has landed upstream.
3. Apply only the fixes that remain necessary as focused commits.
4. Run the fork's targeted regression tests on x86_64 Linux and arm64 macOS.
5. Build the fork with default features disabled and `blk,net,vhost-user` enabled.
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
