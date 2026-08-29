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
branch:     silo/v2 (local until manually published)
upstream:   0d75eb4b9d7f742e9b290b7372e4be491e68b173 (v2 main)
revision:   10b6f752ba8ea735c3d9edaa549599dcf3f98d18
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

Until the branch is published, Cargo commands that activate `krun-bin` must
resolve the normal repository URL through the local checkout without modifying
repository or user configuration:

```bash
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=url.file:///home/nickvd/Projects/libkrun.insteadOf
export GIT_CONFIG_VALUE_0=https://github.com/vandycknick/libkrun.git
```

These variables are temporary implementation plumbing. Once the exact revision
is available from the fork, unset them and verify the build through the normal
GitHub source before publishing Silo.

The fork carries two fixes on top of the recorded upstream v2 commit:

1. Released Unix vsock proxies close their host endpoint immediately while
   retaining deferred proxy cleanup. This fixes the five-second EOF delay in
   [libkrun issue #684](https://github.com/libkrun/libkrun/issues/684).
2. x86_64 initrds remain within one contiguous RAM bank, populate the Linux
   boot protocol's extended address fields above 4 GiB, and report placement
   or guest-memory write failures instead of panicking.

The fork is the only source of these patches. Silo does not retain duplicate
patch files or generate C bindings from a vendored header.

## Cargo Features

Silo disables libkrun's default features and enables only:

```text
blk
net
vhost-user
```

`blk` provides the raw virtio-block path used by Silo disks. `net` provides
the Unix datagram, Unix stream, and Linux TAP networking paths. `vhost-user`
provides the explicit device API needed by ADR 0015's later Linux backend; S2
enables the API but retains libkrun's built-in per-port vsock bridge. The
helper's private adapter calls the block and network APIs directly.

The `krun-bin` feature also unifies nix 0.30's `uio` feature into libkrun's
device graph. The pinned v2 `krun-devices` manifest enables `socket` for its
vhost-user frontend but omits the `uio` feature required by `sendmsg` and
`ControlMessage`. This private feature carrier can be removed when that
dependency edge is fixed in the pinned fork or upstream.

The committed lockfile also retains `kvm-bindings 0.14.0` and `imago 0.2.3`
for libkrun's graph, matching the fork's tested lockfile. `kvm-bindings 0.14.1`
selects an incompatible `vmm-sys-util` type for libkrun's CPUID code, while
`imago 0.2.4` selects `vm-memory 0.18` instead of the `0.17` types used by
libkrun devices. Review these pins on every libkrun update rather than allowing
an incidental transitive update.

Libkrun v2 has no implicit console or vsock devices and no longer injects a
default init binary. Its retained `krun_disable_implicit_init()` symbol returns
`-ENOTSUP`, so Silo does not call it. Silo supplies an explicit kernel and
optional initramfs, adds its console and transitional vsock device explicitly,
and does not use the fallback firmware path. Consequently, Silo neither builds
nor packages `libkrunfw`.

## Build

Build the self-contained helper with:

```bash
cargo build --locked -p krun --features krun-bin --bin krun
```

While the pinned revision remains unpublished, set the process-scoped rewrite
variables from [Source Pin](#source-pin) in the shell running this command.

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

1. Create a new fork branch from the exact upstream release tag.
2. Check whether each downstream fix has landed upstream.
3. Apply only the fixes that remain necessary as focused commits.
4. Run the fork's targeted regression tests on x86_64 Linux and arm64 macOS.
5. Build the fork with default features disabled and `blk,net,vhost-user` enabled.
6. Update the full Git revision in the root `Cargo.toml`.
7. Regenerate and commit `Cargo.lock`.
8. Review the helper's private constants against upstream `include/libkrun.h`.
9. Run Silo's krun unit, integration, lint, and VM boot tests.
10. Inspect the final binary for unexpected dynamic dependencies and compare
    its compressed size with the prior release.

The helper currently mirrors only the libkrun constants it uses: raw disk,
relaxed disk synchronization, raw and ELF kernel formats, the compatibility
virtio-net feature mask, and the DHCP flag. Do not copy unrelated C API
surface into Silo when updating the dependency.

libkrun is Apache-2.0 licensed. Keep the fork's license and required
third-party attribution in Silo release materials.
