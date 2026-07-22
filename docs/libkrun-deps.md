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
branch:     silo/stable-1.19.x
upstream:   v1.19.4
revision:   1b69e60ed03f58fe13bcd7b6f684aa71a404b0f9
```

Release builds must use the committed `Cargo.lock` with `--locked`. A branch
or tag is useful for reviewing the fork, but neither replaces the immutable
commit pin.

The fork carries two fixes on top of upstream `v1.19.4`:

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
```

`blk` provides the raw virtio-block path used by Silo disks. `net` provides
the Unix datagram, Unix stream, and Linux TAP networking paths. The helper's
private adapter calls those APIs directly, so Cargo compilation verifies that
both features are present.

The upstream `init-blob` default feature remains disabled. Silo supplies an
explicit kernel and optional initramfs, disables libkrun's implicit devices,
and does not use the fallback firmware path. Consequently, Silo neither
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

On Linux, `ldd` and `readelf -d` must not report `libkrun.so`. On macOS,
`otool -L` must not report `libkrun.dylib`. The macOS helper still uses
Hypervisor.framework and must be signed with the
`com.apple.security.hypervisor` entitlement before distribution.

## Updating libkrun

For each upstream update:

1. Create a new fork branch from the exact upstream release tag.
2. Check whether each downstream fix has landed upstream.
3. Apply only the fixes that remain necessary as focused commits.
4. Run the fork's targeted regression tests on x86_64 Linux and arm64 macOS.
5. Build the fork with default features disabled and `blk,net` enabled.
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
