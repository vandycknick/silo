# Building libkrun Dependencies

BentoBox links `bento-krun-sys` dynamically against `libkrun`. The libraries do not need to be installed system-wide. Build or fetch them into a local dependency directory, then point Cargo at it with `KRUN_DEPS_DIR`.

The expected layout is:

```text
target/libs/krun/<target-triple>/
  libkrun.so        # Linux
  libkrunfw.so      # Linux
  libkrun.dylib     # macOS
  libkrunfw.dylib   # macOS
```

## Prerequisites

Use the Nix dev shell. Required native tools are provided by `flake.nix`; do not install them with `apt` or Homebrew for this project flow.

```bash
nix develop
```

The shell provides the Rust toolchain plus native build tools such as `clang`, `libclang`, `pkg-config`, `make`, Docker, and platform-specific tools like `patchelf` on Linux.

On macOS, `install_name_tool` and `codesign` come from Apple’s command line tools. If those are missing, install Xcode command line tools once with Apple’s normal developer tooling.

## Build On Linux

From inside `nix develop`:

```bash
make build-libkrun
```

The script does the following:

1. Downloads upstream `libkrunfw-${ARCH}.tgz` for the pinned `LIBKRUNFW_VERSION`.
2. Extracts it into `target/build/libkrun/<target-triple>/prefix`.
3. Clones `containers/libkrun` at the pinned `LIBKRUN_VERSION` with submodules.
4. Builds `libkrun` with `NET=1 BLK=1`.
5. Installs into the local prefix.
6. Copies `libkrun.so` and `libkrunfw.so` into `target/libs/krun/<target-triple>`.
7. Fixes sonames with `patchelf` so the copied libraries are relocatable.

Linux does not build `libkrunfw` from source in this flow. It uses the upstream prebuilt `libkrunfw` release archive, matching the bux dependency pipeline.

## Build On macOS

From inside `nix develop` on Apple silicon:

```bash
make build-libkrun
```

The script does the following:

1. Downloads upstream `libkrunfw-prebuilt-aarch64.tgz` for the pinned `LIBKRUNFW_VERSION`.
2. Builds `libkrunfw.dylib` from that prebuilt kernel-payload source bundle.
3. Clones `containers/libkrun` at the pinned `LIBKRUN_VERSION` with submodules.
4. Builds `libkrun`’s Linux guest `init/init` ELF inside a Docker Linux container from `init/init.c` and `init/dhcp.c`.
5. Builds `libkrun.dylib` on macOS with Cargo features `blk` and `net`, passing the Docker-built init through upstream's `KRUN_INIT_BINARY_PATH` hook.
6. Copies `libkrun.dylib` and `libkrunfw.dylib` into `target/libs/krun/<target-triple>`.
7. Rewrites install names to use `@rpath`.
8. Rewrites `libkrun.dylib`’s dependency on `libkrunfw.dylib` to `@rpath/libkrunfw.dylib`.
9. Ad-hoc codesigns both dylibs.

macOS does not build the embedded Linux kernel payload from scratch. Upstream `libkrunfw` documents that kernel generation should happen in Linux, normally through `krunvm`. The `libkrunfw-prebuilt-aarch64.tgz` archive contains the Linux-generated payload source needed to produce the final macOS dylib locally. Tiny distinction, giant footgun.

`libkrun` also embeds a small Linux guest `init/init` binary with `include_bytes!`. Building that ELF with macOS clang/lld is fragile because the generated Debian sysroot and GNU target naming need to line up exactly. BentoBox instead builds only that Linux ELF inside Docker (`linux/arm64`) and then runs the normal macOS `libkrun.dylib` build locally, pointing Cargo at the Docker-built ELF with `KRUN_INIT_BINARY_PATH`. The host dependency is still just Docker from `flake.nix`; package installation happens inside the ephemeral container.

The default Docker image is `fedora:latest`, matching upstream’s `krunvm` helper approach. Override it if needed:

```bash
KRUN_INIT_BUILDER_IMAGE=fedora:latest make build-libkrun
```

## Use With Cargo

After building dependencies, export `KRUN_DEPS_DIR`:

```bash
export KRUN_DEPS_DIR="$PWD/target/libs/krun/$(rustc -vV | awk '/host:/ { print $2 }')"
```

Then build the krun helper:

```bash
cargo build -p bento-krun
```

For release builds:

```bash
cargo build -p bento-krun --release
```

`bento-krun-sys` uses `KRUN_DEPS_DIR` in its build script to emit Cargo link instructions:

```text
cargo:rustc-link-search=native=$KRUN_DEPS_DIR
cargo:rustc-link-lib=dylib=krun
```

That means `bento-krun-sys` still links dynamically, but it links against the local dependency folder instead of requiring system-wide `libkrun` installation.

`bento-krun` also sets the `krun` binary rpath so the binary can load libraries copied beside it:

- Linux: `$ORIGIN`
- macOS: `@loader_path`

## Package A Relocatable krun Runtime

After building `krun` and the dependency libraries:

```bash
package-krun-runtime debug target/krun-runtime-debug
```

or:

```bash
package-krun-runtime release target/krun-runtime-release
```

The output directory contains the `krun` binary plus `libkrun` and `libkrunfw`, ready to copy together.

## Version Pins

The current script pins are:

```text
LIBKRUN_VERSION=1.18.1
LIBKRUNFW_VERSION=5.2.1
```

Override them only when intentionally updating the native ABI and regenerated bindings:

```bash
LIBKRUN_VERSION=... LIBKRUNFW_VERSION=... make build-libkrun
```

If `libkrun.h` changes, regenerate or update `virt/bento-krun-sys/src/bindings.rs` and keep `virt/bento-krun-sys/include/libkrun.h` in sync.
