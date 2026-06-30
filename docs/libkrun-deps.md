# Building libkrun Dependencies

BentoBox links `krun-sys` dynamically against `libkrun`. The libraries do not need to be installed system-wide. Build or fetch them into a local dependency directory, then point Cargo at it with `KRUN_DEPS_DIR`.

The expected layout is:

```text
target/libs/krun/<target-triple>/
  libkrun.so        # Linux
  libkrun.dylib     # macOS
```

## Prerequisites

Use the Nix dev shell. Required native tools are provided by `flake.nix`; do not install them with `apt` or Homebrew for this project flow.

```bash
nix develop
```

The shell provides the Rust toolchain plus native build tools such as `clang`, `libclang`, `pkg-config`, `make`, and platform-specific tools like `patchelf` on Linux.

On macOS, `install_name_tool` and `codesign` come from Apple’s command line tools. If those are missing, install Xcode command line tools once with Apple’s normal developer tooling.

## Build On Linux

From inside `nix develop`:

```bash
make build-libkrun
```

The script does the following:

1. Clones `libkrun/libkrun` at the pinned `LIBKRUN_VERSION` with submodules.
2. Builds `libkrun` with Cargo features `blk` and `net`, with default features disabled.
3. Copies `libkrun.so` into `target/libs/krun/<target-triple>`.
4. Fixes the soname with `patchelf` so the copied library is relocatable.

BentoBox intentionally builds `libkrun` without the upstream `init-blob` default feature. That avoids building and embedding libkrun's default guest init binary.

BentoBox also does not fetch or package `libkrunfw`. `libkrun` loads `libkrunfw` dynamically only when the caller does not provide an external kernel, firmware, or kernel bundle. BentoBox's `krun` helper requires `--kernel` and calls `krun_set_kernel()`, so this fallback path is not used.

## Build On macOS

From inside `nix develop` on Apple silicon:

```bash
make build-libkrun
```

The script does the following:

1. Clones `libkrun/libkrun` at the pinned `LIBKRUN_VERSION` with submodules.
2. Builds `libkrun.dylib` with Cargo features `blk` and `net`, with default features disabled.
3. Copies `libkrun.dylib` into `target/libs/krun/<target-triple>`.
4. Rewrites the install name to `@rpath/libkrun.dylib`.
5. Ad-hoc codesigns the dylib.

Because BentoBox disables libkrun's `init-blob` default feature and does not package `libkrunfw`, macOS no longer needs Docker, a Linux init-builder container, or the upstream `libkrunfw-prebuilt-aarch64.tgz` bundle for this dependency build.

## Use With Cargo

After building dependencies, export `KRUN_DEPS_DIR`:

```bash
export KRUN_DEPS_DIR="$PWD/target/libs/krun/$(rustc -vV | awk '/host:/ { print $2 }')"
```

Then build the krun helper:

```bash
cargo build -p krun
```

For release builds:

```bash
cargo build -p krun --release
```

`krun-sys` uses `KRUN_DEPS_DIR` in its build script to emit Cargo link instructions:

```text
cargo:rustc-link-search=native=$KRUN_DEPS_DIR
cargo:rustc-link-lib=dylib=krun
```

That means `krun-sys` still links dynamically, but it links against the local dependency folder instead of requiring system-wide `libkrun` installation.

`krun` also sets the `krun` binary rpath so the binary can load libraries copied beside it:

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

The output directory contains the `krun` binary plus `libkrun`, ready to copy together.

## Version Pins

The current script pins are:

```text
LIBKRUN_VERSION=1.19.0
```

Override it only when intentionally updating the native ABI and regenerated bindings:

```bash
LIBKRUN_VERSION=... make build-libkrun
```

If `libkrun.h` changes, regenerate or update `virt/krun-sys/src/bindings.rs` and keep `virt/krun-sys/include/libkrun.h` in sync.
