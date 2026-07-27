# Packaging Silo for Distribution

This guide is for Silo contributors and downstream package maintainers. It
describes how to build the package formats that exist in this source tree, how
those formats relate to the canonical runtime payload, and where to find their
outputs. For ordinary development builds, start with the [README](README.md).

> [!IMPORTANT]
>
> These instructions apply to the Silo source alongside this file. When
> packaging another revision, use the `PACKAGING.md` from that revision. The
> checked-out source controls the product version, toolchains, package layouts,
> and qualification rules.

## Current Status

The accepted [cross-platform packaging ADR](docs/adr/0012-cross-platform-runtime-and-sdk-packaging.md)
defines the intended distribution system. Not every transport in that design is
implemented yet.

| Platform | Implemented | Planned |
| --- | --- | --- |
| macOS arm64 | Runtime and portable archives, `Silo.app`, optional DMG | Notarization, stapling, Homebrew Cask |
| Linux amd64 | Runtime and portable archives | deb, rpm, Arch, signatures, KVM package qualification |
| Linux arm64 | Runtime and portable archives on a native host | Main-branch package CI, deb, rpm, Arch |
| SDKs | Node native addon build | Runtime-carrying Node packages, Python wheels, Go runtime installer |

The current commands do not produce native Linux packages, notarized macOS
artifacts, Sigstore bundles, or published releases. Planned formats below are
identified explicitly; do not infer a command from an ADR description.

## Prerequisites

Enter the repository's Nix development shell before running packaging commands:

```sh
nix develop
```

The shell provides the Rust, Go, Node, Zig, archive, SBOM, and OCI tools used by
the build. `release/toolchains.toml` is the release-toolchain authority; avoid
substituting ambient tool versions for release builds.

Additional platform requirements are:

| Platform | Requirements |
| --- | --- |
| macOS | Apple silicon, macOS 26 or newer, Xcode command-line and SDK tools |
| Linux | Native amd64 or arm64 Linux, Docker daemon, Docker Buildx, matching Docker daemon architecture |

Packaging normally needs network access to fetch dependencies, release tools,
and the default kernel OCI artifact. See [Kernel Selection](#kernel-selection)
for local and offline kernel options.

`CARGO_TARGET_DIR` controls all build, staging, cache, and package output. It
defaults to the repository's `target` directory.

## Choosing a Version

The `VERSION` file in the checked-out source is the product-version authority.
It must contain exactly three numeric components, such as `1.2.3`. There is no
command-line package-version override.

To package an existing revision, check out that revision and verify its version
metadata before building:

```sh
git checkout <tag-or-commit>
nix develop
make version-check
```

Silo does not publish release tags yet. When tagged releases are introduced,
use the release tag and the packaging guide stored in that tag rather than
applying instructions from `main` to older source.

### Preparing a New Version

Version changes are source changes, not packaging flags:

1. Update `VERSION`.
2. Synchronize the product manifests checked by `xtask/src/version.rs`.
3. Refresh `Cargo.lock` and `sdk/node/package-lock.json` without upgrading unrelated dependencies.
4. Inspect the lockfile diffs.
5. Run `make version-check` until it succeeds.
6. Run `make fmt`, `make clippy`, and `make test` before packaging.

Packaging commands use locked dependency resolution. A version bump with stale
lockfiles will fail rather than silently resolving a different release graph.

## Packaging Flow

Every transport starts from one architecture-specific runtime payload. Native
packages and generic archives are sibling consumers of that payload; they do not
consume or invoke one another.

```text
Source checkout
      |
      v
Release build + kernel resolution
      |
      v
Adjacent release runtime
      |
      v
Canonical runtime stage
target/silo-runtime/<target>/release/
      |
      +----------------------+-----------------------+
      |                      |                       |
      v                      v                       v
Runtime archive       Portable CLI archive      Native package
runtime + notices     runtime + CLI + notices   platform-specific
      |                      |                       |
      |                      |             macOS: Silo.app / DMG
      |                      |             Linux: deb/rpm/Arch (planned)
      v                      v
SDK or embedding      Direct CLI distribution
transport
```

The canonical stage contains exactly the private runtime payload:

```text
target/silo-runtime/<target>/release/
  bin/
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

The stage deliberately excludes the public `silo` frontend. Product and SDK
packagers add their frontend or native binding without rebuilding or replacing
the staged runtime files.

## Archive Types

`make archive` creates both generic archive families for the current host target.

| Archive | Intended use | Includes `bin/silo` |
| --- | --- | --- |
| `silo-runtime-<version>-<target>.tar.zst` | Runtime transport for SDKs, embedders, and installers that provide their own frontend | No |
| `silo-<version>-<target>.tar.zst` | Self-contained portable CLI distribution | Yes |

The runtime archive contains:

```text
silo-runtime-<version>-<target>/
  bin/
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
  THIRD_PARTY_NOTICES
  LICENSES/
    libkrun-APACHE-2.0.txt
```

The portable CLI archive contains the same files plus `bin/silo`:

```text
silo-<version>-<target>/
  bin/
    silo
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
  THIRD_PARTY_NOTICES
  LICENSES/
    libkrun-APACHE-2.0.txt
```

Each archive has an adjacent SHA-256 checksum, SPDX JSON SBOM, and provenance
document:

```text
target/packages/<target>/<version>/
  <archive>.tar.zst
  <archive>.tar.zst.sha256
  <archive>.sbom.spdx.json
  <archive>.provenance.json
```

Build and verify both archives with:

```sh
make version-check
make archive
make verify-archive
```

`make archive` performs a release build, resolves the kernel, creates the
canonical stage, audits the release runtime, and produces both archives.
`make verify-archive` verifies the existing outputs; it does not rebuild them.
On macOS, verification also boots a VM from the portable CLI archive.

## Packaging macOS

macOS packaging is supported only on arm64 macOS 26 or newer.

Build the application bundle:

```sh
make package
```

Build the application bundle and DMG:

```sh
make package DMG=1
```

Outputs are versioned together:

```text
target/packages/darwin-arm64/<version>/
  Silo.app/
  silo-<version>-darwin-arm64.dmg
```

The current macOS commands are:

| Command | Result |
| --- | --- |
| `make app` | Build, audit, assemble, sign, and verify `Silo.app` |
| `make package` | Currently equivalent to `make app` |
| `make package DMG=1` | Build the app, then create and verify a DMG |
| `make install` | Build and install the app plus a CLI symlink |

Without an explicit identity, local builds use ad-hoc signing. Supply a
Developer ID Application identity for distribution signing:

```sh
make package DMG=1 \
  BUILD_NUMBER=123 \
  DEVELOPER_ID_APPLICATION='Developer ID Application: Example'
```

This signs the app but does not notarize or staple it. Those release steps are
specified by ADR 0012 but are not implemented yet.

Install to the system locations, or override them for an unprivileged install:

```sh
make install

make install \
  APPDIR="$HOME/Applications" \
  BINDIR="$HOME/.local/bin"
```

A DMG does not put `silo` on `PATH` by itself. The command exposure mechanism is
a symlink to `Silo.app/Contents/MacOS/silo`.

## Packaging Linux

Linux currently produces generic runtime and portable CLI archives. Native deb,
rpm, and Arch packages are specified by ADR 0012 but are not implemented yet.
When added, `make package` should produce those native packages from the same
canonical stage; it should not invoke `make archive`.

Run the current archive flow on a native amd64 or arm64 Linux host:

```sh
nix develop
make archive
make verify-archive
```

Release-profile commands automatically build and run the pinned native Linux
release container. The process refuses a Docker daemon whose architecture does
not match the host instead of silently using emulation or ambient compilers. See
the [Linux release environment](release/README.md) for container details.

Linux archive verification currently checks archive integrity, layout, modes,
SBOM and provenance structure, and release binary constraints. KVM boot
qualification for the generic archive remains planned release work.

## Kernel Selection

Release packages include the resolved default kernel bytes. A normal first VM
start therefore does not download the default kernel.

The default kernel reference can be replaced with another OCI reference:

```sh
make archive KERNEL_REFERENCE=registry.example/silo/kernel:stable
```

Use an absolute path to package a local architecture-matched kernel:

```sh
make archive KERNEL_PATH=/absolute/path/to/kernel
```

Control registry access and cache refresh explicitly:

```sh
make archive KERNEL_OFFLINE=1
make archive KERNEL_REFRESH=1
```

The same kernel options apply to `make build`, `make stage`, `make app`, and
`make package`. Kernel construction and OCI publication are separate operations;
see the [kernel documentation](resources/kernels/README.md).

## Command Reference

| Command | Builds or stages | Output or action |
| --- | --- | --- |
| `make stage PROFILE=release` | Yes | Canonical runtime stage |
| `make verify-runtime PROFILE=release` | No | Audit an existing release runtime |
| `make archive` | Yes | Both generic archives and their sidecars |
| `make verify-archive` | No | Verify both existing archives |
| `make app` | Yes | Versioned `Silo.app` |
| `make package` | Yes | Versioned `Silo.app` |
| `make package DMG=1` | Yes | Versioned `Silo.app` and DMG |
| `make install` | Yes | Installed app and CLI symlink |

Running `make archive` followed by `make package` repeats release preparation.
Cargo and staging may reuse unchanged outputs, but both commands independently
resolve, stage, and audit their inputs. A future aggregate distribution command
should prepare the release once and feed both archive and native packagers.

## Continuous Integration

Pull requests and pushes to `main` run formatting, version, Clippy, and test
checks on Linux and macOS. After those checks pass on `main`:

- Linux amd64 runs `make archive` and uploads both archive families and sidecars.
- macOS arm64 runs `make package DMG=1` and uploads the DMG.

CI artifacts are retained for 14 days. This is build validation, not release
publication: CI does not currently sign Linux packages, notarize macOS output,
publish release assets, or create native Linux packages.

## Architecture and Release Internals

Use these documents for details that intentionally do not live in this
operational guide:

- [ADR 0012](docs/adr/0012-cross-platform-runtime-and-sdk-packaging.md): normative layouts, runtime discovery, ownership, compatibility, and planned transports.
- [Linux release environment](release/README.md): pinned container and toolchain mechanics.
- [Kernel artifacts](resources/kernels/README.md): kernel configuration, construction, verification, and publication.
- [README](README.md): ordinary development and product usage.
