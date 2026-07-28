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
| macOS arm64 | Runtime and portable archives, `Silo.app`, optional DMG, main Release Tip CI | Notarization, stapling, Homebrew Cask |
| Linux amd64 | Runtime and portable archives, main Release Tip CI | KVM archive qualification |
| Linux arm64 | Runtime and portable archives, main Release Tip CI | KVM archive qualification |
| SDKs | Node native addon build | Runtime-carrying Node packages, Python wheels, Go runtime installer |

The current commands do not produce notarized macOS artifacts, release
signatures, or published releases. Official Linux distribution is archive-only;
native Linux distribution packages are not planned requirements.

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

Every transport starts from one architecture-specific runtime payload. The
official Linux transports are the generic runtime and portable CLI archives.
macOS additionally consumes that payload to build `Silo.app` and an optional
DMG; no transport consumes or invokes another.

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
       +----------------------+--------------------------+
       |                      |                          |
       v                      v                          v
Runtime archive       Portable CLI archive       macOS application package
runtime + notices     runtime + CLI + notices    Silo.app / optional DMG
       |                      |                          |
       |                      |                          |
       v                      v                          v
SDK or embedding      Direct CLI distribution    macOS distribution
transport              (official Linux transport)
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

Official Linux distribution consists of generic runtime and portable CLI
archives for amd64 and arm64. It does not provide or require native Linux
distribution packages.

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

## Downstream Repackaging

Downstream maintainers producing a CLI package should repackage the official
portable CLI archive for the exact revision and target they distribute, not
rebuild Silo from source. The runtime-only archive remains the input for SDKs
and embedders that provide their own frontend. This guide is revision-local:
read the `PACKAGING.md` from the archive's source revision before qualifying a
package.

Select the exact target, then verify the archive against its adjacent SHA-256
checksum before extraction. When release signatures are introduced, verify them
as well. Treat each version and architecture as an atomic qualified set: retain
the archive's file modes, third-party notices, helpers, assets, and resolved
kernel together. Do not rebuild, replace, or substitute any component after
qualification. The resulting distribution package is maintained and qualified
by its downstream, not by Silo.

Supported downstream layouts are:

- Preserve the portable archive root and expose `<root>/bin/silo` through a
  downstream-managed symlink.
- Split the portable archive into `/usr/bin/silo` and
  `/usr/lib/silo/{bin,assets}`.

Existing runtime discovery support for libexec or multilib resolver layouts may
be adopted as downstream policy. It is compatibility support, not an official
Linux distribution layout or promise.

Package uninstallers must not delete user-owned XDG state, including runtime
data, configuration, caches, or logs.

## Deferred Archive Installer Contract

No archive installer is implemented today. A future installer must select an
explicit target and version, verify the SHA-256 checksum and any future
signature, and extract safely without accepting path traversal, links, or device
files. It must preserve modes, stage into a temporary location, atomically
install a versioned directory, and default to a user-owned location. A portable
CLI installation may create a PATH symlink to `bin/silo`; a runtime-only
installation has no CLI to expose. The installer must not download content at VM
start or SDK import, and it must never delete user-owned state.

## Kernel Selection

Release artifacts include the resolved default kernel bytes. A normal first VM
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

On macOS, running `make archive` followed by `make package` repeats release
preparation. Cargo and staging may reuse unchanged outputs, but both commands
independently resolve, stage, and audit their inputs. A future macOS aggregate
distribution command should prepare the release once and feed both archive and
application packagers.

## Continuous Integration

`Test` runs formatting, version, Clippy, and test checks on Linux and macOS for
pull requests, pushes to `main`, and manual dispatches. It intentionally has no
path filtering: branch protection needs stable validation reports, and changes
to documentation can be packaging inputs.

`Release Tip` runs after a successful `Test` for a push to `main` (or by manual
dispatch). Automatic runs package the exact SHA validated by `Test`; manual runs
package the selected dispatch SHA. Its Rust cache is isolated to release
packaging and is not used by validation. It also has no path filtering because
there is no baseline and commit metadata can affect artifacts. Three parallel
cells then produce:

- Linux amd64 runs `make archive` and uploads both archive families and sidecars.
- Linux arm64 runs `make archive` and uploads both archive families and sidecars.
- macOS arm64 runs `make archive`, uploads both archive families and sidecars,
  then runs `make package DMG=1` on the same runner and uploads the DMG
  separately.

CI artifacts are retained for 14 days. This is build validation, not release
publication: CI does not currently create release signatures, notarize macOS
output, or publish release assets.

## Architecture and Release Internals

Use these documents for details that intentionally do not live in this
operational guide:

- [ADR 0012](docs/adr/0012-cross-platform-runtime-and-sdk-packaging.md): normative layouts, runtime discovery, ownership, compatibility, and planned transports.
- [Linux release environment](release/README.md): pinned container and toolchain mechanics.
- [Kernel artifacts](resources/kernels/README.md): kernel configuration, construction, verification, and publication.
- [README](README.md): ordinary development and product usage.
