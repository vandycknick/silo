# Packaging Silo for Distribution

## Taild Linux packages

`make archive` builds the native release runtime stage, creates its runtime-only
archive and checksum, builds/hashes the native SDK bridge, generates a target-local
qualified SDK in `target/taild-qualified-source/release`, builds `taild` against that
isolated source with `CGO_ENABLED=1`, then creates the portable archive. It does not
wait for other native targets. Netd's release `CGO_ENABLED=0` recipe must not be used
for taild. Linux release CGO uses `/usr/bin/cc` and `/usr/bin/c++`; cross compilation
is not a native qualification substitute. macOS archives omit taild/service material.

Both runtime roots include `runtime-manifest.json`: `{version, target, files}`.
Version equals the exact SDK product version. Targets are `linux-amd64-gnu`,
`linux-arm64-gnu`, or `darwin-arm64`, matching SDK runtime identifiers. Files are
the complete current bin/assets inventory mapped to lowercase SHA-256 digests;
manifest metadata is never a made-up constant. Stage validation rejects unexpected
entries/symlinks and verifies manifest bytes against current components and VERSION.
The archive checksum is embedded in qualified SDK source for explicit offline
installation. The bridge loader checks the embedded digest, ABI and product version.
`make version-check` also checks the SDK bundle cache-version constant.

Linux portable archives include `bin/taild`, `share/silo-taild` (service, sysusers,
config, examples and acceptance tools), and generated `LICENSES/taild` notices from
the exact Go module graph. The generator fails on missing license material; review
`modules.json` and the SBOM. Godbus is BSD-2-Clause (not MIT), and retains its actual
module license. Runtime notices are generated from the existing template with
the actual locked libkrun revision and vendored signal-registry attribution;
the Apache license remains included. These are archive outputs, not distro
package/signature claims.

For bounded component builds, build each release component separately (CLI, silod,
silo-vmm, netd, agent, init) and stop to inspect a cold-build timeout rather than
blindly retrying. After coordinated `make stage PROFILE=release`, run:

```sh
make runtime-archive PROFILE=release
make go-ffi PROFILE=release
make qualify-go-bridge PROFILE=release
make taild PROFILE=release
make portable-archive
python3 packaging/silo-taild/verify-artifact.py \
  target/packages/0.1.0/linux-amd64-gnu/silo-0.1.0-linux-amd64-gnu.tar.zst \
  target/packages/0.1.0/linux-amd64-gnu/silo-runtime-0.1.0-linux-amd64-gnu.tar.zst
```

Use the source VERSION and native target in the final command. The script extracts
the actual binary into isolated HOME, removes development/native-loader overrides,
installs the actual runtime archive offline, checks versions/config, and rejects
version/hash/traversal and archive-checksum mismatches. It is wired into native
Linux Test and Release Tip lanes. KVM memory and real systemd/tailnet acceptance
remain additional gates in the [operator guide](docs/taild/operator.md).
The current Linux amd64 release runtime passed real packaged guest execution at
256 MiB (2026-10-01, agent 10,444,032 bytes). The current unstripped debug archive
passed at 1 GiB (agent 173,188,384 bytes) and retains that minimum. The historical
debug256 OOM remains a failure. These are native guest execution/memory results,
not a qualification of arbitrary guest workloads, other architectures or tailnets.
Debug qualification archives/bridges use `target/packages-debug`, separate from
release outputs, with the build profile recorded in provenance.

Linux release commands use verified `/usr/bin` C tools, clear Nix wrapper flags,
and give CGO `-B/usr/bin` to select native assembler/linker subprograms. An absolute
CC alone is insufficient because GCC otherwise searches PATH for `as`/`ld`.
Artifact acceptance checks dynamic loaders/search paths and runs without inherited
loader overrides. The host must supply `libgcc_s.so.1` and its normal glibc libraries.
Provenance records the actual module-selected Go toolchains and native compiler.

Release archiving and bridge qualification fail closed on the native ELF audit:
standard interpreter, no RPATH/RUNPATH or absolute DT_NEEDED entries, complete
dependency resolution using the designated system loader with its cache disabled
and only native system library directories, and imported GLIBC versions no newer
than ADR0012's 2.39 floor. GNU host linker subprograms are pinned for Rust as well
as CGO. Do not repair a too-new ABI by merely removing an interpreter/search path
or copying an arbitrary system library closure.

The extracted-archive acceptance script audits both archive payloads and requires
exactly one materialized embedded bridge for closure inspection. It actually
executes `silo-vmm --help`, netd's help entry point, and taild version/install/check.
When rootless user/mount namespaces are available, `no_nix.py` hides `/nix` in the
child while preserving the user UID. Use `--require-no-nix` to make that isolation
mandatory, or `--audit-only` to inspect immutable older archive snapshots without
installing/booting VMs. An unavailable namespace is explicitly unqualified;
static dependency auditing and designated-loader execution still run. Helper
entry-point execution alone is not proof of a guest boot on a clean distro.

The shipped `packaging/silo-taild/kvm.go` is a real SDK consumer for that additional
gate. Build it from the isolated qualified SDK module, then run the built consumer
with `-archive` (the actual runtime archive), `-disk` (a disposable bootable Linux
disk with `/bin/sh`), `-home` (a new absolute evidence directory), and
`-memory-mib 1024` or `256`. It installs offline using the embedded digest, boots the
packaged guest agent, executes a proof command, stops the VM and retains evidence.
It refuses known oversized (>64 MiB agent) artifacts at 256 MiB; passing that size
screen is not itself a memory qualification. Build and VM execution are separate
bounded commands, with normal Go preemption enabled and no FFI override:

```sh
go -C target/taild-qualified-source/release/sdk/go build \
  -o "$PWD/target/packaged-kvm" "$PWD/packaging/silo-taild/kvm.go"
env -u SILO_GO_FFI_PATH -u GODEBUG target/packaged-kvm \
  -archive /absolute/path/silo-runtime-VERSION-TARGET.tar.zst \
  -disk /absolute/path/disposable-linux.ext4 \
  -home /absolute/path/new-acceptance-home -memory-mib 256
```

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
| Linux amd64 | Runtime and portable archives, main Release Tip CI | Archive signing |
| Linux arm64 | Runtime and portable archives, main Release Tip CI | Archive signing |
| SDKs | Node native addon build; Go SDK, native bridge, and explicit runtime installer | Runtime-carrying Node packages, Python wheels, published Go release metadata |

The current commands do not produce notarized macOS artifacts, release
signatures, or published releases. Official Linux distribution is archive-only;
native Linux distribution packages are not planned requirements.

`silo-vmm` contains both the VM monitor and the libkrun worker: one
executable that runs as the supervisor by default and as the `krun` worker
when started with that argv[0]. libkrun is linked into it as a library, so there
is no separate krun binary. Package `silo-vmm` (`bin/silo-vmm`, or
`Contents/Helpers/silo-vmm` in `Silo.app`) and `netd` alongside the guest
assets. macOS signing must use the Hypervisor/Virtualization entitlement union
in `virt/vmm/silo-vmm.entitlements`. See
[silo-vmm architecture](docs/architecture/silo-vmm.md) before treating a
build or inventory check as native release qualification.

## Prerequisites

Enter the repository's release shell before running packaging commands:

```sh
nix develop .#release
```

The shell provides the Rust, Go, Node, Zig, archive, SBOM, and OCI tools used by
the build. `flake.lock` pins the Nix package graph and `rust-toolchain.toml` pins
the Rust release. Packaging does not download a second compiler toolchain or
fall back to ambient release tools when Nix evaluation fails.

Additional platform requirements are:

| Platform | Requirements |
| --- | --- |
| macOS | Apple silicon, macOS 26 or newer, Xcode 26.6 selected with `xcode-select` |
| Linux amd64 | Native Ubuntu 24.04 amd64 |
| Linux arm64 | Native Ubuntu 24.04 arm64 |

On Ubuntu Linux hosts, install the native host packages before entering the
release shell:

```sh
sudo apt-get install build-essential binutils pkg-config
```

Nix supplies the release build tools. These Ubuntu packages provide the native
compiler, linker, archive, and `pkg-config` tools used through `/usr/bin`.

The release shell supplies a portable variant of the Go compiler pinned by
`flake.lock`. It omits Nixpkgs' timezone, MIME, service, and protocol database
patches, so release binaries use upstream runtime paths rather than Nix-store
databases. The compiler itself still lives in `/nix/store`; that is not a runtime
dependency of the generated binaries. Development and CI shells retain ordinary
Nixpkgs Go. No separately installed Go compiler or `actions/setup-go` is needed.

The portable compiler's install check builds a CGO-free, path-trimmed regression
test covering those database lookups, rejects embedded Nix-store paths in that
test executable, and runs it. This checks toolchain portability when the compiler
is built, without adding recursive binary scanning to release packaging.

Packaging normally needs network access to fetch dependencies and the default
kernel OCI artifact. See [Kernel Selection](#kernel-selection) for local and
offline kernel options.

`CARGO_TARGET_DIR` controls build, staging, and package output. It defaults to
the repository's `target` directory. Cargo keeps its registry and Git checkout
caches below `$HOME/.cargo`; Go uses the standard locations reported by
`go env GOCACHE GOMODCACHE`. Release packaging does not create a repository-local
toolchain or dependency cache hierarchy.

Host packages are native-only. The release entry point always selects the
current host OS and CPU and has no target override. The one cross-build exception
is the guest Linux payload: `agent` and `init` are built as static musl programs
for the same CPU as the native host package.

## Choosing a Version

The `VERSION` file in the checked-out source is the product-version authority.
It must contain exactly three numeric components, such as `1.2.3`. There is no
command-line package-version override.

To package an existing revision, check out that revision and verify its version
metadata before building:

```sh
git checkout <tag-or-commit>
nix develop .#release
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
    silo-vmm
    netd
  assets/
    kernel-default
    initramfs
    agent
```

The stage deliberately excludes the public `silo` frontend and the `silod` appliance daemon. Product and SDK
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
    silo-vmm
    netd
  assets/
    kernel-default
    initramfs
    agent
  THIRD_PARTY_NOTICES
  LICENSES/
    APACHE-2.0.txt
```

The portable CLI archive contains the same files plus `bin/silo` and `bin/silod`.
The CLI starts its sibling `silod`; distribute and upgrade them together.
`Silo.app` places the daemon at `Contents/Helpers/silod` and signs it without
virtualization entitlements (the VMM owns virtualization):

```text
silo-<version>-<target>/
  bin/
    silo
    silod
    silo-vmm
    netd
  assets/
    kernel-default
    initramfs
    agent
  THIRD_PARTY_NOTICES
  LICENSES/
    APACHE-2.0.txt
```

Each archive has an adjacent SHA-256 checksum, SPDX JSON SBOM, and provenance
document:

```text
target/packages/<version>/<target>/
  <archive>.tar.zst
  <archive>.tar.zst.sha256
  <archive>.sbom.spdx.json
  <archive>.provenance.json
```

Build both archives with:

```sh
make version-check
make archive
```

`make archive` performs a release build, resolves the kernel, creates the
canonical stage, and produces both archives, checksums, SBOMs, and provenance
documents. Successful construction in the qualified native release environment
is the release correctness signal.

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
target/packages/<version>/darwin-arm64/
  Silo.app/
  silo-<version>-darwin-arm64.dmg
```

The current macOS commands are:

| Command | Result |
| --- | --- |
| `make app` | Build, assemble, sign, and verify `Silo.app` |
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
nix develop .#release
make archive
```

Release commands execute directly on the current host and refuse target
selection through arguments or environment overrides. Linux amd64 packages are
built on native Ubuntu 24.04 amd64, and Linux arm64 packages are built on native
Ubuntu 24.04 arm64. Docker and Buildx are not packaging prerequisites or
fallbacks.

The guest assets remain Linux static-musl binaries for the matching host CPU;
this does not make the host package a cross-host build.

## Release Environment Qualification

The native release environments are qualified when a platform boundary is
introduced or intentionally changed. Qualification uses ordinary platform tools
to inspect one complete native build: `file` and `objdump` on Linux, and `file`,
`otool`, `codesign`, and `hdiutil` on macOS. The review confirms native host
architectures and loaders, static Linux guest assets and `netd`, Apple-only
Darwin dependencies, app signing, DMG mounting, and basic CLI startup.

Repeat that review after changing the Ubuntu baseline, supported CPU, macOS
deployment target, Xcode major version, native linker strategy, `netd` CGO mode,
or guest target. Routine source and dependency changes do not need a custom
binary policy engine. Release builds do not recursively scan arbitrary binary
contents or reimplement ELF, Mach-O, glibc, or platform-loader behavior.

`scripts/qualify-release-artifacts.sh` is the manual boundary-qualification
helper. Run it without arguments to inspect artifacts already collected below
`target/packages`, or pass `--download --run-id <id>` to replace the current
version's package tree with artifacts from one Release Tip run. It is not part
of routine CI or archive construction.

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

Package uninstallers must not delete user-owned state: the Silo home
(`~/.silo`, including installed runtimes, caches, and logs) and the
configuration directory (`~/.config/silo`).

## Go Runtime Installer Contract

The Go SDK implements the explicit runtime-only archive installer specified by ADR 0012. It
selects the current supported target and exact SDK version, verifies the release-compiled SHA-256
digest, rejects path traversal, links, devices, and unexpected files, preserves and validates
modes and notices, stages into a temporary sibling, and atomically installs a complete runtime
below the user-owned Silo home (`~/.silo/runtimes`). It supports exact offline archives and mirrors without
allowing callers to replace the expected digest. Installation never occurs at SDK import,
runtime open, machine creation, or VM start, and it never deletes user-owned state.

Release preparation builds the private Go FFI bridge on each native target. After the qualified
target artifacts are collected under `target/packages`, `make assemble-go-sdk` verifies their
checksum sidecars and combines the bridge binaries and runtime archive digests into generated Go
SDK release source before the nested module tag is created. Ordinary development uses
`SILO_GO_FFI_PATH` instead of committing placeholder native binaries.

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

Apple Silicon macOS builds also resolve and include the Rosetta probe from
`ghcr.io/vandycknick/silo/rprobe:stable`. It uses the same verification and cache
mechanism as the kernel, with separate `rprobe-cache` and `rprobe-provenance`
directories. Override it with `RPROBE_REFERENCE` or `RPROBE_PATH`; control cache
use with `RPROBE_OFFLINE=1` and `RPROBE_REFRESH=1`. For a fully offline build,
set both `KERNEL_OFFLINE=1` and `RPROBE_OFFLINE=1`. Existing adjacent probe files
are not an implicit override. Linux runtime builds do not download the probe.

## Command Reference

| Command | Builds or stages | Output or action |
| --- | --- | --- |
| `make stage PROFILE=release` | Yes | Canonical runtime stage |
| `make archive` | Yes | Both generic archives and their sidecars |
| `make app` | Yes | Versioned `Silo.app` |
| `make package` | Yes | Versioned `Silo.app` |
| `make package DMG=1` | Yes | Versioned `Silo.app` and DMG |
| `make install` | Yes | Installed app and CLI symlink |

On macOS, running `make archive` followed by `make package` repeats release
preparation. Cargo and staging may reuse unchanged outputs, but both commands
independently resolve and stage their inputs. A future macOS aggregate
distribution command should prepare the release once and feed both archive and
application packagers.

## Continuous Integration

`Test` validates pull requests, pushes to `main`, and manual dispatches as a
left-to-right pipeline: change detection fans out to parallel per-OS core check
jobs (Clippy, Cargo tests, and on the primary Linux cell also formatting and
version consistency) and to Node and Go SDK matrices that run only when their
SDK source or shared native contracts changed (manual dispatches run both).
Native SDK bridges build and test on every supported target, while
platform-independent SDK checks run on one primary cell. Everything flows into
a final summary job that gives branch protection one stable result even when an
SDK matrix is skipped.

CI enters the `.#ci` shell rather than `.#default`. That shell carries the
toolchain needed to compile, lint, and test the workspace but omits the
cross-compilation and packaging tools (`zig`, `cargo-zigbuild`, `oras`, `syft`)
and the local conveniences (`docker`, `grpcurl`) that no check invokes, which
is roughly 1.2 GiB of closure every runner would otherwise download.

Rust build outputs are cached per job, because the jobs build different crate
sets and profiles. `rust-cache` already namespaces entries by job, operating
system, architecture, compiler version, and `Cargo.lock`, so the workflow adds
only a prefix that separates validation from release packaging. The Nix store
is deliberately not cached: measured against the lean `ci` shell, restoring a
gigabyte-scale store from the Actions cache costs about as long as fetching it
from the binary cache, and it consumed a third of the repository quota.

Only pushes to `main` write caches. Pull requests restore them and never save,
which keeps the repository at one set of entries instead of one set per open
pull request. GitHub also scopes any pull request cache to the pull request
itself, so it can never feed `main` or release runs.

`Release Tip` runs after a successful `Test` for a push to `main` (or by manual
dispatch). Automatic runs package the exact SHA validated by `Test`; manual runs
package the selected dispatch SHA. Release preparation has four stages:

1. Resolve the exact source revision and version.
2. Build core archives on Linux amd64, Linux arm64, and macOS arm64; the macOS
   cell also builds the application package and DMG.
3. Build the Go FFI bridge and Node native addon on every supported target.
4. Assemble and test the embedded Go release source and a publish-ready npm
   package containing all three Node addons.

The Rust caches are isolated by core/SDK stage and platform. Release work has no
path filtering because commit metadata affects artifacts and every SDK package
must use the same qualified core revision.

GitHub zips Actions artifacts and does not preserve executable modes, so the
DMG is the permission-preserving transport for the runnable macOS app. The
workflow still builds and verifies the loose `Silo.app` on-runner before it
creates and verifies the DMG. Downloading the core and native-SDK artifact for
each target into `target/packages` reconstructs one `target/packages/<version>`
root with sibling `darwin-arm64`, `linux-amd64-gnu`, and `linux-arm64-gnu`
directories. Targets and versions can coexist without path or filename
collisions. The SDK packaging jobs additionally upload generated Go module
source and an npm `.tgz` that is ready for a later publication step.

CI artifacts are retained for 14 days. This is build validation and packaging,
not release publication: CI does not currently create release signatures,
notarize macOS output, run `npm publish`, or publish release assets.

## Architecture and Release Internals

Use these documents for details that intentionally do not live in this
operational guide:

- [ADR 0012](docs/adr/0012-cross-platform-runtime-and-sdk-packaging.md): normative layouts, runtime discovery, ownership, compatibility, and planned transports.
- [Kernel artifacts](resources/kernels/README.md): kernel configuration, construction, verification, and publication.
- [README](README.md): ordinary development and product usage.
