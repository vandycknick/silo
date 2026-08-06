# 12. Cross-Platform Runtime And SDK Packaging

Date: 2026-07-22

Updated: 2026-07-30

## Status

Accepted

## The Problem

Silo is not one executable. A working installation combines a frontend, private
host executables, and architecture-specific guest boot assets:

```text
CLI, Rust consumer, or language SDK
        |
        v
      libvm
        |
        +-- vmmon
        |     +-- Virtualization.framework on macOS
        |     `-- krun helper on Linux
        |
        +-- netd
        |
        `-- kernel-default + initramfs + agent
```

These components must be built, installed, discovered, upgraded, and tested as
one compatible release. Shipping only the `silo` frontend leaves consumers to
assemble a runtime from `PATH`, environment variables, and manually placed
assets. That is not a product installation and cannot provide reliable SDK
distribution.

The distribution problem spans macOS application bundles, code signing,
entitlements, notarization, Node platform packages and native addons, future
Python wheels and Go modules, direct Rust `libvm` consumers, portable GNU/Linux
archives, and custom embedders. The official GNU/Linux product must be usable on
both supported architectures without making Silo responsible for the native
package policy, build matrix, or release qualification of every Linux
distribution.

The normal path should require no user configuration. Explicit configuration is
still necessary for tests, development, custom embedding, and unusual
installations. Silo therefore needs conventions that remain overrideable rather
than configuration that every consumer must reproduce.

This ADR defines immutable product layout, runtime discovery, SDK runtime
transport, user-owned product and state paths, release staging, and native build
environment qualification. It does not add runtime backend selection,
independent component updates, an in-process package manager to `libvm`, or a
Linux archive installer.

## Terminology

| Term | Meaning |
| --- | --- |
| Frontend | The CLI, Rust consumer, Node addon, or future language binding that opens `libvm`. |
| Runtime payload | The co-versioned private helpers and default boot assets required to run VMs. |
| Runtime root | A portable directory containing the fixed `bin/` and `assets/` layout. |
| Product installation | An official Silo.app, DMG, or exact-version portable archive installation. |
| Bundled runtime | A runtime payload carried inside an SDK ecosystem package or wheel. |
| Shared runtime | A runtime installation discovered outside a bundled SDK, including an optional downstream native repackaging. |
| Default assets | `kernel-default`, `initramfs`, and `agent`. |
| Mutable state | Databases, images, machine state, sockets, logs, caches, and downloaded optional assets. |
| Transport | The ecosystem-specific way in which the canonical runtime payload is delivered. |
| Downstream repackaging | An optional third party repackaging an official Linux archive without changing the runtime payload contract. |

## Decision

Silo produces one validated, architecture-specific runtime payload for each
supported target. Official product archives and SDK packages for that target
consume the same staged files rather than rebuilding a transport-specific
variation.

The official Linux distribution is binary archive-only. Silo publishes complete
portable archives for GNU/Linux amd64 and arm64, and does not build, publish, or
qualify native packages for any Linux distribution or third-party repository.
Downstream maintainers may repackage an official archive under their own
policies. Repackaging the official binary archive is the only downstream
packaging model documented by Silo; source-build packaging guidance is out of
scope.

`libvm` resolves fixed native and portable layouts to absolute component paths
and retains them for the lifetime of a `Runtime`. It does not install or download
a runtime. Release CI resolves the default kernel from OCI before packaging, so
a normal first VM start requires no runtime download.

### Core Invariants

- Package-owned product files are immutable. User-owned portable product files
  and mutable state follow XDG conventions on Linux and macOS.
- Convention-based resolution selects one complete runtime component set rather
  than mixing files from unrelated installations. Explicit per-component API
  paths, per-component environment overrides, and machine asset overrides may
  replace individual files.
- Runtime-component installation paths are not persisted in `db_config`; the
  ephemeral run root is not part of durable database identity.
- There is no installed path manifest, `silo-runtime.json`, or
  `--component-info` subprocess protocol.
- Official runtime components are co-versioned and updated atomically. They are
  not upgraded independently.
- An official Linux archive set is exact-version and atomic: its runtime-only
  and portable CLI archives, checksums, SBOMs, and provenance describe the same
  staged release bytes.
- Release host targets always match the current native host OS and architecture.
  Guest Linux assets are the only cross-built components and use static musl for
  the same CPU as the host package.

## Supported Targets And Compatibility

The initial official host matrix is:

| Host | Architecture | Initial distribution promise | Active backend | Packaged backends |
| --- | --- | --- | --- | --- |
| macOS | arm64 | macOS 26 or newer, app/archive/DMG | VZ | VZ and krun |
| GNU/Linux | amd64, arm64 | glibc 2.39 or newer, runtime and portable CLI archives | krun | krun |

The initial release does not support Intel macOS, macOS before version 26,
Windows, other Linux architectures, or cross-architecture guest CPU emulation.
The GNU/Linux glibc 2.39 floor applies to both official architectures. Raising
that floor changes the support matrix and requires an ADR update. The official
promise concerns the GNU/Linux ABI baseline and portable archive, not a specific
Linux distribution release or package manager.

VZ remains the only selected macOS backend. Silo packages and signs the krun
helper on macOS so a later backend selector does not require a new distribution
layout. Packaging a backend does not make it selectable.

The default kernel, initramfs, and agent always match the target architecture.
Optional Rosetta support in VZ does not change the guest kernel architecture.

Official runtime components are co-versioned and updated atomically. The
initial compatibility policy is deliberately strict:

- An official product installation contains one matching CLI and runtime.
- Linux archive users select one exact-version archive for their target.
- Node and Python platform packages use the exact SDK package version.
- Go acquires the exact runtime archive matching the SDK version only through a
  future explicit installer.
- Direct Rust consumers use a co-installed runtime or pass an explicit root.
- Optional downstream native repackagings preserve an exact archive version and
  do not establish an independent Silo compatibility promise.
- Custom mixed-version component paths are unsupported and remain the caller's
  responsibility.
- Runtime components are not upgraded independently.

This avoids compatibility ranges before Silo has an independent component
compatibility promise. A later protocol-negotiation mechanism may be added if
independent updates become necessary; it does not require changing path
discovery.

## Canonical Runtime Payload, Staging, And Provenance

The portable runtime root has this fixed layout:

```text
<runtime-root>/
  bin/
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

All six files are included for every initial target. `krun` contains the pinned
Silo libkrun fork directly. The payload does not contain `libkrun.so`,
`libkrun.dylib`, or `libkrunfw`. Only the krun helper links libkrun code; the
process boundary remains `vmmon -> krun`. Neither `vmmon`, `libvm`, nor a
language binding links libkrun merely by using the launcher library.

The runtime payload does not inherently include the `silo` CLI. Product archives
add the CLI and SDK packages add their native binding. A complete portable CLI
archive has this layout:

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
```

### Development And Release Staging

Make is the public repository build interface. Rust xtask owns build and
packaging orchestration behind Make.

`make` creates a complete adjacent development runtime in the selected Cargo
profile directory:

```text
<cargo-target-dir>/debug/
  silo
  vmmon
  netd
  krun
  assets/
    kernel-default
    initramfs
    agent
```

The release-profile developer layout has the same shape below
`<cargo-target-dir>/release/`. The resolver canonicalizes `current_exe()` and
checks only its direct directory for this layout. It does not infer a workspace
root, inspect `CARGO_TARGET_DIR`, identify a Cargo profile, walk ancestors, or
map a Cargo executable to a stage directory. A raw `cargo build -p cli` may
produce an incomplete directory; running that executable fails with a diagnostic
that identifies the missing adjacent components and recommends `make`.

Canonical staging remains separate from adjacent development runtime discovery.
`make stage` creates the portable six-file payload in predictable target
directories:

```text
target/silo-runtime/darwin-arm64/debug/
target/silo-runtime/darwin-arm64/release/
target/silo-runtime/linux-amd64-gnu/release/
target/silo-runtime/linux-arm64-gnu/release/
```

Developers select a staged root through `RuntimeConfig` or `SILO_RUNTIME_DIR`.
`libvm` does not infer a stage from an arbitrary Cargo executable. The staged
payload is the common input to the app, official Linux archives, SDK platform
packages, and runtime archives. Packagers do not rebuild or substitute
components after staging, except for required platform signing and package
metadata.

### Default Kernel Provenance

Release CI obtains the default kernel from Silo's stable OCI artifact during
staging:

1. Resolve the stable OCI index.
1. Select the target architecture manifest.
1. Verify the expected Silo kernel media types.
1. Verify the platform manifest and layer digests.
1. Extract the kernel as `assets/kernel-default`.
1. Record the index, platform manifest, and layer digests in release provenance.
1. Package those exact bytes into every transport for the target.

End users never receive a release whose default kernel depends on when they
first run it. The installed runtime needs no registry access to boot its default
kernel. The initramfs and agent are built from the corresponding Silo source
release. Staging verifies that all three default assets match the target
architecture.

Additional user-installed kernels are deferred. When added, they live below the
XDG data root and never modify `Silo.app`, an official archive, or optional
downstream package-owned paths.

### Native Release Environment And Staging

A repository-owned staging command builds one canonical payload for the current
native host target:

1. Enter the Nix `.#release` shell pinned by `flake.lock` and
   `rust-toolchain.toml`.
1. Build `silo`, `vmmon`, `netd`, and `krun` for the current host OS and CPU.
1. Use committed lockfiles and locked dependency resolution.
1. Build the guest initramfs and standalone agent as static-musl Linux programs
   for the same CPU.
1. Resolve and verify the target kernel OCI artifact.
1. Normalize file names, modes, and reproducible timestamps where possible.
1. Copy components into the portable runtime layout.
1. Record source, toolchain, and kernel provenance in release metadata.
1. Generate checksums, SBOMs, and provenance records.
1. Report raw and compressed sizes.
1. Hand the exact staged files to each official archive or SDK transport.

Nix supplies release build tools. Native Ubuntu and Apple platform tools supply
the host ABI, loader, SDK, linker, and signing behavior. The release entry point
has no host-target argument or environment override and does not use Docker,
Buildx, emulation, or another process supervisor to select a host package.

Final archives and platform packages are written below:

```text
target/packages/<version>/<target>/
```

Target-qualified CI artifacts retain the version and target hierarchy. Merging
all artifacts therefore reconstructs sibling target directories below one
version without collisions, while another version can coexist beside it.

The native environments are manually qualified when introduced and after an
intentional change to the Ubuntu baseline, supported CPU, macOS deployment
target, Xcode major version, linker strategy, `netd` CGO mode, or guest target.
Qualification uses ordinary platform commands on one completed native build.
Routine releases do not scan arbitrary binary contents, maintain exact runtime
library allowlists, parse glibc symbol versions, or reimplement ELF, Mach-O, and
platform-loader behavior. Successful construction and CLI startup in the
qualified environment are sufficient.

The repository may contain build-time staging configuration. That configuration
is not installed and `libvm` never consults it. The release system composes
native tools around the common staged payload:

```text
Nix release shell + repository-owned staging command
        |
        +-- Apple native tools -> Silo.app, DMG, notarization
        +-- tar/zstd -> official portable archives
        +-- npm tooling -> Node platform packages
        +-- Python tooling -> platform wheels
        `-- Go SDK release metadata -> future explicit archive installer
```

GoReleaser Pro is not part of the design. The common contract is the staged
payload, not one third-party packager.

## Installation Ownership, Mutable XDG State, And Unsupported Old Layouts

Product files are immutable. Silo never writes mutable state into `Silo.app`,
an official archive installation, or an optional downstream package-owned `/usr`
path. Linux and macOS use the same XDG conventions for user-owned product files
and mutable state; Silo does not use `~/Library/Application Support`,
`~/Library/Caches`, or `~/Library/Logs` on macOS.

| Purpose | Environment or configuration | Fallback on Linux and macOS |
| --- | --- | --- |
| Data | `$XDG_DATA_HOME/silo` | `$HOME/.local/share/silo` |
| State and logs | `$XDG_STATE_HOME/silo` | `$HOME/.local/state/silo` |
| Images | Runtime-configured or data root | `$HOME/.local/share/silo/images` |
| Runtime files | `$XDG_RUNTIME_DIR/silo` | `/tmp/silo-<effective-uid>` |

The default data tree is:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/silo/
  state.db
  machines/
  images/
  keys/
  runtimes/
  kernels/
```

Durable operational output has this fixed state layout:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/silo/
  logs/
    machines/
      <machine-id>/
        vm.trace.log
        serial.log
        exec.log
        exec.log.{1,2,3}
        vm.exit.json
        network/
          netd.log
          audit.jsonl
```

Ephemeral per-machine process files use the run root:

```text
<run-root>/
  machines/
    <machine-id>/
      vm.pid
      vm.sock
  networks/
  locks/
```

Canonical machine configuration, disks, and launch-derived artifacts remain
below the data root. Logs and exit records are durable operational state, not
canonical machine configuration. PID files, sockets, network runtime files, and
locks are ephemeral and never belong below the data root in a newly created
layout.

The immutable machine ID owns every durable machine log. A private network's
changing runtime instance ID owns only its run-root socket, PID, policy, and
optional capture files, never a durable log directory. `vmmon` and `netd` write
the durable files; neither provides persisted-log RPCs. `libvm`, including its
Node binding, reads one semantic source at a time (`monitor`, `serial`,
`exec`, `network`, or `network-audit`) without exposing paths or filenames.
Snapshot reads are finite. Follow reads emit the snapshot, hand off without a
byte gap, and remain attached while the machine is stopped and across later
starts until the reader drops the stream. `exec.log` is bounded, lossy JSON
Lines output from structured executions, not process history or an
authoritative result. These interfaces do not create an additional root, a
compatibility reader, or a public path configuration surface.

Existing SQL migration history and old mutable filesystem layouts are
unsupported after this breaking release. Silo does not migrate, adopt, or read
old databases or old layouts. With all Silo processes stopped, users must
manually archive or remove the old state and mutable files before opening the
new layout.

XDG environment paths and `$HOME` must be absolute when used. Silo rejects a
relative value rather than interpreting it relative to the process working
directory.

### Ephemeral Runtime Directory

The run-root resolution order is:

1. Explicit `RuntimeConfig` run root.
1. `$XDG_RUNTIME_DIR/silo`.
1. `/tmp/silo-<effective-uid>`.

The fallback ignores process temporary-directory settings, including `TMPDIR`.
Silo obtains the effective UID and creates or validates
`/tmp/silo-<effective-uid>` as a real, non-symlink directory owned by that
effective user with exact mode `0700`. It rejects symlinks, foreign ownership,
non-directories, and unsafe permissions. It never uses a cross-user `/tmp/silo`
directory.

The run root is ephemeral session placement, not durable database identity.
`Runtime::open` resolves the default run root from the current environment on
every open. An explicit `RuntimeConfig` run root applies to that runtime instance
without requiring the same value on later opens.

`db_config` persists data, state, and image roots as durable database identity;
it does not persist the run root. `Runtime::open` resolves the current run root
for every open. Later explicit data, image, or state roots must match the stored
database identity; the ephemeral run root is intentionally exempt from that
rule.

## Runtime Discovery

Runtime discovery produces one immutable in-memory component set, conceptually:

```rust
struct ResolvedRuntimeComponents {
    vmmon: PathBuf,
    netd: PathBuf,
    krun: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
    agent: PathBuf,
}
```

This is a non-normative internal shape, not a public compatibility promise. The
invariant is that normal resolution selects one coherent installation rather
than mixing helpers and assets from unrelated locations.

### Authoritative Precedence

Resolution follows this order:

1. Explicit per-component API paths.
1. An explicit API `runtime_root` using the portable layout.
1. Existing per-component environment variables.
1. `SILO_RUNTIME_DIR` using the portable layout.
1. A runtime bundled with the caller.
1. A complete development runtime adjacent to the canonical current executable.
1. A portable runtime relative to the canonical current executable, including
   `Silo.app`.
1. One complete helper set from `PATH` when `SILO_ASSET_DIR` is explicit.
1. Conventional native installation locations, for optional downstream
   compatibility only.
1. A missing-runtime error.

Existing environment controls remain available while lookup is centralized:

```text
SILO_VMMON_PATH
NETD_BIN
KRUN_BIN
SILO_ASSET_DIR
```

`SILO_RUNTIME_DIR` selects the complete portable root. Explicit per-component
paths can replace individual files for testing and embedding. All explicit
paths are absolute. A malformed authoritative input, including a relative or
incomplete `SILO_RUNTIME_DIR`, fails immediately instead of falling through to
lower-precedence discovery. Portable-root resolution verifies that derived paths
remain below the selected root and are regular files. `vmmon`, `netd`, `krun`,
and `agent` must be executable. `kernel-default` and `initramfs` must be
readable but need not be executable.

Native-location resolution checks only a small documented set of conventional
paths. It does not query package-manager databases, scan mounted volumes, or
infer a distribution. This is a compatibility path for downstream archive
repackaging, not an official package layout or a promise to test native package
formats.

Explicit machine asset overrides remain independent. An explicit machine kernel,
initramfs, or agent wins for that asset without replacing the other defaults.
Every omitted asset comes from the one asset directory selected by the resolved
installation. `SILO_ASSET_DIR` likewise selects one complete default asset set.

#### Adjacent Development Runtime

For a canonical executable at `<cargo-target-dir>/debug/silo`, the complete
adjacent development layout is:

```text
<cargo-target-dir>/debug/
  silo
  vmmon
  netd
  krun
  assets/
    kernel-default
    initramfs
    agent
```

The release-profile developer layout has the same shape below
`<cargo-target-dir>/release/`. Discovery checks only the canonical executable's
direct directory. It does not walk from `target/debug/deps` to `target/debug`;
tests and consumers in that location use explicit component paths,
`runtime_root`, or `SILO_RUNTIME_DIR`.

#### Portable Executable-Relative Runtime

For a canonical executable at `<portable-root>/bin/silo`, portable discovery
derives and validates this fixed layout:

```text
<portable-root>/
  bin/
    silo
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

#### Silo.app Executable-Relative Runtime

`Silo.app` is a separate executable-relative layout: a canonical executable at
`Silo.app/Contents/MacOS/silo` uses helpers from `Contents/Helpers` and assets
from `Contents/Resources/assets`. App-bundle resolution additionally validates
bundle identifier `sh.silo.app`, exact release compatibility, architecture, and
minimum system version.

#### Controlled PATH Resolution

`PATH` is disabled unless `SILO_ASSET_DIR` is explicitly set and successfully
validates as one complete asset set. When enabled, resolution considers PATH
entries in order, considers only absolute entries, and requires `vmmon`, `netd`,
and `krun` to exist and be executable in one entry. It never combines helpers
from different PATH entries, and higher-precedence explicit helper overrides
still apply. Empty and relative PATH entries are not resolved against the
working directory. If no complete helper set is found, the error reports every
considered absolute candidate.

There is no automatic lookup of historical asset directories, including:

```text
/usr/local/share/silo/assets
$HOME/.local/share/silo/assets
```

Users may select either directory explicitly with `SILO_ASSET_DIR`.

Optional downstream repackagings that choose a conventional native `/usr` layout
must keep all helpers and assets private to Silo, must not place default assets
in a shared data directory, and must preserve one complete exact-version
component set. A conventional layout may use `/usr/bin/silo` with private files
under `/usr/lib/silo/` or an equivalent architecture-aware private library
location. `/usr/local` remains reserved for local administrator installations.
These are resolver compatibility guidelines only, not Silo native-package
production, publishing, or qualification obligations.

A failure identifies the missing component, candidate locations considered, a
malformed supplied override, and the expected native or portable layout.

### No Runtime Manifest

Discovery derives the fixed paths directly after it finds an installation. A
path-bearing manifest cannot remove that prerequisite:

```text
find component
  -> read manifest

find manifest
  -> still requires a convention
```

A manifest becomes justified if components are independently installed,
independently upgraded, content-addressed, supplied by third parties, or chosen
from coexisting compatibility generations. None applies to the initial runtime.
There is also no `--component-info` protocol. Release identity and provenance
belong in application metadata, archive checksums, SBOMs, and provenance records,
not in a subprocess probe required for discovery.

## Product Distributions

### macOS Product Layout And Distribution

The macOS product is a relocatable application bundle:

```text
Silo.app/
  Contents/
    Info.plist
    MacOS/
      silo
    Helpers/
      vmmon
      netd
      krun
    Resources/
      assets/
        kernel-default
        initramfs
        agent
```

The layout defines the component paths without a Silo-specific manifest:

```text
vmmon     = Contents/Helpers/vmmon
netd      = Contents/Helpers/netd
krun      = Contents/Helpers/krun
kernel    = Contents/Resources/assets/kernel-default
initramfs = Contents/Resources/assets/initramfs
agent     = Contents/Resources/assets/agent
```

`Info.plist` carries standard application identity, version, and minimum-system
metadata. It does not contain Silo runtime paths. The initial contract is:

| Key | Value or meaning |
| --- | --- |
| `CFBundleIdentifier` | `sh.silo.app` |
| `CFBundleExecutable` | `silo` |
| `CFBundleShortVersionString` | The public Silo release version |
| `CFBundleVersion` | The monotonically increasing release build number |
| `LSMinimumSystemVersion` | `26.0` |

An SDK comparing itself with an installed app requires an exact
`CFBundleShortVersionString` match. `CFBundleVersion` distinguishes rebuilt
artifacts of the same public release but does not create runtime compatibility
across public versions.

The CLI derives its bundle from the real executable, not the invocation path. It
obtains `std::env::current_exe()`, canonicalizes it, recognizes
`<bundle>/Contents/MacOS/silo`, validates the expected Silo bundle identity from
`Info.plist`, and derives `Helpers` and `Resources` from `Contents`. This
preserves Homebrew Cask invocation:

```text
/opt/homebrew/bin/silo
        |
        | symlink
        v
/Applications/Silo.app/Contents/MacOS/silo
        |
        +-- ../Helpers/vmmon
        +-- ../Helpers/netd
        +-- ../Helpers/krun
        `-- ../Resources/assets
```

It also preserves relocatability to a user-owned location such as
`~/Applications/Silo.app`; no lookup assumes `/Applications`. Copying
`Contents/MacOS/silo` out of the bundle is not a supported command exposure
method because it loses bundle origin. Command exposure uses a symlink. A copied
executable may use an explicit runtime root or conventional shared installation,
but does not claim the copied app's product resources by name alone. The app
bundle is read-only product content; creating or starting a machine never writes
into it.

The initial macOS channels are:

1. A signed, hardened, notarized, and stapled DMG containing `Silo.app`.
1. An official Homebrew tap containing a Cask for the same app bundle.
1. Target runtime archives where an SDK transport requires one.

The Cask installs the app and exposes its CLI with a symlink equivalent to:

```ruby
app "Silo.app"
binary "#{appdir}/Silo.app/Contents/MacOS/silo", target: "silo"
```

A tap is the repository containing package definitions. A Cask is the definition
that installs the prebuilt application. A PKG is deferred until direct
non-Homebrew command installation, installer receipts, enterprise deployment,
or MDM support is required. A DMG does not place a command on `PATH` by itself.

Installing into `/Applications` or a system command directory may require
administrator authorization. A no-admin installation may use:

```text
~/Applications/Silo.app
$HOME/.local/bin/silo -> ~/Applications/Silo.app/Contents/MacOS/silo
```

Production signing happens after the complete app is assembled. Nested code is
signed from the inside out without `codesign --deep`. `vmmon` receives the
Virtualization entitlement and `krun` receives the Hypervisor entitlement. Other
entitlements are granted only when their need is demonstrated for that
executable. The CLI and `netd` do not inherit virtualization entitlements merely
because they share the bundle.

`create-dmg` is the selected DMG builder. `make package` assembles, signs, and
verifies `Silo.app` without creating a disk image by default. `make package
DMG=1` additionally installs the exact locked npm tree and invokes its unmodified
`create-dmg`; local builds use `--no-code-sign`, and protected release builds
supply the explicit Developer ID identity. DMG creation can fail when endpoint
security software races native `hdiutil` conversion, so affected development
hosts build the app locally and leave the DMG step to an unaffected release
runner rather than carrying a divergent Finder-layout implementation.

The release pipeline:

1. Selects macOS 26, Xcode 26.6, and the pinned Nix release shell.
1. Builds arm64 binaries with a macOS 26 deployment target using Apple SDK and
   linker tools resolved through `xcrun`.
1. Builds arm64 guest assets.
1. Resolves the arm64 kernel OCI artifact.
1. Assembles the complete app.
1. Signs nested executables with a Developer ID Application identity.
1. Signs the outer app with hardened runtime and timestamping.
1. Builds the DMG with `create-dmg`.
1. Submits the distribution through `xcrun notarytool`.
1. Staples and validates the notarization ticket.
1. Tests the result on a clean macOS 26 machine without development tools.

Ad-hoc signing remains a development convenience and is not a release signature.

### Linux Archive Distribution

Official Linux releases contain two complete binary archive families for each
of `linux-amd64-gnu` and `linux-arm64-gnu`. Both architectures and both archive
families are first-class release outputs:

- `silo-runtime-<version>-<target>.tar.zst` contains the runtime payload for an
  SDK, embedder, or installer that provides its own frontend.
- `silo-<version>-<target>.tar.zst` contains the same runtime payload plus the
  `silo` CLI and is the official direct Linux product distribution.

The portable CLI archives expand to:

```text
silo-<version>-linux-amd64-gnu/
  bin/
    silo
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent

silo-<version>-linux-arm64-gnu/
  bin/
    silo
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

The top-level archive directory is the runtime root. The archive is relocatable:
users may extract it into a user-owned directory and expose `bin/silo` with a
symlink on `PATH`. It contains no system daemon, service unit, setuid executable,
or privileged installation helper. Product files remain read-only after
extraction; mutable state follows the XDG ownership model.

For each target and exact version, the official release publishes one atomic
archive set: both compressed archives and each archive's SHA-256 checksum, SBOM,
and provenance record generated from the same staged payload. A checksum
identifies its archive bytes; the SBOM and provenance identify how the
corresponding payload was produced. These records must not be mixed across
versions, targets, archive families, or rebuilds. Archive signing and signature
verification are future release capabilities unless a release explicitly
provides them; checksums, SBOMs, and provenance are the current archive release
materials.

Linux binaries are built natively on Ubuntu 24.04 against its glibc 2.39
baseline. Manual environment qualification confirms the native system loaders
on both CPUs and static linking for `netd` and the guest programs. Routine CI
does not parse final ELF symbol versions or maintain an exact shared-library
allowlist. A future baseline change updates the support matrix, requalifies both
official Linux archive targets, and updates this ADR.

#### Optional Downstream Repackaging

Downstream maintainers may optionally repackage the official portable CLI
archive for a Linux distribution. Such a downstream package is not an official
Silo artifact and must preserve the archive's target, exact version, component
bytes, executable modes, and atomic runtime relationship. It may add only
packaging metadata, filesystem placement, and command exposure needed by its
distribution policy. It must not split, substitute, rebuild, mix versions of,
or independently update the Silo helpers or default assets.

If a downstream package uses a conventional native layout, `/usr/bin/silo` may
refer to private runtime files below `/usr/lib/silo/` or an equivalent
architecture-aware private location. Default assets remain private to Silo and
architecture-specific, rather than shared data files. This layout supports the
resolver's optional native compatibility paths. It does not create an official
native package channel, a native package CI obligation, or a Silo support
commitment for the downstream distribution.

The downstream maintainer owns its package metadata, signing, repository
publication, upgrades, removal behavior, and distribution qualification. Silo's
trust boundary ends at the published official archive set. Users and downstream
maintainers should verify the official archive checksum before repackaging;
downstream package trust is established by that downstream's own distribution
mechanisms.

#### Future Explicit Archive Installer

An official archive installer is deferred and is not implemented by this ADR.
If introduced, it is an explicit acquisition command or SDK setup API outside
`libvm`, runtime open, and VM startup. It must select a target and exact version,
verify the archive digest and verify a signature when one is available, reject
path traversal, links, and device entries, preserve file modes, extract into a
temporary directory, and atomically install only a complete verified runtime.

The default install location must be user-owned. When installing a portable CLI
archive, the installer may create a user-owned `PATH` symlink to `bin/silo`; a
runtime-only archive has no CLI to expose. The installer must not require
privilege escalation or delete user machines, images, databases, logs, keys, or
other user state. System-wide installation, native package management, and
implicit acquisition remain outside this deferred installer direction.

## SDK Distributions

### Current Node SDK Compatibility Contract

The Node SDK is a TypeScript facade over a native N-API addon. It does not launch
the `silo` CLI. The package family consists of a platform-neutral `silo` package
and exact-version optional platform packages. The following names are
non-normative conceptual package names:

```text
silo
@silo/runtime-darwin-arm64
@silo/runtime-linux-amd64
@silo/runtime-linux-arm64
```

The neutral package declares every platform package in `optionalDependencies`
at the exact same version. Each platform package declares npm `os` and `cpu`
restrictions; Linux packages also declare `libc: ["glibc"]`. Package-manager
selection therefore installs only compatible optional payloads without an
install script. The exact npm scope is finalized before publication.

The platform package contract is:

```text
native/
  silo.node
runtime/
  bin/
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

The JavaScript loader selects the package from `process.platform` and
`process.arch`, resolves its package-relative `runtime` directory, and passes
that bundled candidate to the native addon. An explicit API root and environment
overrides retain higher precedence. The loader does not use `process.execPath`,
run a postinstall downloader, download at first VM start, search arbitrary global
npm locations, or require a separate Silo CLI installation.

### Future Python SDK Compatibility Contract

A future Python SDK uses platform-specific wheels containing its native binding
and the portable runtime:

```text
silo/
  <native-extension>
  _runtime/
    bin/
      vmmon
      netd
      krun
    assets/
      kernel-default
      initramfs
      agent
```

The wrapper derives `_runtime` from the installed package and supplies the real
directory to its native binding. Helpers must remain executable files and the
kernel must have a stable path, so zip-only imports are unsupported unless the
package is first materialized into a stable directory.

The initial wheel matrix mirrors the supported targets: macOS arm64,
`manylinux_2_39_x86_64`, and `manylinux_2_39_aarch64`. These PEP 600 tags match
the runtime's glibc floor. Wheels do not use first-run downloaders or
installation scripts to acquire the default runtime.

### Future Go SDK Compatibility Contract

Go modules have no clean equivalent to npm optional platform packages or Python
platform wheels. A future Go SDK therefore exposes an explicit installation API
such as `InstallRuntime`. This is a deferred instance of the explicit archive
installer direction, not a current runtime capability. Installation never occurs
during package import, `init()`, runtime open, VM start, or a hidden postinstall
hook.

The exact SDK-matched runtime is installed using the same XDG location on Linux
and macOS:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/silo/runtimes/<version>/<target>/
```

Examples:

```text
$HOME/.local/share/silo/runtimes/0.1.0/darwin-arm64/
$HOME/.local/share/silo/runtimes/0.1.0/linux-amd64-gnu/
$HOME/.local/share/silo/runtimes/0.1.0/linux-arm64-gnu/
```

A future exact Go SDK release may embed the expected SHA-256 digest and default
release URL for every supported target archive. It must verify that digest before
extraction, preserve the archive-installation safety requirements, coordinate
concurrent installers, atomically rename a completed temporary directory into
place, and return the runtime root. It may support explicit mirrors and offline
pre-seeding only when bytes match the expected digest. Signature verification is
required when the selected release provides a signature. `libvm` remains unaware
of the download.

### Direct Rust And Shared SDK Discovery

`libvm` is the native Rust API boundary. Direct Rust consumers may use a
conventionally installed Silo runtime, pass a portable runtime root, or pass
explicit component paths. `libvm` does not download runtime components, install
system packages, pull the default kernel, extract embedded executables, or infer
arbitrary host-application resource directories.

Self-contained Node and Python packages use their package-local runtime before
native shared-installation conventions, subject to the higher-precedence explicit
API and environment overrides in the authoritative discovery order. A macOS SDK
without a bundled runtime may check exactly:

```text
$HOME/Applications/Silo.app
/Applications/Silo.app
```

It validates bundle identity, host architecture, minimum OS version, and app
release metadata before use. It does not use Spotlight, scan mounted volumes, or
execute the first application named `Silo.app`. Linux SDK packages are
self-contained. Selecting a shared native installation instead requires an
explicit override unless compatibility can be established without querying a
package-manager database.

### SDK Size Budget

The initial compressed budget is 50 MiB for each Node platform package and
Python platform wheel carrying the complete runtime. It is a product budget, not
a file-format limit. Release CI reports compressed and installed sizes for every
target. Exceeding the budget requires an explicit reviewed exception with the
responsible components identified. Size pressure does not justify removing
required runtime files or introducing an implicit first-run downloader.

## Integrity And Release Qualification

Distribution channels establish trust differently:

| Channel | Primary trust mechanism |
| --- | --- |
| `Silo.app` | Apple code signature, hardened runtime, notarization, and stapling |
| Homebrew Cask | Signed app plus Cask artifact checksum |
| Official Linux archives | SHA-256 checksums, SBOMs, and provenance for both exact-version target archives |
| npm | Registry integrity plus signed Mach-O files on macOS |
| Python | Wheel/index integrity plus signed Mach-O files on macOS |
| Future Go archive installation | SDK-selected target/version digest, and signature verification when available |

Normal VM launch does not rehash the entire runtime. Release materials retain
required third-party notices, including libkrun's Apache-2.0 attribution.

Archive signatures are not an implied current release guarantee. When official
archive signing is introduced, the release documentation must identify its trust
root, signature format, certificate or key identity, and verification procedure;
until then, archive consumers verify the published SHA-256 checksum and inspect
associated SBOM and provenance records as appropriate.

Each platform environment is qualified when introduced or intentionally
changed. Routine releases then require successful construction and basic startup
in that environment rather than repeating deep binary qualification.

### macOS arm64

- The app launches from `/Applications/Silo.app`.
- The app launches from `$HOME/Applications/Silo.app`.
- A Homebrew-style command symlink resolves the containing app.
- Gatekeeper accepts the app and the stapled notarization validates.
- VZ boots a VM using only packaged files.
- The dormant krun helper has a valid Hypervisor entitlement and signature.
- Boundary qualification confirms that host binaries use Apple system libraries
  and frameworks and that `netd` has no Nix dynamic-library dependency.

### Linux amd64 And arm64

- Each exact-version `linux-amd64-gnu` and `linux-arm64-gnu` archive set contains
  the complete runtime-only and portable CLI layouts.
- Each archive checksum, SBOM, and provenance record corresponds to its exact
  archive family, version, and target.
- Helpers and assets have the intended modes after archive extraction.
- Boundary qualification confirms the native Ubuntu system loaders and declared
  glibc baseline.
- A krun VM boots using only files from the extracted archive root.
- No `libkrun.so` dependency remains.
- No Linux native-package build, install, upgrade, removal, repository, or
  distribution-specific qualification gate is required of official releases.

### Current SDKs

- A clean npm installation with no system Silo boots a VM.
- Missing platform packages produce actionable errors.
- Unsupported targets fail before process spawn.
- Compressed size is reported and remains within budget unless waived.

The Python wheel and future explicit Go installer gates become mandatory when
those SDKs are implemented. Before its first release, the Python SDK must boot
from a clean wheel installation with no system Silo. Before its first release,
the Go SDK must reject unsupported targets before download, verify its exact
runtime archive, enforce archive extraction safety, and boot that installed
runtime.

### General

- Formatting, linting, and relevant unit and end-to-end tests pass.
- Kernel digests and architecture are verified.
- SBOM and provenance records are generated.
- The installation requires no first-run network access for its default runtime.
- Product removal does not remove user machines, images, databases, logs, or
  downloaded optional runtimes without an explicit user action.

## Relationship To ADR 0009

ADR 0009 states that an installation owns default assets and that `libvm` and
language SDKs do not install them. This ADR refines the language-package part of
that statement:

- `libvm` never installs assets.
- An official product archive or app may be the installation that owns default
  assets.
- A language platform package may itself own a bundled runtime.
- SDK runtime transport is packaging behavior, not runtime-library behavior.

ADR 0009's independent explicit machine overrides, per-launch default
resolution, and composite initramfs behavior remain unchanged. This ADR
supersedes two narrower parts of ADR 0009: a language platform package may own
its bundled defaults, and omitted defaults are resolved as one installation
asset set rather than falling through independently across directories.

## Consequences

### Benefits

- The normal CLI and SDK paths receive one complete, coherent runtime without
  manual configuration.
- The same staged files are consumed across official transports, and their
  native build environment is qualified at platform boundaries.
- Both supported Linux architectures receive equivalent first-class official
  archive releases with one clear glibc contract.
- Silo avoids distribution-specific native package production and qualification
  while downstream maintainers can repackage immutable official bytes.
- `libvm` remains a runtime library rather than a package manager.
- Compiling the pinned libkrun fork into the krun helper removes a loader, RPATH,
  and nested-signing failure class.

### Tradeoffs

- Linux users who prefer a native package must use a downstream repackaging or
  manually extract the official archive.
- Native package discovery remains a small compatibility surface without an
  official package test matrix.
- Node and Python target packages duplicate runtime bytes, and security fixes
  require updated SDK platform packages.
- macOS releases require native signing infrastructure; Linux releases require
  native amd64 and arm64 Ubuntu builders and boundary qualification; Go requires
  a secure explicit installer when implemented.
- Package size is a maintained product constraint.
- Convention-based discovery must provide strong diagnostics because there is no
  manifest to inspect.

## Alternatives Considered

The following alternatives are rejected for the initial runtime design.

### Path-Bearing Runtime Manifest

This would centralize component paths, but finding the manifest still requires a
convention. The initial runtime is one atomic compatibility set with
deterministic paths, so the manifest adds another artifact without removing
discovery.

### Component Information Commands

A `--component-info` command could expose component data through a subprocess,
but it adds a subprocess API and startup complexity without a current
independent-versioning requirement.

### Embedded Executable Bytes

Embedding would make transport self-contained, but helpers must be executable
files, kernels need stable paths, macOS signatures must remain valid, and
extraction adds locking, permissions, cleanup, and Gatekeeper failure modes.

### Shared Runtime Only

A shared runtime avoids SDK payload duplication, but requiring every Node and
Python user to install a separate system product makes SDK deployment
unnecessarily fragile.

### Runtime Downloads In `libvm`

This would make acquisition available to all frontends, but acquisition, update,
mirror, and trust policy do not belong in the core runtime library.

### Implicit SDK Downloads

Downloading during import, runtime open, or VM start creates surprising network
access and nondeterministic offline behavior.

### Official Native Linux Packages

Native Linux packages would multiply official release outputs, package metadata,
repository trust policy, upgrade semantics, and distribution-specific
qualification without improving the atomic runtime payload. Official archives
provide one tested contract per architecture while allowing downstream
repackaging where it is valuable.

### One Universal Physical Layout

One layout would reduce resolver cases, but app bundles, portable archives, SDK
packages, optional downstream native paths, and user-owned XDG runtimes have
distinct ownership and installation conventions.

### One Generic Release Tool

A generic tool could centralize release packaging, but a paid generic packager
does not replace Silo's mixed-language staging, per-executable Apple
entitlements, signing order, and clean-machine qualification.

## Accepted Limitations

- The initial host scope excludes Intel macOS, macOS before version 26, Windows,
  other Linux architectures, and cross-architecture guest CPU emulation.
- The initial GNU/Linux glibc 2.39 baseline does not claim compatibility with
  older releases.
- Official Linux distribution is archive-only; Silo does not publish or qualify
  native Linux packages.
- Optional downstream native repackaging has no official Silo support or CI
  matrix beyond archive byte and layout preservation requirements.
- macOS packages the dormant krun helper but selects only VZ.
- zip-only Python imports are unsupported unless the package is first
  materialized into a stable directory.
- A DMG alone does not place a command on `PATH`.

## What This Does Not Decide

This ADR does not decide the following adjacent product or compatibility
questions:

- selecting krun instead of VZ on macOS;
- PKG and enterprise or MDM installation;
- independently updated runtime components and compatibility ranges;
- additional downloaded kernel management;
- final npm scope and Python or Go public API design;
- a future Rust convenience installer, which belongs in a separate explicit
  setup API or crate; and
- the archive-signing mechanism, trust root, and release verification procedure.

## Deferred Implementation Work

The following delivery work remains deferred:

- an explicit user-owned archive installer with target and version selection,
  digest verification, signature verification when available, safe extraction,
  atomic installation, and optional `PATH` symlink creation; and
- a `silo doctor` integrity and diagnostics command that may validate files,
  modes, dynamic dependencies, release checksums, macOS signatures, target
  architecture, and kernel provenance.

These additions must remain outside `libvm`, runtime open, and VM startup. They
must not delete user state. The layouts, discovery rules, XDG ownership model,
and release staging contract in this ADR support them without replacement.

## External References

- [Apple: Bundle resources](https://developer.apple.com/documentation/bundleresources)
- [Apple: Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
- [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Homebrew: Cask Cookbook](https://docs.brew.sh/Cask-Cookbook)
- [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/)
- [OCI Image Specification: Image Manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
- [npm: `package.json` platform metadata and optional dependencies](https://docs.npmjs.com/cli/v11/configuring-npm/package-json)
- [PEP 600: Future `manylinux` platform tags](https://peps.python.org/pep-0600/)
- [Go Modules Reference: Authenticating modules](https://go.dev/ref/mod#authenticating)
