# 12. Cross-Platform Runtime And SDK Packaging

Date: 2026-07-22

Updated: 2026-07-25

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
entitlements, notarization, and Homebrew Casks; Debian, Ubuntu, RHEL, and Arch
layouts; Node platform packages and native addons; future Python wheels and Go
modules; direct Rust `libvm` consumers; and custom embedders.

The normal path should require no user configuration. Explicit configuration is
still necessary for tests, development, custom embedding, and unusual
installations. Silo therefore needs conventions that remain overrideable rather
than configuration that every consumer must reproduce.

This ADR defines immutable product layout, runtime discovery, SDK runtime
transport, user-owned product and state paths, release staging, and package
qualification. It does not add runtime backend selection, independent component
updates, or an in-process package manager to `libvm`.

## Terminology

| Term                 | Meaning                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------- |
| Frontend             | The CLI, Rust consumer, Node addon, or future language binding that opens `libvm`.       |
| Runtime payload      | The co-versioned private helpers and default boot assets required to run VMs.            |
| Runtime root         | A portable directory containing the fixed `bin/` and `assets/` layout.                   |
| Product installation | A CLI distribution such as `Silo.app`, a deb, an rpm, or an Arch package.                |
| Bundled runtime      | A runtime payload carried inside an SDK package or wheel.                                |
| Shared runtime       | A runtime installed through an OS product channel and used by a frontend.                |
| Default assets       | `kernel-default`, `initramfs`, and `agent`.                                              |
| Mutable state        | Databases, images, machine state, sockets, logs, caches, and downloaded optional assets. |
| Transport            | The ecosystem-specific way in which the canonical runtime payload is delivered.          |

## Decision

Silo produces one validated, architecture-specific runtime payload for each
supported target. Product installers and SDK packages for that target consume
the same staged files rather than rebuilding a transport-specific variation.

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

## Supported Targets And Compatibility

The initial host matrix is:

| Host   | Architecture                 | Initial distribution promise | Active backend | Packaged backends |
| ------ | ---------------------------- | ---------------------------- | -------------- | ----------------- |
| macOS  | arm64                        | macOS 26 or newer            | VZ             | VZ and krun       |
| Debian | amd64, arm64                 | Latest stable                | krun           | krun              |
| Ubuntu | amd64, arm64                 | Latest stable or LTS         | krun           | krun              |
| RHEL   | amd64, arm64                 | Latest supported major       | krun           | krun              |
| Arch   | amd64, arm64 where available | Current rolling release      | krun           | krun              |

The initial release does not support Intel macOS, macOS before version 26,
Windows, other Linux architectures, or cross-architecture guest CPU emulation.
Initial GNU/Linux binaries target glibc 2.39. This covers the selected current
distribution generation without claiming compatibility with older releases.
Raising that floor changes the support matrix and requires an ADR update.

VZ remains the only selected macOS backend. Silo packages and signs the krun
helper on macOS so a later backend selector does not require a new distribution
layout. Packaging a backend does not make it selectable.

The default kernel, initramfs, and agent always match the target architecture.
Optional Rosetta support in VZ does not change the guest kernel architecture.

Official runtime components are co-versioned and updated atomically. The
initial compatibility policy is deliberately strict:

- Product packages co-install one matching CLI and runtime.
- Node and Python platform packages use the exact SDK package version.
- Go downloads the exact runtime release matching the SDK version.
- Direct Rust consumers use a co-installed runtime or pass an explicit root.
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

The runtime payload does not inherently include the `silo` CLI. Product packages
add the CLI and SDK packages add their native binding. A complete portable CLI
archive may place `silo` beside the helpers:

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

### Portable Staging

Cargo development builds keep the CLI, helpers, and assets together in the
active profile directory:

```text
target/debug/
  silo
  vmmon
  netd
  krun
  assets/
    kernel-default
    initramfs
    agent
```

`make build` defaults to the debug layout. Bare `make` and `make all` build the
equivalent `target/release` layout for source distribution. Explicit `PROFILE`
values override either default. This development layout is internal and allows
either binary to run directly without an environment override.
`CARGO_TARGET_DIR` replaces `target` for both Cargo and Make-managed development
outputs.

Validated release staging continues to use the portable layout in predictable
target directories:

```text
target/silo-runtime/darwin-arm64/release/
target/silo-runtime/linux-amd64-gnu/release/
target/silo-runtime/linux-arm64-gnu/release/
```

Developers can still select another complete portable root through
`RuntimeConfig` or `SILO_RUNTIME_DIR`. The staged release payload is the common
input to the app, Linux packages, SDK platform packages, and runtime archives.
Packagers do not rebuild or substitute components after staging, except for
required platform signing and container metadata.

### Default Kernel Provenance

Release CI obtains the default kernel from Silo's stable OCI artifact during
staging:

1. Resolve the stable OCI index.
2. Select the target architecture manifest.
3. Verify the expected Silo kernel media types.
4. Verify the platform manifest and layer digests.
5. Extract the kernel as `assets/kernel-default`.
6. Record the index, platform manifest, and layer digests in release provenance.
7. Package those exact bytes into every transport for the target.

End users never receive a release whose default kernel depends on when they
first run it. The installed runtime needs no registry access to boot its default
kernel. The initramfs and agent are built from the corresponding Silo source
release. Staging verifies that all three default assets match the target
architecture.

Additional user-installed kernels are deferred. When added, they live below the
XDG data root and never modify `Silo.app` or package-owned `/usr` paths.

### Release Staging

A repository-owned staging command builds one canonical payload per target:

1. Build `silo`, `vmmon`, `netd`, and `krun`.
2. Use committed lockfiles and locked dependency resolution.
3. Build the guest initramfs and standalone agent.
4. Resolve and verify the target kernel OCI artifact.
5. Strip release binaries.
6. Normalize file names, modes, and reproducible timestamps where possible.
7. Copy components into the portable runtime layout.
8. Inspect dynamic dependencies and runtime search paths.
9. Reject build-machine paths and unavailable shared libraries.
10. Record source and kernel provenance in release metadata.
11. Generate checksums, SBOMs, and attestations.
12. Boot a VM using only the staged tree.
13. Report raw and compressed sizes.
14. Hand those files to each target packager.

The repository may contain build-time staging configuration. That configuration
is not installed and `libvm` never consults it. The toolchain is deliberately
composed because no single free tool safely owns every Silo release concern:

```text
repository-owned staging command
        |
        +-- Apple native tools -> Silo.app, DMG, notarization
        +-- nFPM -> deb, rpm, Arch
        +-- npm tooling -> Node platform packages
        +-- Python tooling -> platform wheels
        `-- tar/zstd -> portable and Go runtime archives
```

GoReleaser Pro is not part of the design. The common contract is the staged
payload, not one third-party packager.

## Installation Ownership, Mutable XDG State, And Migration

Package-owned product files are immutable. Silo never writes mutable state into
`Silo.app` or package-owned `/usr` paths. Linux and macOS use the same XDG
conventions for user-owned product files and mutable state; Silo does not use
`~/Library/Application Support`, `~/Library/Caches`, or `~/Library/Logs` on
macOS.

| Purpose                            | Environment location           | Fallback on Linux and macOS                              |
| ---------------------------------- | ------------------------------ | -------------------------------------------------------- |
| Data root, database, machines      | `$XDG_DATA_HOME/silo`          | `$HOME/.local/share/silo`                                |
| Images                             | `$XDG_DATA_HOME/silo/images`   | `$HOME/.local/share/silo/images`                         |
| Downloaded runtimes                | `$XDG_DATA_HOME/silo/runtimes` | `$HOME/.local/share/silo/runtimes`                       |
| Downloaded kernels                 | `$XDG_DATA_HOME/silo/kernels`  | `$HOME/.local/share/silo/kernels`                        |
| Configuration                      | `$XDG_CONFIG_HOME/silo`        | `$HOME/.config/silo`                                     |
| Cache                              | `$XDG_CACHE_HOME/silo`         | `$HOME/.cache/silo`                                      |
| Logs and durable operational state | `$XDG_STATE_HOME/silo`         | `$HOME/.local/state/silo`                                |
| Sockets, locks, and PID files      | `$XDG_RUNTIME_DIR/silo`        | Linux: owner-isolated temporary directory; macOS: `/tmp/silo-<uid>` |

The default data tree remains compatible with the existing Linux layout:

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
        vm.exit.json
    networks/
      <network-id>/
        netd.log
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

Existing installations may contain logs, PID files, sockets, and exit records
inside `data-root/machines/<machine-id>`. Migration runs only while that machine
is stopped. It moves durable logs and exit records into the state layout, drops
stale ephemeral files, and leaves canonical machine data in place. If the
machine is active, migration fails with an actionable stop-and-retry error.
Legacy files are not silently deleted before their durable replacements have
moved successfully.

Existing `netd.log` files below a legacy run root move to the network-log state
layout only after the associated netd process has stopped. Packet captures are
not covered by this migration contract. Their retention remains a separate
product decision.

XDG environment paths and `$HOME` must be absolute when used. Silo rejects a
relative value rather than interpreting it relative to the process working
directory.

### Ephemeral Runtime Directory

The run-root resolution order is:

1. Explicit `RuntimeConfig` run root.
2. `$XDG_RUNTIME_DIR/silo`.
3. A short, owner-isolated platform fallback.

On Linux, Silo uses Rust's platform temporary-directory resolution rather than
reading `TMPDIR` directly. A private temporary directory uses `<temp-dir>/silo`;
a shared base includes the effective user identity, for example
`/tmp/silo-1000`. On macOS, the fallback is always `/tmp/silo-<uid>`. Darwin's
Unix-domain socket path is limited to 103 bytes, while its normal per-user and
Nix-shell temporary paths leave too little room for Silo's machine and network
socket names.

The directory is created with mode `0700`. Silo verifies that it is a real
directory owned by the effective user and rejects symlinks, foreign ownership,
or unsafe permissions. It never uses a cross-user `/tmp/silo` directory.
Every generated host socket path is validated against the platform byte limit
before a helper is spawned or a bind is attempted. Explicit roots that are too
long therefore fail with the offending path, actual byte length, and maximum
instead of an opaque operating-system `EINVAL`.

The run root is ephemeral session placement, not durable database identity.
`Runtime::open` resolves the default run root from the current environment on
every open. An explicit `RuntimeConfig` run root applies to that runtime instance
without requiring the same value on later opens.

Implementation removes `run_root` from the roots that `db_config` permanently
binds to a state database. Data and image roots remain durable. The database
migration must detect active processes using the previously stored run root and
refuse migration with an actionable error rather than split one live runtime
across two roots. Once no Silo process uses it, old locks, sockets, PID files,
and network runtime files are ephemeral and are not moved into the newly
resolved directory.

`RuntimeConfig` gains a state-root choice using the XDG state default, and
`db_config` persists that durable root beside the data and image roots. The
schema migration derives and stores it once for an existing database. Later
explicit data, image, or state roots must match the stored database identity;
the ephemeral run root is intentionally exempt from that rule.

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
2. An explicit API `runtime_root` using the portable layout.
3. Existing per-component environment variables.
4. `SILO_RUNTIME_DIR` using the portable layout.
5. A runtime bundled with the caller.
6. A complete development runtime adjacent to the canonical current executable.
7. A portable runtime relative to the canonical current executable, including
   `Silo.app`.
8. One complete helper set from `PATH` when `SILO_ASSET_DIR` is explicit.
9. Conventional native package locations.
10. A missing-runtime error.

Existing environment controls remain available while lookup is centralized:

```text
SILO_VMMON_PATH
NETD_BIN
KRUN_BIN
SILO_ASSET_DIR
```

`SILO_RUNTIME_DIR` selects the complete portable root. Explicit per-component
paths can replace individual files for testing and embedding. All explicit
paths are absolute. Portable-root resolution verifies that derived paths remain
below the selected root and are regular files. `vmmon`, `netd`, `krun`, and
`agent` must be executable. `kernel-default` and `initramfs` must be readable
but need not be executable.

Executable-relative development discovery requires `vmmon`, `netd`, and `krun`
beside the running executable and all three assets below its `assets` directory.
`PATH` discovery is disabled unless `SILO_ASSET_DIR` is explicit, and all three
helpers must come from the same absolute `PATH` entry.

App-bundle resolution additionally validates bundle identifier `sh.silo.app`,
exact release compatibility, architecture, and minimum system version. Native
package resolution checks only a small documented set of platform paths; it does
not query dpkg, rpm, Homebrew, Spotlight, or mounted volumes.

Explicit machine asset overrides remain independent. An explicit machine kernel,
initramfs, or agent wins for that asset without replacing the other defaults.
Every omitted asset comes from the one asset directory selected by the resolved
installation. `SILO_ASSET_DIR` likewise selects one complete default asset set.
Transitional asset locations are considered as complete directories and never
mixed per file.

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
belong in application metadata, package metadata, release checksums, SBOMs, and
attestations, not in a subprocess probe required for discovery.

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
      Silo.icns
      THIRD_PARTY_NOTICES.txt
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

| Key                          | Value or meaning                                  |
| ---------------------------- | ------------------------------------------------- |
| `CFBundleIdentifier`         | `sh.silo.app`                                     |
| `CFBundleExecutable`         | `silo`                                            |
| `CFBundleIconFile`           | `Silo.icns`                                       |
| `CFBundleShortVersionString` | The public Silo release version                   |
| `CFBundleVersion`            | The monotonically increasing release build number |
| `LSMinimumSystemVersion`     | `26.0`                                            |

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
but does not claim the copied app's package-owned resources by name alone. The
app bundle is read-only product content; creating or starting a machine never
writes into it.

The initial macOS channels are:

1. A signed, hardened, notarized, and stapled DMG containing `Silo.app`.
2. An official Homebrew tap containing a Cask for the same app bundle.
3. Signed target runtime archives where an SDK transport requires one.

The DMG uses a conventional Finder installation window and contains exactly
these visible root items:

```text
Silo.app/
Applications -> /Applications
```

Hidden Finder presentation metadata and the volume icon are allowed.
Repository Rust code owns writable-image construction, deterministic Finder
presentation, final compression, and transient-lock retries in addition to
application assembly, signing, notarization, mounted-image validation, release
metadata, and publication. Native Apple tools continue to own HFS+ and UDIF
operations. Operational packaging and release guidance lives in
[`PACKAGING.md`](../../PACKAGING.md).

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

The release pipeline:

1. Builds arm64 binaries with a macOS 26 deployment target.
2. Builds arm64 guest assets.
3. Resolves the arm64 kernel OCI artifact.
4. Assembles the complete app.
5. Inspects every Mach-O dependency.
6. Rejects Nix-store, build-prefix, and unavailable non-system dependencies.
7. Signs nested executables with a Developer ID Application identity.
8. Signs the outer app with hardened runtime and timestamping.
9. Submits the app archive through `xcrun notarytool`, then staples and validates
   the accepted ticket on the app.
10. Builds the DMG from the stapled app and verifies the mounted root layout.
11. Signs the DMG with the Developer ID Application identity.
12. Submits the DMG through `xcrun notarytool`, then staples and validates the
    accepted ticket on the image.
13. Revalidates signatures, entitlements, Gatekeeper assessment, and image
    integrity.
14. Tests the exact draft candidate on a clean native macOS 26 machine before
    publication.

Ad-hoc signing remains a development convenience and is not a release signature.

### Linux Product Layouts And Distribution

Distro packages install the public frontend at:

```text
/usr/bin/silo
```

Debian, Ubuntu, and Arch packages use:

```text
/usr/lib/silo/
  bin/
    vmmon
    netd
    krun
  assets/
    kernel-default
    initramfs
    agent
```

RHEL follows package macros and may split private executables from
architecture-specific assets:

```text
%{_libexecdir}/silo/
  vmmon
  netd
  krun

%{_libdir}/silo/assets/
  kernel-default
  initramfs
  agent
```

The resolver models explicit resolved component paths; it does not pretend every
native installation has one physical runtime root. Distro packages do not
install into `/usr/local`, which is reserved for local administrator
installations. A source or administrator installation may use:

```text
/usr/local/bin/silo
/usr/local/lib/silo/bin/
/usr/local/lib/silo/assets/
```

The default assets are architecture-specific: the kernel differs between arm64
and amd64, the agent is a compiled guest executable, and the initramfs contains
architecture-specific executables. Package-owned defaults therefore belong below
a private `lib` directory rather than `/usr/share` or `/usr/local/share`. The
current `/usr/local/share/silo/assets` location is a transitional lookup
fallback, not the canonical destination for new packages.

Release CI produces separate amd64 and arm64 artifacts:

- Debian packages;
- RPM packages;
- Arch binary packages;
- generic `.tar.zst` runtime or CLI archives;
- detached checksums and signatures; and
- SBOM and provenance records.

Silo uses nFPM directly for deb, rpm, and Arch package construction. The
payload contains Rust binaries, a Go binary, generated assets, and a kernel
artifact, so separate Rust-only package generators would duplicate layout
configuration. AUR publication remains separate and requires a reviewed
`PKGBUILD`. The nFPM-produced Arch package remains useful as a direct binary
release.

Linux binaries are built against the glibc 2.39 baseline. CI records the symbol
versions required by each final ELF file and rejects dependencies on newer glibc
or libstdc++ symbols. A future baseline change updates the support matrix and
every Linux transport together. There is no system daemon, service unit, setuid
executable, or privileged runtime installation helper.

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
run a postinstall downloader, download at first VM start, search arbitrary
global npm locations, or require a separate Silo CLI installation.

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
such as `InstallRuntime`. Installation never occurs during package import,
`init()`, runtime open, VM start, or a hidden postinstall hook.

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

The exact Go SDK release embeds the expected SHA-256 digest and default release
URL for every supported target archive. The Go module and its normal module
checksum provenance are therefore the installer's trust root; runtime mirrors
cannot substitute different bytes. Release publication generates these values
from the same staged archives before publishing the SDK module.

The installer selects the exact SDK version and host target, verifies the
archive against the SDK-embedded digest before extraction, rejects archive
traversal, preserves executable modes, coordinates concurrent installers, and
atomically renames a completed temporary directory into place. It reuses an
already verified exact version and supports explicit mirrors and offline
pre-seeding only when their archive matches the embedded digest. The
installation API returns the runtime root. `libvm` remains unaware of the
download.

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
self-contained. Selecting a shared distro installation instead requires an
explicit override unless compatibility can be established without querying
package-manager databases.

### SDK Size Budget

The initial compressed budget is 50 MiB for each Node platform package and
Python platform wheel carrying the complete runtime. It is a product budget, not
a file-format limit. Release CI reports compressed and installed sizes for every
target. Exceeding the budget requires an explicit reviewed exception with the
responsible components identified. Size pressure does not justify removing
required runtime files or introducing an implicit first-run downloader.

## Integrity And Release Qualification

Distribution channels establish trust differently:

| Channel             | Primary trust mechanism                                                              |
| ------------------- | ------------------------------------------------------------------------------------ |
| `Silo.app`          | Apple code signature, hardened runtime, notarization, and stapling                   |
| Homebrew Cask       | Signed app plus Cask artifact checksum                                               |
| deb, rpm, Arch      | Signed package or repository plus package-owned installed files                      |
| npm                 | Registry integrity plus signed Mach-O files on macOS                                 |
| Python              | Wheel/index integrity plus signed Mach-O files on macOS                              |
| Go runtime download | Target digest embedded in the exact Go SDK release and Go module checksum provenance |
| Generic archive     | SHA-256 checksum and keyless Sigstore bundle from the protected release workflow      |

Normal VM launch does not rehash the entire runtime. Release materials retain
required third-party notices, including libkrun's Apache-2.0 attribution.

Each generic archive publishes a detached `*.sigstore.json` bundle. Verification
requires the GitHub Actions OIDC issuer and the certificate identity
`https://github.com/vandycknick/silo/.github/workflows/release.yml@refs/tags/v<version>`,
where `<version>` is the archive's public Silo version. Verification also
requires a transparency-log inclusion proof. The independently published
SHA-256 checksum remains part of the release material.

Every release passes the relevant target gates.

### macOS arm64

- The app launches from `/Applications/Silo.app`.
- The app launches from `$HOME/Applications/Silo.app`.
- A Homebrew-style command symlink resolves the containing app.
- Gatekeeper accepts the app and the stapled notarization validates.
- VZ boots a VM using only packaged files.
- The dormant krun helper has a valid Hypervisor entitlement and signature.
- No unexpected non-system dylib, build-prefix, or Nix-store path remains.

### Linux amd64 And arm64

- Deb, rpm, and Arch packages install, upgrade, and remove cleanly.
- Helpers and assets have the intended owners and modes.
- Binaries satisfy the release's declared glibc baseline.
- A KVM VM boots using only package-owned files.
- The generic archive boots using only its portable root.
- No `libkrun.so` dependency remains.

### Current SDKs

- A clean npm installation with no system Silo boots a VM.
- Missing platform packages produce actionable errors.
- Unsupported targets fail before process spawn.
- Compressed size is reported and remains within budget unless waived.

The Python wheel and Go installer gates become mandatory when those future SDKs
are implemented. Before its first release, the Python SDK must boot from a clean
wheel installation with no system Silo. Before its first release, the Go SDK
must reject unsupported targets before download, verify its exact runtime
archive, and boot that installed runtime.

### General

- Formatting, linting, and relevant unit and end-to-end tests pass.
- Kernel digests and architecture are verified.
- SBOM and provenance records are generated.
- The installation requires no first-run network access for its default runtime.
- Package uninstall does not remove user machines, images, databases, logs, or
  downloaded optional runtimes without an explicit purge operation.

## Relationship To ADR 0009

ADR 0009 states that an installation owns default assets and that `libvm` and
language SDKs do not install them. This ADR refines the language-package part of
that statement:

- `libvm` never installs assets.
- A product package may be the installation that owns default assets.
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
- The same staged files are qualified across transports.
- macOS bundles remain relocatable and Linux packages follow native conventions.
- `libvm` remains a runtime library rather than a package manager.
- Compiling the pinned libkrun fork into the krun helper removes a loader, RPATH,
  and nested-signing failure class.

### Tradeoffs

- Node and Python target packages duplicate runtime bytes, and security fixes
  require updated SDK platform packages.
- macOS releases require native signing infrastructure; Linux releases require
  amd64 and arm64 builders and KVM qualification; Go requires a secure explicit
  installer.
- Package size is a maintained product constraint.
- Convention-based discovery must provide strong diagnostics because there is no
  manifest to inspect.
- Native package layouts require the resolver to model explicit components
  rather than force every installation into one physical root.

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

### One Universal Physical Layout

One layout would reduce resolver cases, but app bundles, FHS packages, SDK
packages, and user-owned XDG runtimes have distinct ownership and installation
conventions.

### One Generic Release Tool

A generic tool could centralize release packaging, but a paid generic packager
does not replace Silo's mixed-language staging, per-executable Apple
entitlements, signing order, and clean-machine qualification.

## Accepted Limitations

- The initial host scope excludes Intel macOS, macOS before version 26, Windows,
  other Linux architectures, and cross-architecture guest CPU emulation.
- The initial GNU/Linux glibc 2.39 baseline does not claim compatibility with
  older releases.
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
- final npm scope and Python or Go public API design; and
- a future Rust convenience installer, which belongs in a separate explicit
  setup API or crate.

## Deferred Implementation Work

The following delivery work remains deferred:

- a `silo doctor` integrity and diagnostics command that may validate files,
  modes, dynamic dependencies, release checksums, macOS signatures, target
  architecture, and kernel provenance; and
- publishing an AUR `PKGBUILD`, which remains separate and requires review.

The layouts, discovery rules, XDG ownership model, and release staging contract
in this ADR support these additions without replacement.

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
- [nFPM documentation](https://nfpm.goreleaser.com/)
