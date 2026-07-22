# 12. Cross-Platform Runtime And SDK Packaging

Date: 2026-07-22

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

Those components must be built, installed, discovered, upgraded, and tested as
one compatible release. Shipping only the `silo` frontend leaves users to
assemble an implicit runtime from `PATH`, environment variables, and manually
placed assets. That is not a product installation and cannot support reliable
SDK distribution.

The distribution problem spans several environments with different native
conventions:

- macOS application bundles, code signing, entitlements, notarization, and
  Homebrew Casks;
- Debian, Ubuntu, RHEL, and Arch package layouts;
- Node platform packages and native addons;
- future Python platform wheels;
- future Go modules, which cannot carry platform runtimes like npm packages or
  Python wheels can;
- direct Rust `libvm` consumers and custom embedders.

The normal path should require no user configuration. Explicit configuration is
still necessary for tests, development, custom embedding, and unusual
installations. Silo therefore needs conventions that remain overrideable rather
than configuration that every consumer must reproduce.

This ADR owns immutable product layout, runtime discovery, SDK runtime
transport, user-owned product and state paths, release staging, and package
qualification. It does not add runtime backend selection, independent component
updates, or an in-process package manager to `libvm`.

## Terminology

| Term | Meaning |
| --- | --- |
| Frontend | The CLI, Rust consumer, Node addon, or future language binding that opens `libvm`. |
| Runtime payload | The co-versioned private helpers and default boot assets required to run VMs. |
| Runtime root | A portable directory containing the fixed `bin/` and `assets/` layout. |
| Product installation | A CLI distribution such as `Silo.app`, a deb, an rpm, or an Arch package. |
| Bundled runtime | A runtime payload carried inside an SDK package or wheel. |
| Shared runtime | A runtime installed through an OS product channel and used by a frontend. |
| Default assets | `kernel-default`, `initramfs`, and `agent`. |
| Mutable state | Databases, images, machine state, sockets, logs, caches, and downloaded optional assets. |
| Transport | The ecosystem-specific way in which the canonical runtime payload is delivered. |

Package-owned product files are immutable. User-owned portable product files
and mutable state follow XDG conventions on both Linux and macOS.

## Determination

Silo produces one validated, architecture-specific runtime payload for each
supported target. Every product installer and SDK package for that target
consumes the same staged files rather than rebuilding its own variation.

Runtime discovery is convention-based. There is no installed path manifest,
no `silo-runtime.json`, and no `--component-info` subprocess protocol. Fixed
native and portable layouts are resolved into absolute component paths and held
in memory for the lifetime of a `Runtime`. Installation paths are not persisted
in `db_config`.

The normal lookup order is:

1. Explicit per-component API paths.
2. An explicit API runtime root.
3. Per-component environment overrides.
4. `SILO_RUNTIME_DIR`.
5. A caller-supplied SDK runtime or the app bundle containing the current
   executable.
6. Conventional OS installations.
7. Transitional `PATH`, sibling, and historical asset fallbacks.
8. An actionable missing-runtime error.

`libvm` resolves local files but never installs or downloads a runtime. Release
CI resolves the default kernel from OCI before packaging, so a normal first VM
start requires no runtime download.

## Supported Targets

The initial host matrix is:

| Host | Architecture | Initial distribution promise | Active backend | Packaged backends |
| --- | --- | --- | --- | --- |
| macOS | arm64 | macOS 26 or newer | VZ | VZ and krun |
| Debian | amd64, arm64 | Latest stable | krun | krun |
| Ubuntu | amd64, arm64 | Latest stable or LTS | krun | krun |
| RHEL | amd64, arm64 | Latest supported major | krun | krun |
| Arch | amd64, arm64 where available | Current rolling release | krun | krun |

The initial release does not support Intel macOS, macOS before version 26,
Windows, other Linux architectures, or cross-architecture guest CPU emulation.

Initial GNU/Linux binaries target glibc 2.39. This covers the selected current
distribution generation without claiming compatibility with older releases.
Raising that floor is a support-matrix change and requires an ADR update.

VZ remains the only selected macOS backend. The krun helper is nevertheless
packaged and signed on macOS so a later backend selector does not require a new
distribution layout. Packaging a backend does not make it selectable.

The default kernel, initramfs, and agent always match the target architecture.
Optional Rosetta support in VZ does not change the guest kernel architecture.

## Runtime Payload

The portable runtime root is:

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
`libkrun.dylib`, or `libkrunfw`.

Only the krun helper links libkrun code. The process boundary remains:

```text
vmmon -> krun
```

Neither `vmmon`, `libvm`, nor a language binding links libkrun merely by using
the launcher library.

The runtime payload does not inherently include the `silo` CLI. Product
packages add the CLI. SDK packages add their native binding. A complete portable
CLI archive may place `silo` beside the helpers:

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

## Portable Staging

Developer and release staging use the portable layout in predictable target
directories:

```text
target/silo-runtime/darwin-arm64/debug/
target/silo-runtime/darwin-arm64/release/
target/silo-runtime/linux-amd64-gnu/release/
target/silo-runtime/linux-arm64-gnu/release/
```

Developers select a staged root through `RuntimeConfig` or
`SILO_RUNTIME_DIR`. `libvm` does not inspect arbitrary Cargo target directories.

The staged payload is the common input to the app, Linux packages, SDK platform
packages, and runtime archives. Packagers do not rebuild or substitute
components after staging, except for required platform signing and container
metadata.

## macOS Product Layout

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

### Bundle-Origin Discovery

The CLI derives its bundle from the real executable rather than from the path
used to invoke it. It obtains `std::env::current_exe()`, canonicalizes that path,
and recognizes the fixed structure:

```text
<bundle>/Contents/MacOS/silo
```

It then validates the expected Silo bundle identity from `Info.plist` and
derives `Helpers` and `Resources` from `Contents`.

This preserves Homebrew Cask invocation:

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
`~/Applications/Silo.app`. No lookup assumes that the app is under
`/Applications`.

Copying `Contents/MacOS/silo` out of the bundle is not a supported way to expose
the command because the copied executable has lost its bundle origin. Command
exposure uses a symlink. A copied executable may still use an explicit runtime
root or a conventional shared installation, but it does not claim the copied
app's package-owned resources by name alone.

The app bundle is read-only product content. Creating or starting a machine
never writes into it.

## Linux Product Layouts

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

The internal resolver therefore models explicit resolved component paths. It
does not pretend that every native installation has one physical runtime root.

Distro packages do not install into `/usr/local`, which is reserved for local
administrator installations. A source or administrator installation may use:

```text
/usr/local/bin/silo
/usr/local/lib/silo/bin/
/usr/local/lib/silo/assets/
```

The default assets are architecture-specific. The kernel differs between
arm64 and amd64, the agent is a compiled guest executable, and the initramfs
contains architecture-specific executables. Package-owned defaults therefore
belong below a private `lib` directory rather than `/usr/share` or
`/usr/local/share`.

The current `/usr/local/share/silo/assets` location is a transitional lookup
fallback, not the canonical destination for new packages.

## XDG User Paths

Linux and macOS use the same XDG conventions for user-owned product files and
mutable state. Silo does not use `~/Library/Application Support`,
`~/Library/Caches`, or `~/Library/Logs` on macOS.

| Purpose | Environment location | Fallback on Linux and macOS |
| --- | --- | --- |
| Data root, database, machines | `$XDG_DATA_HOME/silo` | `$HOME/.local/share/silo` |
| Images | `$XDG_DATA_HOME/silo/images` | `$HOME/.local/share/silo/images` |
| Downloaded runtimes | `$XDG_DATA_HOME/silo/runtimes` | `$HOME/.local/share/silo/runtimes` |
| Downloaded kernels | `$XDG_DATA_HOME/silo/kernels` | `$HOME/.local/share/silo/kernels` |
| Configuration | `$XDG_CONFIG_HOME/silo` | `$HOME/.config/silo` |
| Cache | `$XDG_CACHE_HOME/silo` | `$HOME/.cache/silo` |
| Logs and durable operational state | `$XDG_STATE_HOME/silo` | `$HOME/.local/state/silo` |
| Sockets, locks, and PID files | `$XDG_RUNTIME_DIR/silo` | An owner-isolated directory below `std::env::temp_dir()` |

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

Durable operational output has a fixed state layout:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/silo/
  logs/
    machines/
      <machine-id>/
        vm.trace.log
        serial.log
        vm.exit.json
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
below the data root. Logs and exit records are durable operational state but are
not canonical machine configuration. PID files, sockets, network runtime files,
and locks are ephemeral and never belong below the data root in a newly created
layout.

Existing installations may contain logs, PID files, sockets, and exit records
inside `data-root/machines/<machine-id>`. Migration runs only while that machine
is stopped. It moves durable logs and exit records into the state layout, drops
stale ephemeral files, and leaves canonical machine data in place. If the
machine is active, migration fails with an actionable stop-and-retry error.
Legacy files are not silently deleted before their durable replacements have
been moved successfully.

XDG environment paths and `$HOME` must be absolute when used. A relative value
is rejected rather than interpreted relative to the process working directory.

### Ephemeral Runtime Directory

The run-root resolution order is:

1. Explicit `RuntimeConfig` run root.
2. `$XDG_RUNTIME_DIR/silo`.
3. An owner-isolated path derived from `std::env::temp_dir()`.

Silo uses Rust's platform temporary-directory resolution rather than reading
`TMPDIR` directly. On macOS that API normally returns the user's Darwin
temporary directory, so the fallback is `<temp-dir>/silo`. On systems where the
returned base is shared, including the common Linux `/tmp` case, the fallback
includes the effective user identity, for example `/tmp/silo-1000`.

The directory is created with mode `0700`. Silo verifies that it is a real
directory owned by the effective user and rejects symlinks, foreign ownership,
or unsafe permissions. It never uses a cross-user `/tmp/silo` directory.

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

The exact internal type is not a public compatibility promise. The invariant is
that normal resolution selects one coherent installation rather than mixing
helpers and assets from unrelated locations.

### Precedence

Resolution follows this order:

1. Explicit per-component API paths.
2. An explicit API `runtime_root` using the portable layout.
3. Existing per-component environment variables.
4. `SILO_RUNTIME_DIR` using the portable layout.
5. A runtime bundled with the caller.
6. A runtime relative to the canonical current executable, including
   `Silo.app`.
7. Conventional native package locations.
8. Transitional `PATH`, sibling-binary, and historical asset fallbacks.
9. A missing-runtime error.

Existing environment controls remain available while lookup is centralized:

```text
SILO_VMMON_PATH
NETD_BIN
KRUN_BIN
SILO_ASSET_DIR
```

`SILO_RUNTIME_DIR` selects the complete portable root. Explicit per-component
paths can replace individual files for testing and embedding.

All explicit paths are absolute. Portable-root resolution verifies that derived
paths remain below the selected root and are regular files. `vmmon`, `netd`,
`krun`, and `agent` must be executable. `kernel-default` and `initramfs` must be
readable but need not be executable. App-bundle resolution additionally
validates bundle identifier `sh.silo.app`, exact release compatibility,
architecture, and minimum system version. Native package resolution checks only
a small documented set of platform paths; it does not query dpkg, rpm,
Homebrew, Spotlight, or mounted volumes.

Explicit machine asset overrides remain independent. An explicit machine
kernel, initramfs, or agent wins for that asset without replacing the other
defaults. Every omitted asset comes from the one asset directory selected by
the resolved installation. `SILO_ASSET_DIR` likewise selects one complete
default asset set. Transitional asset locations are considered as complete
directories and never mixed per file.

A failure identifies the missing component, the candidate locations considered,
the malformed override if one was supplied, and the expected native or portable
layout.

## No Runtime Manifest

A path-bearing manifest cannot eliminate discovery:

```text
find component
  -> read manifest

find manifest
  -> still requires a convention
```

Once a convention finds the manifest, the same convention can derive this
atomic runtime's fixed paths directly. A manifest would become justified if
components were independently installed, independently upgraded,
content-addressed, supplied by third parties, or selected among coexisting
compatibility generations. None of those conditions applies to the initial
runtime.

There is also no `--component-info` protocol. Release identity and provenance
belong in application metadata, package metadata, release checksums, SBOMs, and
attestations rather than a subprocess probe required for discovery.

## Version Compatibility

Official runtime components are co-versioned and updated atomically. The initial
compatibility policy is deliberately strict:

- product packages co-install one matching CLI and runtime;
- Node and Python platform packages use the exact SDK package version;
- Go downloads the exact runtime release matching the SDK version;
- direct Rust consumers use a co-installed runtime or pass an explicit root;
- custom mixed-version component paths are unsupported and remain the caller's
  responsibility;
- runtime components are not upgraded independently.

This avoids inventing compatibility ranges before Silo has a real independent
component compatibility promise. A later protocol negotiation mechanism may be
added if independent updates become necessary. It does not require changing the
path-discovery design.

## Default Kernel Provenance

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
kernel.

The initramfs and agent are built from the corresponding Silo source release.
Staging verifies that all three default assets match the target architecture.

Additional user-installed kernels are deferred. When added, they live below the
XDG data root and never modify `Silo.app` or package-owned `/usr` paths.

## macOS Distribution

The initial macOS channels are:

1. A signed, hardened, notarized, and stapled DMG containing `Silo.app`.
2. An official Homebrew tap containing a Cask for the same app bundle.
3. Signed target runtime archives where an SDK transport requires one.

The Cask installs the app and exposes its CLI with a symlink equivalent to:

```ruby
app "Silo.app"
binary "#{appdir}/Silo.app/Contents/MacOS/silo", target: "silo"
```

A tap is the repository containing package definitions. A Cask is the
definition that installs the prebuilt application.

A PKG is deferred until direct non-Homebrew command installation, installer
receipts, enterprise deployment, or MDM support is required. A DMG does not
place a command on `PATH` by itself.

Installing into `/Applications` or a system command directory may require
administrator authorization. A no-admin installation may use:

```text
~/Applications/Silo.app
$HOME/.local/bin/silo -> ~/Applications/Silo.app/Contents/MacOS/silo
```

### Signing

Production signing happens after the complete app is assembled. Nested code is
signed from the inside out without `codesign --deep`.

`vmmon` receives the Virtualization entitlement. `krun` receives the Hypervisor
entitlement. Other entitlements are granted only when their need is demonstrated
for that executable. The CLI and `netd` do not inherit virtualization
entitlements merely because they share the bundle.

The release pipeline:

1. Builds arm64 binaries with a macOS 26 deployment target.
2. Builds arm64 guest assets.
3. Resolves the arm64 kernel OCI artifact.
4. Assembles the complete app.
5. Inspects every Mach-O dependency.
6. Rejects Nix-store, build-prefix, and unavailable non-system dependencies.
7. Signs nested executables with a Developer ID Application identity.
8. Signs the outer app with hardened runtime and timestamping.
9. Builds the DMG.
10. Submits the distribution through `xcrun notarytool`.
11. Staples and validates the notarization ticket.
12. Tests the result on a clean macOS 26 machine without development tools.

Ad-hoc signing remains a development convenience and is not a release
signature.

## Linux Distribution

Release CI produces separate amd64 and arm64 artifacts:

- Debian packages;
- RPM packages;
- Arch binary packages;
- generic `.tar.zst` runtime or CLI archives;
- detached checksums and signatures;
- SBOM and provenance records.

Silo uses nFPM directly for deb, rpm, and Arch package construction. The payload
contains Rust binaries, a Go binary, generated assets, and a kernel artifact, so
separate Rust-only package generators would duplicate layout configuration.

AUR publication remains separate and requires a reviewed `PKGBUILD`. The
nFPM-produced Arch package remains useful as a direct binary release.

Linux binaries are built against the glibc 2.39 baseline. CI records the symbol
versions required by each final ELF file and rejects dependencies on newer glibc
or libstdc++ symbols. A future baseline change updates the support matrix and
every Linux transport together.

There is no system daemon, service unit, setuid executable, or privileged
runtime installation helper.

## Node Distribution

The Node SDK is a TypeScript facade over a native N-API addon. It does not launch
the `silo` CLI.

The package family consists of a platform-neutral `silo` package and exact-
version optional platform packages, conceptually:

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
install script.

The exact npm scope is finalized before publication. The platform package
contract is:

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
overrides retain higher precedence.

The loader does not use `process.execPath`, run a postinstall downloader,
download at first VM start, search arbitrary global npm locations, or require a
separate Silo CLI installation.

## Python Distribution

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

## Go Distribution

Go modules have no clean equivalent to npm optional platform packages or Python
platform wheels. A future Go SDK therefore exposes an explicit installation API
such as `InstallRuntime`. Installation never occurs during package import,
`init()`, runtime open, VM start, or a hidden postinstall hook.

The exact SDK-matched runtime is installed using the same XDG location on Linux
and macOS:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/silo/runtimes/<version>/<target>/
```

Examples are:

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
pre-seeding only when their archive matches the embedded digest.

The installation API returns the runtime root. `libvm` remains unaware of the
download.

## Rust Distribution

`libvm` is the native Rust API boundary. Direct Rust consumers may use a
conventionally installed Silo runtime, pass a portable runtime root, or pass
explicit component paths.

`libvm` does not download runtime components, install system packages, pull the
default kernel, extract embedded executables, or infer arbitrary host-
application resource directories. A future Rust convenience installer belongs
in a separate explicit setup API or crate.

## SDK Shared Discovery

Self-contained Node and Python packages use their package-local runtime before
native shared-installation conventions, subject to explicit API and environment
overrides.

A macOS SDK without a bundled runtime may check exactly:

```text
$HOME/Applications/Silo.app
/Applications/Silo.app
```

It validates bundle identity, host architecture, minimum OS version, and app
release metadata before use. It does not use Spotlight, scan mounted volumes, or
execute the first application named `Silo.app`.

Linux SDK packages are self-contained. Selecting a shared distro installation
instead requires an explicit override unless compatibility can be established
without querying package-manager databases.

## Size Budget

The initial compressed budget is 50 MiB for each Node platform package and
Python platform wheel carrying the complete runtime. It is a product budget,
not a file-format limit.

Release CI reports compressed and installed sizes for every target. Exceeding
the budget requires an explicit reviewed exception with the responsible
components identified. Size pressure does not justify removing required runtime
files or introducing an implicit first-run downloader.

## Release Staging

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
is not installed and is never consulted by `libvm`.

There is no free single tool that safely owns every Silo release concern. The
toolchain is intentionally composed:

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
payload rather than one third-party packager.

## Integrity Boundaries

Distribution channels establish trust differently:

| Channel | Primary trust mechanism |
| --- | --- |
| `Silo.app` | Apple code signature, hardened runtime, notarization, and stapling |
| Homebrew Cask | Signed app plus Cask artifact checksum |
| deb, rpm, Arch | Signed package or repository plus package-owned installed files |
| npm | Registry integrity plus signed Mach-O files on macOS |
| Python | Wheel/index integrity plus signed Mach-O files on macOS |
| Go runtime download | Target digest embedded in the exact Go SDK release and Go module checksum provenance |
| Generic archive | Detached release signature and checksum |

Normal VM launch does not rehash the entire runtime. A future `silo doctor` may
validate files, modes, dynamic dependencies, release checksums, macOS
signatures, target architecture, and kernel provenance.

Release materials retain required third-party notices, including libkrun's
Apache-2.0 attribution.

## Release Gates

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

### SDKs

- A clean npm installation with no system Silo boots a VM.
- A clean Python wheel installation with no system Silo boots a VM.
- Go explicit installation verifies and boots the downloaded exact runtime.
- Missing platform packages produce actionable errors.
- Unsupported targets fail before download or process spawn.
- Compressed size is reported and remains within budget unless waived.

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

- `libvm` never installs assets;
- a product package may be the installation that owns default assets;
- a language platform package may itself own a bundled runtime;
- SDK runtime transport is packaging behavior, not runtime-library behavior.

ADR 0009's independent explicit machine overrides, per-launch default
resolution, and composite initramfs behavior remain unchanged. This ADR
supersedes two narrower parts of ADR 0009: a language platform package may own
its bundled defaults, and omitted defaults are resolved as one installation
asset set rather than falling through independently across directories.

## Consequences

The normal CLI and SDK paths receive one complete, coherent runtime without
manual configuration. The same staged files are qualified across transports,
macOS bundles remain relocatable, Linux packages follow native conventions, and
`libvm` remains a runtime library rather than a package manager. Removing the
dynamic libkrun sidecar also removes a loader, RPATH, and nested-signing failure
class.

The design deliberately duplicates runtime bytes across Node and Python target
packages. Security fixes require updated SDK platform packages. macOS releases
need native signing infrastructure, Linux releases need amd64 and arm64 builders
and KVM qualification, and Go needs a secure explicit installer. Package size
becomes a maintained product constraint.

Convention-based discovery must produce strong diagnostics because there is no
manifest to inspect. Native package layouts also require the resolver to model
explicit components rather than force every installation into one physical
root.

## Rejected Alternatives

### Path-Bearing Runtime Manifest

Rejected because finding the manifest still requires a convention and the
initial runtime is one atomic compatibility set with deterministic paths.

### Component Information Commands

Rejected because `--component-info` adds subprocess API and startup complexity
without solving a current independent-versioning requirement.

### Embedded Executable Bytes

Rejected because helpers must be executable files, kernels need stable paths,
macOS signatures must remain valid, and extraction adds locking, permissions,
cleanup, and Gatekeeper failure modes.

### Shared Runtime Only

Rejected because requiring every Node and Python user to install a separate
system product makes SDK deployment unnecessarily fragile.

### Runtime Downloads In libvm

Rejected because acquisition, update, mirror, and trust policy do not belong in
the core runtime library.

### Implicit SDK Downloads

Rejected because downloading during import, runtime open, or VM start creates
surprising network access and nondeterministic offline behavior.

### One Universal Physical Layout

Rejected because app bundles, FHS packages, SDK packages, and user-owned XDG
runtimes have distinct ownership and installation conventions.

### Dynamic libkrun Sidecars

Rejected and superseded by compiling the pinned libkrun fork directly into the
krun helper.

### One Generic Release Tool

Rejected because a paid generic packager does not replace Silo's mixed-language
staging, per-executable Apple entitlements, signing order, and clean-machine
qualification.

## Deferred Work

The following remain separate decisions or implementation work:

- selecting krun instead of VZ on macOS;
- PKG and enterprise or MDM installation;
- independently updated runtime components and compatibility ranges;
- additional downloaded kernel management;
- final npm scope and Python or Go public API design;
- a `silo doctor` integrity and diagnostics command;
- publishing an AUR `PKGBUILD`.

The layouts, discovery rules, XDG ownership model, and release staging contract
in this ADR are intended to support those additions without replacement.
