# Packaging Silo for Distribution

Silo combines a frontend, private host executables, and architecture-specific
guest boot assets. A package must install these components as one compatible
release rather than distributing the `silo` executable by itself.

> [!IMPORTANT]
>
> This document is accurate only for the Silo source alongside it. When
> packaging another revision or release, use the `PACKAGING.md` from that exact
> source version.

## Supported Targets

Release packaging is host-native. The supported targets are:

| Target | Build host | Product floor |
| --- | --- | --- |
| `darwin-arm64` | Apple Silicon macOS | macOS 26 or newer |
| `linux-amd64-gnu` | x86-64 GNU/Linux | glibc 2.39 |
| `linux-arm64-gnu` | arm64 GNU/Linux | glibc 2.39 |

The Makefile derives the target from the host and rejects unsupported hosts.
Cross-architecture packaging is not a supported release path.

## Prerequisites

Enter the pinned development environment from the repository root:

```bash
nix develop
```

The shell provides the expected Rust, Go, Zig, OCI, archive, and packaging
tools. macOS packaging additionally uses native Apple command-line tools.

Run `make help` for the complete supported interface.

## Building Release Artifacts

Build the same credential-free artifacts as release qualification CI:

```bash
make release \
  KERNEL_REFERENCE=ghcr.io/vandycknick/silo/kernel:stable \
  RELEASE_BUILD_NUMBER=1
```

This runs repository verification, canonical release staging, portable archive
packaging, and, on macOS, ad-hoc application and DMG packaging.

The individual phases are:

```bash
make verify
make release-stage KERNEL_REFERENCE=ghcr.io/vandycknick/silo/kernel:stable
make package-archives
make package-macos RELEASE_BUILD_NUMBER=1
```

Outputs below `target/` are disposable. Each phase replaces its own previous
local output. Release metadata records the current `HEAD` revision and commit
timestamp even when the worktree contains uncommitted changes.

## Release Staging

`make release-stage` builds and validates one canonical payload for the native
target. Package transports consume these exact staged files instead of
rebuilding transport-specific variants.

The runtime stage is:

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

The release stage is:

```text
target/silo-release/<target>/release/
  bin/
    silo
  metadata/
    release.json
    kernel-provenance.json
    inspection.json
```

`release.json` records component paths, modes, sizes, SHA-256 digests, source
identity, target, version, and runtime layout. Kernel provenance records the
resolved OCI index, manifest, configuration, and layer digests.

## Portable Archives

Create deterministic runtime and complete CLI archives with:

```bash
make package-archives
```

The output is:

```text
target/silo-artifacts/<target>/<version>/
  silo-runtime-<version>-<target>.tar.zst
  silo-runtime-<version>-<target>.tar.zst.sha256
  silo-<version>-<target>.tar.zst
  silo-<version>-<target>.tar.zst.sha256
  archives.json
```

The runtime archive contains the private helpers and assets. The complete CLI
archive adds `bin/silo`. Both contain `THIRD_PARTY_NOTICES.txt`, have a single
top-level directory, and use the source commit timestamp for deterministic
archive metadata.

## System Packages

Downstream Linux package maintainers can stage a host-native installation with
standard `DESTDIR` and `PREFIX` values:

```bash
make
make install DESTDIR=/tmp/silo-package PREFIX=/usr
```

This produces:

```text
/usr/bin/silo
/usr/libexec/silo/vmmon
/usr/libexec/silo/netd
/usr/libexec/silo/krun
/usr/lib/silo/assets/kernel-default
/usr/lib/silo/assets/initramfs
/usr/lib/silo/assets/agent
```

`PREFIX` must be absolute. When present, `DESTDIR` must also be absolute.
Package-owned product files are immutable; machine state, images, sockets,
logs, and caches remain in user-owned state directories.

## macOS Application and DMG

macOS packaging consumes the canonical `darwin-arm64` release stage. It does
not rebuild or replace staged components. Packaging must run from the same Git
revision recorded by release staging, and component bytes, modes, sizes, and
digests must still match `release.json`.

Create an ad-hoc signed local package with:

```bash
make package-macos RELEASE_BUILD_NUMBER=1
```

Create a Developer ID signed and notarized package with:

```bash
make package-macos \
  RELEASE_BUILD_NUMBER="$RELEASE_BUILD_NUMBER" \
  MACOS_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
  MACOS_NOTARY_KEYCHAIN_PROFILE=silo-release \
  MACOS_NOTARY_KEYCHAIN=/absolute/path/to/release.keychain-db
```

The identity must already be available to `codesign`. Configure the notary
profile separately with `xcrun notarytool store-credentials`. Omit
`MACOS_NOTARY_KEYCHAIN` only when the profile is in the default Keychain.

The packager directly constructs the image with native Apple tools. It creates
a writable HFS+ image, copies the signed app with `ditto`, installs the volume
icon and deterministic Finder metadata, then performs the final UDZO
conversion:

```text
signed Silo.app
      |
      v
hdiutil create and attach
      |
      v
writable HFS+ image populated by xtask
      |
      v
hdiutil convert with bounded lock retries
      |
      v
verified UDZO DMG
```

Safe, idempotent `hdiutil` creation, detachment, and conversion retry only
`Resource busy` and `Resource temporarily unavailable`, with 2, 4, 8, and
16-second delays. This handles short-lived Spotlight or endpoint-security
locks without hiding malformed-image or permission failures.

Finder presents a plain 660 by 400 icon-view window with hidden chrome.
`Silo.app` uses a 160-pixel icon at `(180, 170)`, and Applications is at
`(480, 170)`. The repository stores this presentation in a deterministic
`.DS_Store`; packaging neither starts Finder nor requires Apple Events
permission.

The image has exactly these visible root items:

```text
Silo.app/
Applications -> /Applications
```

Hidden Finder metadata and the volume icon are allowed. The packager mounts the
completed image read-only and rejects a missing or incorrect link, unexpected
visible content, a damaged app signature, or an image that fails
`hdiutil verify`.

The output is published atomically at:

```text
target/silo-artifacts/darwin-arm64/macos/
  Silo.app/
  Silo-<version>-darwin-arm64.dmg
  macos.json
```

## macOS Signing and Notarization

Production packaging signs `vmmon`, `netd`, and `krun` explicitly, then signs
the outer app. Signing never uses `codesign --deep`; recursive `--deep`
verification is allowed after explicit inside-out signing.

The app and final DMG are submitted separately through `xcrun notarytool`.
Each submission uses explicit submit, wait, and log operations. Accepted
tickets are stapled and validated, and `macos.json` records both submission
UUIDs. This preserves offline Gatekeeper validation after the app is copied out
of the image.

Ad-hoc signing is suitable only for local and credential-free CI
qualification. It does not satisfy the public release trust contract.

## Homebrew Cask

After uploading the notarized DMG to the matching draft GitHub Release,
download that exact asset through GitHub's authenticated release-asset API.
Generate the Cask from the separately downloaded file:

```bash
make package-homebrew-cask \
  PUBLISHED_MACOS_DMG=/absolute/path/to/downloaded-release-asset.dmg
```

The generator performs no network access. It requires a non-symlink regular
file whose size and checksum match the local candidate and `macos.json`. It
also validates the local DMG's Developer ID signature, stapled ticket,
Gatekeeper assessment, and image integrity.

The generated Cask is:

```text
target/silo-artifacts/darwin-arm64/homebrew/Casks/vandycknick-silo.rb
```

The Cask installs `Silo.app` and exposes `Contents/MacOS/silo` as the `silo`
command. Publication to <https://github.com/vandycknick/homebrew-tap> remains a
protected release-workflow operation.

## Verification

Rust packaging changes require:

```bash
cargo fmt --all --check
cargo test -p xtask
make clippy
```

Credential-free native qualification is:

```bash
make release \
  KERNEL_REFERENCE=ghcr.io/vandycknick/silo/kernel:stable \
  RELEASE_BUILD_NUMBER=1
```

Production macOS candidates additionally require:

```bash
codesign --verify --deep --strict --verbose=4 Silo.app
codesign --verify --strict --verbose=4 Silo-<version>-darwin-arm64.dmg
xcrun stapler validate -v Silo.app
xcrun stapler validate -v Silo-<version>-darwin-arm64.dmg
spctl --assess --type execute --verbose=4 Silo.app
spctl --assess --type open \
  --context context:primary-signature \
  --verbose=4 \
  Silo-<version>-darwin-arm64.dmg
hdiutil verify Silo-<version>-darwin-arm64.dmg
```

## Clean-Host Qualification

GitHub-hosted arm64 macOS runners cannot satisfy the VZ boot gate because they
do not provide nested virtualization. Before approving a production release,
test the exact draft asset on a clean native Apple Silicon macOS 26 host.

1. Download the draft DMG identified by the candidate workflow summary.
2. Match its SHA-256 with the workflow summary and `macos.json`.
3. Add `com.apple.quarantine` when the download mechanism did not add it.
4. Verify the DMG signature, stapled ticket, Gatekeeper assessment, and image.
5. Open the image and inspect the app icon, volume icon, labels, positions, and
   Applications link.
6. Copy `Silo.app` to `/Applications` through the displayed link.
7. Verify the installed app signature, stapled ticket, and Gatekeeper assessment.
8. Clear development runtime overrides and run a command in a fresh VZ guest.
9. Confirm helpers and boot assets resolve from inside the installed app.
10. Record the host, tester, date, digest, command, and result in the deployment
    approval.

The VZ check should include a command equivalent to:

```bash
unset SILO_RUNTIME_DIR SILO_VMMON_PATH SILO_ASSET_DIR NETD_BIN KRUN_BIN
/Applications/Silo.app/Contents/MacOS/silo run \
  --image ubuntu:24.04 \
  -- uname -a
```

Approve the protected `release` environment only after every check passes.

## Release Workflows

`.github/workflows/release.yml` is the manual, credential-free,
non-publishing qualification workflow. It builds an ad-hoc macOS package and
portable archives, verifies them, and retains them as workflow artifacts.

`.github/workflows/publish.yml` is the protected production workflow. It must
be dispatched at an existing exact `v<version>` tag. It builds and notarizes a
draft candidate, authenticates and re-downloads the assets, generates and
audits the Cask, then waits for clean-host approval before publication.

Release tags are immutable. A candidate that fails qualification is not fixed
by moving its tag or replacing an uploaded asset. Correct the source, delete
the failed draft, and cut a new version and tag.
