# ADR 0012 Implementation Plan

This document is the execution plan for
[ADR 0012](0012-cross-platform-runtime-and-sdk-packaging.md). It is deliberately
commit-oriented: each stage below must be implemented, verified, documented,
and committed before the next stage starts.

## Implementation Tracker

The implementing agent must keep this tracker current. Leave a commit unchecked
while it is in progress. Check it only after all of that commit's acceptance
criteria pass, then include the tracker update in the same commit as the
implementation.

- [x] Commit 01: Correct and finalize ADR 0012
- [x] Commit 02: Reset the SQL schema and durable root identity
- [x] Commit 03: Split data, state, and run paths securely
- [x] Commit 04: Centralize runtime component resolution
- [x] Commit 05: Remove late helper and asset discovery
- [x] Commit 06: Establish the Make and xtask build interface
- [x] Commit 07: Build adjacent development runtimes and canonical stages
- [x] Commit 08: Isolate release linking and audit binaries
- [x] Commit 09: Produce common release archives and metadata
- [x] Commit 10: Assemble and sign `Silo.app`
- [ ] Commit 11: Build the DMG with `create-dmg` and install on macOS
- [ ] Commit 12: Build and qualify native Linux packages and installs
- [ ] Commit 13: Split and package the Node SDK
- [ ] Commit 14: Add continuous integration and package qualification
- [ ] Commit 15: Add protected release and Homebrew publication

## Instructions For The Implementing Agent

### Commit Discipline

Implement this plan in order, one commit at a time. Do not combine stages merely
because adjacent work touches the same files. The sequence is designed so that
runtime behavior stabilizes before product packaging and SDK transport build on
it.

For every commit:

1. Read `AGENTS.md`, ADR 0012, this plan, and the files named by the commit.
2. Refresh `git status`, the relevant diff, and recent commit history before
   editing. Treat pre-existing changes as belonging to the user or another
   agent.
3. Implement only the current unchecked commit.
4. Keep the smallest maintainable design that satisfies the ADR. Remove code
   made obsolete by the breaking change instead of retaining compatibility
   shims.
5. Run the commit's acceptance commands and fix all failures caused by the
   change.
6. Update this document if file locations, commands, or implementation details
   changed during the work. Do not silently change an architectural decision.
7. Check the current commit in the tracker only after its acceptance criteria
   pass.
8. Inspect `git status` and the complete diff. Stage only files belonging to the
   current commit, including this updated plan.
9. Create a normal, non-amended local Git commit matching the repository's
   current commit-message style.
10. Never push a branch, tag, commit, package, release, Cask, or other change
    upstream. The implementation task ends with local commits only.

If a commit is blocked, leave its checkbox unchecked, record the blocker in the
relevant commit section, and ask the user how to proceed. Do not skip ahead when
later work depends on the blocked behavior.

Do not rewrite, reset, revert, or clean unrelated worktree changes. If concurrent
changes conflict directly with the current stage, stop and ask the user rather
than choosing which work to discard.

### Autonomous Decision Log

From 2026-07-26 onward, when a question would otherwise block progress, the
implementing agent must record the exact question, concise options, selected
default, and rationale in this plan, then proceed with the safest
plan-compatible default. Do not add entries without an actual decision point.

- 2026-07-26, Commit 05 follow-up. Question: How should resolved `krun`
  propagation be tested without requiring KVM or a guest boot? Options: require
  a KVM-backed integration test; mock the backend; or execute a temporary
  `krun` helper through the real Linux backend. Selected default: execute the
  temporary helper in a Linux-native test. Rationale: it verifies the actual
  process boundary and forwarded arguments while remaining portable across
  Linux CI hosts without virtualization support.
- 2026-07-26, Commit 06. Question: Must the new `VERSION` authority govern the
  independently versioned `common/ext4` crate, which is currently `0.1.2`, as
  well as product artifacts? Options: rewrite every workspace crate to `0.1.0`;
  make version-check fail on the existing `ext4` version; or check the shipped
  Rust product manifests and Node package metadata only. Selected default:
  check the shipped product manifests, including `runtime/libvm` because its
  `CARGO_PKG_VERSION` validates the app-bundle version, plus `package.json` and
  both root package versions in the committed Node lockfile. Rationale: `ext4`
  is an existing reusable component rather than a product-version authority,
  and rewriting it would violate this commit's no-unrelated-version-rewrites
  rule.
- 2026-07-26, Commit 06 follow-up. Question: Use the already-locked direct
  `serde_json` dependency vs manual JSON parsing vs external npm/node? Options:
  add the already-locked `serde_json` dependency directly to xtask; manually
  parse OCI JSON; or depend on external npm/node tooling. Selected default:
  direct `serde_json`. Rationale: robust structured parsing is necessary for
  OCI descriptor validation and this adds no new transitive package.
- 2026-07-26, Commit 07. Question: Which stable OCI reference should ordinary
  developer builds consume when no fixed consumer reference is authoritative in
  the repository? Options: require every caller to supply a reference; infer a
  registry path dynamically from CI ownership; or use
  `ghcr.io/vandycknick/silo/kernel:stable` while retaining an explicit override.
  Selected default: `ghcr.io/vandycknick/silo/kernel:stable`. Rationale: the
  existing publisher constructs `ghcr.io/$owner/silo/kernel`, the repository
  identity is vandycknick/silo, and an explicit `KERNEL_REFERENCE`/xtask
  override remains available for forks and mirrors.
- 2026-07-26, Commit 07 follow-up. Question: How should an existing non-empty
  runtime directory be replaced without a reader-visible missing-path window
  on both supported host families? Options: retain the non-atomic backup
  rename; invoke platform commands; or add direct access to the already locked
  maintained `rustix` and `nix` syscall crates. Selected default: use
  `rustix::fs::renameat_with` with the native exchange flag and
  `nix::unistd::geteuid`. Rationale: rustix maps to Linux `renameat2` and Apple
  `renameatx_np`, keeping both paths in one maintained Rust API, while nix
  provides the required effective-UID API. No new transitive dependency is
  introduced and no direct libc call is necessary.
- 2026-07-26, Commit 08. Question: The validated Nix Go 1.26.4 toolchain embeds
  Nix-owned timezone and MIME data paths in `netd` even with `-trimpath` and
  `CGO_ENABLED=0`; should the auditor exempt those paths, keep the Nix compiler,
  or fetch a pinned upstream compiler? Selected default: download and verify the
  official Go 1.26.5 darwin-arm64 archive into the ignored release-tools cache.
  Rationale: allowing Nix strings would weaken the product boundary; Go 1.26.5
  is the current upstream patch release with a published archive digest and is
  compatible with the repository's `go 1.25.5` minimum.
- 2026-07-26, Commit 08. Question: Should the string auditor reject every
  `/tmp/` occurrence, including the documented `/tmp/silo-<effective-uid>`
  runtime fallback? Options: reject all temporary strings; exempt all temporary
  strings; or reject compiler-temporary prefixes while preserving the runtime
  contract. Selected default: reject `/tmp/rustc` and `/tmp/cargo` plus macOS
  temporary roots, while permitting the documented Silo fallback. Rationale: a
  blanket match would reject required production behavior rather than a build
  leak.
- 2026-07-26, Commit 08 follow-up. Question: Does a separate Linux target
  directory satisfy the requirement to build releases in the digest-pinned
  native environment? Options: permit direct Linux release builds after target
  cleanup; document the container as optional; or make repository orchestration
  enter the matching native container. Selected default: build, stage, verify,
  and component release commands enter the matching Docker image, with an
  explicit internal marker preventing recursion. Rationale: target separation
  prevents object reuse but cannot prevent an ambient Nix linker, SDK, or tool
  from participating, so the weaker reading would contradict the required
  environment boundary.
- 2026-07-26, Commit 08 follow-up. Question: Must macOS download separate Rust
  and Zig toolchains, or may the pinned dev-shell executables act as drivers?
  Options: download every compiler; accept arbitrary PATH tools; or accept only
  exact-version dev-shell drivers while forcing Apple SDK, clang, ld, and ar for
  final linkage. Selected default: exact-version drivers plus clean Apple
  linkage and post-link qualification. Rationale: the plan requires native Apple
  final linking, not duplicate toolchain distribution; accepting arbitrary PATH
  tools was neither required nor safe.
- 2026-07-26, Commit 08 correction. Question: Should local release commands
  retain tamper/fingerprint-ledger clean rebuilds, or use persistent incremental
  local builds while protected CI starts from a clean workspace and target?
  Options: tamper/fingerprint clean rebuilds; persistent incremental local
  builds plus clean CI. Selected: persistent incremental local builds plus clean
  CI, by explicit user direction: "prioritize fast compilation/recompilation and
  easy reliable development/package commands; no tamper prevention or
  picture-perfect auditing." Rationale: Cargo, Go, Zig, and kernel caches are
  already the correct dependency-aware rebuild mechanism; clean CI runners and
  targets provide the appropriate release isolation without making every local
  invocation a cold build.
- 2026-07-26, Commit 09. Question: When Syft is not installed in the active
  shell, should archive generation require a Nix-only tool, download a pinned
  binary, or omit local SBOMs? Options: add only a Nix development dependency;
  download and checksum-verify the official pinned Syft archive into the ignored
  release-tools cache; or omit local SBOM generation. Selected default: the
  checksum-verified pinned download, while also adding Syft to future Nix
  shells. Rationale: archives remain usable from the existing shell and CI
  without an unbounded installer or a Nix requirement, while every downloaded
  archive is checked against the reviewed official release digest.
- 2026-07-26, Commit 09 follow-up. Question: Should archive qualification fully
  re-audit every tar header or validate the release contract directly? Options:
  a generic header/fingerprint auditor; trust creation flags completely; or
  validate payload paths, types, modes, bytes, and directly consumed metadata.
  Selected default: validate the practical release contract. Rationale: fixed
  tar flags already normalize headers, while byte equality, executable modes,
  traversal rejection, and archive/SBOM/provenance consistency catch failures
  that affect packaging without turning local incremental builds into a
  perfect-audit system.
- 2026-07-26, Commit 10. Question: Should the generated `.icns` be committed,
  generated during every app assembly, or require an image dependency? Options:
  commit a binary icon; generate `Silo.icns` deterministically from the existing
  mark with macOS `sips` and `iconutil`; or add an image library. Selected
  default: generate it in the ignored app assembly directory with native tools.
  Rationale: it keeps the repository source-only, has no new dependency, and is
  inexpensive beside an incremental release stage.
- 2026-07-26, Commit 10. Question: What should supply `CFBundleVersion` for a
  local build? Options: require every invocation to provide a build number; use
  a wall-clock value; or accept `BUILD_NUMBER` and otherwise use `git rev-list
  --count HEAD`. Selected default: the explicit `BUILD_NUMBER` wins, with the
  commit count as the monotonic local default. Rationale: it follows Ghostty's
  release input while keeping `make app` runnable without release credentials.
- 2026-07-26, Commit 11. Question: How should the pinned `create-dmg` command
  be provided for local and CI packaging? Options: a committed, locked local npm
  installation; Nix's legacy package; or direct `npx` execution. Selected
  default: a committed `packaging/macos/package-lock.json` with local npm
  installation. Rationale: `create-dmg` 8.1.0 is exactly locked and its local
  binary can be reused after the first `npm ci --prefer-offline --no-audit
  --no-fund`; Nix does not provide the selected tool version, and `npx` would
  silently introduce an unpinned network/global fallback.
- 2026-07-26, Commit 11 follow-up. Question: How should a native `hdiutil`
  `Resource temporarily unavailable` failure during the selected `create-dmg`
  ULFO conversion be handled? Options: stop for a fresh host or CI run; retry
  the same pinned tool a bounded number of times; or replace the tool or its
  APFS/ULFO format. Selected default: retry the unchanged local `create-dmg`
  8.1.0 invocation at most three times after a short delay, detaching only an
  invocation-identified image and cleaning only its temporary package output.
  Rationale: this transient is outside Silo's app payload, a bounded retry
  improves local reliability without adding a custom DMG implementation or
  touching unrelated user images.

### Breaking-Change Policy

This implementation intentionally abandons compatibility with existing SQL
migration history and the old mutable-file layout. Do not add migration shims,
old environment aliases, fallback database readers, path aliases, or silent
data adoption unless this plan explicitly requires them.

The runtime-discovery controls explicitly retained by the final decision are
not compatibility accidents. They are part of the new authoritative contract:

```text
SILO_VMMON_PATH
NETD_BIN
KRUN_BIN
SILO_ASSET_DIR
SILO_RUNTIME_DIR
```

Do not rename or remove these variables while implementing this plan.

### Xtask Testing Policy

Do not create a test suite for xtask or its packaging code. In particular, do
not add command mocks, signing mocks, package-manager mocks, snapshot tests,
packaging fixtures, fake external tools, or a test-only abstraction layer around
process execution.

Existing focused tests for already implemented low-level behavior, such as
initramfs serialization, do not need to be deleted. Do not expand them into a
general build-script test suite.

Xtask is qualified by invoking real Make targets and examining, installing, and
booting the real artifacts in local development and CI. Those checks are product
acceptance gates, not tests of xtask internals.

### Rust And Dependency Workflow

For every commit that changes Rust:

1. Run `cargo fmt`.
2. Run the targeted tests listed by the commit.
3. Run `make clippy` before committing.

Do not add a dependency casually. Research maintenance and API fit first, then
confirm the dependency with the user as required by `AGENTS.md`. Prefer crates
already present in `Cargo.lock` when they fit. The runtime resolver will likely
need a maintained plist parser to support both XML and binary `Info.plist`
files; confirm that choice before Commit 04.

### Plan Maintenance

This document is a living implementation record. Keep it accurate while work
proceeds:

- Check completed commits in the tracker.
- Correct stale paths and commands discovered during implementation.
- Record an approved deviation in the affected commit before implementing it.
- Add newly discovered acceptance requirements to the affected unchecked
  commit.
- Do not weaken an acceptance criterion merely because it currently fails.
- When Commit 15 finishes, all tracker entries must be checked and ADR 0012 must
  be marked `Implemented`.

### Reference-First Packaging Rule

Before making a build, Nix, CI, app-bundle, signing, or packaging decision,
inspect the corresponding Ghostty implementation under
`/Users/nickvd/Sources/ghostty`. Record in the current commit notes which pattern
was reused and which Ghostty-specific behavior was intentionally not copied.

The primary Ghostty references are:

- `build.zig` and `src/build/Config.zig` for its typed build graph, profiles,
  artifact selection, and link policy.
- `flake.nix`, `nix/devShell.nix`, and `nix/package.nix` for Nix layout and the
  distinction between development, Nix packages, and shipped native artifacts.
- `src/build/GhosttyDist.zig` for assembling once and qualifying the assembled
  result.
- `.github/workflows/test.yml` for invoking locally reproducible commands from
  CI.
- `.github/workflows/release-tag.yml` for macOS build handoff, nested signing,
  `create-dmg`, notarization, stapling, and staged publication.
- `PACKAGING.md`, `flatpak/`, and `snap/` for the boundary between an upstream
  build and a downstream package environment.

Ghostty is a design reference, not source to transplant blindly. Silo does not
copy Ghostty's Swift app, Xcode project, XCFramework build, Sparkle updater,
Flatpak, Snap, or distro-packaging omissions. Silo keeps Make as its public
entrypoint, uses Rust xtask instead of Zig for orchestration, and owns deb, rpm,
and Arch package production.

For DMG behavior, use the official
[`create-dmg`](https://github.com/sindresorhus/create-dmg) tool rather than
copying its implementation. For Linux package configuration, consult the
official [nFPM documentation](https://nfpm.goreleaser.com/docs/).

## Fixed Architectural Decisions

### Supported Targets

The initial product targets are:

| Product host | Architecture | Active backend | Packaged backend helpers |
| ------------ | ------------ | -------------- | ------------------------ |
| macOS 26+ | arm64 | VZ | VZ and krun |
| Debian stable | amd64, arm64 | krun | krun |
| Ubuntu current LTS/stable | amd64, arm64 | krun | krun |
| RHEL current supported major | amd64, arm64 | krun | krun |
| Arch current | amd64, arm64 where available | krun | krun |

GNU/Linux host binaries have a glibc 2.39 ceiling. Guest `init` and `agent`
remain architecture-matched musl binaries. Intel macOS, Windows, and
cross-architecture guest CPU emulation remain out of scope.

### Runtime Payload

The canonical runtime payload is exactly:

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

The `silo` CLI is added by product packaging and is not part of the six-file
runtime payload. Runtime metadata, provenance, checksums, and SBOMs remain
adjacent release artifacts and are not installed as a runtime path manifest.

### Authoritative Runtime Resolution

`libvm` resolves components once while opening a `Runtime`, converts them to
absolute validated paths, and retains the immutable result for that runtime's
lifetime.

Resolution follows this exact order:

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

Malformed authoritative input fails immediately. For example, a relative or
incomplete `SILO_RUNTIME_DIR` must not fall through to executable-relative or
native-package discovery.

Explicit component choices may replace files supplied by a lower-precedence
complete candidate. Explicit machine kernel, initramfs, and agent overrides
remain launch-specific and independent.

There is no automatic lookup of these historical asset paths:

```text
/usr/local/share/silo/assets
$HOME/.local/share/silo/assets
```

A user may still select either directory explicitly with `SILO_ASSET_DIR`.

### Adjacent Development Runtime

The complete development layout is:

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
`<cargo-target-dir>/release/`.

The resolver canonicalizes `current_exe()` and checks only its direct directory.
It does not infer a workspace root, inspect `CARGO_TARGET_DIR`, identify a Cargo
profile, walk ancestors, or map to `target/silo-runtime`. Tests and consumers
whose executable is under `target/debug/deps` use explicit component paths,
`runtime_root`, or `SILO_RUNTIME_DIR`; discovery does not walk to `target/debug`.

Raw `cargo build -p cli` is allowed to produce an incomplete development
directory. Running that executable must fail with a diagnostic that lists the
missing adjacent components and recommends `make`.

### Portable Executable-Relative Runtime

A complete portable CLI archive has this shape:

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

When canonical `current_exe()` is `<portable-root>/bin/silo`, the resolver
derives the portable root and validates the fixed descendants. `Silo.app` is a
separate executable-relative shape using `Contents/Helpers` and
`Contents/Resources/assets`.

### Controlled PATH Resolution

`PATH` is disabled unless `SILO_ASSET_DIR` is explicitly set and successfully
validates as one complete asset set.

When enabled, PATH resolution:

1. Considers entries in PATH order.
2. Considers only absolute entries.
3. Requires `vmmon`, `netd`, and `krun` to exist and be executable in one entry.
4. Never combines helpers from different PATH entries.
5. Uses higher-precedence explicit helper overrides where supplied.
6. Reports every considered absolute candidate when no complete set is found.

An empty or relative PATH entry is not resolved against the working directory.

### Mutable Roots

The mutable roots are:

| Purpose | Environment | Default |
| ------- | ----------- | ------- |
| Data | `XDG_DATA_HOME/silo` | `$HOME/.local/share/silo` |
| State and logs | `XDG_STATE_HOME/silo` | `$HOME/.local/state/silo` |
| Images | Runtime-configured or data root | `$HOME/.local/share/silo/images` |
| Runtime files | `XDG_RUNTIME_DIR/silo` | `/tmp/silo-<effective-uid>` |

The fallback run root never uses `std::env::temp_dir()` or `TMPDIR`. Every run
root is a real non-symlink directory owned by the effective user with exact mode
`0700`. Unsafe existing directories are rejected rather than silently repaired.

`db_config` persists data, state, and image roots. It does not persist the run
root or runtime-component installation paths.

### Build And Packaging Interface

Make is the public repository interface. Rust xtask owns build and packaging
orchestration behind Make.

The expected user interface is:

```text
make
make build
make PROFILE=release

make cli
make vmmon
make netd
make krun
make agent
make init
make initramfs
make kernel

make stage
make stage PROFILE=release
make archive
make app
make package
make install
```

The default profile is debug. Product packaging and installation always perform
a release build regardless of `PROFILE`.

The Nix development shell prepends the workspace's absolute `target/debug`
directory to PATH. It does not add `target/release`.

### DMG Tooling

Silo does not implement a custom DMG writer or Finder-layout generator. Xtask
assembles, signs, and verifies `Silo.app`, then invokes the pinned
[Sindre Sorhus `create-dmg`](https://github.com/sindresorhus/create-dmg) command.
Local builds use `--no-code-sign`; protected release builds supply the Developer
ID identity. This follows Ghostty's high-level release behavior without copying
its Swift/Xcode application build.

## Commit 01: Correct And Finalize ADR 0012

Suggested intent: `docs: finalize cross-platform packaging architecture`

### Purpose

Make the accepted ADR match the final decisions before implementation begins.
The ADR currently contains the old temporary-directory fallback, compatibility
migration requirements, and broader transitional discovery.

### Ghostty Reference Notes

Inspected Ghostty's `Makefile`, `build.zig`, `src/build/GhosttyDist.zig`,
`nix/devShell.nix`, `nix/package.nix`, `PACKAGING.md`, and
`.github/workflows/release-tag.yml`.

- Reused the high-level separation of typed build orchestration, one assembled
  artifact qualified before transport, clean native macOS signing handoff, and
  downstream package staging through explicit prefix and `DESTDIR` boundaries.
- Reused the release ordering of app assembly, nested signing, `create-dmg`,
  notarization, stapling, and staged artifact handoff as the model for Silo's
  documented release flow.
- Intentionally did not copy Ghostty's peripheral Makefile, Zig build graph,
  Swift/Xcode app, XCFramework, Sparkle updater, Flatpak, Snap, or its
  downstream-owned distro packaging. Silo keeps Make as the public interface,
  Rust xtask as orchestrator, `create-dmg` as the DMG tool, and owns separately
  qualified deb, rpm, and Arch artifacts.

### Required Changes

Update `docs/adr/0012-cross-platform-runtime-and-sdk-packaging.md`:

- Replace every `std::env::temp_dir()` fallback with
  `/tmp/silo-<effective-uid>` on both Linux and macOS.
- State that Silo obtains the effective UID and creates or validates the run
  root as owner-only mode `0700`.
- Remove claims that old databases or old filesystem layouts are migrated.
- State that existing migration history and old mutable layouts are unsupported
  after this breaking release.
- Replace the runtime-discovery precedence with the exact ten-step order in
  this plan.
- Describe the adjacent development layout exactly.
- Describe portable executable-relative and `Silo.app` discovery separately.
- Retain `SILO_VMMON_PATH`, `NETD_BIN`, `KRUN_BIN`, and `SILO_ASSET_DIR`.
- Retain `SILO_RUNTIME_DIR` as the complete portable-root override.
- Specify the controlled PATH rule and same-entry helper invariant.
- Remove automatic historical asset-directory lookup.
- Remove language that calls `/usr/local/share/silo/assets` a transitional
  automatic fallback.
- State that `make` creates the complete adjacent development runtime while raw
  Cargo builds may be incomplete.
- Clarify that release staging remains under `target/silo-runtime`, but libvm
  does not infer that path from a Cargo executable.
- Clarify that Debian, Ubuntu, RHEL, and Arch receive separately qualified
  native-format artifacts made from the same staged bytes.
- State that `create-dmg` is the selected DMG builder.
- State that Make is the public build interface and xtask is its orchestrator.

Update `docs/adr/README.md` only if the ADR status or title changes. It should
remain `Accepted` until Commit 15.

### Acceptance Criteria

- ADR 0012 contains no `std::env::temp_dir()` runtime fallback.
- ADR 0012 contains no promise to migrate old SQL or mutable path layouts.
- The authoritative precedence is identical to this plan.
- The four existing environment controls remain documented.
- PATH is documented as disabled without explicit `SILO_ASSET_DIR`.
- Historical asset directories are not automatic candidates.
- The adjacent development layout and portable layout are both explicit.
- `create-dmg` is named as the DMG implementation.
- Markdown formatting is valid and internal statements do not contradict each
  other.

### Verification

```text
git diff --check
```

## Commit 02: Reset The SQL Schema And Durable Root Identity

Suggested intent: `libvm: reset the state schema for runtime roots`

### Purpose

Create one clean SQL baseline and make durable root identity match ADR 0012.
No existing database is upgraded.

### Required Changes

Replace the current migration history in `runtime/libvm/migrations/` with one
complete `0001_initial.sql`:

- Merge all final table, index, foreign-key, and trigger definitions from
  current migrations 0001 and 0002.
- Delete `0002_images.sql` and `0003_remove_vznat.sql`.
- Do not include the old vznat rewrite or deletion statements.
- Prefer plain `CREATE` statements so a partial fresh schema fails loudly.
- Change `db_config` to store `os`, `data_root`, `state_root`, and `image_root`.
- Remove `run_root` from `db_config`.
- Remove absolute `runtime_dir` from `network_instances`; derive network runtime
  placement from current `LocalPaths` and the network ID.

Update the Rust store and model code:

- Change `DbConfig` and `config_store` reads, inserts, and comparisons.
- Make data, state, and image roots durable database identity.
- Resolve run root from the current `RuntimeConfig` and environment on every
  open.
- Exempt run root from stored-root matching.
- Update network store queries, row decoding, lifecycle reconciliation, and
  cleanup to derive the current runtime directory.
- Remove touched compatibility aliases for the abandoned stored shape.
- Preserve all image/rootfs schema constraints and pruning behavior.
- Do not add old-ledger detection, migration repair, checksum bypasses, or data
  adoption.

Document the reset policy in the relevant libvm README or release-facing docs:
old `state.db` files must be manually removed or archived with all Silo
processes stopped.

### Acceptance Criteria

- Exactly one SQL migration exists.
- A fresh database contains all required machine, network, image, and rootfs
  tables and constraints.
- `db_config` contains `state_root` and does not contain `run_root`.
- Reopening a database with a different default run root succeeds.
- Explicit data, state, or image roots that conflict with stored identity fail.
- Network runtime paths are derived and not stored as durable absolute paths.
- No code attempts to upgrade old migration history.
- Existing store behavior on a fresh database remains covered by real tests.

### Verification

```text
cargo fmt
cargo test -p libvm store
cargo test -p libvm runtime::config
make clippy
git diff --check
```

### Implementation Notes

- `runtime/libvm/migrations/0001_initial.sql` is the sole plain-CREATE baseline;
  it includes the final image and rootfs schema without the old vznat rewrite.
- `state_root` is durable database identity but currently defaults to `data_root`.
  Commit 03 owns the filesystem split.
- Network runtime placement is derived from `LocalPaths::network(network_id)`;
  database rows contain no runtime directory or absolute runtime paths.
- Fresh-database coverage includes schema objects, durable-root conflicts, changed
  run-root reopening, and reconciliation cleanup. `cargo test -p libvm network`
  was also run for the real cleanup path.

## Commit 03: Split Data, State, And Run Paths Securely

Suggested intent: `libvm: separate durable and ephemeral runtime paths`

### Purpose

Implement XDG state placement, short owner-isolated socket paths, and the final
data/state/run filesystem model.

### Required Changes

Refactor `runtime/libvm/src/paths/` and all consumers:

- Add state-root resolution from absolute `XDG_STATE_HOME`, falling back to
  absolute `$HOME/.local/state/silo`.
- Resolve run root from explicit configuration, then absolute
  `XDG_RUNTIME_DIR/silo`, then `/tmp/silo-<effective-uid>`.
- Use `nix::unistd::geteuid`; do not call direct libc when nix exposes the API.
- Create and validate the selected run root without following the final
  symlink.
- Require directory type, effective-user ownership, and exact mode `0700`.
- Handle create races by validating an `AlreadyExists` result.
- Reject foreign ownership, symlinks, non-directories, and unsafe modes.
- Keep data, state, run, and image roots as distinct fields in `LocalRoots`.

Split machine paths:

- Keep machine config, disks, generated launch files, and composite initramfs
  under `data-root/machines/<machine-id>/`.
- Put `vm.pid` and `vm.sock` under
  `run-root/machines/<machine-id>/`.
- Put `vm.trace.log`, `serial.log`, and `vm.exit.json` under
  `state-root/logs/machines/<machine-id>/`.

Split network paths:

- Put netd socket, PID, generated policy, and current packet capture under
  `run-root/networks/<network-id>/`.
- Put `netd.log` under `state-root/logs/networks/<network-id>/`.
- Remove the machine-data `net` symlink and pass the real socket path through
  existing launch configuration.
- Derive cleanup and liveness paths from the current roots.

Use real temporary directories and subprocesses for permission and environment
tests. Do not mock the filesystem.

### Acceptance Criteria

- With no explicit run root or `XDG_RUNTIME_DIR`, the path is exactly
  `/tmp/silo-<effective-uid>`.
- The default machine and network socket paths fit Unix socket path limits on
  macOS and Linux.
- A newly created run root has exact mode `0700`.
- Symlink, wrong-owner, file, and unsafe-mode run roots are rejected.
- Relative XDG and HOME-derived inputs are rejected.
- Logs never appear below the data or run roots in a new layout.
- PID files and sockets never appear below the data root in a new layout.
- The current run root can change between Runtime opens without changing
  durable database identity.
- There is no old-layout migration code.

### Verification

```text
cargo fmt
cargo test -p libvm paths
cargo test -p libvm network
cargo test -p libvm runtime
make clippy
git diff --check
```

### Implementation Notes

- `LocalRoots` now resolves the durable state root independently. Run-root
  creation opens the final path with `O_NOFOLLOW | O_DIRECTORY`, validates its
  effective owner and exact `0700` mode, and uses `nix::unistd::geteuid`.
- Machine process files use `run-root/machines`, durable machine logs use
  `state-root/logs/machines`, and network runtime files use
  `run-root/networks`. The vmmon launch attachment receives the real netd socket
  path, so no machine-data network symlink remains.

## Commit 04: Centralize Runtime Component Resolution

Suggested intent: `libvm: centralize runtime component discovery`

### Purpose

Replace fragmented discovery with one authoritative resolver that returns a
complete immutable component set.

### Required Changes

Add an internal resolver, conceptually producing:

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

Change the public configuration as a deliberate breaking API:

- Add explicit paths for all six components.
- Add explicit `runtime_root`.
- Add a distinct bundled-runtime candidate for SDK frontends.
- Add matching `RuntimeBuilder` methods.
- Keep the retained environment variables exactly as named in this plan.
- Require all explicit paths and roots to be absolute.

Implement candidate resolution in the exact authoritative order:

- API component overrides.
- API portable root.
- Environment component overrides.
- `SILO_RUNTIME_DIR`.
- Caller-supplied bundled root.
- Complete adjacent development runtime.
- Portable executable-relative runtime and `Silo.app`.
- Controlled same-entry PATH helpers with explicit `SILO_ASSET_DIR`.
- Native package locations.

Implement validation:

- Canonicalize selected roots and fixed descendants.
- Reject a portable component whose canonical path escapes its root.
- Require helpers and agent to be regular executable files.
- Require kernel and initramfs to be regular readable files.
- Validate all three files selected by `SILO_ASSET_DIR` as one set.
- Reject malformed authoritative candidates instead of falling through.
- Record considered candidates for final diagnostics.

Implement executable-relative shapes without Cargo-specific inference:

- Adjacent development: helpers beside canonical `current_exe()`, assets in
  its direct `assets/` child.
- Portable: canonical executable in `<root>/bin`, helpers in the same `bin`,
  assets in `<root>/assets`.
- App: canonical executable in `Silo.app/Contents/MacOS`, helpers in
  `Contents/Helpers`, assets in `Contents/Resources/assets`.

For `Silo.app`, validate bundle identifier, exact public version, arm64,
minimum system version 26.0, and fixed layout. Search no package-manager,
Spotlight, or mounted-volume database.

Implement known native candidates only:

- Debian, Ubuntu, and Arch `/usr/lib/silo` layout.
- RHEL libexec and architecture-lib layout.
- Administrator `/usr/local/lib/silo` layout.
- The two documented installed-app locations for a macOS SDK without a bundled
  runtime.

### Acceptance Criteria

- `Runtime` receives one immutable resolved component set.
- Every precedence level is covered by focused libvm tests.
- Explicit malformed input stops resolution immediately.
- Adjacent discovery examines only the executable's direct directory.
- Portable discovery derives only the fixed parent `bin/assets` layout.
- PATH is not read without explicit `SILO_ASSET_DIR`.
- PATH never combines helpers from different entries.
- Empty and relative PATH entries are not working-directory candidates.
- No historical asset directory is searched automatically.
- App-bundle identity and compatibility failures are actionable.
- Missing-runtime errors identify missing components and considered candidates.
- Component installation paths are not persisted.

### Verification

```text
cargo fmt
cargo test -p libvm runtime::components
cargo test -p libvm runtime::builder
make clippy
git diff --check
```

### Implementation Notes

- `Runtime` resolves and retains one immutable internal component set at open.
  The existing launch-time helper and asset fallbacks remain temporarily for
  Commit 05, while vmmon already receives the resolved absolute path through
  its existing configuration plumbing.
- The user-approved `plist = { version = "1.10.0", default-features = false }`
  is used for XML and binary `Info.plist` parsing. This maintained pure-Rust,
  Rust 1.88-compatible choice locked `plist 1.10.0` and its `quick-xml 0.41.0`
  dependency.
- `cargo test -p libvm runtime::builder` initially selected no tests because
  the builder module had none. Focused builder API coverage was added, so the
  planned command now runs one test without changing its filter.
- A canonical executable in the `Silo.app/Contents/MacOS/silo` shape is an
  authoritative app candidate. It validates the bundle before adjacent or
  portable probing, so malformed app metadata cannot fall through to files in
  `Contents/MacOS`. Missing-runtime diagnostics aggregate invalid components by
  candidate, describe the fixed layouts, and recommend `make` for an incomplete
  adjacent development runtime. Linux native locations compile only on Linux;
  macOS checks only the two documented shared app locations.

## Commit 05: Remove Late Helper And Asset Discovery

Suggested intent: `runtime: launch only resolved components`

### Purpose

Make the centralized resolver authoritative by deleting every launch-time
fallback.

### Required Changes

Update vmmon launch:

- Launch the resolved absolute vmmon path directly.
- Remove vmmon PATH and generic sibling lookup.
- Add a private launch argument or launch-only configuration field carrying the
  resolved krun helper path into vmmon.

Update virt/krun launch:

- Consume the resolved krun path supplied by vmmon.
- Remove krun's environment, sibling, and PATH resolver.
- Keep the process boundary `vmmon -> krun`.
- Do not link libkrun into vmmon or libvm.

Update netd launch:

- Launch the resolved absolute netd path directly.
- Remove netd's environment, sibling, and bare-command fallback.

Update default boot assets:

- Use kernel, initramfs, and agent from the resolved installation set.
- Delete independent per-file directory fallthrough.
- Preserve explicit machine asset overrides.
- Ensure an omitted machine asset uses the selected installation's matching
  default.

Update callers:

- Adapt the CLI to the breaking `RuntimeConfig` API.
- Adapt the Node native crate enough to compile; full bundled Node transport is
  Commit 13.
- Update cleanup and subprocess paths so they use the current data/state/run
  root model.
- Update libvm and component documentation.

### Acceptance Criteria

- Searching for the removed late-resolver functions returns no production code.
- vmmon, netd, and krun are always launched with resolved absolute paths.
- `virt` does not read `KRUN_BIN` itself.
- netd does not pass a bare program name to `Command`.
- Default assets cannot come from multiple installations.
- Explicit machine overrides still replace only the requested asset.
- A runtime built from a complete temporary portable tree can prepare and start
  through the centralized paths.
- No runtime component is found by generic sibling or unrestricted PATH lookup.

### Verification

```text
cargo fmt
cargo test -p libvm runtime
cargo test -p libvm vmmon
cargo test -p libvm network
cargo test -p vmmon
cargo test -p krun
make clippy
git diff --check
```

### Implementation Notes

- `Runtime` launches its immutable resolved `vmmon` and `netd` paths directly,
  passes its resolved `krun` path to vmmon as a private argument, and supplies
  default boot assets only from the same resolved installation set.
- Real temporary portable-tree tests record the absolute vmmon, krun, and netd
  paths across the launch boundaries and clean netd using the current
  data/state/run roots. They exercise helper start handshakes without requiring
  host virtualization or a guest boot.
- A Linux-native `virt` test launches a temporary resolved `krun` executable
  through the real backend and verifies its forwarded arguments. It needs no
  KVM, but executes only on Linux hosts and is therefore a Linux CI/host gate.

## Commit 06: Establish The Make And Xtask Build Interface

Suggested intent: `build: make xtask the build orchestrator`

### Purpose

Make Make the stable user interface and move component-specific orchestration
into typed Rust code without creating an xtask test suite.

### Ghostty Reference Notes

Inspected Ghostty's `build.zig`, `src/build/Config.zig`, `flake.nix`,
`nix/devShell.nix`, `nix/package.nix`, and `PACKAGING.md` before changing build
or Nix behavior.

- Reused its high-level typed profile and artifact-selection boundary, root
  version-file preference, and thin-flake/delegated-development-shell layout.
- Intentionally did not copy Ghostty's Zig build graph, source-tarball and
  `DESTDIR` packaging flow, dynamic-linker policy, macOS/Xcode behavior, or
  downstream package derivation details. Silo keeps Make as the public
  interface and Rust xtask as the orchestrator.

### Required Changes

Refactor `xtask/src/main.rs` into small production modules for command running,
host-target mapping, profiles, component builds, and existing initramfs work.
Keep code together where splitting does not improve readability.

Add strong internal types for:

- `Profile` with only debug and release.
- Supported host target identifiers.
- Component identifiers.
- Cargo and guest target mappings.

Replace the current Makefile behavior:

- Set `.DEFAULT_GOAL := build`.
- Keep `PROFILE ?= debug` and reject other values.
- Make `make` and `make build` invoke xtask.
- Add directly invokable `cli`, `vmmon`, `netd`, `krun`, `agent`, `init`,
  `initramfs`, and `kernel` targets.
- Keep component targets as developer conveniences rather than release units.
- Pass an absolute effective `CARGO_TARGET_DIR` through every Cargo and xtask
  process.
- Build netd into the matching Cargo profile directory.
- Build krun on macOS as well as Linux.
- Make guest init and agent honor debug/release profiles for developer builds.
- Use committed lockfiles and `--locked` where supported.
- Add `fmt`, retain `clippy` and `test`, and continue using host-aware excludes.

Introduce one product-version authority suitable for Rust, npm, Info.plist,
package metadata, and archives. A root `VERSION` file is preferred because this
is a mixed-language product. Add a production version-check command, not an
xtask unit test.

Refactor Nix layout following the useful Ghostty separation:

- Keep `flake.nix` thin.
- Move development-shell details under `nix/`.
- Preserve the dedicated kernel shell.
- Add required build and packaging tools as later commits need them.
- Prepend the absolute workspace `target/debug` to PATH.
- Keep the repository scripts directory on PATH after debug binaries.
- Do not add `target/release` to PATH.

This commit may still build an incomplete adjacent runtime. Commit 07 adds the
kernel and complete assets closure.

### Acceptance Criteria

- Plain `make` invokes the build target, not the old first guest target.
- `make PROFILE=release` uses release outputs.
- Every named component target invokes only its real component build.
- macOS can build the dormant krun helper.
- `CARGO_TARGET_DIR=/absolute/path make <component>` writes to that root.
- Entering `nix develop` places the workspace `target/debug` before other Silo
  binary locations on PATH.
- The Makefile contains interface and dependency declarations, not duplicated
  platform build logic.
- Xtask has no new tests, mocks, snapshots, fixtures, or test dependencies.

### Verification

Run every component target supported by the current host:

```text
cargo fmt
make cli
make vmmon
make netd
make krun
make agent
make init
make clippy
git diff --check
```

Repeat at least one component with an absolute custom `CARGO_TARGET_DIR`.

## Commit 07: Build Adjacent Development Runtimes And Canonical Stages

Suggested intent: `build: stage complete Silo runtimes`

### Purpose

Make ordinary development binaries directly runnable and create the canonical
portable payload consumed by every packager.

### Ghostty Reference Notes

Inspected Ghostty's `build.zig`, `src/build/Config.zig`, and
`src/build/GhosttyDist.zig` before changing runtime assembly.

- Reused the assemble-once pattern: generated assets are assembled into one
  complete temporary tree, validated as that tree, then installed through a
  final rename. Reused its qualification boundary by validating the assembled
  layout rather than separately trusting source artifacts after staging.
- Intentionally did not copy Ghostty's source-tarball flow, app/runtime
  selection, Xcode/Swift project behavior, XCFramework outputs, macOS app
  assembly, or signing behavior. Silo retains Make plus Rust xtask and stages
  its six-file runtime independently of future app packaging.

### Required Changes

Add production xtask commands for complete development builds and staging.

For `make build`:

- Build `silo`, vmmon, netd, and krun into the selected profile directory.
- Build matching guest init and agent for the selected profile and architecture.
- Produce initramfs.
- Resolve or reuse the matching stable kernel.
- Populate `<profile-dir>/assets` with `kernel-default`, `initramfs`, and
  `agent`.
- Validate the complete adjacent development layout before success.
- Build asset updates in a temporary sibling directory and rename the complete
  asset directory into place.

For canonical `make stage`:

- Build or consume the complete selected-profile component set.
- Create `target/silo-runtime/<target>/<profile>/bin` and `assets` in a
  temporary sibling tree.
- Copy helpers and assets with explicit modes.
- Validate all six files.
- Atomically replace the final stage.
- Do not include the CLI or metadata in the six-file runtime stage.

Implement OCI kernel acquisition:

- Resolve the stable OCI index.
- Select the exact host/guest architecture manifest.
- Validate index, manifest, config, artifact type, layer media type, platform,
  and all referenced digests.
- Extract only the expected kernel layer as `kernel-default`.
- Cache content by digest so development works offline after acquisition.
- Support an explicit local kernel input and an explicit offline mode.
- Record resolved descriptors outside the runtime root for later provenance.
- Never download the default kernel from libvm or at VM startup.

Use `CARGO_TARGET_DIR` consistently. The resolver does not know or care where
that directory came from because all development files are adjacent.

### Acceptance Criteria

- `make` creates a complete `target/debug` adjacent runtime.
- `./target/debug/silo` resolves helpers and assets with all overrides unset.
- Running `silo` from the Nix shell resolves the same canonical executable.
- `make PROFILE=release` creates a complete adjacent release runtime.
- `make stage PROFILE=release` creates the exact six-file portable payload.
- A custom absolute `CARGO_TARGET_DIR` works without resolver-specific logic.
- A first build may acquire the kernel; an offline repeat uses verified cached
  content.
- Removing one adjacent component produces a diagnostic naming that path and
  recommending `make`.
- The runtime stage contains no path manifest or release metadata.
- Xtask has no new test suite.

### Verification

```text
cargo fmt
make
./target/debug/silo --help
make PROFILE=release
make stage PROFILE=release
make clippy
git diff --check
```

Also run the debug build with an absolute custom `CARGO_TARGET_DIR`, unset all
runtime override variables, and execute that directory's `silo` binary.

Where host virtualization is available, boot one VM from the adjacent debug
runtime and one from the canonical release stage.

### Implementation Notes

- `make build` now builds the full host and guest closure once, resolves the
  kernel before assembly, writes a temporary sibling assets tree, validates it,
  and renames it into the selected profile directory. `make stage` consumes
  that complete adjacent layout and atomically installs only the three helpers
  and three assets under `target/silo-runtime/<target>/<profile>` with explicit
  `0755` and `0644` modes.
- The OCI resolver defaults to `ghcr.io/vandycknick/silo/kernel:stable`, accepts
  `KERNEL_REFERENCE`, `KERNEL_PATH`, and `KERNEL_OFFLINE` through Make (and
  corresponding xtask flags), validates the Silo OCI contract in Rust, caches
  verified content at `$CARGO_TARGET_DIR/kernel-cache/sha256`, and writes
  descriptors outside runtime roots at `kernel-provenance/<target>/<profile>.json`.
- Qualification ran the required debug/release builds, release stage, clippy,
  formatting, and diff checks. An absolute temporary `CARGO_TARGET_DIR` built
  and ran with all runtime overrides unset; its offline rebuild reused the
  verified cache. The release stage was confirmed to contain exactly six files
  with the required modes and no metadata. On macOS arm64 with VZ support, both
  the adjacent debug runtime and release CLI using the canonical stage booted
  `ubuntu:24.04` to guest readiness, then the acceptance machines were stopped
  and removed.
- Follow-up hardening verifies every selected platform config and layer blob by
  descriptor digest before staging, records the complete descriptor set in
  provenance, validates the boot-kernel representation for OCI and local
  inputs, and protects offline reference records with owner-only `0600` files.
  Existing assets and stages exchange atomically through rustix, so readers see
  either complete tree while the displaced tree is cleaned up afterward.

## Commit 08: Isolate Release Linking And Audit Binaries

Suggested intent: `build: enforce portable release linkage`

### Purpose

Prevent Nix development inputs and build-machine paths from leaking into shipped
binaries. Existing local macOS debug artifacts have already demonstrated an
absolute Nix `libiconv` dependency, so post-link auditing is mandatory.

### Required Changes

Separate development and release environments:

- Development may use the Nix shell normally.
- Local release builds use the persistent `<CARGO_TARGET_DIR>/release` Cargo
  layout and persistent Go, Zig, and kernel caches. Protected CI begins with a
  clean workspace and target when isolation is required.
- On macOS, clear Nix compiler/linker variables and select Apple's native SDK,
  clang, linker, archiver, and deployment target 26.0.
- Model the clean Apple environment after Ghostty's `nix/devShell.nix` and
  clean native build handoff, without adding an Xcode project.
- On Linux, build in a digest-pinned native amd64/arm64 environment with glibc
  2.39, initially using a suitable Ubuntu 24.04 base.
- Pin Rust, Go, Zig, cargo-zigbuild, and other release tool versions.
- Build netd with explicit release flags, `-trimpath`, and `CGO_ENABLED=0`
  unless a demonstrated production requirement needs CGo.

Add real artifact auditing commands in xtask:

- Inspect every Mach-O dependency and load command.
- Reject Nix store, package-manager, workspace, target, and temporary paths in
  shipped Mach-O dependencies.
- Reject unexpected `LC_RPATH` and non-system dylibs.
- Require Mach-O dependencies to resolve from the system framework and dylib
  locations.
- Inspect ELF interpreter, `DT_NEEDED`, RPATH, RUNPATH, and symbol versions.
- Reject required glibc symbol versions newer than 2.39.
- Reject `libkrun.so` and `libkrun.dylib` dependencies.
- Verify guest init and agent have no dynamic interpreter or dependencies.

Do not invent fake audit inputs or unit tests for these commands. Run them on
real release outputs.

### Acceptance Criteria

- Repeated local release builds reuse the normal Cargo, Go, Zig, and kernel
  caches without automatically clearing a target directory.
- macOS release binaries contain no `/nix/store` or other non-system load path.
- Linux release binaries contain no RPATH/RUNPATH or Nix loader path.
- Linux host binaries require no glibc symbol newer than 2.39.
- netd's CGo policy is explicit and its final dependencies match that policy.
- Guest assets are static for their musl targets.
- krun does not require a distributed libkrun shared library.
- A clean release stage passes all audits.

### Verification

```text
cargo fmt
make PROFILE=release
make stage PROFILE=release
make verify-runtime PROFILE=release
make clippy
git diff --check
```

### Ghostty Reference Notes

Inspected Ghostty's `nix/devShell.nix`, `nix/package.nix`, `build.zig`,
`src/build/Config.zig`, `src/build/GhosttyDist.zig`, and its test and release
workflows.

- Reused Ghostty's cache-aware build graph and CI split: local Zig builds reuse
  their normal caches (including distcheck), while CI starts from a checkout and
  explicitly restores tool caches. Its macOS shell clears Nix SDK/compiler
  variables before native Apple tooling, and its release workflow hands native
  app work to Xcode outside Nix. Silo applies the same native-link boundary per
  release subprocess through `/usr/bin/xcrun` while retaining compiler caches.
- Intentionally did not copy Ghostty's Zig typed graph, Swift/Xcode project,
  XCFramework, Sparkle, nested-app signing, or Nix package derivation. Silo
  retains Make and Rust xtask, has no Xcode project, and defers app/signing work
  to later commits.

### Implementation Notes

- Approved deviation: local release compilation uses the persistent normal
  `$CARGO_TARGET_DIR/release` layout instead of fingerprinted, per-invocation
  isolated roots. This deliberately removes source/toolchain/output hash
  ledgers, complete and qualification records, qualification checks, and the
  synthetic contaminated-binary build. `make stage PROFILE=release` rebuilds
  incrementally, atomically stages the six canonical files, and validates their
  layout and modes. `make verify-runtime PROFILE=release` audits practical
  release correctness, including architecture, platform minimum, runtime
  dependencies, RPATH, glibc, libkrun, and static guests, but is not a tamper
  prevention mechanism.
- Linux release commands verify a native matching Docker daemon, build the
  digest-pinned architecture-specific Bake target, and run the requested Make
  command in that image with a read-only workspace, writable persistent target,
  and Docker-managed compiler/module cache. The internal marker prevents the
  container command from entering Docker again; a missing daemon fails closed.
- macOS release subprocesses clear Nix/compiler/SDK/package-config variables,
  accept only exact-version Rust/Zig/cargo-zigbuild drivers, use
  clean-environment `xcrun` SDK tools, target arm64 macOS 26.0, remap Rust
  source paths, and use the pinned official Go compiler for `netd`. Its cached
  archive is retained and hash-verified on every release use.
  `netd` is built with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=true`, and
  `-ldflags=-s -w`.
- `make verify-runtime PROFILE=release` audits actual adjacent, staged, and
  guest artifacts. It requires supported ELF loaders and dependencies, checks
  Mach-O arm64/minimum-OS/system load paths, and reads the shipped gzip/newc
  initramfs to confirm it contains the current static guest init.
- `release/Containerfile`, `docker-bake.hcl`, and `toolchains.toml` define the
  digest-pinned Ubuntu 24.04/glibc 2.39 native Linux environment. The container
  validates toolchain-record values, verifies Rustup, Go, Zig, cargo-zigbuild,
  and ORAS downloads, then checks installed versions and architecture before
  use. Kernel resolution is cache-first; `KERNEL_REFRESH=1` updates a mutable
  reference, while `KERNEL_OFFLINE=1` and `KERNEL_PATH` remain explicit options.
  Docker execution remains a native Linux CI/builder gate when unavailable on
  the local host.

## Commit 09: Produce Common Release Archives And Metadata

Suggested intent: `packaging: produce qualified runtime archives`

### Purpose

Create transport-neutral archives and supply-chain metadata from an already
qualified canonical stage.

### Required Changes

Add release artifact commands that consume, but do not rebuild or alter, the
canonical stage:

- Build a runtime-only `.tar.zst` archive.
- Build a portable CLI `.tar.zst` archive containing `bin/silo` plus the six
  runtime files.
- Use one versioned top-level archive directory.
- Normalize entry ordering, ownership, modes, and timestamps using
  `SOURCE_DATE_EPOCH` where possible.
- Preserve executable bits for helpers and agent.
- Generate detached SHA-256 files.
- Include required third-party notices, including libkrun Apache-2.0
  attribution.
- Generate SBOMs with a pinned maintained tool such as Syft.
- Write source revision, version, target, toolchains, kernel descriptors, file
  hashes, and build environment into adjacent provenance records.
- Report raw and compressed sizes.
- Keep all metadata outside the runtime root.
- Add `make archive`; it always uses a release stage.

Add a real archive qualification command:

- Extract into a fresh temporary directory.
- Reject traversal or unexpected entries.
- Re-run binary audits against extracted files.
- Run the CLI using only the extracted portable layout.
- Boot one VM from the extracted tree when host virtualization is available.

### Acceptance Criteria

- Runtime and CLI archives contain the exact expected files and no path
  manifest.
- Runtime file hashes match the canonical stage byte for byte.
- Archive ownership, modes, ordering, and timestamps are normalized.
- Checksums verify independently.
- SBOM and provenance records identify the exact kernel descriptors.
- Extracted helpers remain executable.
- The portable CLI resolves its runtime relative to canonical `bin/silo`.
- The extracted archive passes the same dependency audit as the stage.
- No xtask unit, snapshot, mock, or fixture tests are added.

### Verification

```text
make archive
make verify-archive
git diff --check
```

### Ghostty Reference Notes

Inspected Ghostty's `src/build/GhosttyDist.zig`, release-tag workflow, and
`PACKAGING.md` before adding archive production.

- Reused the assemble-once and qualify-after-extraction boundary: Silo stages
  the complete runtime once, audits that stage, archives it without changing it,
  then extracts and qualifies the transport artifact. Like Ghostty's
  `distcheck`, this keeps normal local build caches available rather than
  forcing a clean rebuild for every archive.
- Intentionally did not copy Ghostty's `git archive` source-tarball flow,
  generated source resources, Minisign publication, automatic GitHub source
  archive warning, or downstream-package build instructions. Silo ships runtime
  payload archives through Make and Rust xtask, while native package production
  remains a later commit.

### Implementation Notes

- `make archive` always performs the persistent incremental release build and
  canonical stage, audits it, then creates runtime and portable CLI archives
  from that unchanged stage. Archives use fixed ordering, modes, uid/gid, epoch,
  and `zstd -19 --threads=0`; generated checksums, SPDX SBOMs, and provenance
  remain beside the archive rather than in the runtime tree.
- The archive includes `THIRD_PARTY_NOTICES` plus the full Apache-2.0 text for
  libkrun as top-level release material. These files are not staged runtime
  files. Qualification rejects non-regular entries, unexpected paths, and
  traversal before extraction, compares the six runtime files byte-for-byte,
  audits extracted binaries, verifies the SPDX JSON/archive name and direct
  provenance fields, runs the non-mutating `silo list --format json` path with
  overrides unset to resolve the extracted runtime, and boots then removes a VZ
  acceptance VM on macOS. It deliberately relies on fixed production tar flags
  for complete header normalization rather than adding a generic tar-header
  audit.

## Commit 10: Assemble And Sign Silo.app

Suggested intent: `packaging: assemble the macOS application bundle`

### Ghostty Reference Notes

Inspected Ghostty's `.github/workflows/release-tag.yml`, macOS plist and
entitlement resources, and `src/build/GhosttyDist.zig`.

- Reused Ghostty's high-level handoff: assemble one final product, write final
  metadata before signing, sign nested code inside-out, strictly verify it, and
  hand that verified product to later distribution stages.
- Reused its cache-friendly philosophy for local assembly: Silo rebuilds the
  existing release stage incrementally and writes only a temporary bundle before
  atomically exchanging the final app directory.
- Intentionally did not copy Ghostty's Swift/Xcode app, XCFramework build,
  Sparkle updater, native app framework, DMG/notarization/stapling flow, or
  source-tarball implementation. Silo keeps a Rust CLI bundle, Rust xtask, and
  a simple Make entrypoint; the later DMG commit owns transport and release
  handoff.

### Purpose

Create the relocatable arm64 application bundle using the qualified release
stage, without introducing Swift or an Xcode project.

### Required Changes

Add repository-owned macOS packaging inputs:

- `Info.plist` template or generated plist fields.
- Silo application icon assets derived from existing brand sources.
- Minimal vmmon Virtualization entitlements.
- Minimal krun Hypervisor entitlements.
- No virtualization entitlements for silo or netd.

Add xtask app assembly:

- Require macOS arm64 and a qualified release stage.
- Create the exact `Silo.app/Contents` layout from ADR 0012.
- Generate final plist values before signing.
- Set bundle identifier `sh.silo.app`.
- Set `CFBundleExecutable` to `silo`.
- Set public version from the product version authority.
- Set monotonic build number from an explicit release input or commit count.
- Set minimum macOS version to 26.0.
- Copy CLI, helpers, assets, and icon without changing staged component bytes.
- Audit every nested executable before signing.

Add local and release signing modes:

- Local mode ad-hoc signs each nested executable with its own entitlements,
  then signs the outer app.
- Release mode requires an explicit Developer ID Application identity, hardened
  runtime, timestamping, and inside-out signing.
- Never use `codesign --deep`.
- Verify every nested signature and the outer bundle strictly.
- Verify actual entitlements after signing.
- Verify bundle-relative runtime resolution through canonical `current_exe()`.

Add `make app`; it always builds a release app, using ad-hoc signing unless
release credentials are explicitly supplied.

### Acceptance Criteria

- `Silo.app` has exactly the ADR layout.
- Plist identity, version, build number, executable, and minimum OS are correct.
- vmmon has the Virtualization entitlement and no unjustified capabilities.
- krun has the Hypervisor entitlement and no unjustified capabilities.
- silo and netd have no virtualization entitlement.
- Every nested binary passes the Mach-O audit.
- Ad-hoc local assembly needs no release secret.
- A direct app CLI run resolves only bundle helpers and assets.
- A symlink to `Contents/MacOS/silo` preserves bundle discovery.
- Copying the CLI out of the bundle does not claim bundle resources.

### Verification

```text
make app
codesign --verify --strict --verbose=4 target/package/macos/Silo.app
git diff --check
```

Xtask must verify every nested executable separately. Gatekeeper assessment is
reserved for the Developer ID signed and notarized artifact in Commit 15 because
an ad-hoc local build is not a distribution artifact.

## Commit 11: Build The DMG With create-dmg And Install On macOS

Suggested intent: `packaging: add macOS DMG and install commands`

### Purpose

Use the same proven DMG tool selected by Ghostty and provide a native macOS
source-install path.

### Ghostty Reference Notes

Inspected `/Users/nickvd/Sources/ghostty/.github/workflows/release-tag.yml`.

- Reused Ghostty's release ordering: assemble and sign the app, hand that app
  to `create-dmg` with an explicit output directory and Developer ID identity,
  then hand the resulting DMG to the release-signing/notarization boundary.
- Intentionally did not copy Ghostty's unpinned global `npm install`, Swift and
  Xcode app build, Sparkle components, keychain/certificate import,
  notarization, stapling, artifact publication, or its fixed `Ghostty.dmg`
  filename. Silo uses the committed local `create-dmg` 8.1.0 binary, its own
  signed app, normalized versioned artifact name, and defers notarization to
  Commit 15.

### Required Changes

Pin `create-dmg` to a reviewed version, initially 8.1.0, in the local packaging
environment and protected CI. Do not run an unbounded latest version.

Add xtask DMG orchestration:

- Require an already assembled and verified `Silo.app`.
- Invoke `create-dmg --overwrite --no-code-sign` for local builds.
- Invoke `create-dmg --overwrite --identity=<identity>` for release builds.
- Pass the app and explicit output directory.
- Normalize the generated filename to Silo's release artifact convention.
- Verify the command result and expected output file.
- Mount the DMG read-only with native Apple tooling.
- Verify it contains the expected `Silo.app` and Applications link.
- Re-verify the app signatures and runtime layout from the mounted image.
- Detach the image on both success and failure.
- Do not implement custom HFS/APFS generation, Finder metadata, backgrounds, or
  icon positioning in Rust or shell.

Add macOS `make package`:

- Always create a release app and DMG.
- Default to local ad-hoc app signing and unsigned DMG when no release identity
  is supplied.
- Never silently use an arbitrary signing identity.

Add macOS `make install`:

- Always install a release app.
- Default to `/Applications/Silo.app` and `/usr/local/bin/silo`.
- Support `APPDIR=$HOME/Applications` and `BINDIR=$HOME/.local/bin`.
- Expose the CLI with a symlink, never a copied executable.
- Replace only an installation that is clearly owned by this command.
- Do not remove user data during reinstall or uninstall operations.

### Acceptance Criteria

- The repository contains no custom DMG writer or Finder-layout implementation.
- Local DMG creation uses the pinned `create-dmg` version and needs no signing
  secret.
- Release mode supplies an explicit identity.
- The normalized DMG name includes product version and target.
- The mounted DMG contains the verified app and Applications link.
- A no-admin install works with user-owned `APPDIR` and `BINDIR`.
- The installed CLI is a symlink whose canonical executable remains in the app.
- `make package PROFILE=debug` still produces a release artifact.
- No xtask tests are added.

### Verification

```text
make package
make install APPDIR="$HOME/Applications" BINDIR="$HOME/.local/bin"
"$HOME/.local/bin/silo" --help
git diff --check
```

Remove only the installation created for this acceptance check; do not touch
unrelated user installations.

For a safe local acceptance run, use a unique workspace-owned path instead of
clobbering `~/Applications` or `~/.local/bin`:

```text
acceptance_root="$(mktemp -d "$PWD/target/silo-install-XXXXXX")"
make install APPDIR="$acceptance_root/Applications" BINDIR="$acceptance_root/bin"
"$acceptance_root/bin/silo" list --format json
rm -rf "$acceptance_root"
```

### Implementation Notes

- `make install` was accepted with a unique workspace-owned app and bin root.
  The installed symlink ran `list --format json` with all runtime overrides
  unset and isolated XDG roots, then that exact root was removed.
- The locked local `create-dmg` command was invoked repeatedly against the
  verified app, including with a `/tmp` output and temporary workspace. It now
  retries only `hdiutil convert ... -format ULFO` `Resource temporarily
  unavailable` failures up to three total same-tool attempts, printing captured
  command output, cleaning only package-owned temporary output, and detaching
  only an exactly identified invocation image. On this macOS host all three
  attempts still failed before producing a DMG, with no invocation image mounted
  afterward. No image can therefore be mounted for the required strict checks.
  Commit 11 remains unchecked pending a fresh host where native `hdiutil`
  completes that step.

## Commit 12: Build And Qualify Native Linux Packages And Installs

Suggested intent: `packaging: add native Linux distributions`

### Purpose

Build separately identified Debian, Ubuntu, RHEL, and Arch artifacts from the
same qualified target stage and provide a source install under `/usr/local`.

### Required Changes

Add pinned nFPM to the development and CI packaging environment. Add
repository-owned packaging configuration under `packaging/linux/`; use xtask to
supply version, architecture, stage path, distribution identity, dependencies,
and output name.

Initial qualification matrix:

| Distribution | Initial environment | Package format |
| ------------ | ------------------- | -------------- |
| Debian | Debian 13 | deb |
| Ubuntu | Ubuntu 26.04 LTS | deb |
| RHEL | RHEL-compatible UBI 10 | rpm |
| Arch | Pinned current snapshot | Arch package |

Build on native amd64 and arm64 runners where the distribution supports the
architecture. Do not emulate guest CPU architecture for qualification.

Package layouts:

- Debian, Ubuntu, and Arch install the CLI at `/usr/bin/silo` and the runtime
  below `/usr/lib/silo/{bin,assets}`.
- RHEL installs helpers below its libexec Silo directory and assets below its
  architecture library Silo directory.
- Helpers and agent use mode `0755`.
- Kernel and initramfs use mode `0644`.
- Package ownership is root without setuid, services, daemons, or privileged
  runtime helpers.

Build separate distro-labeled packages while preserving identical canonical
runtime bytes for a target architecture. Distro metadata may differ; helpers and
assets must not be rebuilt per package.

Declare native package dependencies, including the glibc 2.39 minimum using
each package format's correct syntax.

Add real package qualification commands:

- Build the package with nFPM.
- Inspect package metadata and contents.
- Install in the matching clean distro environment.
- Verify owners and modes.
- Run the CLI with runtime overrides unset.
- Upgrade from the same-version rebuild or prior fixture when one exists.
- Remove the package.
- Verify package removal leaves user data, state, caches, and images untouched.
- Boot with package-owned files on KVM-capable native runners.

Add Linux Make behavior:

- `make package DISTRO=<debian|ubuntu|rhel|arch>` always packages release.
- Plain `make package` detects a supported current host distribution and errors
  clearly on unsupported hosts.
- `make install PREFIX=/usr/local DESTDIR=...` installs the administrator layout
  from a release stage.
- Source install supports staged packaging through `DESTDIR`.
- Source install never writes package-owned files to `/usr` by default.

### Acceptance Criteria

- Each supported distro produces and qualifies its native package format on the
  implementing host architecture.
- Package metadata and target mapping cover both promised architectures where
  available; native cross-architecture execution becomes a required CI job in
  Commit 14.
- Package payload hashes match the canonical stage for that architecture.
- Debian/Ubuntu/Arch and RHEL layouts match ADR 0012.
- Packages contain no service, setuid helper, or mutable user directory.
- Install, upgrade, and removal work in matching clean environments.
- Package removal preserves user-owned mutable data.
- Installed runtime resolution works with all overrides unset.
- Linux binaries pass glibc and dynamic-link audits after extraction and install.
- Generic and native package VM boots use only package-owned files.
- nFPM invocation is real; no xtask package-manager tests or mocks are added.

### Verification

On a supported Linux host:

```text
make package
make install DESTDIR="$(pwd)/target/install-root"
make verify-package
git diff --check
```

Run every distro container qualification available on the host architecture.
Full architecture coverage becomes mandatory in Commit 14 CI.

## Commit 13: Split And Package The Node SDK

Suggested intent: `node: ship exact-version platform runtimes`

### Purpose

Turn the current single native package into a neutral TypeScript facade plus
exact-version platform packages carrying the canonical runtime.

### Required Changes

Confirm the final npm scope with the user before changing public package names.
Until confirmed, ADR names remain conceptual and must not be published.

Create one neutral package and three platform packages:

```text
silo
@silo/runtime-darwin-arm64
@silo/runtime-linux-amd64
@silo/runtime-linux-arm64
```

Adapt names if the approved scope differs.

Neutral package changes:

- Ship only JavaScript, declarations, README, and package metadata.
- Remove the direct native-addon export and native files.
- Declare every platform package in exact-version `optionalDependencies`.
- Use no version range, install script, or postinstall downloader.

Platform package changes:

- Declare exact `os` and `cpu` restrictions.
- Declare `libc: ["glibc"]` on Linux.
- Include `native/silo.node`.
- Copy the qualified canonical stage unchanged below `runtime/`.
- Preserve executable modes.
- Include no CLI unless a separately approved SDK contract requires it.

Loader changes:

- Map only supported `process.platform` and `process.arch` pairs.
- Reject unsupported targets before addon load or process spawn.
- Dynamically import the one expected platform package.
- Validate imported values from `unknown` without `any` or unchecked `as`.
- Report unsupported target, missing optional package, malformed package, and
  missing addon distinctly.
- Resolve the package-relative runtime directory.
- Pass it to the N-API layer as a bundled candidate, not an explicit API root.
- Do not inspect `process.execPath`, global npm locations, PATH, or an installed
  CLI.

N-API changes:

- Add explicit public `runtimeRoot` support.
- Add an internal/bundled candidate input with lower precedence.
- Adapt data, state, run, image, and component configuration to the breaking
  libvm API.
- Do not mutate process-global environment variables to communicate paths.

Packaging and SDK tests may be added because they test the SDK contract, not
xtask. Cover platform mapping, malformed packages, missing packages, exact
versioning, archive contents, and clean installation.

Add real package qualification:

- Use `npm pack --json`.
- Inspect each tarball's exact file list and modes.
- Verify the neutral tarball contains no addon or runtime.
- Verify all package versions match the product version exactly.
- Install local tarballs in a fresh project with scripts disabled.
- Run without a system Silo installation.
- Boot using only the package-local runtime on the target host.
- Report compressed and installed size and enforce the 50 MiB budget.

### Acceptance Criteria

- The neutral package contains no `.node` file and no runtime payload.
- Each platform package contains one addon and the exact six-file runtime.
- Optional dependency versions are exact.
- npm selects only the host-compatible optional package.
- Unsupported hosts fail before native loading.
- Missing or malformed platform packages produce actionable errors.
- Explicit API and environment choices outrank the bundled runtime.
- The bundled runtime outranks executable-relative and native package discovery.
- A clean local tarball installation boots without system Silo.
- Platform packages remain within the size budget or record a reviewed
  exception.
- No xtask tests are added; SDK tests remain under the Node package.

### Verification

```text
cargo fmt
make node-package
make node-package-verify
npm --prefix sdk/node test
npm --prefix sdk/node run typecheck
make clippy
git diff --check
```

## Commit 14: Add Continuous Integration And Package Qualification

Suggested intent: `ci: qualify runtime and package artifacts`

### Purpose

Make the real local Make interface the CI interface and use package execution as
the integration coverage for xtask.

### Required Changes

Add regular CI workflows using commit-pinned actions.

Core checks:

- Rust formatting, clippy, and relevant tests.
- Go tests.
- Node tests and typechecking.
- Nix flake evaluation or checks appropriate to the repository.
- Generated/version metadata consistency.

Development build checks:

- Build adjacent debug runtimes on macOS arm64 and Linux amd64/arm64.
- Run `target/debug/silo` with runtime overrides unset.
- Repeat with an absolute custom `CARGO_TARGET_DIR`.
- Verify the Nix shell PATH behavior.

Release stage checks:

- Build native target stages in isolated release environments.
- Run Mach-O or ELF and glibc audits.
- Verify guest architecture and static linkage.
- Boot a VM from the stage on VZ/KVM-capable runners.

Product checks:

- Build and inspect portable archives.
- Build ad-hoc `Silo.app` and unsigned local DMG.
- Build every distro/architecture package.
- Install, upgrade, remove, and boot native packages.
- Build, pack, clean-install, and boot Node platform packages.
- Report package sizes, checksums, and provenance.

Follow Ghostty's useful CI property: workflows invoke repository commands that a
developer can run. Avoid large workflow-only shell implementations.

Use native architecture runners. Reuse the existing kernel workflow's patterns
for arm64 and pinned actions. Use KVM-capable runners for Linux VM qualification
and macOS 26 arm64 runners for VZ.

Do not add an xtask test job. CI jobs qualify real artifacts and commands.

### Acceptance Criteria

- All workflows use commit-pinned third-party actions.
- CI invokes Make targets rather than duplicating build logic.
- The matrix contains adjacent debug execution on every supported host
  architecture.
- The matrix contains release link and architecture audits for every target.
- macOS app and DMG build locally without release secrets.
- Every distro package has an install, upgrade, removal, and ownership job in
  its matching target environment.
- VZ and KVM boot jobs are required and use only staged or package-owned files.
- Node clean-install jobs use only package-local runtime files.
- Package and SDK sizes are reported.
- No workflow invokes an xtask unit-test suite.
- The workflow dependency graph includes every required qualification job and
  has no publication behavior.
- All locally available commands invoked by the workflows pass before the
  commit is checked off.

### Verification

Run all locally available Make checks and validate workflow syntax and dependency
ordering without publishing or pushing. The implementing agent must not push
merely to trigger CI. After the local commit, the user may push and report CI
failures; fix any reported failures in a new local follow-up commit without
amending or pushing.

```text
make fmt
make clippy
make test
make
make PROFILE=release
make package
git diff --check
```

## Commit 15: Add Protected Release And Homebrew Publication

Suggested intent: `release: publish signed cross-platform products`

### Purpose

Add the protected, secret-bearing release path after unsigned/local packaging
and all qualification workflows are stable.

### Required Changes

Add `.github/workflows/release.yml` for exact version tags and protected manual
dry runs.

Release setup:

- Validate `v<version>` tag syntax.
- Require exact agreement among tag, product version, Cargo product crates, npm
  packages, app metadata, and package metadata.
- Resolve source revision and monotonic macOS build number.
- Grant minimal workflow permissions, including `id-token: write` only where
  keyless signing requires it.

Stage once per target:

- Build and qualify darwin-arm64, linux-amd64-gnu, and linux-arm64-gnu stages.
- Resolve the kernel once per architecture and retain index, manifest, config,
  and layer digests.
- Upload immutable stage artifacts between jobs.
- Make every product and SDK transport consume those staged bytes.
- Do not rebuild runtime components inside transport jobs.

macOS release:

- Import the Developer ID certificate into a temporary keychain.
- Sign nested executables inside-out with correct entitlements, hardened
  runtime, and timestamping.
- Sign the outer app.
- Build the DMG with pinned `create-dmg` and an explicit identity.
- Submit with `xcrun notarytool --wait`.
- Staple and validate both app and DMG.
- Run Gatekeeper and strict signature verification.
- Qualify the downloaded/staged result on a clean macOS 26 environment.

Linux release:

- Build every distro-labeled package from the immutable architecture stage.
- Sign packages or repository material according to the selected channel.
- Re-run package content and installation qualification.
- Publish no service or mutable user files.

Archive and provenance release:

- Publish independent SHA-256 checksums.
- Generate keyless Sigstore bundles with the exact GitHub workflow identity
  required by ADR 0012.
- Require transparency-log inclusion proofs.
- Publish SBOM and provenance records.
- Verify signatures and checksums before making a release public.

Node publication:

- Publish all platform packages first.
- Confirm each exact version is visible from npm.
- Publish the neutral package last.
- Perform a final clean registry installation and boot.

GitHub and Homebrew publication:

- Stage artifacts in a draft release.
- Verify every expected URL and checksum.
- Publish the release only after all target artifacts exist.
- Generate a Homebrew Cask for the same DMG with its exact checksum.
- Test app installation and CLI symlink behavior.
- Update the official tap only after the release artifact is public.
- Do not add a PKG installer or AUR PKGBUILD in this implementation.

The implementation agent must not trigger a publishing run, push a tag, push a
branch, publish npm packages, or update the external tap. It may add and locally
validate the workflow. The user controls all upstream pushes and publication.

Finalize documentation:

- Set ADR 0012 status to `Implemented` and update its date.
- Update `docs/adr/README.md` status.
- Check every tracker entry in this plan.
- Ensure all final commands, package names, layouts, and workflow paths in this
  plan match the repository.

### Acceptance Criteria

- A non-publishing workflow mode exists and gates every publication step behind
  an explicit protected input or version-tag event.
- Workflow dependencies build runtime bytes once per target and route those
  immutable artifacts to all transports.
- The configured macOS path signs inside-out, runs codesign and Gatekeeper
  checks, notarizes, staples, and validates before publication.
- The configured Linux path signs packages or applies the documented repository
  trust mechanism before publication.
- The configured archive path creates checksums and Sigstore bundles with the
  exact expected workflow identity and requires a transparency proof.
- The workflow requires SBOM and provenance records for every target.
- Node platform packages publish before the neutral package in workflow order.
- Homebrew Cask uses the released DMG and exact checksum.
- Clean-target boot jobs are required dependencies for installed product and SDK
  publication and use no development runtime or first-run download.
- Package removal preserves mutable user data.
- ADR 0012 and the ADR index are marked `Implemented`.
- All tracker entries in this document are checked.
- No implementation commit or tag has been pushed by the implementing agent.

### Verification

Validate workflow syntax, permissions, dependency ordering, publication guards,
and every locally runnable command. Do not invoke a real release, notarization,
registry publication, tap update, or other secret-bearing action. The first
user-triggered protected dry run must subsequently prove the configured remote
release gates before an actual release is published.

```text
make fmt
make clippy
make test
make PROFILE=release
make archive
make package
git diff --check
```

Inspect the final local Git history and worktree. Every stage must be represented
by one completed local commit, this tracker must be fully checked, and no
unrelated changes may be included.

## Deferred Work

Do not expand this implementation with the following work:

- Runtime backend selection on macOS.
- Intel macOS or Windows support.
- PKG, enterprise, or MDM installers.
- AUR `PKGBUILD` publication.
- Python wheels.
- The Go SDK installer.
- Independent component upgrades or compatibility ranges.
- Runtime downloads inside libvm.
- A `silo doctor` command.
- A custom DMG implementation.
- An xtask test suite.

The canonical stage, resolver, and package metadata must leave room for these
future additions without implementing them now.
