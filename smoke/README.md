# Real-VM smoke suite

This suite drives the staged CLI, daemon and runtime against real VMs. It is
intentionally outside CI and does not replace the unit or integration suites.

## Prerequisites and running

- Python 3.12+, `uv`, `openssl` and `sqlite3` on PATH (`nix develop` supplies uv
  and openssl).
- Linux: readable and writable `/dev/kvm`. macOS: Apple Silicon with Hypervisor
  Framework support and a signed silo-vmm with hypervisor/virtualization entitlements.
- Run as an ordinary user, not root.
- Run `make stage` first. Use the same `PROFILE` and `CARGO_TARGET_DIR` when
  staging and running; smoke does not build missing components.

```sh
make stage
make smoke
make smoke SMOKE_ARGS="-m slow"       # explicit extended qualification
make smoke SMOKE_ARGS="-k lifecycle"
make smoke SMOKE_ARGS='-m "not daemon and not slow"'
make smoke SMOKE_ARGS="--backend vz"   # macOS only
make smoke SMOKE_ARGS="-k tty_resize --keep"
```

### Guest lifecycle controller (Phase 12)

Main builds the explicit host-only smoke executable separately, then stages
the actual kernel/init/agent. The helper is an example with `test = false`,
not a Cargo test and not a new production control route:

```sh
cargo build -p silo-vmm --example guest-lifecycle-controller
make stage
make smoke SMOKE_ARGS='-k "freeze_real_kernel or freeze_refuses_uncontained" -m "not sdk"'
```

`SILO_SMOKE_GUEST_LIFECYCLE_CONTROLLER` selects an absolute helper path for
nondefault target/profile builds. Tests never build a missing helper. They
retain its digest, staged kernel/agent/initramfs digests, private fixture,
serial output and observed counter/epoch values. A fresh ordinary production
`VirtualMachine` owns its production worker and native host-only vsock mux;
cleanup force-stops/reaps that exact worker and closes attachments even when
an assertion fails while the guest is frozen.

`SILO_SMOKE_GUEST_LIFECYCLE_KERNEL` selects Main's exact locally built workload
kernel instead of the staged default; its adjacent emitted `.config`, when
present, is copied and hashed with the evidence. This does not claim a runtime
generation acknowledgement merely because the emitted symbols are enabled.

The positive cold-guest test independently reads `cgroup.events`, observes
native-exec and SSH workload membership/counter progress, userdata placement,
double-forked descendants in a nested workload group, empty-root freeze,
responsive status/metrics while frozen, mutation refusal, joined duplicate
freezes, exact thaw, a deliberately discarded thaw acknowledgement, real
next-epoch recovery freeze, stale-thaw rejection and unchanged source
identity. The negative cold profile test verifies that image-owned init is
named unsupported before the real kernel freeze changes.

These are cold guest API oracles only. They do not qualify native pause,
capture, restored generation/reseed ordering, restored network replacement,
inherited listener/session reset, activation hooks, or restored identity/
shutdown cutover. Those lanes are the restored activation tests below; no
absent lane is counted as passing and no cold activation substitutes for the
exact host generation barrier.

### Public pause and resident resume (Phase 13)

```sh
cargo build --locked -p libvm --example live_acceptance
make smoke SMOKE_ARGS='tests/test_pause.py tests/test_guest_lifecycle.py -k pause --keep'
```

The real CLI gate retains one guest counter stream across pause and ClockOnly
resume. It checks frozen workload evidence, user-owned authority, fresh-manager
reconciliation, exact replay and GetOperation, stale-token and paused-cancel
refusal, fenced new execution, unchanged boot/run identity and reseed count,
and the exact generation acknowledgement. A second pause is stopped without
resuming; the gate waits for the actual owners and checks storage-lease release.
The image-owned-init negative gate rejects before allocating a live command.

`live_acceptance` is a standalone Rust public-API consumer, not a VM-starting
Cargo test. Only the supervisor-verified immutable build/lane qualification
grants public pause. Runtime files or environment variables cannot grant it.

### Full live capture (Phase 14)

`tests/test_capture.py` requires an isolated test-only capture candidate.
Production capture remains `lane-not-qualified`; no runtime file grants it.
Build with `python -m silo_smoke.capture_candidate --destination PATH --runtime
STAGED_RUNTIME` through `uv run --project smoke` with `PYTHONPATH=smoke`.
The destination must be outside the repository and staged runtime, with matching
Cargo ancestor depth and build environment. The builder checks native/build
identity equality and leaves the production stage unchanged.

Point `SILO_SMOKE_BIN_DIR` and `SILO_SMOKE_RUNTIME_DIR` at the candidate's `bin`
and `runtime` directories, then run:

```sh
uv run --project smoke pytest smoke/tests/test_capture.py smoke/tests/test_capture_multidisk.py smoke/tests/test_capture_lifecycle.py -m slow --keep
```

The root-family gates exercise raw and flat-overlay matched disk/RAM cuts,
source continuation, acquired and borrowed pause authority, sealed-file
immutability, independent retained RAM, and retention through source/alias
removal, home relocation and GC. Unsupported readonly virtiofs must be refused
before staging or freezing. The child-only syscall tracer holds real capture
durability boundaries for manager/monitor/worker death, including pool-file sync,
pool publication and catalog commit. The catalog boundary is an actual WAL sync
after the candidate identity becomes visible, before capture provenance commits.
Pre-seal cancellation waits for the monitor's exact request-admission event
before releasing the held syscall; it verifies acquired-resume, acquired-preserve
and borrowed-pause policies. Post-seal cancellation preserves the known seal.
These are process-crash tests, not physical power-loss simulation. Retain failed
workspaces; archive evidence before pruning completed generated payloads.

The lifecycle cases hold real boundaries across manager death, stop and
post-seal cancellation. Missing continuation evidence remains pending while
the exact run lives and becomes unknown after it ends. Holding the worker's
vsock muxer exercises genuine continuation deadlines without injected errors
or changed timeouts. The failure oracle checks the coherent published seal,
Error fences and the source's durable workload counter, not survival of an
exec session whose readiness has been invalidated.

### Restored guest activation (Phase 12)

`silo_smoke/guest_restored.py` joins the standalone `native-live-api` owner
(`--silo-fixture` real-Silo boot) with the attach-only guest controller
(`guest-lifecycle-controller --attach`). It never uses the diagnostic native
init, console oracles or echo streams. Build, stage and point at the exact
inputs first:

```sh
cargo build --locked -p silo-vmm --example guest-lifecycle-controller --example native-live-api
make stage
export SILO_NATIVE_ROOT=/home/nickvd/Projects/worktrees/libkrun/silo-production
export SILO_SMOKE_KERNEL_CONFIG="$KERNEL_BUILD/.config"   # staged kernel's emitted config
export CC=/usr/bin/gcc                                     # needs static libc for the guest probe
make smoke SMOKE_ARGS='-m "not slow and not sdk" -k "freeze or generation or activation" --keep'
make smoke SMOKE_ARGS='-m "slow and not sdk" -k activation --keep'
```

`SILO_SMOKE_NATIVE_LIVE_API` overrides the entry path; `SILO_SMOKE_RESTORED_EVIDENCE`
selects a parent directory for per-cohort evidence (default: the workspace,
which is removed after a passing run unless `--keep`). The kernel config must
contain `CONFIG_VMGENID=y` and `CONFIG_VIRTIO_SILO_VMGENID=y`.

One cold AgentPid1 source (populated private root `disk0`, ext4 data `disk1`,
complete two-block shutdown manifest, real netd behind a transparent
datagram relay) starts a persistent userdata witness, renames its managed NIC
and seeds neighbours, proves source wire/gateway positives, holds captured
exec/SSH/forward sessions, collects same-boot capture profile files and freezes
through the real guest RPC before native pause and one full capture. Children
restore that read-only cut sequentially, each with its own subnet, MAC and
netd. Per child: parked/fenced native state, `generation-fresh`, CPU release,
exact timely native ACK correlated with the driver's `generation_state`, guest
`Activate` (replay, conflict, stale source Thaw), destination `Thaw`, and only
then native command `activate`, which is provider fence release, never guest
activation. After release the child must reach its new gateway, answer paired
destination ARP/ICMP probes but not its old address on the same wire, emit no
source identity, relay its selected listener with the destination token, and
reject the old instance, cursor and listener. The positive test runs two
children and an ordinary source ClockOnly resume/Thaw. Slow tests cover hook
failure/timeout/background descendants, listener conflict, lost Activate reply
replay, lost Thaw with a real next-epoch freeze, and captured-topology refusal;
failed children stay frozen and fenced and are stopped/reaped by their native
owner. `restored-report.json`, `attach/`, `wire.jsonl`, native command logs and
`inputs.json` under the cohort evidence directory are the evidence.
Activated status must report the destination IPv4 and no captured source IPv4.
The agent refreshes kernel-observed system facts once at activation completion
(including failure), notifying status watchers without syscalls on each read.

Options override environment variables. Paths should be absolute when supplied
explicitly. The Makefile sets binary and runtime directories for the selected
profile; use the corresponding pytest options to override them.

| Environment | pytest option | Default / meaning |
| --- | --- | --- |
| `SILO_SMOKE_BIN_DIR` | `--silo-bin-dir` | `<repo>/target/debug`; must contain silo |
| `SILO_SMOKE_RUNTIME_DIR` | `--silo-runtime-dir` | `<repo>/target/silo-runtime/<host-target>/debug` |
| `SILO_SMOKE_BACKEND` | `--backend krun\|vz` | `krun`; `vz` requires macOS |
| `SILO_SMOKE_CACHE` | `--cache-dir` | `${XDG_CACHE_HOME:-~/.cache}/silo-smoke` |
| `SILO_SMOKE_KEEP` | `--keep` | `1` retains workspaces even on success |
| `SILO_SMOKE_SYSTEM_IMAGE` | none | Appliance OCI reference; defaults to `ghcr.io/vandycknick/silo/system:dev`; set it empty to skip system tests |
| `SILO_SMOKE_DISTRO_IMAGES` | none | `label=oci-ref` list for the SSH distro lane; defaults to `arch=ghcr.io/vandycknick/archlinux:latest,system=<system image>`; set it empty to skip |
| `SILO_SMOKE_SYSTEMD_IMAGE` | none | Optional Phase F systemd image with vsock SSH socket activation |
| `SILO_SMOKE_CURL_IMAGE` | none | Optional Phase F image containing curl for live secret-provider tests |

Failed tests and `--keep` preserve stopped machine files and per-machine logs,
not just the outer workspace directory. Teardown still force-stops every
registered VM and terminates owned daemons; retention never authorizes leaving
processes running. Only successful, non-retained workspaces remove their
registered machines and private root. Cleanup uses that workspace's private
Home and never removes machines from another Home.

Host targets are `linux-amd64-gnu`, `linux-arm64-gnu` and `darwin-arm64`.

Markers: `daemon` starts a private daemon; `system` needs the appliance image;
`sdk` runs Go/Node examples; `linux_only` and `macos_only` select host-specific
checks. The default selection excludes `slow`; `make smoke SMOKE_ARGS='-m slow'`
overrides it to run extended checks. An explicit marker expression replaces the
default, so use `-m 'not daemon and not slow'` to retain the fast selection while
excluding daemon tests. `live` tests require explicit selection with `-m live`.

The SDK lane skips when Go, Node, the built Node SDK or the Go FFI library is
missing. The system and distro lanes pull their published default images from
ghcr.io; `SILO_SMOKE_SYSTEM_IMAGE= SILO_SMOKE_DISTRO_IMAGES= make smoke` runs
fully offline. Pulled images are kept under `<cache>/image-catalog/<schema-hash>`:
each embedded initial schema gets a separate fixture cache. It contains immutable
`images/{objects,streams,source-blobs,transport}` bytes and a sanitized image-only
SQLite catalog. Fixtures use SQLite backup, never copy active database/WAL files,
and seed only unopened private Homes. Machine/private roots, operations, network
state, locks and temporary files are never copied. Stream paths are remapped to
the destination Home; no mutable JSON cache exists. Source-blob reuse verifies
size and SHA-256 on blocking workers with bounded scratch buffers. Old-format
state/cache is not imported; this hard-breaking release requires reinstalling and
wiping prior Silo state. The systemd-owned SSH lane and the curl image have no
published default; nothing in this repository builds them yet. On macOS, daemon-managed VMs use krun even when direct CLI tests
select vz.

### Default-suite cost strategy

The Phase 7 baseline in `.tmp/phase07-default-qualified.xml` ran the complete
73-case non-slow/non-SDK/non-live selection in 966.09 seconds. The inode ENOSPC
case alone took 82.141 seconds. Its guest workload now creates empty files until
the actual create returns ENOSPC, then performs one checked `syncfs` before
reporting that errno. Committing the journal after every empty inode was setup
cost, not the resource-exhaustion oracle. The real ext4 upper, zero free inodes,
remaining free blocks, immutable-lower hash, ample host space and post-deletion
capacity recovery assertions are unchanged. Block, host-error and copy-up
workloads retain their per-file checked writes and fsyncs.

Overlay and stopped tests share one session-built probe and immutable OCI image
body, published under their existing separate registry references. Every case
still creates its own Home, catalog, writable root and real guest. No mutable
machine state or previously booted fixture is shared. Overlay diagnostics batch
all existing procfs/sysfs reads and `df` commands into one fail-fast guest exec.
Capacity checks obtain the same two independent guest statvfs projections with
one `stat` invocation, still comparing each fresh post-effect metrics frame
against both real filesystems. Stopped byte/inode oracles, full logical hashing,
copy/replay order, fresh boots and exact-boot closure checks are unchanged.

Phase 12 measured 199 `info` invocations taking 101.91 seconds in the six
stopped fork/replay and exact-boot snapshot cases. Identity-only path and SQL
lookups now use the existing independent read-only catalog process, without
caching machine identities or reconciling live state. Explicit CLI state,
readiness and clean-stop assertions remain. The same six cases passed before
and after, taking 291.08 and 233.94 seconds respectively; `info` calls fell to
80. These are targeted-run timings, not a full-suite speed claim. Raw commands
and timings are retained in `.tmp/plan/evidence/phase-12/stopped-speedup.json`
and its adjacent `stopped-{before,after}-command-times.jsonl` files.

The Phase 9 complete default baseline is
`.tmp/phase09-corrected-default.xml`, with its command and call-only durations in
`.tmp/plan/evidence/phase-09/full-smoke-bg618.log`: 87 passed in 988.84 seconds.
The four two-child fork calls took 49.51 seconds (clean-flat), 48.64
(dirty-replay-flat), 45.75 (clean-raw) and 44.01 (dirty-replay-raw); the two
exact-boot snapshot calls took 45.57 and 45.20 seconds. JUnit testcase times also
include setup/teardown, so compare them separately from pytest's call durations.

Stopped tests now batch each guest-copy proof's same `cat`, absence `test` and
two `stat` invocations into one fail-fast guest exec. A textual boundary keeps
the complete `cat` result available for the same host-side exact-byte assertion;
the original hardlink inode/link-count comparison remains host-side too. Source
setup invokes the same durable-write probe before the same hardlink/machine-ID
writes and `sync`, but within their existing shell session. Snapshot children
read their common file and kernel command line in one exec, still checking exact
common bytes and the captured argument separately before the Data mutation.
This removes ten CLI/agent round trips per fork case and three per snapshot
case, 46 in the default selection, without caching any guest or disk result.
All logical disk hashes, child/source inode checks, cold boots, run identities,
dirty replay, lifecycle cleanup and existing deadlines remain in place.

The probe source is `virt/vmm/tests/guest/overlay_probe.rs`. Pytest's session
fixture compiles it with rustc for Linux musl and embeds that new executable in
the OCI layer; use a new pytest session after changing it, not a retained image.
This does not rebuild the production initramfs. Stage the production binaries
with `make stage` as usual before measuring. For the after measurement, retain
the same kernel/config qualification, fault monitors, system-image fixture,
host filesystem, resource conditions and environment as the Phase 9 baseline,
and run the complete unchanged selection:

```sh
make stage
make smoke SMOKE_ARGS='-m "not slow and not sdk and not live" --junitxml=../.tmp/phase10-default-qualified.xml --durations=20'
```

Compare the full wall time and the six affected call durations against the
retained Phase 9 baseline, and compare the same testcase identities/counts and
outcomes in both JUnit reports. Native/runtime changes in the same integration
are a timing confounder; attribution requires a paired run with the same staged
native bytes and only the smoke batching changed. These changes remove known
redundant sessions, not assertions or default cases. No elapsed-time improvement
is established until the complete selection runs.

Phase 11 additionally batches fourteen Data-device transport lookups and the
two persistence setup/readback clusters without crossing lifecycle boundaries.
The reserved-encoding positive controls reuse the session's immutable OCI body;
each control machine and malformed image remains private to its test. This
removes 19 guest sessions and three redundant image constructions.

The complete 87-case selection passed before and after with identical staged
monitor, kernel, initramfs, agent and netd bytes: 943.32 seconds before and
931.16 seconds after (12.16 seconds lower, still above 15 minutes). The after
run used an isolated Phase-10 source checkout plus the smoke changes, preserving
fault-fixture source-hash checks while native implementation continued elsewhere.
One earlier comparison was invalidated by those checks and is retained as a
failure, not timing evidence. Reports and input hashes are under
`.tmp/plan/evidence/phase-11/`; this single pair does not establish a general
performance guarantee.


## Isolation and evidence

Every test creates a short workspace under `/tmp/silo-smoke-*` on Linux or
`/private/tmp/silo-smoke-*` on macOS. It gets private `HOME`, `SILO_HOME`,
`XDG_CONFIG_HOME` and `SILO_RUN_ROOT`. Subprocesses receive an explicit environment,
not the developer's daemon configuration. Socket paths stay within the Unix
socket path-length budget. A session guard records the live daemon's default
control socket inode and modification time and asserts they remain unchanged.

Concurrent sessions serialize shared registry CA creation and OpenSSL serial
updates with a close-only file lock; a thread-local lock cannot protect
independent pytest processes.

Teardown stops/removes registered VMs and terminates tracked daemons. Failed
runs and runs with `--keep` retain the workspace and print its path; successful
runs otherwise remove it. Command transcripts and daemon output are in
`/tmp/silo-smoke-*/evidence/*.log` (or the macOS equivalent). Keeping evidence
does not keep the VMs running.

## Images and registry

The first run downloads the architecture-matched Alpine 3.21.3 minirootfs and
verifies its pinned SHA-256. Verified cached archives are reused offline. The
base tar plus an overlay forms one gzip-compressed OCI layer, with a config and
manifest served by a session-local HTTPS registry bound to `127.0.0.1`. BASIC
adds `/etc/proof` and the unprivileged silo user/home. The agent is injected by
the initramfs, not included in the image.

To add an image, define an `ImageSpec` in `silo_smoke/images.py`, build it once
in a session fixture, then publish it through the registry:

```python
from silo_smoke.images import GuestDir, GuestFile, ImageSpec, build, fetch_alpine

spec = ImageSpec(
    name="example",
    files={"etc/example": GuestFile(data=b"example\n", mode=0o644)},
    dirs={"opt/example": GuestDir()},
    remove=frozenset(),
    append={},
)
image = build(spec, fetch_alpine(config.cache_dir))
reference = registry.publish(image, spec.name)
```

Paths are relative to the guest root. Overlay entries replace matching base
members; `append` adds bytes to existing text files and `remove` drops base
members. Absolute paths, traversal and duplicate normalized paths are rejected.
Keep scenario-specific additions in separate specs rather than changing BASIC.
BASIC also removes Alpine's busybox `/sbin/init` so the agent stays PID 1
(the agent hands off to any executable init it finds).

Specs can pull real Alpine packages: `ImageSpec.packages` lists
`ApkPackage(name, version)` entries fetched from the v3.21 `main` repository and
verified against the per-architecture hashes in `APK_SHA256`, and their payload
is laid down before `files`. `CA_TRUST` is BASIC plus `ca-certificates`, which
gives the guest the `update-ca-certificates` trust backend the agent needs when
a private network policy installs a certificate authority. Adding a package
means pinning its hashes for both architectures. `IPROUTE` adds `iproute2-ss`
(with `libmnl` and `libcap2`) so a guest can list vsock listeners with
`ss --vsock`; pins come from the v3.21 APKINDEX `P`/`V`/`D` fields and the
SHA-256 of the downloaded archives.

Linux trusts the registry through the workspace's `SSL_CERT_FILE`, which points
at `<workspace>/ca-bundle.pem`: the host's CA bundle plus the suite CA, because
that variable replaces (not extends) the trust store for Go and rustls consumers
and `netd` still has to verify public upstreams. On macOS,
the Rust OCI client's platform verifier ignores that variable. Trust the stable
suite CA once in your login keychain after it has been generated (preflight
prints the instruction):

```sh
security add-trusted-cert -r trustRoot \
  -k ~/Library/Keychains/login.keychain-db <cache>/registry-ca/ca.pem
```

Here `<cache>` is the resolved smoke cache directory. Changing that directory
or replacing its CA requires trusting the new certificate. The registry's leaf
certificate is issued per session with localhost/127.0.0.1 subject alternatives.

## Flat-overlay and VMDK qualification

`tests/test_overlay.py` drives the normal staged CLI/libvm/monitor/worker path.
Opaque raw remains the default. Managed overlay needs an immutable admitted
kernel/base-initramfs/resolved-config/profile/architecture/attachment tuple;
schema support and kernel track names do not grant admission.

Prepare the two pure host consumers and stage production binaries after all
changes have landed:

```sh
cargo build -p disk-image --example format_upper
cargo build -p libvm --examples
make stage
```

The Rust musl target for the guest architecture must already be installed.
The smoke session builds `virt/vmm/tests/guest/overlay_probe.rs` directly with
`rustc`, using the existing self-contained musl linker convention. It includes
the exact production init effective-options verifier by source path. No Cargo
test launches a VM. `debugfs`, `e2fsck`, `unshare`, `mount`, `umount`, and GNU
`cp` are needed by the corresponding Linux qualification fixtures.

### Initial candidate, then production acceptance

Before there is a positive tuple, run only the controlled candidate:

```sh
make smoke SMOKE_ARGS="-k overlay_candidate_qualification --keep"
```

For a freshly built local kernel, stage that exact output and supply its actual
resolved configuration as evidence input (not as an admission switch):

```sh
KERNEL_BUILD=/absolute/path/to/the/completed/kernel/build
make stage KERNEL_PATH="$KERNEL_BUILD/vmlinux"
export SILO_SMOKE_KERNEL_CONFIG="$KERNEL_BUILD/.config"
make smoke SMOKE_ARGS="-k overlay_candidate_qualification --keep"
```

This uses a normal opaque create for its disposable flattener-produced lower,
the real `format_upper` implementation for its upper, and the shipped monitor
in foreground mode, which starts its real krun worker. It does not call libkrun
directly and does not insert a database/home/environment qualification grant.
Kernel, base initramfs, composite and monitor/worker are private snapshots;
evidence hashes the exact bytes consumed, so restaging cannot silently change
the recorded tuple.

Retained `overlay-candidate-tuple.log`, candidate serial/trace/output logs and
formatter output contain exact artifact digests, host lane, actual guest kernel
version, UUIDs, measured serials/geometry/RO, mountinfo, current module defaults,
and accepted verifier/profile evidence. The staged manifest must bind the
kernel, base-initramfs and **native executable** digests to those private
snapshots. The actual worker `/proc/PID/exe` hash must match the consumed
monitor/worker snapshot. The candidate records the real binary's
`capabilities --backend krun --json` build identity and corrected signed native
revision; these are provenance, not a feature grant. For an authenticated OCI
kernel, its artifact metadata supplies the resolved-config digest. For a local
kernel, set `SILO_SMOKE_KERNEL_CONFIG` to its actual resolved `.config`; Main
must independently retain the build provenance associating that config with
the exact tested kernel. Hashing an arbitrary config file is not that proof.

Main reviews this observed evidence, records the immutable exact tuple in the
qualification table, rebuilds and stages. Then run the real production path:

```sh
make smoke SMOKE_ARGS="-k 'vmdk or overlay' --keep"
make smoke SMOKE_ARGS="-m slow -k 'vmdk or overlay' --keep"
```

The candidate is not the production-path positive gate. Full normal acceptance
includes >2 GiB production mapping against an independent whole-file linear
oracle and a sector-record oracle, an explicit reader-offsets-as-bytes negative
control, actual worker FD access modes, spaces/relocation, metadata/hardlinks/
index/EXDEV/whiteouts, `/tmp` policies and restoration of hidden disk contents,
fresh public metrics compared with independent guest statvfs, real block/inode/
copy-up ENOSPC, isolated host ENOSPC, recovery and replacement growth, >65k
directories, discard/zero lengths, and raw regression. The historical 4.5 GiB
`a`, empty occurrence and repeated 1 MiB `b` fixture retains seed 14 and its
independent concatenation negative control; it does not replace production
mapping evidence.

The Linux FD gate observes `IN_OPEN` events on the actual immutable lower,
including an open/close positive control, before launching a fresh CLI with
soft=hard=256. It requires the typed preflight error naming both limits and no
backing open. A separate soft=256/hard=512 launch must raise and boot, and the
actual worker's inherited `/proc/PID/limits` must show 512/512.
The bounded attachment edge also boots two roots plus fourteen real raw Data
disks with the raised limit and checks all sixteen guest identities, actual
lower RO handles, upper RW handle and fourteen actual Data RW handles. The
`records + 256` check is numeric admission, not a reservation of free FDs;
concrete native resource/open failures remain failures with their diagnostics.

### Controlled real-native failures

Serial/access/reordering negatives must pass unchanged host/private validation.
Main builds isolated source-copy fixtures, never production feature/env bypasses:

```sh
PYTHONPATH=smoke uv run --project smoke python -m silo_smoke.overlay_faults \
  --destination "$HOME/.cache/silo-overlay-faults-phase08" \
  --native-source /home/nickvd/Projects/worktrees/libkrun/silo-production \
  --production-monitor "${SILO_SMOKE_RUNTIME_DIR:-target/silo-runtime/linux-amd64-gnu/debug}/bin/silo-vmm" --build
export SILO_SMOKE_FAULT_MONITORS="$HOME/.cache/silo-overlay-faults-phase08"
make smoke SMOKE_ARGS="-k 'overlay_native or overlay_injected_request' --keep"
```

The destination must be new and outside the repository and native source tree.
The controller refuses changed source anchors and archives the clean, signed
production HEAD reported by the current monitor, after checking its signed commit
and the retained `overlay.APPROVED_NATIVE_REVISION` prerequisite ancestry. It
refuses a dirty source or a monitor/source HEAD mismatch; it never archives the
active working tree. This is fixture provenance, not a production admission grant.
The manifest records the actual native HEAD, declared baseline, full archive
digest, original/mutated source hashes, replacement text, commands and binary
hashes. The COPY uses its own explicit native path patch and the unchanged build
observer. Its `buildIdentity` binds the copied source content with unknown Git
provenance; no synthetic revision label or old baseline identity is substituted.
After each build, the actual binary must answer `capabilities --backend krun
--json` with this content-bound, qualification-ineligible identity. The exact
identity and stdout/stderr/exit status are retained in the manifest and
`capabilities.log`. Old fixture manifests are historical evidence, never migrated
or silently reused for new monitor bytes.
Production validators, dependency/cache/pin and stage remain untouched. Rebuild
fixtures after production source changes; never add observer/fault binary
hashes to the production admission table.

Missing/truncated/swapped serial fixtures alter only the copied native
`build_disk_image_id` response construction. Duplicate uses a third real raw
Data device with its unique `silo-data-0` attachment key; only its native GET_ID
response becomes `silo-root-lower`. Acceptance requires actual virtqueue GET_ID
responses from two distinct native device objects and explicit guest duplicate
rejection, not a missing/replaced attachment or host JSON rejection. Reordering
reverses the copied worker's disk attachment order after validation. Access
fixtures change only the actual copied native RO setting.

The copied init `effective-index-off` fixture changes only the mount request;
the production verifier remains byte-identical. It must reach the exact
effective-profile rejection before any candidate workload or rescue shell.
This is explicitly an injected-request gate. Separately, the scratch
no-export-handle gate measures actual `name_to_handle_at` EOPNOTSUPP, requires
successful OverlayFS mounting and actual effective index=off, and runs both a
production positive control and the same verifier's downgrade rejection. A
failed mount or an unrelated parser error does not pass.

The slow controlled historical native fixture uses the same real monitor/worker
and guest verifier with `[a, empty, b, b]`: a valid flattener-produced ext4 prefix
inside sparse 4.5 GiB `a`, repeated 1 MiB `b`, and five FLAT records. The guest
gets only bounded read positions/lengths. Whole-occurrence and record oracles,
the deliberate byte-offset negative, and actual three-a/two-b RO worker handles
are checked independently. This controlled repeated-extent proof does not
claim libvm's current semantic single-stream profile accepts repeated closures;
the separate >2 GiB positive gate still uses the full normal production path.
Journal authority has two actual-disk reader controls: a valid active inode 8
with deliberately wrong `s_jnl_blocks` must boot; an invalid active inode/map
with its initially matching valid backup preserved must reject before replay,
leaving the entire failed upper unchanged. These are real production-init
reads over a real virtio disk, not only pure inode parser cases.


### Exhaustion, recovery and slow cases

The host ENOSPC fixture creates a bounded tmpfs inside a private unprivileged
user/mount namespace and bind-mounts only a disposable upper file. DB, logs,
immutable lower and evidence remain outside. It first proves actual host errno
28 and ample guest space, then requires actual guest write/fsync EIO or ENOSPC,
run-bound worker diagnostics retaining host ENOSPC, and sticky checked guest
shutdown failure. The original upper is revealed unchanged when the namespace
ends. A namespace mount feasibility probe is not VM qualification; missing KVM
access or namespace support is a failed prerequisite, never skip-as-pass.
While stopped, the same exhausted disposable directory also exercises real
replacement-growth ENOSPC: the old bytes/path/capacity record must remain
unchanged and failed staging must leave no published private generation.

Dirty recovery retains immutable source bytes and two private copies before
either replay. Growth checks old-prefix identity before boot, stable UUID,
preserved committed contents, independent copies, exact backing/span/tail,
GDT consumption across 16 GiB, and sparse growth to 1 TiB. No host repair or
public flat snapshot/export is used. Directory scale, full range-operation
matrix, host exhaustion, >2 GiB mapping and clean/dirty growth are marked slow.
Range-operation cases include 512-byte sector-aligned middle and tail requests
that are deliberately not host-4KiB aligned, in addition to aligned middle,
tail and whole-device cases. Both discard and zero must actually read zero,
preserve every outside byte and preserve capacity after close/reopen. No-op
discard and host-block edge rounding are failures, not acceptable outcomes.
`BLKZEROOUT` supplies a real guest zero-range request; these behavior receipts
do not by themselves claim which native opcode a kernel fallback selected.
`fstrim` compares upper length to a baseline captured before trimming.
Orderly persistence/recovery gates use normal CLI/libvm stop and the run-bound
guest handshake, exercising real writer drains, storage shutdown and poweroff.
They require a current-run native terminal artifact with actual status0, no
signal/force reason, terminal owners and the three established storage facts
on the qualified Linux Raw profile. Persistence/clean-recovery gates retain
raw serial evidence and still require RECOVER clear, restart identity,
persistent bytes and unchanged lower content. Explicit dirty SIGKILL
recovery cases remain separate.
Unexecuted HVF, KVM arm64 and VZ lanes remain pending.

On Linux, `Workspace` honors a process-local `TMPDIR`; choose a short durable
parent for large growth/copy gates, rather than the host's 32 GiB `/tmp` tmpfs.
For example, after creating `$HOME/sm` as a private directory:

```sh
TMPDIR="$HOME/sm" make smoke SMOKE_ARGS="-m slow -k 'vmdk or overlay' --keep"
```

Large growth cases explicitly reject a tmpfs workspace. Unix socket paths
must still fit the harness's existing 100-byte budget, so keep the parent
short. Replacement evidence records both logical length and actual
`st_blocks * 512` allocation; comparisons to the original 64 MiB source remain
bounded to that original prefix even for a 1 TiB target. Fault-build copies
also belong on durable storage, not `/tmp`. The dedicated host-ENOSPC tmpfs
remains separately bounded and does not exhaust the workspace filesystem.

### Native opcode and unsupported-hole-punch proof

Run `test_overlay_native_range_opcode_and_real_fallback` only after the
corrected signed native pin, rebuilt stage, observed candidate and immutable
exact kernel/init/**native binary** tuple have completed the qualification flow
above. The source-copy build command also creates `range-observer`. Then:

```sh
TMPDIR="$HOME/sm" make smoke SMOKE_ARGS="-m slow -k overlay_native_range_opcode_and_real_fallback --keep"
```

This genuinely slow Linux matrix covers DISCARD and WRITE_ZEROES flags 0/1, aligned
middle/tail/whole and sector-aligned 512-byte middle/tail ranges that are not
host-4K-aligned. Each case creates a real private user/mount namespace and
either a bounded 8MiB tmpfs or ramfs containing **one controlled 4MiB Raw Data
file only**. Ramfs itself is not size-bounded; the controller never fills it,
never permits unbounded guest writes to it, and keeps database, logs, all root
storage, copies and evidence outside. Actual owned-FD `fallocate` controls
measure PUNCH_HOLE/KEEP_SIZE and ZERO_RANGE/KEEP_SIZE, preserving and checking
the original bytes on EOPNOTSUPP; ramfs must actually report EOPNOTSUPP.

The first lane uses the unmodified corrected staged CLI/libvm/monitor/worker,
checks actual worker writable handles to that same device/inode, guest zero
reads, every host byte inside/outside the range, unchanged logical length,
stop/reopen, capacity and guest reads after restart. A separate unqualified
COPY-only monitor then logs actual parsed native requests, correlates their
device object with that real Data device's GET_ID, and requires exact range
coverage by the requested opcode **and actual parsed flags**. `zero` uses the
real BLKZEROOUT ioctl and must yield WRITE_ZEROES flags=0. `zero-unmap` uses
real block-device `fallocate(PUNCH_HOLE|KEEP_SIZE)`; the exact built kernel's
`block/fops.c` selects BLKDEV_ZERO_NOFALLBACK without NOUNMAP, and
`drivers/block/virtio_blk.c` maps this to WRITE_ZEROES flags=1. Both operations
run in the unmodified production lane before the separately labelled observer.
DISCARD must report flags=0. Every Data-device request receipt must match the
expected opcode/flags and cover the exact requested range; bytes inside/outside,
length and reopen checks remain mandatory. Raw finalized `vm.exit.json`
diagnostics avoid logger-chunk fragmentation. Ordinary-WRITE fallback is not
native WRITE_ZEROES evidence and fails this gate. The observer is never staged
or admitted, and cannot substitute for the
unmodified production-path lane.

`native-range/` retains real host errno/FD controls, worker FD identities,
native request receipts, complete case evidence and a child-workspace pointer.
With `--keep`, that child workspace retains the private consumed monitor,
kernel, base/composite initramfs and configuration snapshots. If actual native
Raw open cannot use ramfs or a kernel refuses/rounds partial-sector requests,
preserve that real failure: do not skip, fabricate EOPNOTSUPP, relabel an
ordinary write, or claim the fallback gate passed. Report the exact missing
prerequisite to Main; an exact-owned-FD syscall-fault fixture would then need
the separately approved bounded implementation, never a production bypass.

Foreign-effective-UID host metadata remains the documented F3 P2 fixture gap;
mode/hardlink/ACL tests must not be reported as having exercised that branch.

Source-copy native provenance comes from the actual privately snapshotted
production monitor's `capabilities --backend krun --json` build identity,
not a duplicate Cargo pin parser. A stale production monitor is rejected
before archiving.

### Whole private-stage replacement with retained qualified files

`test_overlay_qualified_stage_replacement_uses_retained_triplet` uses only
private complete runtime clones, never Main's stage. Its successor contains
byte-identical kernel/base assets and the existing unqualified reordered
fixture monitor. An owned CLI starts in its own process group. Real IN_OPEN
events on the first post-admission `.lower-UUID.tmp` publication trigger
SIGSTOP; the controller waits for the owned CLI's threads to stop and records
its actual descriptors. It requires the three original kernel/base/native
device/inode identities as read-only CLOEXEC descriptors, an actually held
private output, no kernel/composite publication and no monitor exec. Earlier
capability-query opens and native file cursor positions are not this proof.
If interception misses that actual boundary it fails with descriptor/event
evidence rather than proceeding with a weaker race oracle.

While those qualified files are held, it atomically swaps the whole private
stage and unlinks the retired tree, then verifies all three old inodes have
zero links and retain their exact bytes. After resume, the real guest must
start, its published kernel/base prefix must match, and both actual
monitor/worker `/proc/PID/exe` must identify the old deleted inode and admitted
SHA256 recorded by `overlay_stage.ADMITTED_NATIVE_SHA256` after Main's observed
candidate review (currently the admitted shared-IRQ native build).
A fresh start against the complete successor must reject its actual unknown
native hash without allocating a new run. Cleanup always resumes and reaps
the owned CLI, with bounded group termination only for that owned process;
the existing workspace cleanup owns registered VM teardown.

```sh
make smoke SMOKE_ARGS="-k overlay_qualified_stage_replacement_uses_retained_triplet --keep"
```

Retained `overlay-stage-*` evidence includes events, stopped-process FD
identities, unlinked asset hashes, actual monitor/worker executable identities,
CLI stdout/stderr and the fresh-start refusal. The gate requires both guest
asset copies to accept authenticated link removal; it must fail, not waive
that boundary, if copying still compares stale link/ctime fingerprints.

Machine/run identity assertions compare parsed UUID values, not compact versus
hyphenated serialization spellings. Malformed or different identities still
fail. Storage-key/path spellings remain unchanged; the private-stage gate
shares the same metrics identity check through `overlay.evidence`.

Filesystem identity checks use numeric kernel statfs magic (`stat -f %t`),
including OVERLAYFS_SUPER_MAGIC `0x794c7630` and TMPFS_MAGIC `0x01021994`.
BusyBox/GNU human-readable filesystem names are not an acceptance ABI.

The metadata guest oracle first requires the lower's exact fixture bytes:
2750 literal `x` user-xattr bytes, the named UID1234 read-only access ACL with
mask/read-only group/other entries, and the v2 effective CAP_NET_BIND_SERVICE
capability blob. It then independently requires those bytes to survive the
specified copy-up operations. Missing xattrs report actual path/name/errno;
presence or preservation alone cannot hide a wrongly rendered lower.

`test_overlay_native_symlink_4095_and_flat_4096_refusal` checks the 4KiB ext4
symlink boundary through real production creation and the guest kernel:
4095 target bytes must survive exact native `readlink`, while an otherwise
identical fixture with a 4096-byte target must fail flat materialization
without publishing a machine. Raw failure output is retained; no incidental
error wording or Cargo-launched VM supplies this oracle.

The maintenance-path and real host-ENOSPC shutdown faults now use the same
normal CLI handshake. They require the host's exact-run COMPLETED/FAILED
receipt (numeric result2 with its diagnostic), a current native terminal
record with unforced status0, false guest/host-flush facts and a nonclean
reconciled outcome. Old guest terminal-log wording and a cancelled invoking
exec are not the failure oracle. Actual backend errno and storage/byte
oracles remain mandatory; guest ENOSPC is not the retained host-fsync-EIO gate.

F10 command scripts use ordinary `exec sh -c`, not an interactive shell left
waiting at its prompt after input EOF. Silent successful guest operations
such as `syncfs` use the ordinary exec result; JSON decoding is reserved for
probe commands whose output contract is JSON.

Reserved metadata rejection is causal coverage across layers: core
`acl_mode_capability_and_reserved_metadata_are_validated`,
`socket_pax_and_device_profiles_have_no_payload_and_no_host_extraction` and
`production_flat_materialization_rejects_malformed_layers_and_forward_links_atomically`
cover typed metadata/device rejection and failed-staging cleanup. The native
CLI gate first admits the otherwise equivalent valid image, then requires
mutated reserved-xattr/char0 images to fail without machine or rootfs-artifact
publication. Raw CLI errors are evidence, not pinned display text. Guest
candidate rejection similarly keeps explicit workload/rescue prohibition and
the active-journal no-write oracle, not incidental diagnostic substrings.

Exact-tail growth uses the existing public Rust `storage_acceptance` consumer,
built with `cargo build -p libvm --example storage_acceptance`. Its
`set-root-capacity MACHINE BYTES` action calls `Machine::update` with the exact
byte count against the same private Home/runtime and checks the returned
published capacity. No retiring SDK, parser expansion or production shim is
involved. Whole-MiB growth retains the accepted CLI `disk=NMiB` grammar.
The fixture records runtime output. Dirty recovery captures the exact run's
SIGKILL terminal artifact and waits for both owned monitor/worker PIDs to be
gone; a terminal Error label is not confused with a live process or rewritten
to Stopped. Directory-scale inspection follows actual guest PID1 shutdown and
RECOVER clear, and checks numeric EXT4_INDEX_FL/link-count fields without host
journal replay or whole-line wording assertions.

The host-ENOSPC replacement lane retains its actual errno28 receipt and full
bounded filesystem, then checks real public-update refusal, unchanged semantic
record/old file bytes and absence of a partial generation. Hidden CLI error
chains are recorded, not matched as an errno oracle.

The sixteen-total-disk gate keeps two roots plus fourteen Data disks. Exact
serial IDs select each Data block device; fourteen guest threads synchronize
eight rounds of distinct 64KiB writes and flushes, invalidate each dedicated
Data cache, and perform real readback. It records actual sysfs virtio identities
and `/proc/interrupts` routing/counter changes to prove shared routed-line
delivery beyond dedicated transports, not enumeration alone. After stop, a
separate host oracle checks every byte of every 8MiB backing (including all
untouched outside bytes) and unchanged length. Cold reopen repeats concurrent
reads/capacity checks and host-byte verification; immutable lower hash and
actual lower-RO/upper-RW/Data-RW evidence remain mandatory. This is not Phase5
host-flush certification.

The byte-exact Rust consumer also covers shrink, overlimit and non-sector-aligned
capacity refusals after a successful same-size stopped-update calibration.
Those values cannot be represented by the CLI's integer MiB/GiB grammar, so
parser rejection is never counted as storage-admission proof. The existing
hot-update CLI gate retains an accepted `128mib` request.

The bounded host-ENOSPC refusal record includes exact before/after scratch
directory inventories (name, device/inode, type/mode, size, links, ownership and
symlink target) before any refusal/integrity assertion. This preserves cleanup
diagnostics after the private mount namespace is gone without relaxing the
unchanged-directory oracle.

Before replacement exhaustion, the fixture holds the actual original
`node-state.lock` FD and creates only an empty bounded-filesystem mount target.
After the ordinary whole-directory bind, it explicitly file-binds that retained
original onto the visible lock path using `/proc/self/fd/N`, inherited only by
the mount child with source canonicalization disabled. It verifies and records
visible dev/inode equality with the pre-bind original. A directory bind is not
assumed to clone nested mounts. Cleanup removes the owned nested lock mount,
parent bind, original upper bind and scratch mount in order, then closes the FD.
The required production lock is never copied, unlinked or filtered from the
unchanged-directory oracle; DB/log/lower/evidence stay outside the bounded FS.

## Run-bound shutdown, retained inodes and generation leases

The existing fast lifecycle smoke now also observes Linux's actual
monitor/worker identities, their root/lease FD inode identities, terminal
process state, independent lease release, ext4 RECOVER clear, the exact-run
three-fact exit record and the atomically reconciled storage outcome. It
reuses its existing boots rather than adding VMs to the default selection.
This keeps the default lane bounded; Main records actual elapsed time and
must keep the complete default selection below 15 minutes.

The extended controllers are all explicitly `slow`, use normal staged
CLI → libvm → monitor → worker launches and introduce no SDK consumer:

```sh
make stage
cargo build -p libvm --examples
make smoke SMOKE_ARGS='-m "not slow and not sdk" -k lifecycle'
make smoke SMOKE_ARGS='-m "slow and not sdk" -k shutdown'
```

`storage_acceptance` is a standalone consumer of the public Rust image
remove/prune API. It boots no VM itself and is not a Cargo test. Smoke uses
the staged `examples/storage_acceptance`, falling back to the explicit
debug example build above. With a custom Cargo target directory, copy the
example to the selected smoke binary directory's `examples/` subdirectory.

Rebuild all libvm examples after changing the initial schema: both
`root_metrics` and `storage_acceptance` embed its checksum, just like the CLI.
An old helper must refuse a new-format Home, not bypass schema admission.

`test_shutdown_cli_clean_independent_facts` keeps two real guest writers
active at stop and checks persisted acknowledged content after restart.
The outcome matrix covers healthy managed flat-overlay, forced termination,
actual worker SIGKILL, an actual guest kernel panic (retained serial evidence),
image-owned PID1, unmounted externally writable Data and writable host shares.
Unsupported shapes remain supported VM launches but cannot certify clean.
Their external files/directories must survive ordinary machine removal.

The worker-crash regression distinguishes read-only observation from durable
reconciliation: `info` must report the observed forced result without changing
the persisted storage outcome or launch-operation roots. An explicit public
CLI stop then commits that terminal result and retires the operation.
Manager-forced exit records may omit `storageShutdown`: they are durable
forced run fences, not invented monitor-finalizer certificates. The forced
gate checks actual terminal owners, independent lease release and persisted
forced classification without inferring attachment closure from missing facts.

The guest-panic case deliberately uses the controlled **image-owned PID1**
fixture, not the agent-owned PID1 healthy-shutdown profile. Its `/sbin/init`
installs a USR1 trap that exits77. Before signalling it, the controller
requires the observed agent boot report to identify a child agent, actual
`/proc/1` PID/TGID and init command, and the kernel's `SigCgt` bit proving the
USR1 handler is installed. Absent prerequisites fail the gate with retained
diagnostics. Ordinary root guest exec sends USR1 to PID1; stdout/stderr and
the result are preserved. Only new current-run serial output with the actual
kernel panic prefix and `Attempted to kill init! exitcode=0x00004d00`
satisfies the panic oracle. This tests a genuine Linux init-death panic on
the unchanged production kernel, not an agent-owned-PID1 crash or surrogate
worker termination. No SysRq/debug kernel feature is required or enabled.

The orphan gate enables a scoped child subreaper, captures pidfds and stable
start identities, sends SIGSTOP to the **entire actual native worker**, and
kills **only its monitor**. Before any worker kill or group cleanup it requires
the stopped worker to remain live, its exact lease OFD to block an independent
EX|NB probe, real image prune to preserve closure bytes/operation roots, and
start/removal/replacement to refuse destructive reuse. SIGCONT then runs the
unchanged watchdog; `waitpid` must observe exit 125 and actual reap before a
new lease probe succeeds. Removing the machine's remaining semantic root and
pruning must finally collect otherwise-unreachable lower bytes. Survival
while the machine root remains is not, by itself, claimed as operation-only
GC proof; focused storage tests cover that independent case.

The retained-inode race gate replaces original pathnames after native
attachment construction for opaque root, overlay upper and external Raw
Data. It checks actual monitor/worker FD inode identities, writes through
the guest, requires the replacement inode's digest to remain unchanged,
then restores and reads the pinned generation. No original-path reopen is
used as the final sync oracle.

`test_shutdown_real_retained_host_fsync` starts the CLI under a child-only
Linux x86_64 ptrace controller. It follows only that launch's forks and
monitor threads, detaches the actual native worker at exec, and observes
post-worker-reap fsync on every writable Raw backing, including external
Data in an explicitly unsupported shape, plus checked close on **every
retained monitor attachment**, including read-only VMDK lower and Raw disks.
The test binds the actual ready monitor's unique FD/device/inode for each
current disk after launch generates the lower descriptor, publishes a bounded
run-bound target snapshot and waits for tracer admission before requesting
stop. Close-only targets have no fabricated sync result. Earlier transient
opens/closes and later reuse of an already-closed FD cannot satisfy the gate.
The healthy case leaves syscalls unmodified. The negative case replaces
only the exact retained target FD's sync return with `-EIO`; evidence labels
this **injected syscall EIO, not physical media failure**. Guest ENOSPC,
failed output publication and fabricated evidence JSON cannot satisfy it.
The guest fact remains independently successful for managed-root cases;
host-flush becomes false on injected failure, closure stays independently
observable and the final storage outcome cannot be clean. For external
Data the real sync/close observations remain required even though its guest
fact is already noncertifying.

The trace request and `retained-fsync-receipt.json` retain actual device,
inode, monitor/thread/worker identities, native terminal state, syscall
number/FD, sync return and close return. The tracer has a 240-second total
deadline and pidfd-only owned-process cleanup; it does not change ptrace
policy or production binaries. Missing ptrace/kernel permissions are a
failed/pending qualification gate, not a skip relabelled as a pass.
Darwin/HVF/VZ qualification is not inferred from Linux observations.

`ptrace-lifecycle.jsonl` separately records early exit events, actual terminal
wait statuses and exec former-TID/sibling retirement. A kernel `ESRCH` after
an already observed ptrace stop is a lost-stop transition, not terminal
proof: the thread remains tracked until its actual terminal wait or the
kernel's exec-collapse event accounts for it. Early exit events are resumed
to allow real termination. Any missing retained-fsync/close return remains a
hard gate failure, even when a thread later dies; lifecycle evidence never
fills in a storage syscall result.

Standalone candidate launches now supply a real shared lease and the strict
current storage context/start request; they have no no-lease foreground path.
The macOS Rosetta helper similarly requires an explicitly owned 0700
`--storage-directory` with the worker-input arguments, retains a close-only
FD8 lease and publishes durable holders through the production publisher
before releasing config. Those standalone fixtures do not substitute for
the production CLI/SQL operation-retention gates above.

## Stopped fork, checkpoint and restore gates

`tests/test_stopped.py` is the maintained production CLI controller for Phase 7.
Its presence is not a qualification result. Main must run it against the staged
production runtime after the implementation owners hand off:

```sh
cargo fmt
make clippy
cargo test -p libvm --lib machine::stopped_storage::tests:: -- --nocapture
cargo test -p libvm private_copy -- --nocapture
cargo test -p libvm snapshot -- --nocapture
cargo test -p libvm storage::stream -- --nocapture
cargo build -p libvm --example storage_acceptance
make stage
make smoke SMOKE_ARGS='tests/test_stopped.py -m "not slow" --keep'
make smoke SMOKE_ARGS='tests/test_stopped.py -m slow -k "not host_ext4" --keep'
```

No Cargo test boots a guest or queries KVM/HVF. The `machine::stopped_storage`
unit tests use actual private raw files and SQLx catalogs with never-started
machines, including nonbootable byte fixtures. They use the existing test-only
real-store constructor, not `Runtime::new`'s native host discovery, and retain a
real monitor component without invoking its native query. `SILO_TEST_MOCK_VMM_BINARY`
may select the prebuilt mock-enabled monitor, as for the other libvm unit tests.
The native controller boots two distinct raw/flat children,
checks source and sibling hashes before each intentional boot, observes actual
dirty ext4 recovery independently, and checks preserved filesystem UUIDs,
guest machine-id/hardlinks, fresh host IDs/runs and actual socket namespaces.
Network intent is explicitly `none`; this does not qualify a network/MAC lane.

`tests/test_native_capabilities.py` owns real machine-less native queries,
including invalid launch descriptors, immutable build binding and mutable-grant
refusal. It creates no VM, but the linked query may open/query the system KVM fd
or resolve optional HVF symbols, so it belongs to smoke rather than Cargo tests:

```sh
make stage
make smoke SMOKE_ARGS='tests/test_native_capabilities.py -m "not slow and not sdk"'
```


The raw snapshot fixture installs current-schema managed Data and complete
nondefault configuration before its first launch, under the actual source
lifecycle lock. This is test construction, not an ownership-import API:
ordinary `--disk PATH` still declares an external resource. The fixture compares
root/Data bytes, geometry/order, null versus empty process settings, Unicode
environment/labels, userdata, hardware and kernel arguments. It independently
hashes exact pinned kernel/base-initramfs/agent objects. Both default-selected
and source-private custom boot paths are covered. Only a private copy of the
staged runtime is replaced, never the shared staged installation. Children
must restore/boot after source deletion, unrelated OCI root removal/GC, old
runtime boot-byte replacement and snapshot alias/retention release.

Commands are explicit about intent:

```sh
silo fork VM --name CHILD
silo snapshot create VM --name CHECKPOINT
silo snapshot inspect image:CHECKPOINT
silo snapshot list
silo restore image:CHECKPOINT --name CHILD
silo image remove image:CHECKPOINT       # alias only
silo snapshot remove image:sha256:HEX    # explicit retention only
```

Fork is stopped-only for admitted opaque raw and development flat overlay;
snapshot/restore artifacts are opaque raw only. Flat publication preparation is
rejected before effects, not flattened into an artifact. `--live` on fork or
snapshot creation and `--execution` on restore are separate, still-refused
execution operations, not implicit stop/cold-boot fallbacks. An exact checkpoint
preserves configured secrets, guest credentials, dirty journals and deleted-data
remnants. It is neither sanitization nor application-consistency certification.
External disks/shares require explicit `--external-requirements` at snapshot
capture; snapshot records never store destination host mappings. Fork/restore
may instead supply complete `--map-disk ORDER=PATH` / `--map-share TAG=PATH`
destination mappings. An unresolved requirement blocks start; an intentionally
shared mapping is not independent private storage.

`stopped.py` uses a separate bounded SHA-256/raw reader and records device,
inode, mode, logical length and allocation independently from the production
StreamHasher. Logical SQL/schema snapshots use independent read-only sqlite3
processes; WAL/SHM physical bytes are deliberately not compared. Rejection gates
compare the complete logical catalog and owned persistent/runtime inventories.
`stopped-refusal-delta.log` retains changed table rows and file entries before
assertion/teardown, including both values. Lifecycle status and error fields
remain part of the logical catalog oracle, not exempt telemetry.
Positive mock-capability refusal is covered by the maintained hypervisor-free
`live_capabilities` and CLI `early_rejection` tests, not relabelled native proof.

The slow gates reuse Phase 5's real pidfd/holder/OFD evidence: SIGSTOP the entire
actual worker, kill only its monitor, and require fork/snapshot/start/resize/
remove to remain fenced while real GC preserves its closure. Resize and removal
run first and must leave the exact running source row unchanged, including its
run ID, monitor PID and null error, while the orphan worker is still stopped and
its OFD lease remains busy. Stopped mutations perform holder/old-operation
preflight before node-state lock allocation or reconciliation writes; they do
not persist a synthetic stopping/error observation as a refusal side effect.
Resuming the unchanged watchdog must produce actual exit125 before capture is
admitted.
`stopped_trace.py` is a child-only Linux x86_64 ptrace controller. Its retention
and cancellation gates alter no syscall returns or bytes. One gate holds the
real immutable source FD read while the normal CLI removes the snapshot alias and explicit retention and
runs GC, then resumes the real restore and boots its child. Another stops actual
source fsync, cancels only the async fork waiter via `storage_acceptance`, checks
the surviving blocking owner's lifecycle/OFD/operation fences, resumes the
worker and requires complete publication before GC retirement. Requests,
exact syscall FD/inode/TID and source-identity receipts, command output and return
statuses are retained in `boundary-*.json`/`boundary-*.log`. The controller waits
on SIGCHLD rather than imposing a polling sleep on each syscall, inspects FDs
only for boundary-relevant syscall numbers, and stops syscall tracing after the
held boundary's release and checked injected return (if any). Lifecycle tracing
and pidfd/EXITKILL cleanup remain active. `boundary-trace.json` retains syscall
entry counts and the last 32 boundary candidates even on cancellation, so a
timeout does not lose all selection evidence. `boundary-lifecycle.jsonl` records
ESRCH from any stop inspection or resume, including disappearing `/proc` status
or memory, as a lost stop awaiting an actual terminal wait, never as exit proof.
Only a kernel exec event can account for collapsed former TIDs without a
terminal wait. Neither path supplies a missing checked injected return. Host-only
regressions in `test_native_live_api.StoppedTraceLifecycleTests` schedule real
SIGKILL between a stop and ptrace inspection, without replacing syscall or wait
results. These are process/syscall evidence, not a power-loss simulation. The controller's
240-second deadline and helper's
60-second boundary wait are unchanged; missing ptrace permission is an unresolved
gate.

The negative syscall matrix injects exactly one EIO/ENOSPC/EACCES at actual
source sync, child copy/FICLONE, child file sync, no-replace rename or
post-publication directory sync. Scope is the held source inode or the newly
owned child `.copy-UUID/file-0`/parent FD, never an arbitrary path or read result.
`boundary-injected.json` labels the exact errno as injected syscall failure,
not physical media/power-loss evidence. The source's complete bytes/config/
semantic storage must remain unchanged, no partial child may be catalog-visible,
and a subsequent real retry must produce a complete independent copy. The
runtime owner's dedicated real SQLite trigger-abort test complements these
OS boundaries; no fake commit-success response is admitted.

### Actual mounted filesystem inputs

`SILO_SMOKE_STOPPED_DIR` selects an existing writable **host-mounted** directory
for persistent state, private disks, immutable artifacts and evidence. Its
generated runtime sockets/locks use a separately owned short `/tmp/silo-run-*`
tree, recorded in `runtime-placement.log` and retained/cleaned with the workspace.
That socket placement does not move disk bytes off the requested filesystem.
`SILO_SMOKE_STOPPED_FS` optionally requires its exact `findmnt` filesystem type.
Every native create records process-visible target/source/type/mount options,
kernel and actual state `st_dev` in `stopped-host-mount.log`. A path's name,
an ext4 image sitting on Btrfs, or a mount visible only in another namespace
does not qualify the ext4 lane. Never use `/boot` or overmount a system path.

After Main independently sees the owner-authorized isolated mount:

```sh
MOUNT=/absolute/owner-mounted-ext4
findmnt --target "$MOUNT" --output TARGET,SOURCE,FSTYPE,OPTIONS
SILO_TEST_COPY_DIR="$MOUNT" cargo test -p libvm private_copy -- --nocapture
SILO_TEST_COPY_DIR="$MOUNT" cargo test -p libvm --lib machine::stopped_storage::tests:: -- --nocapture
SILO_SMOKE_STOPPED_DIR="$MOUNT" SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_ARGS='tests/test_stopped.py -m "not slow" --keep'
SILO_SMOKE_STOPPED_DIR="$MOUNT" SILO_SMOKE_STOPPED_FS=ext4 \
  make smoke SMOKE_ARGS='tests/test_stopped.py -m slow --keep'
SILO_TEST_COPY_DIR="$MOUNT" SILO_TEST_COPY_CROSS_DIR=/actual/other/filesystem \
  cargo test -p libvm private_copy_real_cross_filesystem -- --ignored --nocapture
```

`test_stopped_host_ext4_fork_requires_actual_mount` fails, rather than reporting
a pass/skip, without an explicit process-visible ext4 input. Copy-provider output
must separately show the actual sparse/streaming fallback method on that mount;
native byte equivalence alone does not prove which syscall strategy ran.
The owner-authorized image/mountpoint is not assumed usable until `findmnt`
inside the executing process observes ext4. The Linux qualification run used
an isolated loop-mounted ext4 image and observed `SparseCopy` for both children;
all 26 native stopped cases passed there. `/tmp` tmpfs and `/home` Btrfs results
do not substitute for that ext4 evidence. On a small test filesystem, run
bounded batches: preserve text logs and reports outside the mount, then remove
successful disposable payloads before the next batch. `--keep` retains full
workspaces, so an entire retained suite requires substantially more capacity.

If a writable reflink-enabled XFS mount becomes available, rerun the same
copy/integration and native cases there with the required `xfs` type, excluding
only the specifically ext4-named test; record the actual successful reflink
method and isolation evidence. Otherwise record `pending-lane:xfs`, with its
real availability reason. APFS/fclonefileat and native macOS remain
`pending-lane:macos`, owned by the actual-host Phase 25 matrix, not inferred
from Linux. Preserve and rerun Phase 4's existing opcode/unaligned-range,
pre-operation backing length/reopened-capacity, unsupported-punch fallback and
maintenance-upper fstrim/sentinel oracles unchanged alongside these new gates.

## Public native capture/restore API proof

`silo_smoke/native_live_api.py` drives the standalone
`native-live-api` example through the real Silo engine and libkrun Rust API.
It is an explicitly invoked Linux x86_64 KVM proof, never a Cargo VM test.
It does not deliver the monitor's public live commands or qualify other host
lanes. Native diagnostic controller modules supply guest transport and
independent validation, not the native operations under test.

Build from clean, revision-bound native source. The production producer
identity deliberately rejects dirty or unknown native provenance. Do not
enable diagnostic native features or bypass that check to obtain a passing
capture. Build the example and stage the runtime before invoking a cohort:

```sh
cargo build --locked -p silo-vmm --example native-live-api
make stage KERNEL_PATH="$PRODUCTION_KERNEL"
python3 smoke/silo_smoke/native_live_api.py \
  --native-root "$NATIVE_CHECKOUT" \
  --entry target/debug/examples/native-live-api \
  --netd "$STAGED_RUNTIME/bin/netd" \
  --guest-init "$GUEST_INIT" --register-fixture "$REGISTER_FIXTURE" \
  --kernel "$PRODUCTION_KERNEL" --kernel-config "$KERNEL_CONFIG" \
  --evidence "$NEW_EVIDENCE_DIRECTORY" --case api
```

Use absolute input paths and a new evidence directory for each invocation.
`--guest-init` and `--register-fixture` are the retained real-provider guest
programs from the native standalone proof, not Silo's normal guest agent.
Keep the exact executable, kernel, configuration and guest input bytes needed
to reproduce the cohort, together with the source and input identities.

Run bounded cohorts sequentially. `positive` exercises generation on the
production kernel; `api` exercises capture and fresh-process restore;
`incremental` checks baseline and dirty-union behavior. `faults`, `late`,
`absent`, `expiry` and `restore-timeout` use the separately built generation
diagnostic kernel. `partial` requires the distinct fixture in
`virt/vmm/examples/native_live_api/native_generation_partial.{patch,h}`,
applied after the production driver patch, instead of the earlier generation
fault patch. Preserve the ordinary kernel configuration and keep these
diagnostic kernels separate from production inputs.
For the guest-protocol driver-absence control, also run `--case absent` with
an otherwise identical kernel built with `CONFIG_VMGENID=y` and
`# CONFIG_VIRTIO_SILO_VMGENID is not set`. Verify the emitted configuration
against the image's embedded configuration. The device must remain present,
with no processed acknowledgement and a failed five-second deadline, followed
by acknowledged stop and process reap. A diagnostic driver refusing probe is
separate evidence, not a substitute for this driver-disabled build.
The pending-generation cohort captures and resumes the exact source request
within its original deadline. It authenticates and seals the immutable capture
outputs after the source's exact ACK, before restoring the child. Output identity
and writer-closure checks guard that deferred seal; the deadline is not renewed.

`restore-failures` uses the production kernel. `failures` additionally needs
`--enospc-directory` naming a new empty mountpoint inside a private user/mount
namespace (`unshare --user --map-root-user --mount`). Its bounded tmpfs
exercises actual ENOSPC; do not substitute host disk exhaustion or `/dev/full`.
Run `capabilities` last, with `--monitor "$STAGED_RUNTIME/bin/silo-vmm"`,
only after the exercised native lane's support declarations have been approved.
The Phase 14 implementation delivers capture without production qualification:
capture reports `lane-not-qualified`; restore, fork and incremental remain
`not-delivered`. The public pause qualification is revision-bound. Standalone
native proofs grant no additional public capability.

`api-report.json`, per-process logs, captured manifests and input identities
are the evidence. Ordinary successful cohorts require acknowledged native
cleanup. OS reaping is a separate fact, not a native stop acknowledgement;
the explicit worker-death case instead requires the expected SIGKILL status
and released ownership. Cleanup success never turns an unexpected restore
failure into a passing proof. Keep failed payloads for diagnosis.
Completed candidates must close writers before reporting success. Failed RAM
attempts instead retain their output descriptors until explicit abandonment;
the failure cohort checks writer closure after that resolution, without
mistaking retained failure ownership for a completed candidate.
Remove successful bulk RAM/disk outputs only after preserving their evidence
and confirming that every owner and retained consumer has terminated.

## Capture-side multiple writable disk gates

After Main stages the explicitly isolated Phase 14 candidate, run:

```sh
make smoke SMOKE_ARGS='tests/test_capture_multidisk.py -m slow --keep'
```

The eight cases cover raw and flat roots, each with two additional real
managed-writable ext4 disks installed before first launch under the existing
stopped-fixture lifecycle-lock convention. Ordinary `--disk` remains external;
this is fixture construction, not a new ownership-import API. The guest mounts
only its original source devices. It races ordered direct numbered writes,
dirty shared page-cache pages and unsynchronized metadata churn against capture.
Independent readers compare the exact pinned RAM GPAs with sealed disk files,
require an observed unsynced cache difference and ext4 journal/recovery feature
bits, and never mount, fsck or replay a sealed disk. Recovery bits establish the
mounted dirty-journal state, not a claim about which journal transactions need
replay. Later source writes overwrite the same numbered/cache offsets on both
disks while hashes and inode identities establish independent immutable copies.

Six failure cases inject a checked `ENOSPC` syscall return into the second Data
copy after the other included disks copied successfully. This faults actual
FICLONE or destination writes, not fsync or a fabricated success. They require
a producer-written failed record, no new snapshot or capture provenance,
policy-correct source continuation (acquired resume, acquired preserve and
borrowed user pause), unchanged run/boot/reseed identity and final staging
retirement. This is injected syscall-error evidence, not physical exhaustion or
power-loss evidence.

`capture-copy.json` records actual successful copy syscall returns.
`capture-multidisk-copy.log` retains those observations alongside the monitor's
actual Clone/SparseCopy method and planned logical lengths. Successful FICLONE
returns zero; its logical length is never reported as physical transferred
bytes. Host filesystem/device/mount options are observed with `findmnt` in
`stopped-host-mount.log`. `SILO_SMOKE_CAPTURE_FS` may require an exact filesystem
type; durable `TMPDIR` selects the workspace parent. An image filesystem or a
directory name never establishes a host storage lane. These tests do not grant
production qualification or establish the APFS/non-reflink matrix, restored
children, sibling divergence, restore-time journal ordering or recapture.
