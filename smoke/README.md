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

Phase 22 makes `linux-erofs-overlay-v1` the libkrun OCI default and removes the
flat profile and root-profile selector. Linux x86_64 stable 7.2.2 and
longterm 6.18.48 production roots passed boot/lifecycle and kernel-mutated
flatten export followed by raw boot. Independent umoci extraction used the prior
raw reference environment; a separate readonly EROFS traversal matched every
published-corpus row without exclusions. Performance must be remeasured in the
mandatory Phase 24 sweep; public live lanes remain unqualified. See the
[changeset conformance evidence](../runtime/oci/testdata/changesets/README.md#observed-admission-and-phase-22-default-gates).

### Controlled EROFS encoder qualification

Build `cargo build --locked -p libvm --example erofs_qualification` and the
stable/longterm workload kernels with the current fragments. Build upstream
erofs-utils 1.9.4 separately; it is a verifier, not a production dependency.

```sh
export SILO_SMOKE_EROFS_KERNELS='{"stable":"/absolute/stable/build/vmlinux","longterm":"/absolute/longterm/build/vmlinux"}'
export SILO_SMOKE_EROFS_UTILS=/absolute/erofs-utils-1.9.4
uv run --project smoke pytest smoke/tests/test_erofs.py --keep
```

Each kernel must have its resolved `.config` beside `vmlinux`. The fixture
producer authenticates packs, composes fsmeta twice, checks exact retained
loading, and publishes a descriptor through the existing storage/VMDK codec.
The suite runs upstream `fsck.erofs` and `dump.erofs`, then mounts the actual
VMDK in a guest using a static, independently authored C probe. It covers
empty/metadata-only packs, byte names and symlinks, ownership and timestamps,
xattrs and ACLs, hardlinks and special inode types, NULL chunks, 1024 device
slots, and a sparse file larger than 2 GiB. Rich fixtures also round-trip
export handles and verify indexed-overlay copy-up and clean remount.

The 1024-slot fixture uses structural fsck and guest reads instead of passing
1024 `--device` arguments, which exceed erofs-utils' 256-device CLI limit.
All other fixtures use `fsck.erofs --extract` to verify file data without
extracting host special files. Monitor identity, kernel/config digests,
descriptor backing digests, and guest output are retained. These are
candidate-only format/attachment checks, not a production-root or live
qualification grant. Other host/architecture lanes remain pending.


### Controlled Distribution registry

`test_distribution_registry.py` runs CNCF Distribution 3.1.2 as a real local
TLS server, with anonymous access and deletion enabled. It verifies exact-byte
OCI VM artifact graphs, shared blobs, tag replacement, upload continuation
across restart, missing-dependency refusal and offline garbage collection.
The initial Linux run passed all 23 registry tests, including the existing
loopback-registry test. This is registry compatibility evidence, not yet an
end-to-end Silo artifact round trip or GHCR qualification. GHCR is deferred.

The harness downloads the official Linux amd64 or arm64 archive and verifies
both archive and extracted executable against pinned SHA-256 values in
`silo_smoke/distribution_registry.py`. No Docker daemon is needed. For offline
execution, seed the exact release archive under
`<SILO_SMOKE_CACHE>/distribution-registry/3.1.2/<arch>/`.
There is no macOS release asset or substitute server fallback.

```sh
uv run --project smoke pytest smoke/tests/test_distribution_registry.py smoke/tests/test_registry.py
```

The registry uses the suite's private CA. Offline GC requires the server to
be stopped; it restarts on the same address. Failed runs retain identity,
configuration and server/GC logs. A registry fixture never modifies the
user's Docker configuration or hosted registry credentials.

`test_artifact_stopped.py` drives the staged CLI in local and private-daemon
mode against this registry. It covers raw and converted images plus stopped
checkpoints, raw/zstd identity, trust refusal without catalog effects, source
OCI deletion, offline registry GC, decoded-flat eviction, chunk-only
reconstruction and real guest boot with retained boot assets. Its interrupted
pull case removes a real registry chunk, corrupts one completed local cache
entry, then proves the retry refetches only invalid/missing bytes.
The Linux stopped-artifact gate passed all seven cases, including both local
and daemon routes (`artifact-stopped-corrected.xml`, 338.87 s). This establishes
the controlled Distribution lane only; GHCR remains deferred.

```sh
cargo build --locked -p libvm --example storage_acceptance
uv run --project smoke pytest smoke/tests/test_artifact_stopped.py
```

`test_artifact_live.py` is a functional slow selection, not a performance
qualification. Use the exact-input isolated capture/restore candidate's
`SILO_SMOKE_BIN_DIR` and `SILO_SMOKE_RUNTIME_DIR`; production admission must
remain unchanged. It publishes a real matched-cut checkpoint, pulls into a
fresh home, removes source/registry dependencies, and exercises exact restore
or incompatible-producer refusal. The destination has its own private runtime.
The Linux candidate gate passed all three cases
(`artifact-live-exact-binding.xml`, 159.89 s). Restored machines preserve
the complete captured boot binding and independently verified boot bytes,
not a hardcoded ABI version.

```sh
uv run --project smoke pytest smoke/tests/test_artifact_live.py -m slow
```

### Stopped handoff between runtimes

`test_handoff.py` drives two real daemons with independent Homes, runtime IDs,
config directories and run roots. It covers raw relocation and growth, a
deliberately stopped running-source fork, stale-plan refusal without catalog
mutation, destination crash/recovery, and repeated layered-overlay return cycles.
Read-only catalog queries, private-file hashes and guest markers verify the
result independently of the coordinator's reports. The old owner must refuse
start, and terminal recovery must work after payload cleanup.

```sh
uv run --project smoke pytest smoke/tests/test_handoff.py
```

All five Linux cases passed against the staged runtime in 207.63 s
(`.tmp/plan/evidence/phase-19/handoff-smoke-freshness.xml`). This qualifies the
two-local-runtime stopped protocol, not remote transport or live execution
relocation. The cases are included in the default non-slow suite.


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

Phase 15 restore gates use the same builder with `--restore`. It requires
production capture and restore to be delivered but still `lane-not-qualified`,
then admits only pause, capture and restore in the copied compilation.
Fork and incremental admission remain unchanged. This is test isolation,
not production qualification; use the resulting private CLI and runtime together.

Point `SILO_SMOKE_BIN_DIR` and `SILO_SMOKE_RUNTIME_DIR` at the candidate's `bin`
and `runtime` directories, then run:

```sh
uv run --project smoke pytest smoke/tests/test_capture.py smoke/tests/test_capture_multidisk.py smoke/tests/test_capture_lifecycle.py -m slow --keep
```

The root-family gates exercise raw and EROFS-overlay matched disk/RAM cuts,
source continuation, acquired and borrowed pause authority, sealed-file
immutability, independent retained RAM, and retention through source/alias
removal, home relocation and GC. Unsupported readonly virtiofs must be refused
before staging or freezing. The child-only syscall tracer holds real capture
write and record-settlement boundaries for manager/monitor/worker death, plus
pool-file sync, pool publication and catalog checkpoint barriers. The catalog
boundary is an actual WAL sync after capture provenance commits but before
the checkpoint can be acknowledged.
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
The checkpoint durability gate records successful `fsync`/`fdatasync` calls
through real `/proc/<tid>/fd` device/inode observations. Every captured pool
payload must have a file barrier and a later publication-directory barrier,
followed by the catalog barrier. Capture staging must have none.


### Execution restore and retained closure (Phase 15)

`tests/test_restore.py` drives actual `silo snapshot create --live` followed by
`silo restore image:<checkpoint> --name <child>`, with automatic execution-kind
dispatch and no cold-boot recovery fallback:

```sh
uv run --project smoke pytest smoke/tests/test_restore.py -m slow -k 'not pending_hardware_irq' --keep
```

The raw and EROFS-overlay cases cover acquired and borrowed freeze authority,
fresh machine/run/generation identity and reseeding, unchanged boot ID, sibling
disk isolation, exact captured kernel/initramfs/agent objects, source removal,
home relocation, GC, recapture and generation-lease release after owned processes
are reaped. The detached `restore_execution.c` daemon is independent of the
source exec session. Its guest-local read protocol exposes sustained register
sentinels (GPR, x87, SSE, and YMM when genuinely enabled), a parked SIMD worker,
timer progress and pending timerfd/signalfd events. An independent host reader
reads the pinned RAM page and sealed disk log; every record at the boundary and
the exact first resumed append must be consecutive, not just a later larger value.
The timerfd/signal events are kernel-event witnesses, not hardware IRQ proof.

Corruption cases alter real captured RAM, disks, state/layout/maps, boot assets
and provenance. Compatibility cases use the public native execution codec to
alter a real CPU/profile/producer/XSAVE envelope, then rebuild the object digests,
canonical checkpoint identity, dependency edges and authenticated local seal.
Only the precise native refusal subject satisfies those cases. Producer refusal
is intentionally checked before device decoding; its original device binding is
retained explicitly. All rejections require no child/catalog/budget leak.
Verification consumers may leave an unlocked stable lease inode by pool design;
unsupported selected-backend refusal may not acquire even that consumer.
The helper `native-live-api` must be staged with the selected candidate.
Foreign-lane compatibility still requires a real foreign-lane checkpoint, not a
synthetic mixed-architecture envelope.

The genuine hardware IRQ case uses a separate `capture_candidate --restore
--irq-probe` runtime and is **not** a production-lane qualification:

```sh
uv run --project smoke pytest smoke/tests/test_restore.py -m slow -k pending_hardware_irq --keep
```

It requires the exact candidate-bound `assets/restore-irq-witness` manifest and
immutable assembly inputs staged by that builder. Four virtual CPUs retain
ordinary Linux on CPUs 0/1, with the source-only privileged AP2 witness and a
never-started AP3 in explicitly reserved memory. The compile-gated native probe
only constructs AP2 during a user pause; restored initialization must refuse.
The test captures a real vector-224 LAPIC IRR with IF=0, independently decodes
the sealed execution envelope and reads its guest RAM publication, then restores
through the normal CLI activation path. Only the restored AP2's own guest STI
releases the pending interrupt. Exactly one interrupt and EOI, sustained progress,
preserved GPR/x87/SSE/YMM state, empty IRR/ISR on recapture and independent source
delivery are required. No host IRQ injection or post-restore CPU reseeding is
used. Normal builds have no probe endpoint; select the non-probe suite separately.

### Restore activation lifecycle (Phase 15)

`tests/test_restore_lifecycle.py` uses the same `--restore` candidate and
selection. Its VM cases are `slow`; the host-only oracle cases are not:

```sh
uv run --project smoke pytest smoke/tests/test_restore_lifecycle.py -m slow --keep
```

Each case boots a one-vCPU `--network private` source with the
`restore-network` witness (`virt/vmm/tests/guest/restore_network.c`): a
keepalive TCP stream and an unconnected UDP sender (sequence plus fresh
getrandom UUID) to real host peers through netd's host-loopback NAT, a forward
target listener and a durable progress record. A preserving live checkpoint is
restored with the real `silo restore`. The workspace selects netd's own packet
capture (`networking.drivers.netd.pcap`); the child's capture and trace log are
followed from creation so destroyed children keep their evidence.
The capture is nanosecond classic pcap with `LINKTYPE_ETHERNET=1`, recorded
at netd's vfkit datagram connection in both directions, before ingress switch
filtering and after successful egress writes. Original Ethernet headers,
including ARP and IPv6 frames, are retained; MAC addresses are never inferred
from configuration. The old stack-level `LINKTYPE_RAW=101` capture stripped
ingress MACs and observed egress before Ethernet headers were added, so it
cannot satisfy this oracle and is rejected. Capture write failures terminate
the attachment and are reported on close rather than silently losing evidence.

Order evidence is the child monitor's `restore ...` trace events (listed in
`silo_smoke/restore_lifecycle.py`). Wire evidence is netd's capture and, under
`stopped_trace` with `observeNetEgress`, every native `virtio-net` send toward
netd. The positive case requires no frame before `restore exposure committing`,
only the reserved destination MAC/IPv4 (no source MAC, IPv4, ARP or
MAC-derived IPv6), host delivery, Running only after the native commit, the
same restored process, rebound machine forward, no reopened TCP stream, exec
session or session forward, and divergent UUIDs for equal sequences once the
source resumes. Failure cases hold real native threads only after the event
preceding the action: the sole `fc_vcpu` at its next `KVM_RUN` (missing or late
generation ACK), the `vsock muxer` (undelivered Activate, crashes) or the native
socket write carrying the actual guest THAWED gRPC response (lost Thaw ACK,
refrozen or reaped). That reply is matched to the logged activation ID, with
HTTP/2 DATA and short-write reassembly, not to a thread name or an unrelated
socket write: Unix proxy replies can be forwarded by the virtio event owner.
The held receipt retains the response bytes proving guest thaw before delivery.
Listener conflicts and failing activation hooks need no hold. Failed startup
never publishes Running or sends traffic past the fence. Manager death cancels
startup and requires positive child reaping, including after an uncertain Thaw.
Worker death is observed during activation rather than at the startup deadline.
The stop-only gate suspends the live manager so it cannot clean up the parked
`activation-failed` child before inspection: resume, start and pause are refused,
listeners remain closed, and normal stop must reap it. The tracer explicitly
detaches only that manager before SIGSTOP; monitor/worker tracing remains active.
These cases require monitor events and `--activation-hook`; without them they
fail, never skip.

### Live fork acceptance, crash and sharing gates (Phase 16)

`tests/test_fork.py` needs an isolated candidate that also admits delivered
live fork: `python -m silo_smoke.capture_candidate --destination PATH --runtime
STAGED_RUNTIME --restore --fork`. It requires production fork to be delivered,
native and still `lane-not-qualified`, admits pause, capture, restore and fork
only in the private compiled copy, and leaves the production stage unchanged.
Point `SILO_SMOKE_BIN_DIR`/`SILO_SMOKE_RUNTIME_DIR` at it, then run:

```sh
uv run --project smoke pytest smoke/tests/test_fork.py -m slow --keep
```

Every case drives the real `silo fork SOURCE --live` against the detached
`restore_execution.c` witness. Oracles: the CLI's single `LiveForkResult`
document (strict keys, kebab `kind` tags, every requested child named with a
reserved machine/run identity), the durable journal (`live_fork`,
`live_fork_child`) and `fork_event` CLOCK_MONOTONIC phase stamps, bracketed by
the harness's own dispatch/exit clock; the authenticated local cut under
`images/tmp/<operation>/cut`; source monitor trace lines; `/proc`; and the guest.

- Four children (raw and flat profiles, `--network private`, a source host
  forward): all Running with distinct machine/run/MAC and private-network
  identities matching their bound restore requests. Each netd process owns
  a distinct instance and Unix data socket, and its reserved address matches
  the guest; numeric IPv4 may repeat across those isolated networks. Fresh
  VM generation, inherited boot ID, no
  inherited forward, matched RAM/disk cut read independently from the cut,
  exact continuation in every child and in the resumed source, distinct
  writable inodes, one shared RAM inode and no unowned VM process.
- Child k (index 2) fails in its own activation hook after the seal; the result
  names it `failed`/`activation` while its siblings run and continue the cut.
  A failed child is destroyed or stop-only `activation-failed`, never Running.
- Physical sharing for N = 1, 2 and 4: each child reads the same 128 MiB guest
  tmpfs blob from the baseline; the exact `rw-p` RAM VMAs of every child's
  krun worker share one (device, inode); RSS minus PSS proves shared clean pages;
  a 32 MiB private write grows only the writer's `Private_Dirty`. RSS sums are
  recorded but never used as physical RAM.
- Source stop, removal and prune leave the cut's RAM inode and bytes intact
  while children run; a child can be recaptured and restored. Stopping and
  removing the last child then lets prune remove the operation's transient root.
- Pre-freeze refusal: 17 children without `--max-children`, a 100%-private
  batch twice `MemAvailable`, and sixteen children under `RLIMIT_NOFILE=48` are
  refused with no capture staging, no source trace staging line, no child, no
  cut and no new ledger record for this home. A second same-user home holds an
  admitted batch (its capture held by `stopped_trace` before the seal); home
  A's batch that alone fits is refused with the reported requirement including
  home B's batch. Home B is then cancelled before its seal: no child or cut, its
  ledger records gone and the source `unchanged` and still running.
- Post-seal cancellation (held at the source continuation record) leaves every
  child Running or Cancelled. Manager SIGKILL before the seal recovers one cut
  (never a recapture) and abandons every child; SIGKILL right after the first
  durable child stamp recovers by reconciling submitted children and
  abandoning the rest. Recovery runs through `silo fork --operation`; no case
  leaves an orphan monitor/worker.
- A running source may keep mapping its accepted capture baseline, and capture
  GC waits for that exact source launch lease. Every case therefore asserts the
  cut's removal only after its children and the source run have ended and
  prune has run; the source-deletion case alone proves retention by children.

All new cases are `slow`; the default selection and its identities are
unchanged. Traced cases use the existing `stopped_trace` controller through
`silo_smoke.fork_process`, so its 240 s whole-session bound applies.

### OCI ingest budget cohort (Phase 24)

`tests/test_ingest_budget.py` measures ADR 0014 cold prepare and expanded-byte
linearity on fixed 1, 4 and 12 GiB single incompressible file entries. Each
image uses the normal BASIC Alpine builder plus one GNU tar layer. A native
`head -c N /dev/urandom | tee ... | gzip -1` pipeline streams the tar payload
through SHA-256 into a temporary compressed blob; `curl --upload-file` then
publishes it through the existing Distribution upload API. Python does not
generate, compress or upload the payload in byte loops, and no expanded file
is staged. The 12 GiB entry exceeds the ADR's 10 GiB
expanded-layer requirement. Digests, exact compressed and expanded byte counts,
registry identity and the loopback TLS link are recorded. This synthetic
scaling lane does not replace the ADR's full distro/metadata/platform corpus.
The small base is also published through the session registry; large layers
use the existing disk-backed Distribution registry rather than retaining
17 GiB of layer `bytes` in the session registry's memory.

There is no standalone OCI **container** prepare command. `silo image pull`
acquires complete VM artifacts (`app/cli/lib/commands/live.rs`), not container
layers. The actual measured command is:

```sh
silo create REF --name NAME --pull missing --disk-size 256mib --network none
```

The timer starts immediately before CLI dispatch and ends after successful
exit. Each size records an unprepared create and a second create of the same
prepared lower; `prepareSeconds` is the first duration minus the second, with
neither clamping nor a private-copy allowance. This subtracts ordinary stopped
machine creation, including upper formatting. Both stopped machines are then
removed. Product path: `create::Cmd::run` resolves the source and calls
`create_machine`; `image/oci.rs::acquire_composition` downloads and decodes
missing layers through `ingest_changeset`, publishes pack/index results, calls
`compose_retained` to produce EROFS fsmeta, and saves the OCI catalog selection
before returning the materialized lower. Per-size evidence asserts two layer
results and one composition, and records real pack streams, index roots, maps,
composition records and fsmeta objects already present after create exits.
No VM is started and no opaque raw conversion is timed.

The baseline HTTP GETs and gunzips **both of the same published layers** to
`/dev/null`, with no tar extraction, hashing or packing. Both streaming
stdlib `urllib`/`zlib` and `curl | gzip -dc` are measured; the faster duration
is used, making the comparison conservative. Each baseline and prepare
dispatch is independently cache-conditioned. `coldPrepareRatio` is the
largest prepare/baseline ratio across the three sizes in a sample, gated at
1.5. Absolute seconds, bytes and `prepareSecondsPerGiB` are retained for every
size. `linearity` is largest-size seconds/GiB divided by smallest-size
seconds/GiB, gated at 1.25. Both gates use the median of five independently
reported cold and warm samples; min/max are retained, and one intervening
warm-up is discarded.

Cold dispatches fsync and per-file evict all `owned_inputs(silo)` **and the
registry blob store**, with mincore residency evidence and truthful
`partial-cold` labels, never global cache dropping. Warm means a second
**prepare after prune**, with page cache intact, not a retained-lower cache hit.
`silo image remove` only removes managed image aliases, so this OCI lane instead
removes the stopped machines, explicitly releases its OCI cache reference with
`shutdown.storage_tool(silo, "remove-image", REF)`, then calls
`shutdown.storage_tool(silo, "prune")` between every size and sample. Removing
machines alone is insufficient: the `image_ref` selection intentionally retains
its composition until the reference is released. Before each prepare, the
harness asserts no OCI reference/artifact for that manifest and no reusable
layer results for any of its diff IDs. After cleanup it also proves that the
previous composition/recipe/fsmeta, pack/index/map objects and source blobs have
disappeared, so neither the selection nor its layers can become cache hits.
The shared warm-up primes the registry corpus; warm residency is observed,
not assumed to fit in RAM.

Reserve **55 GiB free** before fixture generation: the approximately 17 GiB
gzip corpus plus three times the largest entry (download, staged/published
pack working set) plus 2 GiB margin. The registry occupies a session-owned
budget workspace on the same filesystem as the per-test workspace. The corpus
is generated **once per pytest session**, never inside the sample loop. Once
corpus blobs exist, each size checks its remaining `3 * entryBytes + 2 GiB`
working-set headroom. Successful sample scratch is pruned immediately.
Compressed generation scratch is removed on every exit; the session fixture
always stops the registry and deletes its blob store and incomplete uploads,
including after failed setup, failed measurements, and `--keep`. Failed
per-test workspaces still retain ordinary product diagnostics.
Expect minutes per three-size sample and tens of minutes for the full schedule
on ordinary local SSD storage (an estimate, not a measured result). Measured
create and baseline operations retain their 300 s bound. Untimed fixture
generation, checksum and upload steps instead allow 120 s per GiB, with a
120 s minimum (1440 s for the 12 GiB layer); slow setup is not a prepare-budget
failure and never shrinks the corpus.

Use the same candidate/environment as the fork budget and an existing durable
evidence directory. The pinned Distribution binary is reused from the smoke
cache, or its verified release is downloaded during fixture setup. `bash`,
`head`, `tee`, `sha256sum`, `curl` and `gzip` must be installed. The shared
storage acceptance example must be built
by Main as for the fork budgets.

```sh
SILO_SMOKE_BUDGET_EVIDENCE=/absolute/durable/evidence \
SILO_SMOKE_BUDGET_DIR=/absolute/durable/scratch TMPDIR=/short/durable/path \
  uv run --project smoke pytest smoke/tests/test_ingest_budget.py -m '' -k 'not budget_gate'
uv run --project smoke pytest smoke/tests/test_ingest_budget.py -k budget_gate
```

Evidence is written under `$SILO_SMOKE_BUDGET_EVIDENCE/ingest-<stamp>/`:
`reference-host.json`, `fixture.json`, per-size records, `samples.jsonl`,
`summary.json` and `summary.md`. Summary metrics are keyed by metric then cache
cohort, with explicit `budgeted` flags; over-target medians fail admission.
This Linux Distribution lane reports its actual host identity, not an
unmeasured claim about the ADR's XFS/APFS reference hosts.

### Live fork budget cohorts (Phase 16)

`tests/test_fork_budget.py` measures ADR 0021 full capture interruption,
restore to Running and four-child fork to Running. Use the same `--fork`
candidate, durable workspace storage (tmpfs is refused) and a durable evidence
directory outside the workspace. `SILO_SMOKE_BUDGET_DIR` selects a mounted
workspace parent; sockets and runtime locks then use a separately owned short
runtime directory, never the RAM or disk bytes. Without it, `TMPDIR` selects
the workspace as usual and must be short enough for Unix socket paths:

The isolated candidate builder accepts `--profile debug|release` (default
`debug`) and records the selected profile in its manifest. For optimized budget
qualification, stage an unqualified release runtime with `make stage
PROFILE=release`, then build the `--fork --restore --profile release` candidate
against that runtime. The exact production/candidate qualification-identity
check still applies; a release candidate cannot reuse a debug runtime's binding.
Keep failed debug measurements as evidence of that build, not release results.
The candidate's direct Cargo invocation must also receive the staged release
environment from `xtask/src/release.rs::configure_command`. On Linux this pins
the system compiler/linker and target rustflags and removes the listed Nix
compiler variables. Selecting `--release` alone does not reproduce those inputs;
the identity check rejects that mismatch before granting candidate admission.

```sh
SILO_SMOKE_BUDGET_EVIDENCE=$PWD/.tmp/plan/evidence/phase-16 \
SILO_SMOKE_BUDGET_DIR=/home/$USER/sm/phase16-ext4 TMPDIR=/home/$USER/sm \
  uv run --project smoke pytest smoke/tests/test_fork_budget.py -m slow
```

The exact fixture, cache method and boundaries are in
`silo_smoke/fork_budget.py`: `restore-execution` image, 2 vCPUs, 4096 MiB RAM,
`--network private`, EROFS overlay with a 2 GiB upper holding exactly 1 GiB of
guest-written `/dev/urandom` bytes (logical, allocated and nonzero upper bytes
are recorded separately). Each test runs five cold samples, one discarded
warm-up and five warm samples sequentially and reports median, minimum and
maximum per cohort. Cold samples fsync and `POSIX_FADV_DONTNEED` every owned
input file before dispatch, with mincore(2) residency before and after; there
is no global `drop_caches` and no sudo. Pages a live process still maps (the
running source) remain resident and the sample is labelled `partial-cold`.
Fresh capture RAM written inside the timed fork is part of the measurement.
Historical flat-overlay measurements do not qualify this EROFS fixture. The
mandatory Phase 24 sweep must retain new measurements; no current performance
success is inferred from the earlier runs.

Gated values: fork4 is CLI dispatch to the last durable child `running` stamp
(API entry, seal to Running and caller end-to-end are separate fields); capture
interruption is the larger of the source monitor's conservative staging-to-
continuation interval and an independent host observation of the guest's
durable 50 ms witness writes in the source backing. At fixture setup, a real
`FICLONE` probe between sibling files in the budget workspace selects the lane,
independently of the capture request's disk copy contract. Reflink lanes subtract
zero from every gate and budget cold restore. On non-reflink lanes the ADR
allowance (upper allocated bytes at the measured sequential copy rate) is
subtracted, and cold restore is recorded but not budgeted. The actual disk-seal
duration is recorded; restore is dispatch to CLI exit with the child Running and
ready. Samples, the reference-host record (CPU, memory, kernel, filesystem, input
hashes, candidate manifest, reflink probe result and errno) and
`summary.json`/`summary.md` are written before assertions. Recompute a summary
with `python -m silo_smoke.fork_budget DIRECTORY`. A running source keeps its
accepted capture baseline, so every successful fork sample stops and removes
its children, stops the source and prunes before the next; the next sample
restarts the same source (its populated upper preserved) with a fresh witness
and host observer outside the timed window. At most one sample's cut exists;
failed samples stay in the retained workspace. Per-file residency inventories
are kept in each sample record.
A median over its target fails the gate and blocks admission.

### Deferred live and layered budgets (Phase 24)

The additional performance-only cohorts in `tests/test_fork_budget.py` use the
same `SILO_SMOKE_BIN_DIR`, `SILO_SMOKE_RUNTIME_DIR`, `SILO_SMOKE_BUDGET_DIR`
and `SILO_SMOKE_BUDGET_EVIDENCE` candidate/workspace selection above. They do
not change product qualification or capabilities. Use an exact-input candidate
with incremental capture and restore support for the incremental cohort.
All three use `SCHEDULE`: five cold samples, one discarded warm-up and five
warm samples. Cold means per-file eviction of `owned_inputs(silo)` with
residency evidence, not an empty prepared-image pool. A partially evicted
sample remains explicitly labelled `partial-cold`. Both reported cohorts are
budgeted for every new gate, including non-reflink incremental capture.

| Pytest selector (`-k`) | Measured boundary and median gate | Additional free-space preflight |
| --- | --- | --- |
| `test_fork_budget_incremental_ten_percent_dirty` | Incremental workload interruption, larger of monitor staging-to-continuation interval and independent durable-workload gap, at most 1.0 s after copy allowance | 14 GiB |
| `test_fork_budget_warm_create_stopped_machine` | Prepared-image `silo create` dispatch to command exit, at most 2.0 s, no allowance | 4 GiB |
| `test_fork_budget_boot_layered_within_raw` | `silo start` dispatch to product trace's first guest-agent-serving event, median layered seconds / median raw seconds at most 1.2 | 6 GiB |

Space figures are additional free bytes required at setup and each sample,
not total workspace sizes. Incremental capture reserves two complete 4 GiB
RAM outputs (staging and published immutable stream), a 2 GiB private upper
and its published stream, plus 2 GiB margin; its current baseline already
occupies disk. Create reserves one 2 GiB upper plus 2 GiB margin. Boot reserves
two 2 GiB roots plus 2 GiB margin. Image preparation and raw conversion happen
outside timing. The create and boot fixtures use the same image, 2 vCPUs,
4096 MiB RAM, private network and `--disk-size 2gib` as the existing budget
source, but do not write its capture-only payload.

Incremental uses `incremental_image` with the existing durable execution
witness and the full 1 GiB guest-written, nonzero upper proof. Its first live
checkpoint establishes the baseline. The current memory probe has fixed
96 MiB storage, so this cohort instead preallocates a private 512 MiB tmpfs
and overwrites exactly 410 MiB there using `dd if=/dev/urandom bs=1M count=410
conv=notrunc` before each timed checkpoint. This is 10.009765625 percent of
configured 4096 MiB RAM, the requested whole-MiB rounding of ten percent.
Guest kernel, agent and witness activity can dirty additional pages. Samples
record the exact workload byte count and fraction separately from
`productDirtyFraction`, derived from the product's
`memory.stats.identityBytesHashed / logicalBytes` at its 8 MiB chunk resolution;
the product exposes no separate page-granular dirty-fraction field.
They retain the complete memory receipt, raw interruption, monitor disk-seal
times and one-upper allowance inputs. A real workspace `FICLONE` probe selects
zero allowance on reflink filesystems or allocated upper bytes divided by the
host's measured sequential copy rate otherwise. The target stays 1.0 s.
After each sample the source run ends, its machine and previous checkpoint
alias/retention are removed, and storage is pruned. Except after the last
sample, the newest checkpoint is restored outside timing with its inherited
accepted baseline, so the next incremental is based on the preceding cut
without retaining an unbounded chain of source-run-pinned staging outputs.

Warm create retains a stopped lower keeper so per-sample pruning cannot turn
the next prepared-image create into a cold prepare. It checks that every new
machine is stopped and its root is `linux-overlay`, then removes it and
prunes. ADR "warm" means an already prepared lower here; page-cache cold and
warm measurements are both reported and gated.

Boot converts the same image once through `Silo.root_image(reference, "raw")`
before measurement. Each pair creates stopped raw and layered machines,
alternates which profile starts first, and evicts before each cold start.
The timing marker is the existing product trace line `guest agent became
responsive ... machine_id=<id>` in `logs/machines/<hex>/vm.trace.log`
(`virt/vmm/src/state.rs`, `log_state_changes`). This is emitted on the first
validated guest status RPC receipt (`observe_status`), not on a socket dial:
the guest agent is already serving from `/` after init mounted the raw or
overlay root and executed `switch_root`. This is the earliest host-recorded
serving-on-root boundary, not a kernel mount timestamp. It intentionally
precedes full `GuestReportedReady` policy (provisioning and host-verified SSH).
No product instrumentation change is needed.

Both timing endpoints use host `CLOCK_REALTIME`: harness `time.time_ns()`
immediately before spawning `silo start`, and the monitor's UTC trace timestamp.
There is no guest-clock or wall/monotonic conversion; the host wall clock must
remain stable during each start. `Silo.wait_ready(..., poll_interval=0.02)`
is only a liveness check, never the measured endpoint. Samples normalize the
CLI/catalog's compact machine UUID to the monitor's hyphenated spelling and
select the exact `machine_id`/`run_id` generation-start event (not a capture's
`generation` counter). They name the trace path and line pattern, retain the
marker's line and nanosecond timestamp, and preserve a full trace copy before removal.
They record dispatch-relative and preceding-phase deltas for whichever existing
monitor events occur: generation start, monitor initialization, primary-VM
spawn dispatch, krun worker spawn, Running, first agent response, agent-reported
Ready and full product readiness. Later readiness phases remain diagnostic,
not part of the gate. `availablePhases` and `unavailablePhases` distinguish
observed phases from unavailable kernel-start, initramfs and root-switch
timestamps; none is invented from polling or guest uptime.

Samples also retain command-exit durations, alternating profile order and both
complete cache inventories. Machines are stopped after each start (flushing the
trace appender), then removed and pruned after the pair. `bootLayered` and
`bootRaw` remain unbudgeted raw metrics; `bootLayeredRatio` uses the ratio of
the cohort medians, not the median of paired ratios, with the unchanged 1.2
gate. The ratio's min/max and values describe the individual pairs.

Each cohort writes `samples.jsonl`, `summary.json`, `summary.md`,
`reference-host.json` and `fixture.json` under
`$SILO_SMOKE_BUDGET_EVIDENCE/<label>-<stamp>/`, with cache labels, free-space
proof, fixture proof and timings in each sample. A median equal to its target
passes. For example, with the four environment variables above set:

```sh
uv run --project smoke pytest smoke/tests/test_fork_budget.py -m slow \
  -k 'test_fork_budget_incremental_ten_percent_dirty'
uv run --project smoke pytest smoke/tests/test_fork_budget.py -m slow \
  -k 'test_fork_budget_warm_create_stopped_machine'
uv run --project smoke pytest smoke/tests/test_fork_budget.py -m slow \
  -k 'test_fork_budget_boot_layered_within_raw'
uv run --project smoke pytest smoke/tests/test_fork_budget.py -m slow \
  -k 'copy_allowance or reflink_probe or budget_gate'
```

### Incremental capture and named disk recovery (Phase 20)

These are maintained **functional** gates, not performance qualification. Use
the same clean, exact-input KVM x86_64 runtime and VM-generation-aware workload
kernel required by the restore gates. Production capture, restore, fork and
incremental capability tables remain unchanged. Build a separate private
candidate, outside both the repository and production runtime, with matching
Cargo ancestor depth, build environment and profile:

```sh
PYTHONPATH=smoke uv run --project smoke python -m silo_smoke.capture_candidate \
  --destination /absolute/private/phase20-candidate \
  --runtime /absolute/production/staged-runtime --restore --incremental --profile release
export SILO_SMOKE_BIN_DIR=/absolute/private/phase20-candidate/bin
export SILO_SMOKE_RUNTIME_DIR=/absolute/private/phase20-candidate/runtime
uv run --project smoke pytest smoke/tests/test_incremental.py -m slow --keep
uv run --project smoke pytest smoke/tests/test_artifact_live.py -m slow --keep
uv run --project smoke pytest smoke/tests/test_restore.py -m slow \
  -k 'corrupt_real_closure or real_native_incompatibility' --keep
```

The builder refuses missing/dirty native provenance, mismatched build identity,
IRQ diagnostic candidates and a production lane that is not still unqualified.
`--incremental` requires `--restore`; `--fork` may additionally admit the local
fork functional gates in the same isolated compilation. The resulting CLI,
monitor and helper examples must be used together. No runtime flag grants
production capability support.

For Linux release stages, match `xtask/src/release.rs`'s system compiler/linker
environment, including `CARGO_TARGET_DIR`, target linker and target Rust flags.
`--profile debug` is appropriate only for a debug production stage. A mismatch
is an evidence failure, not a reason to weaken the builder's identity check.

Prerequisites are `/dev/kvm`, a static C toolchain (`CC`, default `cc`), `debugfs`,
`sqlite3`, the restore fixture kernel/agent/initramfs and loopback TLS support.
The host-writer gate additionally requires the workload kernel's
`CONFIG_PAGE_REPORTING=y` and `CONFIG_VIRTIO_BALLOON=y`, a negotiated reporting
queue and the matching `native-live-api inspect-devices` example. No missing
driver, absent reports or unsupported lane is converted into a passing test.
Artifact gates also use the existing pinned controlled Distribution binary
(downloaded through its fixture when not already cached) and offline registry
GC. The child-only syscall gates require Linux x86_64 ptrace of owned descendants;
they never attach to an unrelated process. Every command is bounded, and failed
workspaces retain their evidence.

`test_incremental.py` pins guest tmpfs pages and independently reads their exact
GPAs from sealed RAM after CPU stores, real O_DIRECT block-read DMA, repeated
same-page writes and explicit nonzero-to-zero replacement. It checks canonical
complete maps, full-file SHA evidence, catalog dependencies, bitmap/control
record bounds, the lowered crossover, explicit full selection and worker-local
baseline invalidation. Its first restored-child recapture must reuse the
inherited map/token while retaining restore-time dirties. A real RAM-fsync
pre-seal cancellation must preserve the abandoned dirty union. The separate
coverage-loss case first observes an actual successful KVM_GET_DIRTY_LOG return
(and its returned bitmap), substitutes only `-EIO`, then requires actual-state
recovery, a full `coverage-lost` capture and renewed incremental reuse. This is
an explicitly recorded syscall fault, never injected success or synthetic RAM.

The host-writer case requires an observed `/dev/hvc0` serial token, byte-exact
bidirectional vsock transport and actual balloon free-page-report completions.
It decodes the bounded saved device queues, reads their real used indices and
entries from sealed RAM and requires the reporting ring's chunks in the dirty
bitmap. An explicit full capture at the same borrowed pause must have identical
complete RAM bytes, identity and layout before the source can resume.

The incremental artifact case reuses the source-free live-checkpoint pipeline:
two incremental generations after full capture, both parent records/aliases
removed and locally collected, complete standalone OCI closure, real registry
GC, pull into a fresh home and first-child incremental recapture. The original
source OCI publication is unavailable during offline restore. The incompatible
CPU artifact still imports, then names the exact `cpu.cpuid` compatibility pin
at `restore-preflight` before allocation. Only the separately invoked
`silo recover-disks IMAGE --name CHILD` creates new stopped private disks with
`stopOutcome: unknown`; an explicit subsequent start proves a different boot ID,
the captured disk marker and absence of a RAM-only marker. Registry bytes are
already collected, source home quarantined and source OCI unavailable.

The existing real-closure corruption and exact-native-refusal matrices also run
against genuinely incremental-derived snapshots. They cover byte corruption of
RAM, root, layout, execution/device state, boot assets, map/root pages and
provenance, plus exact CPU, XSAVE, native-producer, host-build, unscaled TSC-rate
and captured MSR-model-value refusals before allocation. An empty actual MSR
inventory refuses fixture preparation instead of inventing a register. These
checksum-corruption cases do not claim to replace bounded
malformed-schema/ABI/GPA decoder tests. KVM arm64/GIC and HVF/macOS/timebase
lanes remain outside this KVM x86_64 fixture, not inferred qualified.

Native `liveBytesRead`, baseline copying, full/overlay writes,
`identityBytesHashed` and mandatory `wholeFileBytesHashed` are distinct evidence.
The independent smoke oracle deliberately reads immutable output for
authentication; it does not count that as a live RAM scan. No unchanged timing
target is relaxed or qualified by these functional cases.

### Raw/qcow2 import, cloud disks, boot pinning and conversion (Phase 17)

`tests/test_cloud_disk.py` uses only the staged CLI and the staged monitor.
Prerequisites: `make stage` with a runtime whose `assets/kernel-default` is the
Phase 17 workload kernel (GPT/MBR scanning, `VFAT_FS`, `NLS_CODEPAGE_437`,
`NLS_UTF8`; identity in Main's phase-17 evidence), plus `sfdisk`, `blkid`,
`e2fsck`, `debugfs` and `sqlite3` on PATH. `SILO_SMOKE_QEMU_IMG` optionally
names a `qemu-img` for an additional `check`/`compare` of every qcow2 fixture;
when unset the log records that this cross-check was not exercised.

```sh
make stage
make smoke SMOKE_ARGS='tests/test_cloud_disk.py -m "linux_only and not sdk"'
make smoke SMOKE_ARGS='tests/test_cloud_disk.py --backend vz'   # macOS VZ lane only
```

A session fixture creates two never-booted whole-disk ext4 roots from the
loopback registry (identical except `/etc/phase17-identity`, both carrying
`/usr/local/bin/phase17-probe` and an ESP fstab line). Smoke-only bounded
encoders then write GPT/MBR tables, a FAT16 ESP and qcow2 v2/v3 containers
(allocated, DEFLATE-compressed, unallocated and v3 explicit-zero clusters, exact
refcounts). Each table is read back by `sfdisk --json`, the ESP by `blkid`,
ext4 partitions by `e2fsck -fn`/`debugfs` on byte-range extracts; no Silo
parser is the oracle. The guest oracle is the probe: the mounted root's device
number, partition number/start/size and its parent's virtio serial.

Gates: raw and both qcow2 encodings import to one ImageId/stream with
accumulated aliases/provenance, never-booted private roots equal the raw
SHA-256, inputs stay unmodified; whole-disk, GPT (sparse slot 4) and MBR slot 4
roots boot with the identical pinned kernel/initramfs/agent and stop clean
(ESP never mounted); DPS auto refuses ambiguous/missing/wrong-ISA/no-auto/
read-only and foreign platforms with candidates; unsupported containers,
forbidden qcow2 features, special files, symlinks and incompatible layouts
refuse before image/alias/machine publication; a cloned GPT on an attached
disk never replaces the `silo-root` serial; fstab-mounted vfat reads with NLS
options and a late ESP mount is never certified clean; opaque expansion keeps
both GPT copies, the partition and the ext4 block count; pinned bundles survive
source and packaged-asset removal and change only by `silo set
boot-assets=packaged` while stopped; image/snapshot creation preserves
semantic configuration and every snapshot disk; explicit conversion is cached
per manifest/platform/flattener across packaged upgrades and boots.

Shuffled attachment order cannot be produced by libvm (root is always first),
so one test uses a disposable agentless candidate launch through the shipped
monitor: the cloned GPT is the first attachment and the root the second. It
writes no catalog or qualification state and is not product acceptance.
Invalid bootstraps there must print the init fail-closed line, never run the
probe, and leave both disks byte-identical. The VZ refusal/conversion test is
`macos_only` and requires `--backend vz`; on Linux it is `pending-lane:macos`,
never passed.

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

The Phase 14 default baseline,
`.tmp/plan/evidence/phase-14/default-journal-complete.xml`, contains 106 testcase
rows totaling 983.640 seconds (suite wall time 983.983 seconds). The suite header
reports 115 tests, so use the actual testcase rows for per-case comparisons.
Overlay cases contribute 423.935 seconds and stopped-storage cases 292.336
seconds, together 72.8% of the recorded case time. These totals identify the
dominant controllers, not a measurement of any individual setup operation.

Those two modules now seed each unopened private Home from a session-local
image-only cache prepared from that session's exact OCI bytes. Preparation
creates stopped, never booted machines through the staged CLI, then uses the
existing sanitized SQLite backup and reflink-aware immutable pool copier.
Overlay and stopped references have separate catalogs, so no extra image
reference can pin the OCI closure during stopped-storage collection checks.
Each case still creates its
own machines, writable disks, runtime namespace, catalog and locks; no
previously booted root or machine/operation/network row is carried over. The
cache is not reused across pytest sessions. Invalid OCI variants still take
their original acquisition/materialization paths, and acquisition/cache tests
retain fresh, unseeded Homes. The common `vm` fixture's Home is the only other
seeded Home; see the Phase 16 notes below.

The two exact-boot snapshot cases contribute 88.861 seconds and the retained
stage-replacement case 16.181 seconds to that baseline. Their private runtime
trees now use reflinks when the destination filesystem supports them, falling
back to ordinary copying otherwise. Copies still dereference staged symlinks,
preserve file modes/timestamps/xattrs and allocate private inodes, never
hardlinks. Replacing, modifying or unlinking either private tree cannot modify
the original stage or its sibling. All boot-byte hashes, held-FD/unlink oracles,
fresh boots, shutdown ownership and existing readiness/deadline checks remain.
No Phase 15 speed result is claimed until the complete default selection is
rerun with the same qualified inputs.

Phase 12 measured 199 `info` invocations taking 101.91 seconds in the six
stopped fork/replay and exact-boot snapshot cases. Identity-only path and SQL
lookups now use the existing independent read-only catalog process, without
caching machine identities or reconciling live state. Explicit CLI state,
readiness and clean-stop assertions remain. The same six cases passed before
and after, taking 291.08 and 233.94 seconds respectively; `info` calls fell to
80. These are targeted-run timings, not a full-suite speed claim. Raw commands
and timings are retained in `.tmp/plan/evidence/phase-12/stopped-speedup.json`
and its adjacent `stopped-{before,after}-command-times.jsonl` files.

The Phase 15 default run, `.tmp/plan/evidence/phase-15/default-speed-final.xml`,
took 955.552 seconds of suite wall time: 120 testcase rows, 119 passed and the one
opt-in internet case skipped (the header's `tests` count is not the row count).
That exceeds the 900-second rule, so Phase 16 removes more redundant smoke work
without removing any boot, stop, replay, hash or guest check:

- Identity-only lookups use a fresh read of the independent read-only catalog
  process instead of CLI `info`: the source in each `stopped.fork` distinctness
  check, the two-child test's final three-machine uniqueness check, the expected
  machine in `overlay.metrics`, and the log path and terminal machine ID in
  `overlay.shutdown_watch`/`orderly_guest_shutdown`. Both sides of every
  comparison are normalized with `UUID`. The child's own `info` state, run and
  readiness assertions stay. In the six stopped fork/exact-boot cases this
  removes 22 `info` calls. The common `vm` fixture takes its ID from its own
  `wait_ready` response, one fewer `info` for each of its 11 default cases.
- `overlay.evidence` returns `Evidence(observation, metrics)`. Overlay
  persistence uses that already validated frame as its pre-restart agent
  identity instead of collecting a second one. Evidence now samples metrics
  before its read-only diagnostics. Each `metrics` call still sets its own
  new freshness cutoff and compares against independent guest statvfs, and the
  post-restart frame is still collected fresh.
- The common `vm` fixture seeds its fresh Home from a session-local BASIC-only
  catalog. That catalog is prepared like the overlay/stopped catalogs, in its
  own preparation Home and never merged with them. The fixture asserts the seed
  carried exactly the BASIC reference, then runs its unchanged create, start and
  readiness. The general `workspace`/`silo` fixtures, lifecycle, image-cache and
  malformed-image tests stay unseeded.
- In each two-child fork case, the first child's machine-ID read and the
  source's final `/second-only` absence check join the existing guest-copy
  batch, with a second textual boundary and exact-byte checks. That is two fewer
  guest sessions per case, eight in the default selection.

Overlay `info` removals are counted from command evidence, not listed here.
None of these removals has a measured elapsed-time effect until Main runs a
controlled before/after pair of complete suites.

Command timing is recorded so the before/after pair can be compared. Every
`Silo.run` appends one monotonic duration line to the workspace's
`evidence/timing.log`: an `operation` (`silo <label>`), an `outcome`
(`exit-<code>`, `timeout` or `spawn-error`) and `seconds`. Readiness polls use
the `wait-ready` label, so the remaining `info` count does not depend on boot
time. `wait_ready`, `overlay.metrics`, each `root_metrics` attempt,
`stopped.backing`, `image_cache.seed`, catalog preparation and the exact-boot
private-runtime copy are timed at their harness callsites, with an exception
recorded under its type name. Successful cleanup deletes that log, so teardown
publishes a summary of count, total and maximum seconds per operation/outcome,
plus the cleanup time itself. The summary's size does not grow with the
number of calls. It goes into the JUnit `silo-smoke-timings` testcase property
for the `workspace` and `stopped_silo` fixtures, and into the
`silo-smoke-timings-prepare-<catalog>` suite properties for session
preparations. Use `--junitxml` to keep them.

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
`/tmp/silo-smoke-*/evidence/*.log` (or the macOS equivalent), command and
harness durations in `evidence/timing.log`. Keeping evidence does not keep the
VMs running.

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

## EROFS-overlay and VMDK qualification

`tests/test_overlay.py` drives the normal staged CLI/libvm/monitor/worker path.
OCI creation now defaults to EROFS overlay on libkrun, with no profile selector.
Managed overlay requires Linux 6.6 or newer; compatibility is a kernel-config
property verified by the kernel track's gate at build time, not by per-boot
artifact qualification. Custom kernels are not rejected for having new hashes.

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

This uses the `overlay_candidate_lower` libvm example to acquire an authenticated
EROFS composition with exact fsmeta and ordered pack occurrences, the real
`format_upper` implementation for its upper, and the shipped monitor in
foreground mode, which starts its real krun worker. It does not call libkrun
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

Main reviews the observed compatibility evidence and the kernel track's build-time
configuration gate, then exercises the real production path without rebuilding an artifact allowlist:

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

Run `test_overlay_native_range_opcode_and_real_fallback` after staging the
corrected signed native pin and passing the kernel track's build-time configuration
gate and the real overlay integration flow above. The source-copy build command
also creates `range-observer`. Then:

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

### Whole private-stage replacement with owned boot files

`test_overlay_owned_stage_replacement_rechecks_monitor` uses private complete
runtime clones, never Main's stage. A child-only Linux x86_64 syscall tracer holds
the first write to the private launch-kernel temporary file, before kernel or
composite publication. The gate checks that pinned kernel/base pool objects and
the monitor are held as read-only CLOEXEC descriptors with independent inode and
content evidence, then atomically swaps the stage and unlinks the retired tree.

The pre-exec metadata recheck must refuse the changed monitor before spawning it,
without hashing or reopening the replaced executable path. Pinned guest assets
remain owned independently of the stage. A fresh start must then boot with the
successor monitor; changing a Silo-managed monitor does not require an artifact
admission record. The controller retains EXITKILL and bounded descendant cleanup.

```sh
make smoke SMOKE_ARGS="-k overlay_owned_stage_replacement_rechecks_monitor --keep"
```

Retained `overlay-stage-*` and `boundary-*` evidence includes the held syscall,
source and destination descriptor identities, retained asset hashes, CLI refusal
and actual successor monitor/worker identities after the fresh successful boot.

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
The outcome matrix covers healthy managed EROFS overlay, forced termination,
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
environment/labels, userdata, hardware and kernel arguments. Each child's full
boot binding must equal the source binding, including its ABI, and independent
hashes verify exact pinned kernel/base-initramfs/agent objects. Both default-selected
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

Ordinary fork and snapshot capture require a stopped source and admit opaque raw
and EROFS-overlay roots subject to their boot/backend admission. Layered
snapshot/restore artifacts retain the exact fsmeta, ordered pack and metadata
graph, not a flattened lower or a requirement to regenerate from OCI. Obsolete
flat profiles are rejected before effects. Live execution operations remain
separate and publicly unqualified, not implicit stop/cold-boot fallbacks. An
exact checkpoint preserves configured secrets, guest credentials, dirty journals
and deleted-data remnants. It is neither sanitization nor application-consistency
certification.
External disks/shares require explicit `--external-requirements` at snapshot
capture; snapshot records never store destination host mappings. Fork/restore
may instead supply complete `--map-disk ORDER=PATH` / `--map-share TAG=PATH`
destination mappings. An unresolved requirement blocks start; an intentionally
shared mapping is not independent private storage.

`stopped.py` uses a separate bounded SHA-256/raw reader and records device,
inode, mode, logical length and allocation independently from the production
StreamHasher. Logical SQL/schema snapshots use independent read-only sqlite3
processes; WAL/SHM physical bytes are deliberately not compared. Catalog reads
allow SQLite to wait up to five seconds for a concurrent writer, within the
existing 15-second subprocess limit; persistent contention still fails.
Rejection gates
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
terminal wait. Wait order is not creation order: an auto-attached child can stop,
run and be reaped before its creator's fork/vfork/clone event stop is dequeued.
Each `child-event` announcement is therefore balanced per TID against that
TID's terminal wait, exec collapse or manager detach, in either order, and
records `ended_before_announcement`; a reaped TID is never re-owned, and an
announced TID still owing an end fails the gate. No lifecycle path supplies a
missing checked injected return. Host-only
regressions in `test_native_live_api.StoppedTraceLifecycleTests` schedule real
SIGKILL between a stop and ptrace inspection, without replacing syscall or wait
results. A separate real-subprocess clone-race probe reproduced the late
announcement failure before correction and passed afterward. It is not a
permanent suite requirement: observing that ordering depends on kernel
scheduling, even when a child's exit is already waitable.
These are process/syscall evidence, not a power-loss simulation. The controller's
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
Phase 15 delivers capture and restore without production qualification:
both report `lane-not-qualified`; fork and incremental remain `not-delivered`.
The public pause qualification is revision-bound. Standalone native proofs
grant no additional public capability.

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
