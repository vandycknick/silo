# Live operation performance: budgets, batches, measurements

Tracks [ADR 0021](../adr/0021-live-snapshots-and-forks.md)'s live-operation and
start budgets from command start until the guest agent is ready, plus capture
interruption and exec round trips. `Running` alone is not the latency endpoint.
The Phase 24 batches below retain their historical clocks and measurements;
their numbers are medians of five cold and five warm samples on a running
4 GiB-RAM, 2-vCPU fixture with a 2 GiB layered upper holding a 1 GiB random
payload, a private network and an in-guest witness proving continuation.
Reference host: AMD Ryzen 5 3600; ext4 is a loop device without reflinks, Btrfs
is the host's `/home`. The Phase 30 baseline uses its separately labeled cohorts.

Raw evidence (samples, syscall traces, probes) lives under
`.tmp/plan/evidence/phase-24/` in the working tree; this file keeps the
durable summary.

## What each target measures

| Target | Clock | Exercises |
|---|---|---|
| Start to agent ready | command start → guest agent ready | CLI and store preamble, launch, boot and guest-agent readiness; image init as PID 1 is the default. |
| Capture total | command start → snapshot complete and source agent ready under the continuation policy | cut, source continuation and durable publication; record separately from interruption. A preserved user pause remains paused by policy. |
| Capture interruption | source workload unavailable → thawed and agent ready, or the preserved-pause outcome | workload freeze, upper seal, device/vCPU serialization, touched RAM capture and receipt. The retained 4 GiB gates include their recorded copy and disk-sealing allowances; these do not permit violating Phase 30 scaling. |
| Restore to agent ready | command start → child guest agent ready, witness continuing | closure shape and trust checks, private upper clone or written-byte copy, launch, private RAM mapping, generation acknowledgement, activation and thaw. Local publication seeds first-restore trust without hashing RAM; imports and transport retain full authentication. |
| Fork to all agents ready | command start → every requested child guest agent ready | one cut including pause, admission and child restores; the retained Fork4 gate requires all four agents. Durable fork is the default; fast same-host fork is a separate explicit mode. |
| Exec round trip | command start → guest command completes and CLI returns | complete agent request and response, not application readiness. |

`make perf` runs the standalone `perf/` project serially and gates the retained
4 GiB fixture and Phase 30 targets; `make smoke` does not run budgets. Every new
performance figure records both default image init and agent-as-PID-1
(`--kernel-arg init=`), with the mode labeled. Historical rows keep their
original evidence and are not silently converted to the new clock or mode.

## Phase 30 baseline (2026-11-15)

The Phase 30 targets are not yet met. Each implementation slice must append its
measured result, including raw samples, both init modes and clock endpoints;
the baseline is not a passing qualification.

These are the plan's three-sample medians in seconds, measured on the same
Ryzen 5 3600 host with Btrfs, Linux 7.2.11 and idle guests. Alpine uses 2 vCPUs;
the Arch cohort uses 30 GiB RAM, 10 vCPUs and a 100 GiB disk. "Image" is default
image init as PID 1; "agent" is `--kernel-arg init=`. msb 0.7.15 ran earlier on
the same host that day, with its default init and 4 GiB disk, not a matched Arch
guest. The comparison is informational.

| Operation | msb 2 GiB | Silo 2 GiB image / agent | msb 30 GiB | Silo 30 GiB image / agent | Arch 30 GiB image / agent |
| --- | ---: | ---: | ---: | ---: | ---: |
| Create + start | 0.31 | 1.12 / 1.14 | 0.42 | 1.57 / 1.82 | 3.28 / 3.17 |
| First exec | 0.03 | 0.26 / 0.28 | 0.03 | 0.30 / 0.33 | 0.34 / 0.36 |
| Fork, first | 1.11 | 1.07 / 1.08 | 11.00 | 6.45 / 6.51 | 8.13 / 8.03 |
| Fork, second | 0.53 | 0.85 / 0.87 | 2.43 | 1.80 / 1.84 | 3.38 / 2.44 |
| Snapshot, full | 1.06 | 1.88 / 1.88 | 11.60 | 7.76 / 7.79 | 21.26 / 20.17 |
| Snapshot, incremental | 0.38 | 1.61 / 1.74 | 1.76 | 3.36 / 3.18 | 42.11 / 22.97 |
| Restore, first | 0.21 | 0.83 / 0.85 | 0.36 | 2.39 / 2.42 | 12.14 / 10.56 |
| Restore, second | 0.21 | 0.53 / 0.56 | 0.37 | 0.65 / 0.65 | 1.93 / 1.93 |
| `run -- /bin/true` | 0.45 | 1.21 / 1.69 | 0.72 | 2.15 / 3.25 | 4.64 / 6.96 |

The baseline table records command wall time. `silo start` returns after guest
agent readiness by default (`--no-wait` skips waiting). Live restore and fork
return after activation, including the agent's `Activate` and `Thaw` RPCs, so
command return is their agent-ready boundary. Snapshot rows include publication,
not just the pause. "Create + start" includes creation, unlike the start-only
target. First exec is a separate round trip; `run -- /bin/true` ends at workload
exit. These three-sample observations do not establish five-run gate medians.
Evidence: `.tmp/plan/evidence/phase-30/bench2/bench.sh`,
`bench2/results.csv` and `bench2/msb-bench.md`; attribution and comparison
research: `.tmp/research/msb-timings.md` and `.tmp/research/boxd-timings.md`.

### Causes C1-C8

- **C1, disk capacity scans.** Capture walks the entire logical upper:
  0.93 s inside the pause for a 100 GiB disk with only 17 MB allocated.
  Publication walks it three more times at about 4 s each. Post-resume
  publication is 13-17 s with that disk versus 1.5-2 s with the default disk.
- **C2, freed RAM written as zeros.** Guest-freed pages become dirty zero pages.
  Incremental capture writes 7.9-14.7 GiB of real zeros, extending the pause,
  allocating disk space and adding restore hashing. On Arch, default systemd
  init costs about 19 s more than agent-as-PID-1 on incremental snapshot
  (24.0 s versus 6.5 s in capture-memory). Even agent-only 10-vCPU incremental
  capture takes 6.5 s versus 5.7 s full; that additional cause is not isolated.
  Free-page reporting is a suspect, not a confirmed explanation.
- **C3, repeated lower validation.** Each restore, fork child and create rereads
  the prepared lower, about 1.2 GiB and 1 s for Arch, instead of reusing image
  validation.
- **C4, untouched RAM scan.** First capture reads all 30 GiB of configured RAM
  in about 5.7 s to find about 0.7 GiB of data.
- **C5, first-restore RAM hashing.** Cold restore hashes the RAM stream before
  execution, about 5.3 s in the owner trace, despite local capture provenance.
- **C6, completion polling.** CLI capture polling backs off to 1 s, delaying
  observation of a completed operation.
- **C7, fixed command overhead.** About 0.5 s per command and 1.5 s per snapshot
  remain outside useful guest work. Exec round trips cost 0.26-0.40 s versus
  about 0.03 s for msb; second restore at 2 GiB is 0.53 s versus 0.21 s.
- **C8, agent-init run gap.** `run -- /bin/true` is 0.5-2.3 s slower with
  agent-as-PID-1 than image init. The cause is not yet explained.

### Adopted contract and targets

No restore or fork step may scale with configured RAM or logical disk size.
Capture work scales with changed bytes, and full capture pause with touched
RAM. A 30 GiB and a 500 GiB disk with identical written data must take the same
snapshot, fork and restore time within measurement noise. Reflink disk steps
are constant-time clones regardless of written data. Without reflinks, the
only permitted disk cost is copying bytes actually written to the upper, an
accepted rare slow case. Configured-length scans and repeated publication
passes are contract violations, not allowances.

Local snapshot publication seeds the warm receipt, so the first local restore
does not hash RAM. Silent local corruption between capture and restore is not
detected at restore. `silo snapshot verify IMAGE` rereads and authenticates every
RAM, state and disk byte against recorded identities, exiting nonzero on failure.
RAM and disk mismatches name the stream, chunk index and byte range; state
mismatches name the whole object's role, digest and length. Missing, truncated,
writable or replaced members are structural failures. Recorded-zero chunks are
read and checked; warm and composition receipts are ignored. Imported, pulled or
transported snapshots, export and handoff still authenticate every byte.
Changed-to-zero pages are explicit zero ranges, holes with format-level zero
markers rather than inheritance; zero chunks are never hashed or stored.

Durable fork remains the default. The separately selected fast same-host fork
has no RAM file; source and children share guest memory copy-on-write, siblings
share physical pages, and children do not survive host crash or reboot.
Mechanism details await the Phase 30 design review.

The approved idle Arch cohort uses 30 GiB RAM, 10 vCPUs, a 100 GiB disk and
default image init, with command start to agent ready as the latency clock:

| Operation | Target |
| --- | --- |
| Start | Under 1 s |
| Local snapshot restore, first or repeated | 0.5 s |
| Durable fork with baseline | 1 s |
| First durable fork | 2 s |
| Fast same-host fork | 0.5 s |
| Incremental snapshot | 2 s total, with a 1 s pause |
| Full snapshot | Pause proportional to touched RAM |
| Exec round trip | 0.1 s |

Image init as PID 1 stays the default, with both init modes reported. The
existing 4 GiB fixture gates remain in force alongside this cohort. The
standalone perf suite reports Silo versus target as gating pass/fail, Silo
versus msb on a roughly equal setup as informational, and appends run history.
msb is skipped with a reason when unavailable. Reaching msb's 0.3-0.4 s start
latency is a later stretch goal, not a Phase 30 gate.

## Implemented Phase 30 validation and store admission (2026-11-15)

These are implemented path changes, not new performance measurements or claims
that the targets pass.

Local composition validation receipts are keyed by `LowerResultId` and schema
version. They bind canonical recipe/result identities, ordered layer occurrences,
fsmeta identity and length, and every unique pack/fsmeta inode's fingerprint.
Producer-bound compose or exact validation seeds them; a changed fingerprint
forces exact authentication or refusal. Hits on local create, start, restore and
fork-child paths read no lower payload. They are a validation cache, not
retention roots or transport authority, and import, transport, export, handoff
and explicit verification do not honour them. See
[ADR 0014](../adr/0014-layered-oci-image-storage.md#local-composition-validation-receipts).

RAM and writable disks now share the owned `SealedStreamPublication` path.
Fresh local reflinks carry producer identity without publication rereads;
required copies hash inline, and recovery/replay authenticate bytes.
Independent same-identity pool streams skip scanning only when their
`verified_object` receipt matches the current fingerprint. The snapshot
publication transaction seeds warm receipts for RAM and those disks.

### Runtime opening and recovery

`RuntimeOpenMode::Observation` uses `Store::open_observation`: after connection
and schema admission it validates pending operation records, retires only those
proven abandoned through each operation's own lease, removes their disposable
temporary workspaces and reconciles the restore budget. A live operation lease
prevents retirement. Observation does no store-wide work: no immutable-pool or
historical-lease scan, no published-map authentication and no per-chunk queries.

CLI exec, shell, cp, logs, forward, list, info, pause, resume, and snapshot/image
listing and inspection use this mode. It is not a read-only database capability:
runtime configuration and capability validation still run, and connection/schema
admission can create the catalog and its initial schema. Other mutating commands
use the default `Maintenance` mode; a cached observation runtime must complete
`recover_maintenance` before that work.
Cold handoff capabilities, planning and status initialize an `Observation`
backend, transfer operations initialize `Maintenance`
(`app/cli/lib/daemon/control/handoff.rs`), and source observation reuses the
runtime's open store instead of reopening it (`runtime/libvm/src/handoff/source.rs`),
so planning never triggers store-wide recovery.

`Maintenance` adds orphan object and stream discovery, transport-cache
collection, historical lease-inventory validation, and constructed-child,
capture and fork recovery. Orphan discovery uses bounded metadata-only scans and
set-based anti-joins against catalog retention without authenticating healthy
published stream maps. Checkpoint and ownership rechecks still fence deletion.

Pending-operation recovery stays on every runtime open so that prior completed
work does not leave cleanup for a later refused live operation or planning
command. Such a command finds nothing to recover and leaves the catalog and
state files byte-identical, as ADR 0021 requires. Successful operations still
defer retirement of their own records to the next open, as before Phase 30.
The explicit read-only capability-observation path remains separate from this
writable runtime admission and does not run recovery.

Retention semantics are unchanged from before Phase 30. Removing an image or
releasing a snapshot removes references only; artifacts, compositions and layers
remain until explicit prune. Explicit prune and layer recovery retain full
validation and their checkpoint/recheck fences. The daemon's management runtime
opens once in `Maintenance` and is reused, not reopened per RPC.

Implementation: `runtime/libvm/src/runtime/core.rs`, `store/store.rs`,
`store/image_store.rs`, `store/operation_store.rs`, `store/layer_store.rs` and
`app/cli/lib/daemon/control.rs`. Snapshot verification is
`SnapshotStore::verify`; its traversal and stream versus object diagnostics are
defined in [ADR 0021](../adr/0021-live-snapshots-and-forks.md#on-demand-verification).

## Results by batch

| Batch | Lane | Capture excess (5 s) | Restore (2 s) | Fork4 (10 s) |
|---|---|---:|---:|---:|
| Baseline (Phase 22) | ext4 | 8.72 / 7.77 | 11.32 / 8.47 | 24.86 / 25.28 |
| Batch 1, contract preserved | ext4 | 4.39 / 4.19 pass | 10.21 / 7.21 | 20.14 / 23.11 |
| Batch 2, contract changes | ext4 | 2.16 / 1.12 pass | 3.56 / 4.32 | 13.79 / 15.16 |
| Batch 2, contract changes | Btrfs | 1.35 / 1.35 pass | 0.77 / 0.93 pass | 3.89 / 3.38 pass |
| Batch 3, ext4 path + single cut mode (gated) | ext4 | 2.16 / 1.18 pass | 0.70 / 0.62 pass | 8.15 / 6.56 pass |
| Batch 3 | Btrfs | 2.42 / 2.42 pass | 0.67 / 0.76 pass | 3.16 / 3.11 pass |

Cold / warm. "Capture excess" is interruption minus the non-reflink copy
allowance (about 1.3 s on this host).

## Batch 1: contract preserved

Every hash, authority check, durability barrier and admission order stayed;
only the work spent reaching them changed.

- Exact word-wise zero test (`vm_spec::capture::is_all_zero`, and the same in
  the libkrun sparse writer) instead of byte-wise scans.
- Extent-aware hashing: holes are fed to the digest from a zeroed buffer and
  never read.
- Relocation barrier grouping: payload fsyncs, renames, one fsync per
  directory, one ownership transaction (was 37 serial fsyncs).
- Read-only `GetOperation` polls no longer journal a durable command record.
- Writeback hints during copies; completed-output verification overlapped with
  `sync_all`.
- Restore: two-lane closure authentication, synchronous 64 KiB executable
  digest, shared preflight capability query.

Measured effect: capture pause 8.94 → 5.51 s; manager work after the seal
4.67 → 3.56 s; restore about 1.2 s faster; child construction unchanged
(writeback bound).

## Batch 2: contract changes (ADR 0021 revised)

1. RAM chunks are hashed by the worker during the native write; disks are
   hashed by the monitor during the copy. No read-back verification.
2. The stream identity (SHA-256 over the ordered chunk-digest list) is the
   identity of RAM and disk streams on every live path. Whole-file digests are
   computed only for blobs that leave the host.
3. libvm validates a cut structurally at retention. Owned reflink RAM and
   writable-disk publication bind producer identity and unchanged inode facts
   without rereading payloads; copies hash inline. Independent dedup streams
   require a matching `verified_object` receipt or full authentication. Phase 30
   seeds local restore trust in the publication transaction; imported, pulled or
   transported snapshots, export and handoff independently authenticate bytes.
4. A fork is a local branch: the cut is written and closed, not synchronized.
5. Children hash their private copy as it is written, start at
   `constructed`, and become `durable` in the background. Current recovery adopts
   pending barriers while an exact monitor or run lease remains live; deletion
   waits for positive liveness reconciliation.
6. Durable restore checks closure shape before allocating. Required byte
   authentication runs concurrently with the private copy; trusted local
   objects with unchanged inode facts avoid that read.

Phase 30 reverses the former no-warm-receipt publication rule: publication of a
snapshot produced on this host seeds the warm receipt for its first restore.
Silent local corruption between capture and restore is not detected at restore;
explicit verification, export and handoff authenticate bytes independently.
File/directory synchronization and catalog durability are unchanged. Local fork
RAM restore trusts producer-computed identities and unchanged owned inode facts
without rehashing RAM. These amendments do not remeasure historical batch results.

Measured effect on ext4: pause 5.51 → 2.52 s; manager 3.56 → 1.46 s; restore
7.21 → 3.5–4.3 s. Child construction stayed at about 9 s for four children.
On Btrfs every budget passes with margin (manager 0.05 s, construction 0.40 s).

### Why ext4 and Btrfs differ

Same binary, same syscalls. Two kernel facts differ:

- `FICLONE` succeeds on Btrfs, so a child's private upper is a reflink; on
  ext4 it fails and 1 GiB per child is written to the device.
- ext4 `data=ordered` makes every journal commit (any fsync, SQLite
  `synchronous=FULL`, the 5 s jbd2 timer) write out all newly allocated dirty
  data first. Small metadata syncs therefore pay for the whole copy drain;
  Btrfs has no such coupling.

On ext4 without reflinks the floor for restore and fork is the private copy's
bytes at the device's sequential write rate (about 1 s per 1 GiB here).

## Batch 3: ext4 and simplification

1. One capture mode: the monitor and worker never synchronize staged files;
   durability is libvm's, at checkpoint publication (pool file and directory
   syncs plus a checked WAL checkpoint after the catalog commit) and in each
   child's background barrier. `CutDurability` and the native `durable` flag
   were deleted.
2. Live-child launch writes (composite initramfs, config, secrets, network
   policy, leases, run/log directories) are deferred and enrolled in the
   child's barrier; stopped machines keep inline durability. Recovery adopts
   the barrier of a `constructed` child whose run is alive and deletes only
   children with no live run; fork and restore do not return before their
   barriers settle.
3. Catalog `PRAGMA synchronous = NORMAL` in WAL mode: consistent after any
   crash, process-crash durable; the boundaries that need power-loss
   durability (handoff receipts/fences/commits, checkpoint publication,
   commit-then-unlink garbage collection, machine deletion) run a checked
   `wal_checkpoint(PASSIVE)` after their commit and fail closed if it cannot
   complete.
4. Capability discovery caches validated reports per process (stat/digest
   keyed, replacement still invalidates); disk-map verification overlaps
   `inspect-restore`.
5. Budgets: the non-CoW copy allowance applied to restore and fork as it
   did to capture; the harness probed `FICLONE` in the budget workspace
   to choose the lane. Phase 30 moves these gates from smoke to `make perf`.

| Batch 3 | Lane | Capture raw / gated | Restore raw / gated | Fork4 raw / gated |
|---|---|---:|---:|---:|
| cold | ext4 | 3.40 / 2.16 | 3.60 / 0.70 (recorded, not budgeted) | 13.11 / 8.15 |
| warm | ext4 | 2.42 / 1.18 | 3.51 / 0.62 | 11.53 / 6.56 |
| cold | Btrfs | 2.42 | 0.67 | 3.16 |
| warm | Btrfs | 2.42 | 0.76 | 3.11 |

Every gate passes on both lanes (ext4 allowance: 1.24 s per 1 GiB copy at
the measured 872 MB/s; fork4 subtracts four copies). ext4 warm fork segments:
pause 2.37 s, manager 1.06 s, construction 7.07 s, prepared→Running 0.62 s.
The remaining ext4 gap to the raw numbers is the private copy bytes at device
rate, which the allowance is defined to cover.

## Deferred budgets (ADR 0014 table, ADR 0021 incremental)

Measured 2026-11-09 on the Batch 3 runtime with the new cohorts in
`smoke/tests/test_fork_budget.py` (incremental, prepared create, layered vs
raw boot) and `smoke/tests/test_ingest_budget.py` (cold OCI prepare). The
boot marker is the monitor's `guest agent became responsive` trace event
(agent serving from the mounted root), timed from `silo start` dispatch.

| Budget | Target | ext4 cold / warm | Btrfs cold / warm | Result |
|---|---|---:|---:|---|
| Warm create of a stopped machine (Alpine lower) | 2 s | 0.70 / 1.01 | 0.56 / 0.74 | pass |
| Warm create, 4 GiB single-layer lower | Original 2 s; historical pre-receipt size-dependent revision discussed below | not run | 6.15 (one sample) | missed original target; not requalified after receipts |
| Incremental capture, 10 % dirty (410 MiB) | 1 s + allowance | 7.44 / 7.77 raw, 5.92 / 6.25 gated | 2.74 / 2.21 | miss |
| Layered / raw boot ratio | 1.2 | 1.21 / 1.44 | 1.25 / 1.32 | miss |
| Cold OCI prepare / (download + decompress) | Original 1.5; revised 10 on Btrfs | not run | 6.0 (1 GiB), 9.2 (4 GiB) | missed original target; not requalified |
| Prepare linearity (s per GiB, largest / smallest) | 1.25 goal, no longer an admission gate | not run | 8.7 → 12.4 s/GiB (1.43); 12 GiB exceeded 300 s | missed original target; not requalified |

**Ingest budget revision, owner decision 2026-11-09.** ADR 0014 now records
a 10× cold-prepare budget on the Btrfs reference host; 1.5× remains the
product goal for the ingest pipeline rewrite. Linearity is reported per
size, with 1.25 a goal rather than an admission gate until that rewrite.
The 2 s prepared-lower create gate up to 1 GiB allocated remains. The former
larger-lower 1.35 s/GiB slope is historical pre-receipt evidence from two sizes,
not a validated bound or a post-receipt allowance. Composition receipts are now
implemented and avoid lower payload reads on hits at every size; larger-lower
latency still requires post-receipt measurement.
All revised ingest numbers and the missed original targets above cite
`.tmp/plan/evidence/phase-24/deferred-btrfs/ingest-20261109T121355Z/`:
`size-cold-0-1073741824.json`, `size-cold-0-4294967296.json`,
`reference-host.json` and `fixture.json`. The same cohort's 12 GiB
unprepared-create timeout is in
`.tmp/plan/evidence/phase-24/deferred-btrfs-ingest.log`; it is not a measured
12 GiB prepare duration. These incomplete first-cohort observations are not
five-run qualification medians; revising the budgets does not turn them
into passes or establish qualification on another filesystem.

Attribution from the evidence:

- **Incremental.** The vCPU pause is 2.8–3.5 s on ext4 and 2.1–2.4 s on
  Btrfs. The native writer hashes only the affected 8 MiB chunks (77–80 of
  512) but rebuilds a complete sparse RAM file each time: it reads and
  rewrites about 1.23 GB of clean baseline data in addition to the 444 MB
  dirty data. On ext4 the workload-observed interruption is 4–5 s longer than
  the pause because the guest's first flush after resume waits for the host
  ext4 journal to drain the unsynchronized capture staging (`data=ordered`).
  Disk sealing alone is 1.1–1.2 s on Btrfs (clone plus full upper hash).
  Report: `.tmp/plan/research/phase24-incremental-memory-cost.md`.
- **Boot.** The recorded 0.15–0.31 s host-side layered penalty predates removal of per-boot asset hashing and duplicate CLI inspection; remaining pre-launch work includes a second lower consumer lease, VMDK descriptor publication and per-file syncs, and requires remeasurement (`.tmp/plan/research/phase24-layered-prelaunch-cost.md`).
- **Ingest.** The recorded size-dependent cost comes from repeated bulk
  materialization and authentication: decoded spool, private-to-published
  pack copy, composition validation and lower hashing. Prepared create
  rereads the retained payload through pack authentication, EROFS body
  validation and logical-lower hashing. The cause of the additional
  size-dependent slowdown is not yet attributed. Review:
  `.tmp/plan/research/phase24-ingest-cost.md`; measurements are cited above.

## Batch 4: boot path

Owner decision 2026-11-09: exact boot-tuple qualification (`ADMITTED_BOOTS`,
per-start SHA-256 of kernel, initramfs and monitor) is removed. Overlay roots
require Linux 6.6 or newer, read from the kernel header or ELF
`linux_banner`; owned asset handling (held FDs, 0400 copies, pre-exec
replacement recheck) stays. The duplicate start inspection is gone, the lower
resolver reuses the launch lease instead of registering a second consumer,
and launch artifacts are synchronized once at the spawn boundary (layered
start: 13 explicit syncs → 7, raw 9 → 6).

Batch 4c's 2026-11-09 contract keeps the 8 MiB chunk-list identity and defines
the 1 s incremental target on one contiguous 410 MiB dirty region in a 4 GiB
guest; scattered dirties may require a full-RAM rehash, exposed through
`identityBytesHashed`. Incremental RAM capture reflinks the retained baseline
on CoW lanes and overlays only dirty runs; non-reflink lanes then rebuilt
the complete file from the baseline, without a pre-pause copy. Both yielded
the same bytes, and `CaptureMemoryStats.seedMethod` records `clone` or
`rebuild`. Phase 30 disallows configured-RAM scans and requires changed-byte
scaling on every lane. The retained capture and incremental interruption gates
subtract a separate disk-sealing allowance (sealed upper allocated bytes /
host-measured sequential SHA-256 rate), in addition to the existing non-CoW
copy allowance where applicable. Restore and fork-to-agent-ready do not gain
this allowance. Allowances do not authorize size-dependent reflink work.
The historical allowance accounts for the measured Btrfs disk sealing cost of
1.1–1.2 s for a 2 GiB upper with 1 GiB payload, not a changed RAM target;
raw timings, both allowances and rate inputs remain in evidence. Attribution:
`.tmp/plan/research/phase24-incremental-memory-cost.md`, sections 1 and 3.

| Boot, dispatch → agent responsive (s) | ext4 raw | ext4 layered | ratio | Btrfs raw | Btrfs layered | ratio |
|---|---:|---:|---:|---:|---:|---:|
| before Batch 4, cold / warm | 0.741 / 0.678 | 0.897 / 0.979 | 1.21 / 1.44 | 0.637 / 0.609 | 0.794 / 0.803 | 1.25 / 1.32 |
| 4a tuple removal | 0.568 / 0.509 | 0.678 / 0.721 | 1.19 / 1.42 | 0.518 / 0.443 | 0.585 / 0.537 | 1.13 / 1.21 |
| 4b lease reuse + coalesced syncs | 0.541 / 0.479 | 0.612 / 0.663 | 1.13 / 1.38 | 0.522 / 0.441 | 0.593 / 0.536 | 1.14 / 1.22 |

Cold passes on both lanes. The warm miss is not layered work: dispatch to
monitor generation start is bimodal for both profiles (ext4 warm raw
0.21–0.23 s or 0.41 s; layered 0.23–0.24 s or 0.38–0.40 s; Btrfs 0.17–0.18
or 0.24–0.31 s). The slow mode is a shared ~170 ms host event that layered
samples happened to hit three times out of five; layered-only cost is the
30–65 ms visible in the cold medians. Next step: a start span in libvm to
name the shared event (startup recovery checkpoint, capability subprocess or
WAL checkpoint are the candidates), then remove it for every start.

## Batch 4c: incremental seed, writeback hints, allowances

Owner decisions: the 1 s incremental target is the defined fixture (contiguous
410 MiB dirty region); no pre-pause baseline copy on non-reflink hosts; a
disk-sealing allowance (sealed upper allocated bytes at the host's warm
SHA-256 rate) joins the copy allowance for capture and incremental.

Changes: the native RAM writer seeds its output by `FICLONE` from the
retained baseline on CoW lanes and overlays only dirty runs (receipts report
`seedMethod`); staging writes issue `sync_file_range` hints per 8 MiB so a
guest flush after resume does not wait on an ext4 journal drain; a start
timeline line attributes every start stage; recovery no longer checkpoints
batches that retired nothing; the harness quiesces writeback before every
sample and measures the hash rate in-process.

| Btrfs, cold / warm (s) | raw | gated | target | |
|---|---:|---:|---:|---|
| Capture interruption | 2.46 / 2.46 | 1.84 / 1.84 | 5 | pass |
| Incremental 10 % | 1.97 / 1.87 | 1.32 / 1.21 | 1 | miss |
| Restore | 0.54 / 0.36 | | 2 | pass |
| Fork4 | 2.94 / 2.84 | | 10 | pass |
| Boot layered / raw | 1.11 / 1.11 | | 1.2 | pass |

Incremental: the memory phase fell from about 1.25 s to about 0.65 s (clone
seed on all 22 samples); the vCPU pause is 1.81–1.84 s of which disk sealing
(clone, then read, zero-classify and hash the 1.08 GB upper) is 1.13–1.15 s.
The single remaining lever is hashing disk chunks in parallel (digests are
independent; the identity is their ordered list), which would also shorten
full capture and restore verification.

Boot: with writeback quiesced before every sample the warm bimodality is
gone (raw 0.41, layered 0.46 on Btrfs); the layered-only start work is the
15 ms lower resolve.

ext4 lane: the original loop backing file on the Btrfs root degraded to
19 562 extents and 260–455 MB/s (872 MB/s at Batch 3); it was replaced by a
fresh image (854 MB/s copy, 1.67 GB/s hash) and the four cohorts rerun:

| ext4 fresh lane, cold / warm (s) | raw | gated | target | |
|---|---:|---:|---:|---|
| Capture interruption | 3.83 / 2.41 | 1.90 / 0.49 | 5 | pass |
| Incremental 10 % | 4.51 / 3.23 | 2.63 / 1.35 | 1 | miss |
| Restore | 3.48 / 3.20 | 1.67 (recorded) / 1.38 | 2 | pass |
| Fork4 | 10.77 / 11.25 | 5.68 / 6.16 | 10 | pass |
| Boot layered / raw | 1.05 / 1.11 | | 1.2 | pass |

Incremental on ext4 uses the rebuild path (no reflink): vCPU pause
2.2–2.9 s, of which disk sealing is 1.0–1.3 s. The post-resume stall that
the writeback hints target fell from 4–5 s to 0.6–1.4 s, and two of eleven
samples still show 2–3 s of host-side pre-pause latency on the conservative
clock.

**Ingest.** The 2026-11-09 owner decision records the original cold-prepare,
linearity and large prepared-create targets as missed, with revised ADR
budgets backed by the ingest evidence directory cited above, not a passing
claim. The later ingest rewrite targets single-pass decode→pack and removal of
spool/publication copies, following `.tmp/plan/research/phase24-ingest-cost.md`.
Composition receipts are implemented in Phase 30; this does not requalify the
historical measurements. Live-operation budgets are unchanged by the ingest decision.

## Batch 4d: final live-budget closeout (2026-11-09)

Final cohorts close the remaining incremental miss. Cold /
warm medians below are seconds except boot ratios; **all eight budgets pass
on both lanes** under the recorded gate definitions (cold restore on ext4
remains informational). This closes the live-budget sweep, not the revised
ingest or large prepared-lower-create qualification.

| Lane | Capture raw → gated | Incremental raw → gated | Restore raw → gated | Fork4 raw → gated | Boot layered/raw | Warm create |
|---|---|---|---|---|---|---|
| Btrfs | 1.74 / 1.74 → 1.09 / 1.09 | 1.55 / 1.20 → 0.90 / 0.55 | 0.54 / 0.36 (no allowance) | 2.21 / 2.14 (no allowance) | 1.11 / 1.11 | 0.56 / 0.74 |
| Fresh ext4 | 3.86 / 2.41 → 2.04 / 0.58 | 2.85 / 2.42 → 0.86 / 0.43 | 3.48 / 3.20 → 1.67 / 1.38 | 10.65 / 8.38 → 5.80 / 3.50 | 1.05 / 1.11 | 0.70 / 1.01 |

Evidence for capture, incremental and fork4:
`.tmp/plan/evidence/phase-24/batch4d-btrfs/` and
`.tmp/plan/evidence/phase-24/batch4d-ext4/`. Restore and boot reuse the
Batch 4c cohorts (same restore monitor except parallel seal):
`.tmp/plan/evidence/phase-24/batch4c-btrfs/` and
`.tmp/plan/evidence/phase-24/batch4c-ext4/`. Warm-create measurements:
`.tmp/plan/evidence/phase-24/deferred-btrfs/warm-create-20261109T112829Z/`
and `.tmp/plan/evidence/phase-24/deferred-ext4/warm-create-20261109T112350Z/`.

## Post-closeout capture and publication changes

The Phase 24 cohorts above remain dated evidence, not measurements of the later
implementation. Phase 27 pipelined native RAM capture using three 32 MiB packs
and two hash/write workers (96 MiB pack scratch), preserving 8 MiB identities,
explicit zero overlays and joined failure/cancellation. It also reduced repeated
publication authentication to one pass. The plan records these 30 GiB,
4-vCPU observations in `.tmp/plan/evidence/phase-27/perf-*.log`:

| Guest | Pause before → after | Publication before → after | Wall before → after |
| --- | --- | --- | --- |
| Idle, 560 MiB nonzero | about 8.5 → 5.9 s | 2.7-4.0 → 2.7-3.2 s | 11.3-12.5 → 8.5-9.1 s |
| 8 GiB dense | 16.2-18.7 → 9.4-9.6 s | 50-53 → 29-35 s | 66-72 → 38-44 s |

Phase 28 removed RAM admission/reservations, made incremental capture the default
when a valid baseline exists, and replaced RAM publication copies with reflinks
where supported. The recorded restored-guest comparison (30 GiB RAM, 4 GiB
random payload, 256 MiB new data) is in `phase-27/perf-restored.log`:

| Capture | Wall | Paused | Publication | Live RAM read | Child RssFile afterwards |
| --- | --- | --- | --- | --- | --- |
| Booted source, full | 14.4 s | 8.5 s | 5.7 s | 30 GiB | not applicable |
| Restored child, default incremental | 7.5 s | 0.6 s | 6.7 s | 0.52 GiB | 280 MiB |
| Restored child, explicit full | 30.2 s | 22.8 s | 7.3 s | 30 GiB | 23.2 GiB |

The incremental publication still cost 6.7 s because it reread every populated
RAM extent, not just changed chunks. Commit `10ae51ed` removes that read on the
first owned reflink publication: producer identities and stable inode facts bind
the clone. Replay from sealed state and copy fallbacks still authenticate bytes;
independent dedup streams use matching verified receipts or full authentication.
Phase 30 now seeds warm receipts for RAM and sealed writable disks in the local
publication transaction; silent local corruption between capture and restore is not detected
at restore. Explicit verification, export and handoff authenticate every byte.
Local fork RAM trusts producer/owned-inode authority. The Phase 30 baseline above
records later timings; none of these historical numbers is relabeled as a new
result.

The published Git dependency pin `662b359c` includes the pipeline and Linux
balloon reclaim. Phase 29 adds contained image-init live operation support and
retained-descriptor workload reclaim; it does not change these performance
budgets. See [ADR 0021](../adr/0021-live-snapshots-and-forks.md) for the current
resource, publication and guest-containment decisions.
