# Live operation performance: budgets, batches, measurements

Tracks the ADR 0021 live-operation budgets (capture interruption, restore to
`Running`, four-child fork) across the performance batches that shaped the
implementation. Numbers are medians of five cold and five warm samples on the
same fixture: a running 4 GiB-RAM, 2 vCPU machine with a 2 GiB layered upper
holding a 1 GiB random payload, a private network and an in-guest witness that
proves continuation. Reference host: AMD Ryzen 5 3600; ext4 lane is a loop
device without reflinks, Btrfs lane is the host's `/home`.

Raw evidence (samples, syscall traces, probes) lives under
`.tmp/plan/evidence/phase-24/` in the working tree; this file keeps the
durable summary.

## What each target measures

| Target | Clock | Exercises |
|---|---|---|
| Capture interruption | source vCPUs paused → running again | workload freeze, upper seal (1 GiB copy on non-reflink hosts), device/vCPU serialization, 4 GiB sparse RAM write, receipt. Non-reflink hosts get an allowance of the upper's allocated bytes at the host's sequential copy rate. |
| Restore to `Running` | `silo restore` dispatched → child `Running`, witness continuing | closure shape check, byte authentication, private upper copy, monitor/worker launch, private RAM mapping, VM generation ack, agent activation, thaw. |
| Fork4 to `Running` | `silo fork` with four children dispatched → all four `Running` | one fork cut (pause included), manager admission, four concurrent restores sharing one RAM inode. |

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
3. libvm validates a cut structurally at retention; full byte re-read only at
   publication, export and handoff.
4. A fork is a local branch: the cut is written and closed, not synchronized.
5. Children hash their private copy as it is written, start at
   `constructed`, and become `durable` in the background; recovery deletes a
   child that never became durable.
6. Restore checks closure shape before allocating, authenticates bytes
   concurrently with the private copy, and reuses previously verified objects
   whose inode metadata is unchanged.

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
5. Budgets: the non-CoW copy allowance now applies to restore and fork as it
   did to capture; the smoke harness probes `FICLONE` in the budget workspace
   to choose the lane.

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

Measured 2026-11-09 on the Batch 3 candidate with the new cohorts in
`smoke/tests/test_fork_budget.py` (incremental, prepared create, layered vs
raw boot) and `smoke/tests/test_ingest_budget.py` (cold OCI prepare). The
boot marker is the monitor's `guest agent became responsive` trace event
(agent serving from the mounted root), timed from `silo start` dispatch.

| Budget | Target | ext4 cold / warm | Btrfs cold / warm | Result |
|---|---|---:|---:|---|
| Warm create of a stopped machine (Alpine lower) | 2 s | 0.70 / 1.01 | 0.56 / 0.74 | pass |
| Warm create, 4 GiB single-layer lower | 2 s | not run | 6.15 (one sample) | miss |
| Incremental capture, 10 % dirty (410 MiB) | 1 s + allowance | 7.44 / 7.77 raw, 5.92 / 6.25 gated | 2.74 / 2.21 | miss |
| Layered / raw boot ratio | 1.2 | 1.21 / 1.44 | 1.25 / 1.32 | miss |
| Cold OCI prepare / (download + gunzip) | 1.5 | not run | 6.0 (1 GiB), 9.2 (4 GiB) | miss |
| Prepare linearity (s per GiB, largest / smallest) | 1.25 | not run | 8.7 → 12.4 s/GiB (1.43); 12 GiB exceeded 300 s | miss |

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
- **Ingest.** Prepare runs at roughly 100 MB/s expanded and gets slower per
  GiB as the layer grows; the baseline gunzip runs at about 750 MB/s. The
  prepared-lower create also scales with lower size (6.15 s for 4 GiB), so
  create reads the lower rather than only formatting the upper. Not yet
  attributed.

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
on CoW lanes and overlays only dirty runs; non-reflink lanes keep rebuilding
the complete file from the baseline, without a pre-pause copy. Both yield
the same bytes, and `CaptureMemoryStats.seedMethod` records `clone` or
`rebuild`. Capture and incremental interruption gates on every lane now
subtract a separate disk-sealing allowance (sealed upper allocated bytes /
host-measured sequential SHA-256 rate), in addition to the existing non-CoW
copy allowance where applicable. Restore and fork-to-Running do not gain
this allowance. This accounts for the measured Btrfs disk sealing cost of
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
