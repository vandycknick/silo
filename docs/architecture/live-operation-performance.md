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
