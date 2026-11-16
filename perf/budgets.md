# Retained 4 GiB and OCI performance gates

These serial gates retain the 4 GiB and OCI fixtures alongside Phase 30's
agent-ready scenario. Wave two measures capture pause exactly, separately from
post-resume seal latency and workload gaps. `make smoke` does not collect them.

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

The perf shell supplies pinned Distribution 3.1.2, verified against the same
binary identity as smoke. The ingest lane resolves `registry` on PATH and skips
with `enter the perf shell: nix develop .#perf` when absent, never downloading it.
`bash`, `head`, `tee`, `sha256sum`, `curl` and `gzip` are also in that shell.
Budget cohorts run serially and stage their matching runtime automatically:

```sh
make perf PERF_ARGS='tests/test_ingest_budget.py'
```

Evidence is written under `$SILO_SMOKE_BUDGET_EVIDENCE/ingest-<stamp>/`:
`reference-host.json`, `fixture.json`, per-size records, `samples.jsonl`,
`summary.json` and `summary.md`. Summary metrics are keyed by metric then cache
cohort, with explicit `budgeted` flags; over-target medians fail admission.
This Linux Distribution lane reports its actual host identity, not an
unmeasured claim about the ADR's XFS/APFS reference hosts.

### Live fork budget cohorts (Phase 16)

`tests/test_fork_budget.py` measures ADR 0021 full capture pause,
restore to agent ready and four-child fork through activation. Workspaces and evidence
default to durable directories under the Cargo smoke root; tmpfs is refused.
`SILO_SMOKE_BUDGET_DIR` and `SILO_SMOKE_BUDGET_EVIDENCE` optionally override them.
Short runtime directories keep sockets/locks separate from durable disk bytes.
The reference-host record includes the staged monitor SHA-256/build identity,
kernel/config and remaining runtime inputs. Debug failures do not qualify release.

```sh
make perf PERF_ARGS='tests/test_fork_budget.py'
```

All five measurement cohorts run when this module is selected.

Allowance, gate, writeback and small-file hash-probe unit tests (no guest):

```sh
uv run --project perf pytest perf/tests/test_fork_budget.py -k 'budget_gate or copy_allowance or hash_rate or quiesce' -n 0
```

The exact fixture, cache method and boundaries are in
`silo_perf/fork_budget.py`: `restore-execution` image, 2 vCPUs, 4096 MiB RAM,
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

Before every dispatch in every cohort (cold, discarded warm-up and warm), the
shared cache-conditioning step calls `os.sync()`, then polls `/proc/meminfo`
until `Dirty` + `Writeback` is below 16 MiB or the 30-second post-sync wait
expires. This keeps the previous sample's teardown writeback out of the measured
interval without dropping warm page-cache contents; cold samples still perform
their per-file eviction. Each sample retains `writeback` with
`dirtyBytesBefore` (before sync), `dirtyBytesAtDispatch` and `waitedSeconds`
(post-sync polling time). A timeout retains the remaining dirty bytes rather than
claiming the disk was quiet. Boot pairs retain separate raw/layered records under
`writeback`, and repeat conditioning before each profile's start.

Gated values: fork4 is CLI dispatch to the last durable child `running` stamp
(API entry, seal to Running and caller end-to-end are separate fields). Capture
pause is exactly the source monitor's `capture pause established` to
`capture pause released with ClockOnly`, not staging-to-continuation time or the
host-observed gap between durable 50 ms witness writes. The witness gap remains
an independent workload-unavailability diagnostic. `pauseToSealSeconds` separately
records pause established to final seal, which can extend beyond source resume.

At setup a real `FICLONE` probe between sibling workspace files selects the lane,
independently of the request's disk-copy contract. Reflink lanes subtract zero
**copy allowance** and budget cold restore. Non-reflink lanes subtract the
non-CoW allowance (upper allocated bytes at the measured sequential copy rate);
cold restore remains recorded but unbudgeted. Capture and incremental pause
subtract a **disk-sealing allowance** only when identity work occurs inside the
measured pause: sealed upper allocated bytes divided by the measured warm
sequential SHA-256 rate. Deferred reflink identity work occurs after source
continuation at `capture-disk-identity`, is separately reported seal latency,
and receives no pause allowance. Its `diskSealAllowance.includedInInterval` is
false and `diskSealAllowanceSeconds` is zero. Restore and fork receive no
disk-sealing allowance.

Samples retain raw timing, copy fields, `diskSealAllowance`,
`diskSealAllowanceSeconds` and `gatedExcessSeconds`; summaries report allowances
and their inputs. `diskIdentityInPause` identifies whether the identity work was
included in the pause. Measured disk-seal duration remains a diagnostic, not the
allowance, and no post-resume time is subtracted from a pause gate.

The reference-host hash probe writes and fsyncs a fresh 1 GiB `/dev/urandom`
file in the budget workspace, then hashes it twice using in-process
`hashlib.sha256` (OpenSSL) over 8 MiB reads without evicting pages, outside all
timed operations. This avoids PATH-dependent `sha256sum` implementations and
lets OpenSSL use the host's SHA acceleration. `sequentialHash` in
`reference-host.json` keeps
both ordered `passes` (`cold`, then `warm`) with timings, rates, digests and
mincore residency before/after; `cold` labels the initial pass, not a forced
cache eviction. The second pass must start fully resident, so its CPU-bound
rate, not a read-bound cold rate, becomes `sequentialHash.bytesPerSecond`
(and the top-level seconds, digest and cache evidence). Scratch files are
removed after probing.

Restore is dispatch to CLI exit with the child Running and ready. Samples, the
reference-host record (CPU, memory, kernel, filesystem, input hashes, monitor
SHA-256 and build identity, reflink probe result and errno, measured rates) and
`summary.json`/`summary.md` are written before assertions. Recompute a summary
with `python -m silo_perf.fork_budget DIRECTORY`. A running source keeps its
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
and `SILO_SMOKE_BUDGET_EVIDENCE` staged-runtime/workspace selection above.
The incremental cohort requires native incremental capture and restore support.
All three use `SCHEDULE`: five cold samples, one discarded warm-up and five
warm samples. Cold means per-file eviction of `owned_inputs(silo)` with
residency evidence, not an empty prepared-image pool. A partially evicted
sample remains explicitly labelled `partial-cold`. Both reported cohorts are
budgeted for every new gate, including non-reflink incremental capture.

| Pytest selector (`-k`) | Measured boundary and median gate | Additional free-space preflight |
| --- | --- | --- |
| `test_fork_budget_incremental_ten_percent_dirty` | Exact native pause established to released, at most 1.0 s after non-CoW copy allowance and only disk identity work included in that pause; workload gap and pause-to-seal latency are separate diagnostics | 14 GiB |
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
The 1 s target applies to this defined contiguous 410 MiB region under the
unchanged 8 MiB chunk identity, not arbitrary dirty-page placement. Scattered
dirty pages can require up to a full-RAM rehash, visible through
`identityBytesHashed`. Guest kernel, agent and witness activity can dirty
additional pages. Samples
record the exact workload byte count and fraction separately from
`productDirtyFraction`, derived from the product's
`memory.stats.identityBytesHashed / logicalBytes` at its 8 MiB chunk resolution;
the product exposes no separate page-granular dirty-fraction field.
They retain the complete memory receipt, exact pause, independent workload gap,
pause-to-seal latency and separate one-upper copy and disk-sealing allowance
inputs. Copy allowance is zero on reflink filesystems or allocated source-upper
bytes divided by the measured sequential copy rate otherwise. Disk-sealing
allowance is sealed upper allocated bytes divided by the measured hash rate
only when that work is inside the pause; post-resume identity completion has
`includedInInterval = false` and zero pause allowance. The target stays 1.0 s.
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

Prelaunch attribution comes from one additional CLI stderr line emitted just
after successful monitor exec: `DEBUG machine start timeline machine_id=<uuid>
run_id=<run> runtime_discovery_ms=<n> catalog_open_recovery_ms=<n>
lifecycle_admission_ms=<n> lower_resolve_authentication_ms=<n> secrets_netd_ms=<n>
launch_publication_ms=<n> durability_barrier_ms=<n> admit_spawn_ms=<n> total_ms=<n>`.
The CLI uses the shared, no-ANSI/no-target tracing formatter with progress-safe
stderr output. Normal invocations default to warnings and errors. Boot samples
explicitly set `RUST_LOG=info,libvm::runtime::start_timeline=debug` to collect
this diagnostic without raising monitor verbosity. Samples preserve stderr as
`<machine-name>-start.trace.log` alongside the monitor trace and require exactly
one timeline with the matching machine and run. Each profile records it under
`startTimeline`, including `stagesMilliseconds`, `totalMilliseconds` and the
original marker line/source. All duration fields use host monotonic `Instant`.
Runtime discovery includes component/backend selection and the capability exec;
catalog opening includes startup recovery. Those two costs are measured once
when opening the runtime and attributed to the start using it, not guest boot.
The remaining stages measure this lifecycle attempt: admission (including locks
and reconciliation), lower validation/authentication and root preparation,
secrets/root resize/private netd, launch artifact publication, the durability
barrier, and storage admission plus command preparation/exec. `total_ms` sums
runtime opening and this start attempt; it is not CLI dispatch-to-spawn (CLI
setup, lookup/inspect and any idle time between runtime opening and start are
excluded). Keep the dispatch-to-generation delta to expose that residual.
This diagnostic does not change the boot gate or its CLOCK_REALTIME endpoint.

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
passes. For example:

```sh
make perf PERF_ARGS='tests/test_fork_budget.py -k test_fork_budget_incremental_ten_percent_dirty'
make perf PERF_ARGS='tests/test_fork_budget.py -k test_fork_budget_warm_create_stopped_machine'
make perf PERF_ARGS='tests/test_fork_budget.py -k test_fork_budget_boot_layered_within_raw'
make perf PERF_ARGS="tests/test_fork_budget.py -k 'copy_allowance or reflink_probe or budget_gate'"
```
