# Serial performance suite

```sh
make perf
make perf PROFILE=release PERF_COHORTS=arch-30g
make perf PROFILE=release PERF_SYSTEMS=silo,msb PERF_COHORTS=alpine-30g
make perf PERF_COHORTS=disk-invariance PERF_SAMPLES=5 PERF_ARGS='--keep'
```

`make perf` enters `nix develop .#perf --command`, just as `make kernel` enters
its kernel shell. It then reuses `smoke-prereqs`, including `smoke-kernel`, staged
runtime, authenticated kernel configuration and matching-profile helpers. No
manual VM image, runtime, kernel, workspace or private Home setup is required.
The smoke harness is an editable uv path dependency, not a copied harness.
`PROFILE` has the same default as the rest of the repository (debug); use release
for qualification. Public image acquisition needs internet and KVM/HVF must be
available to the ordinary user. Keep the host idle and use durable disk storage.

All tools are supplied by `nix/perfShell.nix`, including uv, Python 3.12, build
prerequisites, filesystem utilities, Distribution 3.1.2 and microsandbox 0.7.15.
The msb x86_64 Linux release and both Linux Distribution releases are pinned by
SHA-256. Nix patches msb's ELF dependencies and wraps it with its bundled
`libkrunfw.so.5.6.1`, `MSB_PATH` and `MSB_LIBKRUNFW_PATH`. No system-wide install,
Python downloader or implicit msb installer exists. Distribution retains its
release bytes so the shared harness verifies its executable against the existing
pin. Other platforms omit unavailable release tools. A missing msb executable
skips that system with `enter the perf shell: nix develop .#perf`.
`PERF_MSB_BIN` can select another explicit executable, otherwise PATH is used.

`PERF_COHORTS` is a comma-separated selection (empty means all),
`PERF_SYSTEMS` defaults to `silo` and accepts `silo,msb`, `PERF_SAMPLES` defaults
to 3, and `PERF_ARGS` supplies pytest arguments. The Make recipe forces `-n 0`
after those arguments. The benchmark also rejects xdist workers. `PERF_SHELL=`
is available when already inside the required shell. No host-global cache drop
or privileged operation is performed.

## Clock and sequence

Start, fork and restore are timed from command start until the command returns
with the guest agent ready. Running-state publication alone is not readiness.
The next `exec -- /bin/true` round trip is its own metric, never added to the
agent-ready measurement. Run-to-exit measures command start through `/bin/true`
exit; create and snapshots measure their full CLI command wall time.

Every driver executes the same declaration-ordered scenario in
`silo_perf/drivers.py` and `silo_perf/scenario.py`:

1. Run to exit, create, start, first exec.
2. Settle 3 seconds, first fork, exec in child, second fork, exec in child.
3. Remove the fork source and children. Prepare a separate fresh source and
   settle 3 seconds, so forks cannot seed the durable snapshot baseline.
4. Full snapshot, incremental snapshot, first restore, exec, second restore, exec.
5. Remove every retained VM, image alias and snapshot, including on failure.

Image acquisition and preparation occur before the timed scenario. Each sample
owns a private smoke Workspace. msb also gets private `MSB_HOME` and `HOME` below
the perf cache (`${XDG_CACHE_HOME:-~/.cache}/silo/perf`). Its commands match the
bench2 exact idle procedure, including `snap create --full` for both snapshots
and eager restores. msb create boots the VM, so its one measured create command
supplies both its `create` and `start` metrics; there is no invented second start
command or duration. CoW restores from the evidence's supplemental comparison
are not part of this shared eager-restore scenario.

Silo never parses default CLI JSON. It knows all requested VM/alias names.
`snapshot_id` reads `image_alias.snapshot_id` through the existing read-only
`catalog_observer`; cleanup removes `image:NAME` with `image remove`, then the
resolved `image:ID` with `snapshot remove`. The lookup is isolated in one function
for a future explicit-format inspect API. Failed workspaces retain diagnostics,
but cleanup still removes benchmark VMs and snapshots. `--keep` keeps successful
workspace evidence, not running VMs or snapshot retention roots.

## Cohorts and targets

Cohorts are data in `cohorts.toml`. All Silo cohorts run in image-init (default)
and agent-as-PID-1 (`--kernel-arg init=`) modes.

| Cohort | Guest and shape | Systems |
| --- | --- | --- |
| `alpine-2g` | Alpine, 2 vCPU, 2 GiB RAM, default disk | Silo, msb |
| `alpine-8g` | Alpine, 2 vCPU, 8 GiB RAM, default disk | Silo, msb |
| `alpine-30g` | Alpine, 2 vCPU, 30 GiB RAM, default disk | Silo, msb |
| `arch-30g` | `ghcr.io/vandycknick/archlinux:20260831.150324`, 10 vCPU, 30 GiB RAM, `--disk-size 100gb` | Silo |
| `disk-invariance` | Same Alpine, 2 vCPU, 2 GiB RAM, 30 and 500 GiB disks, identical deterministic 64 MiB payload | Silo |

Disk invariance compares medians of both fork, both snapshot and both restore
metrics. Equality means absolute difference at most the larger of 0.10 seconds
or 30% of the smaller median, explicitly accounting for the observed idle-host
noise in the evidence. Those values and written payload size are cohort data.
The invariant fails the run when exceeded; no disk-copy allowance is subtracted.
The payload is written and synced outside timing on each fresh source.

`targets.toml` is the sole Phase 30 gate configuration, keyed by
system/cohort/mode/metric. The approved Arch image-init targets are start 1 s,
first/repeated restore 0.5 s, first fork 2 s, second fork 1 s, incremental
snapshot 2 s and every first-exec round trip 0.1 s. A median equal to its target
passes. `exec` is the shared target for the separately reported `*_exec` metrics.

An exceeded target normally reports FAIL and fails the run. All currently unmet
Arch targets carry `expected_fail = true` plus their Phase 30 slice references,
and instead report NOT YET (XFAIL-style, nonfatal). A met target reports PASS,
even while marked. Each qualified fix removes its expected-failure marker;
never increase a target to hide a regression. Add another keyed target entry to
extend the gate matrix. msb comparisons are informational, not gates.

The original fixed 4 GiB fixture, 1 GiB random upper, cold/warm arithmetic tests
and OCI 1/4/12 GiB ingest cohorts live in `tests/test_fork_budget.py` and
`tests/test_ingest_budget.py`. They have no smoke slow/serial lane markers and
remain explicitly runnable alongside the new default scenario. See
[retained budget contracts](budgets.md) for their distinct historical clocks,
cache conditioning, evidence and free-space requirements (55 GiB for ingest).
The optional ingest lane resolves Nix's `registry` from PATH and skips with the
perf-shell command when absent, never downloading a tool itself.

```sh
make perf PROFILE=release PERF_ARGS='tests/test_fork_budget.py'
make perf PROFILE=release PERF_ARGS='tests/test_ingest_budget.py'
```

Explicit test paths in `PERF_ARGS` replace default scenario collection.

## History and trends

Every completed system/cohort/mode/metric appends one JSON line containing the
samples, median/min/max, commit, Silo/msb versions, timestamp, run ID and host
fingerprint (CPU model, physical RAM, workspace filesystem/options, kernel and
architecture). The default file is
`${XDG_DATA_HOME:-~/.local/share}/silo/perf/history.jsonl`; override `PERF_HISTORY`.
It is append-only with an exclusive file lock. Invalid or truncated records are
reported with their line number rather than silently discarded.

The final plain-text table shows each Silo mode, its target verdict, msb median,
Silo/msb ratios and percent changes from the previous entry with the same host
and exact system/cohort/mode/metric key. Negative delta is faster. Missing or
zero previous medians have no relative delta.

```sh
nix develop .#perf --command uv run --project perf python -m silo_perf.report
nix develop .#perf --command uv run --project perf python -m silo_perf.report --history /path/history.jsonl
nix develop .#perf --command uv run --project perf pytest perf/tests/test_reporting.py -n 0
```

## Adding a competitor

Implement `Driver` in a new class and add it to `REGISTRY` in
`silo_perf/drivers.py`. Implement command construction, availability, cohort
support, modes, untimed preparation and complete cleanup; return the measured
metric values for each shared action. Unsupported lifecycle steps may be folded
into a real command as msb does for create/start, never synthesized from guesses.
The scenario, cohort selection, history and table do not need a second procedure.
Add the competitor's pinned Nix derivation and one entry to `competitors` in
`nix/perfShell.nix`; do not add an installer to Python or Make.
