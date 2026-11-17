# Serial performance suite

```sh
make perf
make perf PERF_COHORTS=arch-30g
make perf PERF_SYSTEMS=silo,msb PERF_COHORTS=alpine-30g
make perf PERF_COHORTS=disk-invariance PERF_SAMPLES=5 PERF_ARGS='--keep'
make perf PERF_COHORTS=arch-30g-busy,alpine-8g-busy,alpine-2g-raw
```

`make perf` enters `nix develop .#perf --command`, just as `make kernel` enters
its kernel shell. It then reuses `smoke-prereqs`, including `smoke-kernel`, staged
runtime, authenticated kernel configuration and matching-profile helpers. No
manual VM image, runtime, kernel, workspace or private Home setup is required.
The smoke harness is an editable uv path dependency, not a copied harness.
Performance is measured only on release binaries: `make perf` always stages a
fresh release build first and ignores `PROFILE` and `SMOKE_PROFILE`, and the
suite refuses to start outside that path. Never point it at an existing build
by hand. Public image acquisition needs internet and KVM/HVF must be
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

## Stream-map format accounting

The fresh-state format uses sparse Merkle roots, 64 KiB RAM identities and
8 MiB disk/pack/lower identities. Transport payloads remain 8 MiB. Existing
homes and artifacts cannot be reused. Capture evidence records actual nonzero
`identityBytesHashed` and the native change-file `recordCount`, rather than
interpreting a dense digest vector or treating SHA volume as dirty coverage.
The incremental budget retains the full bounded receipt. Ingest evidence
counts all distinct root/node objects through catalog metadata outside the
timed create; it does not decode a tree just to report its size. Targets,
agent-ready clocks and tolerance are unchanged. No new measured results are
claimed by this format change.


## Clock and sequence

Start, fork and restore are timed from command start until the command returns
with the guest agent ready. Running-state publication alone is not readiness.
The next `exec -- /bin/true` round trip is its own metric, never added to the
agent-ready measurement. Run-to-exit measures command start through `/bin/true`
exit; create and snapshots measure their full CLI command wall time.

Every driver executes the same declaration-ordered scenario in
`silo_perf/drivers.py` and `silo_perf/scenario.py`:

1. Raw cohort only: time `image_convert_raw`, including image acquisition.
2. Time `create_first`, then remove that machine outside timing. For ordinary
   Silo OCI roots this is **first create, includes image pull and preparation**
   in an empty Home. For raw roots it is first create from the converted image.
3. Time `run_true` (a **warm run**, after first create), repeated `create`,
   `start`, and first exec.
4. Populate busy sources outside timing, settle 3 seconds, first fork and exec.
   Rewrite busy sources, then second fork and exec. Time `fork_of_fork` from
   the first child.
5. Remove all fork sources and children. Create and start a separate source,
   populate it, write a correctness marker and settle 3 seconds. Forks cannot
   seed its durable snapshot baseline.
6. Time full snapshot, rewrite busy sources, then time incremental snapshot.
   Change the marker after capture. Raw cohort only: time `snapshot_verify`
   of the incremental snapshot; verification must succeed.
7. Time first restore and exec, then second restore and exec. Outside timing,
   check that both restores contain the pre-snapshot marker, then take another
   untimed fork and check that it contains the post-change marker. This extra
   fork runs after both restores, so it cannot warm their measurements.
8. Time `snapshot_of_restored`, a first live capture of the first restored
   child, whose RAM can be file-backed. Then stop and start the snapshot source,
   confirm exec readiness, repopulate busy RAM, and time `snapshot_after_restart`.
   The restart and workload are outside snapshot timing.
9. After every existing row, rewrite the identified snapshot source and fork it
   twice outside timing. Time `snapshot_source_after_two_forks`, then
   `snapshot_fork_child_first` and `snapshot_fork_child_second` on the first
   child (rewrite its busy workload before the second snapshot, outside timing).
10. Remove every retained VM and snapshot, including on failure.

`create_first`, `image_convert_raw`, `snapshot_verify`, `fork_of_fork`,
`snapshot_of_restored`, `snapshot_after_restart`, `snapshot_source_after_two_forks`,
`snapshot_fork_child_first` and `snapshot_fork_child_second` are informational,
with no timing targets. Operational and guest-visible correctness errors always fail.
The first-create command has a 300-second timeout, not the one-second repeated
create target. All workload and lifecycle commands have the same hard bound.

Metric names for both systems are `create_first`, `run_true`, `create`, `start`,
`start_exec`, `fork_first`, `fork_first_exec`, `fork_second`, `fork_second_exec`,
`fork_of_fork`, `snapshot_full`, `snapshot_incremental`, `restore_first`,
`restore_first_exec`, `restore_second`, `restore_second_exec`,
`snapshot_of_restored`, `snapshot_after_restart`, `snapshot_source_after_two_forks`,
`snapshot_fork_child_first`, and `snapshot_fork_child_second`. The raw Silo cohort adds
`image_convert_raw` and `snapshot_verify`.

Live forks do no content hashing or map/pool publication. A child has owned
complete bytes but unknown identity. Its first snapshot pays full RAM identity
inside its pause and full disk identity after resume; the second is incremental.
The source retains its identified anchor and hashes changes since its last
snapshot, including writes across both forks. The additional rows expose this
moved cost using full CLI wall time, without warming any existing row, changing
its clock, or relaxing a target. No new performance result is claimed here.

Each sample owns a fresh smoke Workspace. **No image cache is seeded or
persisted by the live scenario**: receipt creation, prepared layers and
composition construction are product work, not harness preparation.
The loopback fixture serves generated smoke images, not mirrors of these
published Alpine/Arch images. These cohorts therefore acquire their images from
Docker Hub/GHCR; history rows and the table explicitly identify the image source
as remote. First-create timings include network variability.

msb also gets private `MSB_HOME` and `HOME` below the perf cache
(`${XDG_CACHE_HOME:-~/.cache}/silo/perf`). Its real `msb pull` runs before
`create_first`; unlike Silo this first-create figure excludes image pull.
Both first and repeated create are measured rather than assuming preparation is
free. msb create boots the VM, so repeated create supplies both its `create`
and `start` metrics; there is no invented second start command or duration.
Its directly supported fork-from-child, snapshot-of-restored and stop/start
snapshot cases use the same scenario. Both durable snapshots use
`snap create --full` and restores are eager, as in bench2; CoW restore is not
part of the shared comparison.

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
| `arch-30g-busy` | Same Arch shape; 4 GiB populated RAM, scattered rewrites, 512 MiB root-disk payload and 1024 small files | Silo, informational |
| `alpine-8g-busy` | Same 8 GiB Alpine shape; 2 GiB populated RAM, scattered rewrites, 256 MiB root-disk payload and 512 small files | Silo, msb, informational |
| `alpine-2g-raw` | Alpine 2 vCPU / 2 GiB, converted whole-disk raw root; incremental snapshot verification required | Silo, informational |

The ordinary freshly created, otherwise-idle cohorts are **best-case** numbers,
not evidence for dirty or fully populated guests. Busy cohorts exercise populated
RAM, scattered dirty coverage and real disk writes. The raw cohort is a
correctness regression lane, not a performance target: it times
`silo image convert REF --disk-format raw --format json`, then creates and runs
from the returned `image:ID`, and verifies the incremental snapshot.
Informational cohort rows are labelled explicitly and never fail on timing,
even if a target is accidentally configured for them.

Not measured: fully populated RAM, large Homes with many retained snapshots, or
an actual non-reflink ext4 host. Busy guests finish their bounded workloads before
each timed operation; they are not continuously running application-load tests.
The raw-root cohort does not qualify attached extra raw disks.

Disk invariance compares medians of both fork, both snapshot and both restore
metrics. Equality means absolute difference at most the larger of 0.05 seconds
or 10% of the smaller median. The table prints this rule explicitly.
One measured residual is accepted as cohort data: `snapshot_full` may differ by
up to 0.15 seconds, because a fresh ext4 disk keeps a few backup superblock
chunks that grow slowly with its size.
Those values and written payload size are cohort data.
The invariant fails the run when exceeded; no disk-copy allowance is subtracted.
The payload is written and synced outside timing on each fresh source.

`targets.toml` is the sole Phase 30 gate configuration, keyed by
system/cohort/mode/metric. The approved Arch image-init targets are start and
create 1 s, first restore 0.75 s, repeated restore 0.5 s, first fork 2 s, second fork 1.25 s,
full snapshot 3 s, incremental snapshot 1.5 s, run-to-exit 2 s and every
first-exec round trip 0.1 s. `exec` is the shared target for the separately
reported `*_exec` metrics.

A median at or below its target reports PASS; above target through
`target * (1 + tolerance)`, inclusive, it reports `PASS (within 10%)` with the
default tolerance, so a repeated restore at 0.504 s against 0.5 s is accepted.
Above that bound it reports FAIL, or NOT YET when `expected_fail = true`, and
only FAIL fails the target gate.
Change the top-level `tolerance = 0.10` in `targets.toml` to adjust the default,
or add `tolerance` to an individual target table to override it; values must be
finite and in `[0, 1)`, and the accepted verdict displays the configured percent.

First/second fork and incremental snapshot remain marked `expected_fail = true`
with slice `30a` until disk tracking and format work qualify them. A target met
within tolerance passes even while marked, so its marker can be removed.
Each qualified fix removes its expected-failure marker; never increase a target
to hide a regression. Add another keyed target entry to extend the gate matrix.
msb comparisons are informational, not gates.

## Busy workload commands

Parameters, including fixed seeds, live in `cohorts.toml`. All guest work uses
`/bin/sh`, `mkdir`, `mount` (Silo), `dd`, `wc`, `printf`, `test` and `sync`,
with BusyBox-compatible arguments. Random bytes are generated by the host's
existing Python stdlib `random.Random(seed).randbytes`, in bounded 1 MiB chunks,
into a temporary file below the cohort workspace. Silo uploads with
`silo cp --owner 0:0 --mode 600 HOST_FILE NAME:/absolute/path`; msb uses
`msb copy HOST_FILE NAME:/absolute/path`. Both use their streaming file RPC,
not exec stdin, and receive byte-identical seeded payloads. No guest Python,
compiler, OpenSSL, installation, `/dev/urandom`, repeated seed block or zero-fill
shortcut is used. Unique pseudo-random bytes avoid flattering compression or
deduplication. Generation has a 300-second checked deadline; each copy/exec
command has a 300-second timeout and is killed/reaped on timeout or cancellation.
Failed commands include their exit code and stderr tail in the raised error.
Host staging files are removed on success or failure; transient guest input
files are removed after each step, also when copy or execution fails.

Reading the cached pinned Arch OCI layers confirmed `/usr/bin/{dd,wc,mount,
sync,head,openssl}` and `/usr/bin/sh -> bash`. OpenSSL exists, but the shared
host-seeded input keeps the bytes and guest commands comparable with BusyBox
Alpine. Static inspection of the cached Alpine layer confirms BusyBox links for
`sh`, `dd`, `mkdir`, `mount`, `sync`, `head` and `wc`; its BusyBox binary contains
the `fullblock` option. A live run exposed a product exec-stdin queue limit;
large payloads therefore use file copy, never a series of small exec calls.
Silo's copy help and upload implementation support absolute guest destinations,
numeric root ownership and streamed regular files, including tmpfs paths.
The inspected msb copy implementation likewise reads bounded chunks and awaits
each file-RPC write. msb is not on this session's PATH, so its installed-release
copy help and live multi-GiB transfer remain unconfirmed.

For Silo, initial setup is exactly
`silo exec NAME --user root -- /bin/sh -ec 'mkdir -p /fill; mount -t tmpfs -o size=4864m tmpfs /fill'`
for Arch, or `size=2560m` for Alpine. msb mirrors the bench2 tmpfs procedure by
adding `--tmpfs /fill:2560M` to its Alpine run/create commands, then executes
`msb exec NAME --user root -- /bin/sh -ec 'test -d /fill'`.

The initial RAM payload is copied **directly to `/fill/ram`**, then checked with
`test "$(wc -c < /fill/ram)" -eq BYTES` (4294967296 for Arch, 2147483648 for
Alpine). It is retained as the populated region, not copied again inside tmpfs.
Each rewrite or disk payload is instead copied to
`/fill/.perf-workload-input`. The tmpfs budget includes the populated region,
the larger of one disk/rewrite payload, and 256 MiB headroom. Staging therefore
does not require a second complete RAM region or fill the root disk.

Every subsequent guest script is passed as
`silo exec NAME --user root -- /bin/sh -ec SCRIPT` or
`msb exec NAME --user root -- /bin/sh -ec SCRIPT`, with stdin closed.
The scripts are constructed by `silo_perf.workload.writes`:

* Rewrite: after checking the staged input size, run `read_offset=0;
  for offset in OFFSETS; do dd if=/fill/.perf-workload-input of=/fill/ram
  bs=4096 skip="$read_offset" seek="$offset" count=64 iflag=fullblock
  conv=notrunc; read_offset=$((read_offset + 64)); done`.
  Distinct 256 KiB runs start at scattered 4 KiB-aligned offsets.
  Sampling 1638 of 16384 runs (Arch) or 819 of
  8192 (Alpine) rewrites approximately 10% of the region without 100,000
  individual `dd` processes.
* Disk: `mkdir -p /perf-workload; i=0; while [ "$i" -lt 8 ]; do
  dd if=/fill/.perf-workload-input of=/perf-workload/data-$i bs=1M
  skip="$((i * N))" count=N iflag=fullblock;
  test "$(wc -c < /perf-workload/data-$i)" -eq FILE_BYTES;
  i=$((i + 1)); done; i=0; while [ "$i" -lt SMALL_FILES ]; do
  printf '%s\n' 'SEED:GENERATION' "$i" > /perf-workload/small-$i;
  i=$((i + 1)); done; sync`.
  `N=64`, `FILE_BYTES=67108864`, `SMALL_FILES=1024` for Arch;
  `N=32`, `FILE_BYTES=33554432`, `SMALL_FILES=512` for Alpine.
  The script first checks the complete staged input size. After either step,
  run `rm -f /fill/.perf-workload-input`; this also runs on failure. All
  generation, copy, rewriting and cleanup happen outside measured intervals.

Generation starts at 0 independently for fork and snapshot sources. Each
initial workload fills RAM, rewrites scattered runs, and writes/syncs disk;
generation 1 between captures rewrites RAM and every disk payload with fresh
seeded data. Restart repopulation uses generation 2. Fill, rewrite and disk
payload seeds are respectively `base + 3*generation + {0,1,2}`. Offset sampling
uses `random.Random(base + generation).sample(range(RUNS), floor(RUNS*0.10))`;
indices are multiplied by 64 to obtain page offsets. Base seeds are 3001
(Arch) and 3002 (Alpine).

Print the exact expanded commands, including every offset and input seed/size,
without starting any VM:

```sh
uv run --project perf python - <<'PY'
import shlex
from pathlib import Path
from silo_perf.drivers import copy_command
from silo_perf.model import load_cohorts
from silo_perf.workload import INPUT, writes
for name, cohort in load_cohorts().items():
    if cohort.workload is None:
        continue
    for generation in range(3):
        for step in writes(cohort.workload, generation, initialize=generation != 1):
            print(name, f"generation={generation} seed={step.seed} bytes={step.size}")
            for system in ("silo", "msb"):
                if system == "msb" and cohort.msb_image is None:
                    continue
                print(shlex.join(copy_command(system, Path("/WORKSPACE/payload"), "NAME", step.destination)))
                print(shlex.join([system, "exec", "NAME", "--user", "root", "--", "/bin/sh", "-ec", step.script]))
                if step.destination == INPUT:
                    print(shlex.join([system, "exec", "NAME", "--user", "root", "--", "/bin/sh", "-ec", f"rm -f {INPUT}"]))
PY
```

All cohorts also write `/perf-snapshot-marker` with `before-snapshot` and sync
before capture, then replace it with `after-snapshot` and sync afterward.
Untimed guest `test "$(cat /perf-snapshot-marker)" = VALUE` checks enforce the
snapshot/restore and post-change fork semantics.

The original fixed 4 GiB fixture, 1 GiB random upper, cold/warm arithmetic tests
and OCI 1/4/12 GiB ingest cohorts live in `tests/test_fork_budget.py` and
`tests/test_ingest_budget.py`. They have no smoke slow/serial lane markers and
remain explicitly runnable alongside the new default scenario. See
[retained budget contracts](budgets.md) for their distinct historical clocks,
cache conditioning, evidence and free-space requirements (55 GiB for ingest).
The optional ingest lane resolves Nix's `registry` from PATH and skips with the
perf-shell command when absent, never downloading a tool itself.

```sh
make perf PERF_ARGS='tests/test_fork_budget.py'
make perf PERF_ARGS='tests/test_ingest_budget.py'
```

Explicit test paths in `PERF_ARGS` replace default scenario collection.

## History and trends

Every completed system/cohort/mode/metric appends one JSON line containing the
samples, median/min/max, verdict and effective tolerance (both null for ungated
metrics), an informational flag, local/remote image source, commit, Silo/msb
versions, timestamp, run ID and host fingerprint (CPU model, physical RAM,
workspace filesystem/options, kernel and architecture).
The default file is
`${XDG_DATA_HOME:-~/.local/share}/silo/perf/history.jsonl`; override `PERF_HISTORY`.
It is append-only with an exclusive file lock. Invalid or truncated records are
reported with their line number rather than silently discarded.
The verdict and tolerance fields are required; use a fresh `PERF_HISTORY` path
for records predating this format rather than mixing schemas.

The final plain-text table shows each Silo mode, its target verdict, msb median,
Silo/msb ratios and percent changes from the previous entry with the same host
and exact system/cohort/mode/metric key. Negative delta is faster. Missing or
zero previous medians have no relative delta.
The trend report includes each recorded verdict using its original tolerance,
independent of subsequent target configuration changes.

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
