# macOS Docker build performance

## September 2026 investigation

A reported amd64 Python/uv build took 27.4 seconds on OrbStack and 63.1 seconds
on Silo. Slow stages included native layer extraction and export, not just the
Rosetta-translated `RUN` commands. The build context was only 264 KiB and its
transfer took at most 0.1 seconds; host directory sharing was not the obvious
bottleneck in this workload.

| Stage | OrbStack | Silo |
| --- | ---: | ---: |
| First `uv sync` | 6.7 s | 20.6 s |
| Second `uv sync` | 3.0 s | 5.5 s |
| Copy virtualenv between stages | 0.4 s | 4.3 s |
| Export layers | 7.7 s | 23.1 s |

BuildKit overlaps stages, so these timings are not independently additive.
Both builds targeted amd64; Docker itself ran natively on arm64 in both VMs.

## Confirmed scheduling defect

Silo's launchd definition specified `ProcessType=Background`. The running
service reported `spawn type = background (5)`, and its VM's vCPU and block
worker threads inherited priority 4. This is a scheduling restriction, not
merely permission to keep a service running without an open terminal.

Apple documents `Background` as work not directly requested by the user, with
resource restrictions to avoid disrupting the user experience. `Standard` is
the normal/default service classification. `Interactive` has a different,
stronger purpose; it is not needed for this fix.

References:

- [Apple launchd.plist reference](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)
- The installed `launchd.plist(5)` manual, `ProcessType` section.

### Live native-CPU comparison

Ran the same arm64 Alpine 3.23 BusyBox gzip workload inside both engines, with
CPU affinity restricted to guest CPUs 0–3, a 512 MiB container memory limit,
and 64 MiB of incompressible input on tmpfs. No package downloads or persistent
disk I/O occurred inside the timed compression operations. Two repetitions:

| Workload | OrbStack | Silo with Background policy |
| --- | ---: | ---: |
| One gzip process | 1.04 s | 4.19–4.39 s |
| Four concurrent gzip processes, elapsed | 1.10 s | 4.26–4.86 s |

This establishes a substantial native-CPU deficit, independent of Rosetta,
package fetching, and Docker layer export.

### Controlled launchd A/B/A/B

Launched the same signed Silo release helper and Linux initramfs four times,
alternating `Background`, `Standard`, `Background`, `Standard`. Every temporary
VM had four vCPUs and 512 MiB RAM. The guest ran the same native compression
workload, then powered off. Reclaim was disabled in these disposable VMs to
exclude memory maintenance as a variable. The existing system VM was untouched.
Each temporary launchd job was unloaded after the run.

| Policy | One gzip process | Four concurrent gzip processes, elapsed |
| --- | ---: | ---: |
| Background | 3.37–4.26 s | 3.55–4.48 s |
| Standard | 1.04–1.09 s | 1.11–1.30 s |

All four guests reached the completion marker and exited successfully. Normal
scheduling removed the native-CPU deficit in this test without changing the
hypervisor, guest kernel, Rosetta, filesystem, or vCPU count. Host physical-core
placement was not measured, so the result should not be described as proof of
specific P-core/E-core placement.

The service definition now uses `Standard`. Existing installations need a daemon
stop/start so Silo can regenerate and reload their launchd definition. Replacing
the executable alone cannot change an existing process's inherited policy.
This does not change guest reclaim's intentionally low scheduling priority.

## Other differences, not yet changed

### CPU allocation

OrbStack exposed ten vCPUs and approximately 12 GiB RAM; Silo exposed four vCPUs
and 8 GiB. This may affect highly parallel builds. The matched four-CPU tests
above show that CPU count alone did not explain the observed deficit. Keep the
current allocation for the first post-fix build comparison to isolate scheduling.

### Filesystem cloning

Both engines reported `overlayfs` with `io.containerd.snapshotter.v1`, but their
underlying filesystems differed:

- OrbStack: Btrfs, mounted with `noatime,nodatasum,nodatacow` among other options.
- Silo: ext4 on its raw virtio-block data disk, mounted with `relatime`.

An isolated container probe created a 64 MiB source file and attempted Linux
`FICLONE` and `copy_file_range` into new files. OrbStack supported cloning;
Silo returned `ENOTSUP` for `FICLONE` and performed a data copy instead.

| Operation | OrbStack | Silo |
| --- | ---: | ---: |
| `FICLONE` | success, approximately 6–229 microseconds | unsupported |
| `copy_file_range`, 64 MiB | approximately 5–107 microseconds | 47–71 milliseconds |

These were buffered operations without a timed destination fsync, not durable
SSD throughput measurements. The probe used the existing amd64 Python images
on both engines, so its timings are not a native-CPU comparison. The clone
capability difference is unambiguous, but the actual BuildKit copy syscall path
has not been traced. This is a plausible contributor to cross-stage `COPY`
performance, not proof of the entire 4.3-second stage's cause.

Changing a populated data disk's filesystem is a separate migration/design
question. Do not reformat it or weaken fsync semantics to improve a benchmark.
Docker versions also differed: OrbStack 29.4.0, Silo 29.8.0.

## Next validation

After reloading the corrected service, repeat the original build on both
engines with `--no-cache --progress=plain`. This forces execution of build steps
but does **not** empty uv cache mounts or image stores; interpret it as a
warm-dependency comparison, not a reproduction of the original cold build.
Do not prune existing caches to manufacture a cold result without permission.
A complete post-fix build timing has not yet been measured.

Investigation scripts, per-run logs, and launchd/thread snapshots are retained
locally under `/tmp/silo-build-investigation/`. The initial investigation did not
restart existing VMs, prune caches, or change CPU allocation or filesystems.

## Live activation and requested resource resize

After the initial investigation, the user requested ten vCPUs and 12 GiB for
Silo, with no filesystem change. Updated the user's daemon configuration and
restarted Silo after checking for active workloads. No containers or builds were
running; the active guest shell was monitoring with `htop` and was disconnected.
The existing Docker context was preserved.

The replacement VM reported ten vCPUs and 12288 MiB configured RAM. Its launchd
job reported `spawn type = daemon (3)` rather than `background (5)`. Host reclaim
qualified successfully. Repeating the native compression benchmark in the live
VM, still restricted to four guest CPUs, produced:

- Single process: 1.05 seconds in both repetitions.
- Four concurrent processes: 1.12–1.13 seconds elapsed.

These match the earlier OrbStack CPU results. Both scheduling and total VM
allocation changed at activation, so the earlier isolated A/B/A/B remains the
causal control. Full application build performance still needs a fresh comparison.

The observed OrbStack instance uses a RunningBoard-managed app launchd job with
`spawn type = app (1)`, and ships a bundled `LaunchAtLoginHelper.app`. Its
`app.start_at_login` setting was false at inspection time. This is distinct from
Silo's explicit LaunchAgent with `RunAtLoad` and restart-on-failure supervision;
normal scheduling does not remove those lifecycle guarantees.
