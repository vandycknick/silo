"""Reproducible cold/warm budget cohorts for ADR 0021 and ADR 0014.

Fixture (exact, never shrunk): the `restore-execution` image (BASIC Alpine plus
the static `restore_execution.c` witness), 2 vCPUs, 4096 MiB configured RAM,
`--network private`, default layered root with a 2 GiB logical upper. Inside the
guest, exactly 1024 x 1 MiB of `/dev/urandom` bytes are written to
`/fork-budget.payload` with `conv=fsync` before any timed operation, so the
upper carries 1 GiB of guest-created, nonzero, non-sparse data. The host records
the upper's logical, allocated and nonzero bytes separately; a 1 GiB-capacity
upper could not hold that payload plus ext4 metadata, hence the 2 GiB capacity.

Cohorts: five `cold` samples, one discarded `warm-up`, five `warm` samples,
strictly sequential. Before each cold dispatch every owned input file (this
workspace's Silo home, the selected runtime directory and CLI) is fsynced and
`POSIX_FADV_DONTNEED`-evicted per file, with mincore(2) evidence; no global
drop_caches and no sudo. Pages still mapped by live processes (the running
source) cannot be evicted, so such samples are labelled `partial-cold`. A fork
writes its fresh capture RAM during the timed window; that warming is part of
the measured operation and is never re-evicted.

Measured boundaries (all reported; the gated value is named):
- fork4 (gated): CLI dispatch (harness CLOCK_MONOTONIC just before spawn) to
  the last child's durable `running` stamp. API entry to Running, seal to
  Running and caller end-to-end (dispatch to exit) are recorded separately.
- capture interruption (gated): the larger of the source monitor's
  conservative staging-written..continuation-finished interval and the
  host-observed gap in the guest witness's durable writes.
- restore: `silo restore` dispatch to its exit with the child already Running
  and ready (or the first later Running+ready observation). Cold restore is
  recorded on every lane but gated only when the workspace supports reflinks.
- layered boot: CLI dispatch (harness CLOCK_REALTIME time.time_ns) to the
  monitor trace's first validated guest status receipt (`guest agent became
  responsive`), proving serving on the switched root. Full product readiness
  is a later diagnostic phase. The gate is median layered / median raw <= 1.2.

A real FICLONE probe of sibling files in the budget workspace selects the lane
at fixture setup, independently of the capture request's disk copy contract.
Without reflinks, the gated value subtracts the upper's allocated bytes at the
host's measured sequential copy rate: one upper for capture, one sealed upper
for restore, one sealed upper per child for fork4. Reflink lanes subtract zero.
Samples and summaries retain raw and gated values, allowance inputs and actual
disk-seal durations; targets do not change.

A running source keeps its accepted capture baseline, and a local cut retires
only after that exact source run ends. Each successful fork sample therefore
stops and removes its children, stops the source and prunes; the next sample
restarts the same source (populated 1 GiB upper preserved) with a fresh witness
and a fresh host observer outside the timed window. At most one sample's cut
exists at a time. Restore samples stop and remove their child before the next.
Failed samples remain in the retained workspace for diagnosis.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from uuid import UUID

from . import overlay, page_cache, restore_lifecycle
from .cli import Silo

RAM = "4096mib"
UPPER = "2gib"
PAYLOAD = "/fork-budget.payload"
PAYLOAD_MIB = 1024
SAMPLES = 5
CHILDREN = 4
GIB = 1024 ** 3
TARGETS = {"fork4": 10.0, "captureInterruption": 5.0, "restore": 2.0,
           "incremental": 1.0, "warmCreate": 2.0, "bootLayeredRatio": 1.2}
EVIDENCE_VARIABLE = "SILO_SMOKE_BUDGET_EVIDENCE"
SCHEDULE = tuple([("cold", index) for index in range(SAMPLES)] + [("warm-up", 0)]
                 + [("warm", index) for index in range(SAMPLES)])


@dataclass(frozen=True)
class Metric:
    record: str
    raw_key: str
    copy_allowance: bool = False
    denominator: str | None = None
    unit: str = "s"


METRICS = {
    "fork4": Metric("fork4", "dispatchToRunningSeconds", copy_allowance=True),
    "captureInterruption": Metric("capture", "interruptionSeconds", copy_allowance=True),
    "restore": Metric("restore", "dispatchToRunningSeconds", copy_allowance=True),
    "incremental": Metric("incremental", "interruptionSeconds", copy_allowance=True),
    "warmCreate": Metric("warmCreate", "dispatchToExitSeconds"),
    "bootLayered": Metric("bootLayered", "dispatchToReadySeconds"),
    "bootRaw": Metric("bootRaw", "dispatchToReadySeconds"),
    "bootLayeredRatio": Metric("bootLayered", "dispatchToReadySeconds",
                               denominator="bootRaw", unit="ratio"),
}


# These are host monitor observations, not guest kernel mount timestamps.
BOOT_PHASES = (
    ("monitorGenerationStart", "silo-vmm generation started", {}),
    ("monitorStarting", "silo-vmm starting", {}),
    ("primaryVmSpawn", "starting primary VM after probe release", {}),
    ("workerSpawn", "krun worker spawned", {}),
    ("vmRunning", "vm state changed", {"current": "Running"}),
    ("agentResponsive", "guest agent became responsive", {}),
    ("agentReportedReady", "guest agent status changed", {"current": "Some(Ready)"}),
    ("agentReady", "silo-vmm readiness changed",
     {"ready": "true", "reason": "GuestReportedReady"}),
)


def boot_timing(text: str, *, trace: Path, machine_id: str, run_id: str,
                dispatched_ns: int, exited_ns: int) -> dict:
    """Start dispatch to the first product agent-serving event in this generation.

    Both endpoints use host CLOCK_REALTIME: time.time_ns immediately before
    spawning the CLI and the monitor's UTC trace timestamp. No polling or
    guest clock participates. The host wall clock must remain stable.
    """
    # CLI/catalog IDs are compact hex; the monitor logs UUIDs with hyphens.
    machine_id = str(UUID(machine_id))
    found = restore_lifecycle.events(text, names=tuple({name for _, name, _ in BOOT_PHASES}))
    generations = [index for index, event in enumerate(found)
                   if event.name == "silo-vmm generation started"]
    starts = [index for index in generations
              if found[index].fields.get("machine_id") == machine_id
              and found[index].fields.get("run_id") == run_id]
    assert len(starts) == 1, ("expected one matching boot generation", machine_id, run_id, starts)
    start = starts[0]
    end = next((index for index in generations if index > start), len(found))
    generation = found[start:end]
    phases: dict[str, restore_lifecycle.Event] = {}
    for phase, name, fields in BOOT_PHASES:
        matches = [event for event in generation if event.name == name
                   and all(event.fields.get(key) == value for key, value in fields.items())
                   and event.fields.get("machine_id", machine_id) == machine_id]
        if matches:
            phases[phase] = matches[0]
    assert "agentResponsive" in phases, ("monitor never logged guest serving", trace, run_id)
    ready = phases["agentResponsive"]
    assert ready.fields.get("machine_id") == machine_id, ready.line
    assert dispatched_ns <= generation[0].realtime_ns <= ready.realtime_ns, (
        "boot trace precedes dispatch or host CLOCK_REALTIME moved backwards", trace)
    ordered = sorted(phases.items(), key=lambda item: item[1].realtime_ns)
    previous_name, previous_ns = "dispatch", dispatched_ns
    deltas = []
    for phase, event in ordered:
        deltas.append({
            "phase": phase, "realtimeNs": event.realtime_ns,
            "dispatchToPhaseSeconds": (event.realtime_ns - dispatched_ns) / 1e9,
            "previousPhase": previous_name,
            "previousPhaseToPhaseSeconds": (event.realtime_ns - previous_ns) / 1e9,
            "line": event.line,
        })
        previous_name, previous_ns = phase, event.realtime_ns
    available = [phase for phase, _ in ordered]
    return {
        "dispatchToReadySeconds": (ready.realtime_ns - dispatched_ns) / 1e9,
        "callerEndToEndSeconds": (exited_ns - dispatched_ns) / 1e9,
        "dispatchRealtimeNs": dispatched_ns,
        "marker": {
            "source": str(trace),
            "linePattern": "guest agent became responsive ... machine_id=<id>",
            "line": ready.line, "realtimeNs": ready.realtime_ns,
            "clock": "host CLOCK_REALTIME: harness time.time_ns and monitor UTC trace timestamp",
        },
        "availablePhases": available,
        "unavailablePhases": [phase for phase, _, _ in BOOT_PHASES if phase not in available]
                             + ["kernelStart", "initramfs", "rootSwitch"],
        "phases": deltas,
    }


def evidence_directory(label: str) -> Path:
    """Durable text evidence outside the (deleted-on-success) workspace."""
    value = os.environ.get(EVIDENCE_VARIABLE)
    assert value, f"set {EVIDENCE_VARIABLE} to a durable directory for budget evidence"
    parent = Path(value).expanduser().resolve()
    assert parent.is_dir(), parent
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = parent / f"{label}-{stamp}"
    directory.mkdir(mode=0o700)
    return directory


def _digest(path: Path) -> str:
    return "sha256:" + overlay.digest(path)


def _findmnt(path: Path) -> dict:
    result = subprocess.run(["findmnt", "--json", "--target", str(path), "--output",
                             "TARGET,SOURCE,FSTYPE,OPTIONS"], capture_output=True, text=True,
                            timeout=15, check=True)
    mounts = json.loads(result.stdout)["filesystems"]
    assert len(mounts) == 1, mounts
    return mounts[0]


def reflink_probe(directory: Path) -> dict:
    """Probe the budget filesystem, cleaning up both sibling files on every exit."""
    error_number = None
    with tempfile.NamedTemporaryFile(dir=directory, prefix="budget-reflink-source-") as source, \
            tempfile.NamedTemporaryFile(dir=directory, prefix="budget-reflink-destination-") as destination:
        source.write(b"\xa5" * 4096)
        source.flush()
        try:
            fcntl.ioctl(destination.fileno(), 0x40049409, source.fileno())  # FICLONE
        except OSError as error:
            if error.errno not in {errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL}:
                raise
            error_number = error.errno
    return {"method": "FICLONE", "directory": str(directory),
            "reflink": error_number is None, "errno": error_number}


def reference_host(silo: Silo) -> dict:
    """Reference-host record (ADR 0014 acceptance budgets): hardware, filesystem, inputs."""
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    memory = next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemTotal:"))
    filesystem = _findmnt(silo.ws.silo_home)
    assert filesystem["fstype"] not in {"tmpfs", "ramfs"}, (
        "budget cohorts need durable storage; point TMPDIR at a short durable path", filesystem)
    runtime = silo.ws.config.runtime_dir
    inputs = {"silo": silo.ws.config.silo, "silo-vmm": runtime / "bin/silo-vmm",
              "kernel": runtime / "assets/kernel-default", "initramfs": runtime / "assets/initramfs",
              "agent": runtime / "assets/agent"}
    manifest = silo.ws.config.bin_dir.parent / "candidate-manifest.json"
    candidate = None
    if manifest.is_file():
        value = json.loads(manifest.read_text())
        candidate = {"path": str(manifest), "sha256": _digest(manifest), "scope": value.get("scope"),
                     "candidateMonitorSha256": value.get("candidateMonitorSha256")}
    # Same convention as the other smoke gates: the staged kernel's emitted .config.
    configured = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
    kernel_config = None
    if configured:
        path = Path(configured).resolve(strict=True)
        kernel_config = {"path": str(path), "sha256": _digest(path)}
    return {
        "cpu": cpu, "logicalCpus": os.cpu_count(), "memTotalKiB": int(memory),
        "kernel": platform.release(), "machine": platform.machine(),
        "workspace": str(silo.ws.root), "filesystem": filesystem,
        "reflinkProbe": reflink_probe(silo.ws.root),
        "inputs": {name: {"path": str(path), "sha256": _digest(path)} for name, path in inputs.items()},
        "guestKernelConfig": kernel_config, "candidate": candidate,
    }


def nonzero_bytes(path: Path) -> int:
    """Nonzero 4 KiB blocks within the file's data extents (holes read as zero)."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    zero = bytes(4096)
    total = 0
    try:
        size = os.fstat(fd).st_size
        position = 0
        while position < size:
            try:
                start = os.lseek(fd, position, os.SEEK_DATA)
            except OSError:
                break
            end = os.lseek(fd, start, os.SEEK_HOLE)
            cursor = start - start % 4096
            while cursor < end:
                data = os.pread(fd, min(8 * 1024 * 1024, end - cursor), cursor)
                if not data:
                    break
                for offset in range(0, len(data), 4096):
                    block = data[offset:offset + 4096]
                    if block != zero[:len(block)]:
                        total += len(block)
                cursor += len(data)
            position = end
    finally:
        os.close(fd)
    return total


def upper_proof(path: Path) -> dict:
    metadata = path.stat()
    return {"path": str(path), "logicalBytes": metadata.st_size,
            "allocatedBytes": metadata.st_blocks * 512, "nonzeroBytes": nonzero_bytes(path)}


def write_payload(silo: Silo, name: str) -> dict:
    """Guest-created 1 GiB random payload, durably written into the upper."""
    started = time.monotonic()
    output = silo.exec(name, "sh", "-eu", "-c",
                       f"dd if=/dev/urandom of={PAYLOAD} bs=1M count={PAYLOAD_MIB} conv=fsync 2>/dev/null;"
                       f" sync; stat -c %s {PAYLOAD}; sha256sum {PAYLOAD}",
                       user="root", timeout=600).stdout.split()
    assert int(output[0]) == PAYLOAD_MIB * 1024 * 1024, output
    return {"guestPath": PAYLOAD, "bytes": int(output[0]), "sha256": output[1],
            "writeSeconds": round(time.monotonic() - started, 3),
            "source": "/dev/urandom, bs=1M count=1024 conv=fsync"}


def sequential_copy_rate(silo: Silo, path: Path) -> dict:
    """Host sequential copy rate of the upper's allocated bytes on the same filesystem."""
    scratch = silo.ws.root / "budget-sequential-copy.raw"
    allocated = path.stat().st_blocks * 512
    started = time.monotonic()
    subprocess.run(["cp", "--reflink=never", "--sparse=always", str(path), str(scratch)],
                   check=True, timeout=600)
    fd = os.open(scratch, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    seconds = time.monotonic() - started
    copied = scratch.stat().st_blocks * 512
    # Harness-generated scratch only, removed at once to bound disk use.
    scratch.unlink()
    return {"method": "cp --reflink=never --sparse=always + fsync", "allocatedBytes": allocated,
            "copiedAllocatedBytes": copied, "seconds": round(seconds, 6),
            "bytesPerSecond": allocated / seconds}


def gated_timing(seconds: float, *, allocated_bytes: int, bytes_per_second: float,
                 reflink: bool, copies: int = 1) -> dict:
    """Subtract only the ADR's unavoidable private-copy cost, without clamping."""
    allowance = 0.0 if reflink else copies * allocated_bytes / bytes_per_second
    return {
        "copyAllowance": {
            "lane": "reflink" if reflink else "non-reflink",
            "reflink": reflink, "upperAllocatedBytes": allocated_bytes,
            "privateCopies": copies, "copyBytes": copies * allocated_bytes,
            "bytesPerSecond": bytes_per_second,
        },
        "nonCowAllowanceSeconds": allowance,
        "gatedExcessSeconds": seconds - allowance,
    }


def owned_inputs(silo: Silo) -> list[Path]:
    return page_cache.inputs(silo.ws.silo_home, silo.ws.config.runtime_dir, silo.ws.config.silo)


def cache_state(silo: Silo, cohort: str) -> dict:
    """Per-file eviction/residency evidence, retained whole in the sample record."""
    paths = owned_inputs(silo)
    return page_cache.evict(paths) if cohort == "cold" else page_cache.residency(paths)


def headroom(silo: Silo, required: int) -> dict:
    free = shutil.disk_usage(silo.ws.silo_home).free
    assert free >= required, (
        f"budget sample needs {required} bytes free under {silo.ws.silo_home}, has {free}; "
        "free space first rather than filling the disk")
    return {"freeBytes": free, "requiredBytes": required}


def describe(values: list[float]) -> dict:
    return {"samples": len(values), "median": statistics.median(values), "min": min(values),
            "max": max(values), "values": values}


def summarize(samples: list[dict]) -> dict:
    """Median of five, min/max, per cohort; never mixes cold and warm."""
    summary: dict = {"targets": TARGETS, "metrics": {}, "pass": {}}
    for metric, spec in METRICS.items():
        for cohort in ("cold", "warm"):
            chosen = [sample for sample in samples
                      if sample["cohort"] == cohort and spec.record in sample]
            if not chosen:
                continue
            assert len(chosen) == SAMPLES, (metric, cohort, len(chosen))
            raw = [sample[spec.record][spec.raw_key] for sample in chosen]
            if spec.denominator is not None:
                denominator = [sample[spec.denominator][spec.raw_key] for sample in chosen]
                assert all(value > 0 for value in denominator), denominator
                described = describe([value / base for value, base in zip(raw, denominator, strict=True)])
                described["median"] = statistics.median(raw) / statistics.median(denominator)
                described["medianMethod"] = "median layered seconds / median raw seconds"
            else:
                described = describe(raw)
            described["gatedMedian"] = described["median"]
            if spec.copy_allowance:
                described["gatedMedian"] = statistics.median(
                    sample[spec.record]["gatedExcessSeconds"] for sample in chosen)
                described["nonCowAllowanceSeconds"] = describe(
                    [sample[spec.record]["nonCowAllowanceSeconds"] for sample in chosen])
                described["allowanceInputs"] = [sample[spec.record]["copyAllowance"] for sample in chosen]
            described["budgeted"] = all(metric in sample["gates"] for sample in chosen)
            summary["metrics"].setdefault(metric, {})[cohort] = described
            if described["budgeted"]:
                summary["pass"][f"{metric}/{cohort}"] = described["gatedMedian"] <= TARGETS[metric]
    summary["cacheLabels"] = sorted({f"{sample['cohort']}:{sample['cache']['label']}" for sample in samples})
    summary["coldFullyEvicted"] = all(sample["cache"]["label"] == "cold" for sample in samples
                                      if sample["cohort"] == "cold")
    summary["cohorts"] = sorted({sample["cohort"] for sample in samples})
    return summary


def markdown(summary: dict, host: dict) -> str:
    lines = ["| Metric | Cohort | Raw median | Gated median | Min | Max | Target | Unit | Result |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for metric, cohorts in summary["metrics"].items():
        for cohort, value in cohorts.items():
            result = summary["pass"].get(f"{metric}/{cohort}")
            verdict = "recorded (not budgeted)" if result is None else ("pass" if result else "FAIL")
            target = summary["targets"].get(metric)
            target_text = f"{target:.1f}" if target is not None else "not budgeted"
            lines.append(f"| {metric} | {cohort} | {value['median']:.3f} | "
                         f"{value['gatedMedian']:.3f} | {value['min']:.3f} | "
                         f"{value['max']:.3f} | {target_text} | {METRICS[metric].unit} | {verdict} |")
    lines += ["", f"Host: {host['cpu']}, {host['logicalCpus']} CPUs, {host['memTotalKiB']} KiB, "
              f"kernel {host['kernel']}, {host['filesystem']['fstype']} at {host['filesystem']['target']}.",
              f"Cache labels: {', '.join(summary['cacheLabels'])}."]
    return "\n".join(lines) + "\n"


class Evidence:
    """Append-only sample text plus the final summary, outside the workspace."""

    def __init__(self, label: str, host: dict, *,
                 summarize: Callable[[list[dict]], dict] = summarize,
                 markdown: Callable[[dict, dict], str] = markdown) -> None:
        self.directory = evidence_directory(label)
        self.host = host
        self.samples: list[dict] = []
        self._summarize = summarize
        self._markdown = markdown
        (self.directory / "reference-host.json").write_text(json.dumps(host, indent=2, sort_keys=True) + "\n")

    def record(self, name: str, value: object) -> None:
        (self.directory / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def allowance(self, metric: str, timing: dict) -> None:
        self.host.setdefault("nonCowAllowances", {})[metric] = {
            **timing["copyAllowance"],
            "nonCowAllowanceSeconds": timing["nonCowAllowanceSeconds"],
        }
        self.record("reference-host.json", self.host)

    def sample(self, value: dict) -> None:
        self.samples.append(value)
        with (self.directory / "samples.jsonl").open("a") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")

    def finish(self) -> dict:
        summary = self._summarize(self.samples)
        self.record("summary.json", summary)
        (self.directory / "summary.md").write_text(self._markdown(summary, self.host))
        return summary


def main() -> None:
    """Recompute a retained cohort summary from its text samples."""
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("directory", type=Path, nargs="+")
    args = parser.parse_args()
    for directory in args.directory:
        samples = [json.loads(line) for line in (directory / "samples.jsonl").read_text().splitlines() if line]
        host = json.loads((directory / "reference-host.json").read_text())
        print(f"## {directory.name}\n")
        print(markdown(summarize(samples), host))


if __name__ == "__main__":
    main()
