"""Reproducible cold/warm budget cohorts for ADR 0021 full capture, restore and fork.

Fixture (exact, never shrunk): the `restore-execution` image (BASIC Alpine plus
the static `restore_execution.c` witness), 2 vCPUs, 4096 MiB configured RAM,
`--network private`, flat-overlay root with a 2 GiB logical upper. Inside the
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
  conservative staging-durable..continuation-finished interval and the
  host-observed gap in the guest witness's durable writes. Without a clone
  contract the ADR allowance adds the upper's allocated bytes at the host's
  measured sequential copy rate; the actual disk-seal duration is recorded too.
- restore (gated): `silo restore` dispatch to its exit with the child already
  Running and ready (or the first later Running+ready observation).

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
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import time

from . import overlay, page_cache
from .cli import Silo

RAM = "4096mib"
UPPER = "2gib"
PAYLOAD = "/fork-budget.payload"
PAYLOAD_MIB = 1024
SAMPLES = 5
CHILDREN = 4
GIB = 1024 ** 3
TARGETS = {"fork4": 10.0, "captureInterruption": 5.0, "restore": 2.0}
EVIDENCE_VARIABLE = "SILO_SMOKE_BUDGET_EVIDENCE"
SCHEDULE = tuple([("cold", index) for index in range(SAMPLES)] + [("warm-up", 0)]
                 + [("warm", index) for index in range(SAMPLES)])


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
    metrics = {
        "fork4": lambda sample: sample["fork4"]["dispatchToRunningSeconds"],
        "captureInterruption": lambda sample: sample["capture"]["gatedExcessSeconds"],
        "restore": lambda sample: sample["restore"]["dispatchToRunningSeconds"],
    }
    for metric, value in metrics.items():
        for cohort in ("cold", "warm"):
            chosen = [value(sample) for sample in samples
                      if sample["cohort"] == cohort and metric in sample.get("gates", ())]
            if not chosen:
                continue
            assert len(chosen) == SAMPLES, (metric, cohort, len(chosen))
            described = describe(chosen)
            summary["metrics"].setdefault(metric, {})[cohort] = described
            summary["pass"][f"{metric}/{cohort}"] = described["median"] <= TARGETS[metric]
    summary["cacheLabels"] = sorted({f"{sample['cohort']}:{sample['cache']['label']}" for sample in samples})
    summary["coldFullyEvicted"] = all(sample["cache"]["label"] == "cold" for sample in samples
                                      if sample["cohort"] == "cold")
    summary["cohorts"] = sorted({sample["cohort"] for sample in samples})
    return summary


def markdown(summary: dict, host: dict) -> str:
    lines = ["| Metric | Cohort | Median s | Min s | Max s | Target s | Result |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for metric, cohorts in summary["metrics"].items():
        for cohort, value in cohorts.items():
            lines.append(f"| {metric} | {cohort} | {value['median']:.3f} | {value['min']:.3f} | "
                         f"{value['max']:.3f} | {TARGETS[metric]:.1f} | "
                         f"{'pass' if summary['pass'][f'{metric}/{cohort}'] else 'FAIL'} |")
    lines += ["", f"Host: {host['cpu']}, {host['logicalCpus']} CPUs, {host['memTotalKiB']} KiB, "
              f"kernel {host['kernel']}, {host['filesystem']['fstype']} at {host['filesystem']['target']}.",
              f"Cache labels: {', '.join(summary['cacheLabels'])}."]
    return "\n".join(lines) + "\n"


class Evidence:
    """Append-only sample text plus the final summary, outside the workspace."""

    def __init__(self, label: str, host: dict) -> None:
        self.directory = evidence_directory(label)
        self.host = host
        self.samples: list[dict] = []
        (self.directory / "reference-host.json").write_text(json.dumps(host, indent=2, sort_keys=True) + "\n")

    def record(self, name: str, value: object) -> None:
        (self.directory / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def sample(self, value: dict) -> None:
        self.samples.append(value)
        with (self.directory / "samples.jsonl").open("a") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")

    def finish(self) -> dict:
        summary = summarize(self.samples)
        self.record("summary.json", summary)
        (self.directory / "summary.md").write_text(markdown(summary, self.host))
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
