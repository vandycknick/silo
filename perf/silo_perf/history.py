from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
from typing import Iterable


@dataclass(frozen=True)
class Host:
    cpu: str
    ram_bytes: int
    filesystem: str
    kernel: str
    architecture: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def host(workspace: Path) -> Host:
    if platform.system() == "Linux":
        cpu = next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")), platform.machine())
        ram = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                   if line.startswith("MemTotal:"))
        fs = subprocess.run(["findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--target", str(workspace)],
                            capture_output=True, text=True, check=True, timeout=15).stdout.strip()
    else:
        def sysctl(key: str) -> str:
            return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True,
                                  check=True, timeout=15).stdout.strip()
        cpu, ram = sysctl("machdep.cpu.brand_string"), int(sysctl("hw.memsize"))
        fs = subprocess.run(["stat", "-f", "%T", str(workspace)], capture_output=True,
                            text=True, check=True, timeout=15).stdout.strip()
    return Host(cpu, ram, fs, platform.release(), platform.machine())


@dataclass(frozen=True)
class Record:
    system: str
    cohort: str
    mode: str
    metric: str
    samples: tuple[float, ...]
    median: float
    minimum: float
    maximum: float
    git_commit: str
    silo_version: str
    msb_version: str | None
    host: Host
    timestamp: str
    run_id: str

    def __post_init__(self) -> None:
        if not self.samples or not all(math.isfinite(value) and value >= 0 for value in self.samples):
            raise ValueError("samples must be nonempty, finite and nonnegative")
        if (self.median, self.minimum, self.maximum) != (
                statistics.median(self.samples), min(self.samples), max(self.samples)):
            raise ValueError("history summary disagrees with samples")

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.host.fingerprint, self.system, self.cohort, self.mode, self.metric


def history_path() -> Path:
    default = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "silo/perf/history.jsonl"
    return Path(os.environ.get("PERF_HISTORY", str(default))).expanduser()


def parse(text: str) -> list[Record]:
    records: list[Record] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            value["host"] = Host(**value["host"])
            value["samples"] = tuple(value["samples"])
            value["minimum"] = value.pop("min")
            value["maximum"] = value.pop("max")
            fingerprint = value.pop("host_fingerprint")
            record = Record(**value)
            if fingerprint != record.host.fingerprint:
                raise ValueError("host fingerprint disagrees with host")
            records.append(record)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError(f"invalid performance history line {number}: {error}") from error
    return records


def load(path: Path) -> list[Record]:
    try:
        return parse(path.read_text())
    except FileNotFoundError:
        return []


def append(path: Path, records: Iterable[Record]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0, os.SEEK_END)
        if stream.tell():
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b"\n":
                stream.write(b"\n")
        for record in records:
            value = asdict(record)
            value["min"], value["max"] = value.pop("minimum"), value.pop("maximum")
            value["host_fingerprint"] = record.host.fingerprint
            stream.write((json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def previous(record: Record, history: Iterable[Record]) -> Record | None:
    return next((entry for entry in reversed(list(history))
                 if entry.key == record.key and entry.run_id != record.run_id), None)


def delta(record: Record, history: Iterable[Record]) -> float | None:
    old = previous(record, history)
    return None if old is None or old.median == 0 else (record.median / old.median - 1) * 100


def now() -> str:
    return datetime.now(timezone.utc).isoformat()
