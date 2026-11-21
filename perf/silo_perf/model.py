from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import math
from pathlib import Path
import tomllib
from typing import Mapping
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Mode(StrEnum):
    IMAGE = "image"
    AGENT = "agent"
    DEFAULT = "default"


@dataclass(frozen=True)
class Workload:
    memory_mib: int
    disk_mib: int
    disk_files: int
    small_files: int
    dirty_percent: int
    dirty_chunk_kib: int
    seed: int

    def __post_init__(self) -> None:
        for name in ("memory_mib", "disk_mib", "disk_files", "small_files",
                     "dirty_percent", "dirty_chunk_kib", "seed"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"workload {name} must be a positive integer")
        if self.dirty_percent > 100:
            raise ValueError("workload dirty_percent must be at most 100")
        if self.disk_mib % self.disk_files:
            raise ValueError("workload disk_mib must be divisible by disk_files")
        if self.dirty_chunk_kib % 4 or self.memory_mib * 1024 % self.dirty_chunk_kib:
            raise ValueError("workload dirty chunks must be page aligned and divide memory")
        if self.memory_mib * 1024 // self.dirty_chunk_kib * self.dirty_percent // 100 == 0:
            raise ValueError("workload must dirty at least one chunk")

    @property
    def tmpfs_mib(self) -> int:
        dirty_mib = (self.memory_mib * self.dirty_percent + 99) // 100
        return self.memory_mib + max(self.disk_mib, dirty_mib) + 256


@dataclass(frozen=True)
class Cohort:
    name: str
    image: str
    cpus: int
    memory_gib: int
    disks: tuple[str, ...] = ("",)
    msb_image: str | None = None
    written_mib: int = 0
    noise_relative: float = 0.10
    noise_absolute_seconds: float = 0.05
    # Accepted, measured residuals: metric name to its absolute allowance.
    metric_noise_absolute_seconds: Mapping[str, float] = field(default_factory=dict)
    informational: bool = False
    raw_root: bool = False
    workload: Workload | None = None
    hibernate: bool = False

    def __post_init__(self) -> None:
        if self.workload is not None and self.workload.tmpfs_mib >= self.memory_gib * 1024:
            raise ValueError("workload tmpfs must leave guest memory available")
        if self.raw_root and self.msb_image is not None:
            raise ValueError("raw-root cohorts are Silo only")


def load_cohorts(path: Path = ROOT / "cohorts.toml") -> dict[str, Cohort]:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    cohorts: dict[str, Cohort] = {}
    for name, values in data.items():
        values["disks"] = tuple(values.get("disks", [""]))
        if "workload" in values:
            values["workload"] = Workload(**values["workload"])
        cohorts[name] = Cohort(name=name, **values)
    return cohorts


class Verdict(StrEnum):
    PASS = "PASS"
    WITHIN_TOLERANCE = "PASS (within tolerance)"
    FAIL = "FAIL"
    NOT_YET = "NOT YET"

    def render(self, tolerance: float) -> str:
        if self == Verdict.WITHIN_TOLERANCE:
            return f"PASS (within {tolerance * 100:.12g}%)"
        return self.value


def validate_tolerance(tolerance: float) -> None:
    if (isinstance(tolerance, bool) or not isinstance(tolerance, (int, float))
            or not math.isfinite(tolerance) or not 0 <= tolerance < 1):
        raise ValueError("tolerance must be finite and in [0, 1)")


@dataclass(frozen=True)
class Target:
    seconds: float
    tolerance: float
    expected_fail: bool = False
    slice: str = ""

    def __post_init__(self) -> None:
        if not math.isfinite(self.seconds) or self.seconds <= 0:
            raise ValueError("target seconds must be finite and positive")
        validate_tolerance(self.tolerance)
        if self.expected_fail and not self.slice:
            raise ValueError("expected_fail requires a slice reference")

    def evaluate(self, seconds: float) -> Verdict:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("measurement must be finite and nonnegative")
        if seconds <= self.seconds:
            return Verdict.PASS
        bound = self.seconds * (1 + self.tolerance)
        if seconds <= bound:
            return Verdict.WITHIN_TOLERANCE
        return Verdict.NOT_YET if self.expected_fail else Verdict.FAIL


TargetKey = tuple[str, str, str, str]


def load_targets(path: Path = ROOT / "targets.toml") -> dict[TargetKey, Target]:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    tolerance = data.pop("tolerance", None)
    validate_tolerance(tolerance)
    return {(system, cohort, mode, metric): Target(**{"tolerance": tolerance, **value})
            for system, cohorts in data.items() for cohort, modes in cohorts.items()
            for mode, metrics in modes.items() for metric, value in metrics.items()}


def target_for(targets: Mapping[TargetKey, Target], system: str, cohort: str,
               mode: str, metric: str) -> Target | None:
    target_metric = "exec" if metric.endswith("_exec") else metric
    return targets.get((system, cohort, mode, target_metric))


def image_source(reference: str) -> str:
    if reference.startswith(("sha256:", "disk:")):
        return "local"
    hostname = urlsplit("//" + reference).hostname
    return "local" if hostname in {"localhost", "127.0.0.1", "::1"} else "remote"


def invariant(first: float, second: float, cohort: Cohort, metric: str) -> bool:
    if not all(math.isfinite(value) and value >= 0 for value in (first, second)):
        raise ValueError("invariance medians must be finite and nonnegative")
    smaller = min(first, second)
    absolute = cohort.metric_noise_absolute_seconds.get(metric, cohort.noise_absolute_seconds)
    return max(first, second) <= smaller + max(absolute, cohort.noise_relative * smaller)
