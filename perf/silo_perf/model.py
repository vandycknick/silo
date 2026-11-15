from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
from pathlib import Path
import tomllib
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]


class Mode(StrEnum):
    IMAGE = "image"
    AGENT = "agent"
    DEFAULT = "default"


@dataclass(frozen=True)
class Cohort:
    name: str
    image: str
    cpus: int
    memory_gib: int
    disks: tuple[str, ...] = ("",)
    msb_image: str | None = None
    written_mib: int = 0
    noise_relative: float = 0.30
    noise_absolute_seconds: float = 0.10


def load_cohorts(path: Path = ROOT / "cohorts.toml") -> dict[str, Cohort]:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    return {name: Cohort(name=name, **{**values, "disks": tuple(values.get("disks", [""]))})
            for name, values in data.items()}


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_YET = "NOT YET"


@dataclass(frozen=True)
class Target:
    seconds: float
    expected_fail: bool = False
    slice: str = ""

    def __post_init__(self) -> None:
        if not math.isfinite(self.seconds) or self.seconds <= 0:
            raise ValueError("target seconds must be finite and positive")
        if self.expected_fail and not self.slice:
            raise ValueError("expected_fail requires a slice reference")

    def evaluate(self, seconds: float) -> Verdict:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("measurement must be finite and nonnegative")
        if seconds <= self.seconds:
            return Verdict.PASS
        return Verdict.NOT_YET if self.expected_fail else Verdict.FAIL


TargetKey = tuple[str, str, str, str]


def load_targets(path: Path = ROOT / "targets.toml") -> dict[TargetKey, Target]:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    return {(system, cohort, mode, metric): Target(**value)
            for system, cohorts in data.items() for cohort, modes in cohorts.items()
            for mode, metrics in modes.items() for metric, value in metrics.items()}


def target_for(targets: Mapping[TargetKey, Target], system: str, cohort: str,
               mode: str, metric: str) -> Target | None:
    target_metric = "exec" if metric.endswith("_exec") else metric
    return targets.get((system, cohort, mode, target_metric))


def invariant(first: float, second: float, cohort: Cohort) -> bool:
    if not all(math.isfinite(value) and value >= 0 for value in (first, second)):
        raise ValueError("invariance medians must be finite and nonnegative")
    return abs(first - second) <= max(cohort.noise_absolute_seconds,
                                      cohort.noise_relative * min(first, second))
