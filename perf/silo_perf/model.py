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


def invariant(first: float, second: float, cohort: Cohort) -> bool:
    if not all(math.isfinite(value) and value >= 0 for value in (first, second)):
        raise ValueError("invariance medians must be finite and nonnegative")
    return abs(first - second) <= max(cohort.noise_absolute_seconds,
                                      cohort.noise_relative * min(first, second))
