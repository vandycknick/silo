from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
import os
from pathlib import Path
import statistics
import subprocess
from uuid import uuid4

import pytest

from silo_smoke import image_cache, preflight
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace
from silo_perf.drivers import Context, Names, REGISTRY
from silo_perf.history import Record, append, history_path, host, load, now
from silo_perf.model import Verdict, invariant, load_cohorts, load_targets, target_for
from silo_perf.report import render
from silo_perf.scenario import sample


def selection(variable: str, available: tuple[str, ...], default: str) -> list[str]:
    selected = [value.strip() for value in (os.environ.get(variable) or default).split(",") if value.strip()]
    if not selected or len(set(selected)) != len(selected) or any(value not in available for value in selected):
        raise ValueError(f"{variable} must select unique values from {','.join(available)}")
    return selected


def test_live_operations(config: SmokeConfig, registry: LoopbackRegistry) -> None:
    if os.environ.get("PYTEST_XDIST_WORKER"):
        pytest.fail("perf must run serially, without xdist")
    cohorts = load_cohorts()
    chosen = selection("PERF_COHORTS", tuple(cohorts), ",".join(cohorts))
    systems = selection("PERF_SYSTEMS", tuple(REGISTRY), "silo")
    count = int(os.environ.get("PERF_SAMPLES", "3"))
    if count <= 0:
        raise ValueError("PERF_SAMPLES must be positive")
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "silo/perf"
    cache.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                            text=True, check=True, timeout=15).stdout.strip()
    silo_version = subprocess.run([str(config.silo), "--version"], capture_output=True,
                                  text=True, check=True, timeout=15).stdout.strip()
    run_id = uuid4().hex
    stamp = now()
    history = load(history_path())
    targets = load_targets()
    records: list[Record] = []
    failures: list[str] = []
    mark = preflight.check(config)
    versions: dict[str, str] = {}
    try:
        for system in systems:
            driver_type = REGISTRY[system]
            unavailable = driver_type.available()
            if unavailable:
                print(f"SKIP {system}: {unavailable}")
                continue
            for cohort_name in chosen:
                cohort = cohorts[cohort_name]
                if not driver_type.supports(cohort):
                    print(f"SKIP {system}/{cohort_name}: cohort is Silo only")
                    continue
                for mode in driver_type.modes:
                    disk_medians: dict[str, dict[str, float]] = {}
                    for disk in cohort.disks:
                        timings: dict[str, list[float]] = defaultdict(list)
                        fingerprint = None
                        msb_version = None
                        for index in range(count):
                            workspace = Workspace(config, registry.ca_path, parent=cache)
                            failed = True
                            try:
                                image_cache.seed(config.cache_dir, workspace.silo_home)
                                identity = host(workspace.root)
                                if fingerprint is not None and identity != fingerprint:
                                    raise ValueError("host fingerprint changed within a cohort")
                                fingerprint = identity
                                prefix = f"p{run_id[:8]}-{index}"
                                context = Context(workspace, cache, cohort, mode, disk,
                                                  Names(prefix + "a", prefix + "b"))
                                driver = driver_type(context)
                                try:
                                    versions[system] = driver.version()
                                except BaseException as error:
                                    try:
                                        driver.cleanup()
                                    except BaseException as cleanup_error:
                                        raise BaseExceptionGroup("version probe and cleanup failed", [error, cleanup_error])
                                    raise
                                msb_version = versions.get("msb")
                                measured = sample(driver)
                                for metric, seconds in measured.items():
                                    timings[metric].append(seconds)
                                failed = False
                            finally:
                                try:
                                    image_cache.persist(config.cache_dir, workspace.silo_home)
                                finally:
                                    workspace.cleanup(failed=failed)
                        if fingerprint is None:
                            raise ValueError("cohort produced no samples")
                        disk_medians[disk] = {metric: statistics.median(values) for metric, values in timings.items()}
                        label = cohort_name if len(cohort.disks) == 1 else f"{cohort_name}/{disk}"
                        for metric, values in timings.items():
                            target = target_for(targets, system, cohort_name, mode.value, metric)
                            median = statistics.median(values)
                            verdict = None if target is None else target.evaluate(median)
                            record = Record(system, label, mode.value, metric, tuple(values),
                                            median, min(values), max(values), commit,
                                            silo_version, msb_version, fingerprint, stamp, run_id,
                                            verdict, None if target is None else target.tolerance)
                            records.append(record)
                            if target is not None and verdict == Verdict.FAIL:
                                failures.append(f"{system}/{label}/{mode}/{metric} exceeds "
                                                f"{target.seconds:g}s plus {target.tolerance:.0%} tolerance")
                    if len(cohort.disks) > 1:
                        first, second = (disk_medians[disk] for disk in cohort.disks)
                        for metric in ("snapshot_full", "snapshot_incremental", "fork_first", "fork_second",
                                       "restore_first", "restore_second"):
                            if not invariant(first[metric], second[metric], cohort):
                                failures.append(f"{cohort_name}/{mode}/{metric}: configured disk changed median "
                                                f"{first[metric]:.3f}s vs {second[metric]:.3f}s beyond "
                                                f"{cohort.noise_relative:.0%} or {cohort.noise_absolute_seconds:g}s noise")
    finally:
        records = [replace(record, msb_version=versions.get("msb")) for record in records]
        append(history_path(), records)
        print("\n" + render(records, history, targets))
        assert preflight.live_daemon_unchanged(mark), "the live daemon socket changed during perf"
    assert not failures, "\n".join(failures)
