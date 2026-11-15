from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

import pytest

from silo_smoke.catalog_observer import observe
from silo_smoke.distribution_registry import DistributionRelease, install_distribution
from silo_smoke.errors import SmokeEnvironmentError
from silo_perf.drivers import snapshot_id
from silo_perf.history import Host, Record, append, delta, load, parse, previous
from silo_perf.model import Cohort, Target, Verdict, invariant, load_cohorts, load_targets, target_for
from silo_perf.report import render, trend


HOST = Host("unit CPU", 64 * 1024**3, "btrfs", "unit kernel", "x86_64")


def record(*, median: float = 2.0, system: str = "silo", mode: str = "image",
           run_id: str = "current", host: Host = HOST) -> Record:
    return Record(system, "arch-30g", mode, "start", (median,), median, median, median,
                  "commit", "silo test", "msb test", host, "2026-11-15T00:00:00Z", run_id)


@pytest.mark.parametrize(("seconds", "expected_fail", "verdict"), [
    (0.5, False, Verdict.PASS), (1.0, False, Verdict.PASS), (1.001, False, Verdict.FAIL),
    (1.001, True, Verdict.NOT_YET), (1.0, True, Verdict.PASS),
])
def test_target_evaluation(seconds: float, expected_fail: bool, verdict: Verdict) -> None:
    assert Target(1.0, expected_fail, "30g").evaluate(seconds) == verdict


@pytest.mark.parametrize("seconds", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_target(seconds: float) -> None:
    with pytest.raises(ValueError):
        Target(seconds)


@pytest.mark.parametrize("seconds", [-1.0, float("nan"), float("inf")])
def test_invalid_measurement(seconds: float) -> None:
    with pytest.raises(ValueError):
        Target(1.0).evaluate(seconds)


def test_expected_failure_requires_slice() -> None:
    with pytest.raises(ValueError, match="slice"):
        Target(1.0, expected_fail=True)


def test_checked_in_targets_and_cohorts() -> None:
    cohorts = load_cohorts()
    assert tuple(cohorts) == ("alpine-2g", "alpine-8g", "alpine-30g", "arch-30g", "disk-invariance")
    assert cohorts["arch-30g"].cpus == 10
    assert cohorts["arch-30g"].disks == ("100gb",)
    assert cohorts["disk-invariance"].disks == ("30gib", "500gib")
    targets = load_targets()
    assert len(targets) == 7
    assert target_for(targets, "silo", "arch-30g", "image", "restore_first_exec") == Target(0.1, True, "30g")
    assert target_for(targets, "msb", "arch-30g", "default", "start") is None
    assert all(target.expected_fail and target.slice for target in targets.values())


def test_history_append_and_parse(tmp_path: Path) -> None:
    path = tmp_path / "history" / "history.jsonl"
    assert load(path) == []
    first, second = record(run_id="old"), record(median=1.0)
    append(path, [first])
    path.write_text(path.read_text().rstrip("\n"))
    append(path, [second])
    assert load(path) == [first, second]
    value = json.loads(path.read_text().splitlines()[0])
    assert value["samples"] == [2.0]
    assert (value["median"], value["min"], value["max"]) == (2.0, 2.0, 2.0)
    assert value["host_fingerprint"] == HOST.fingerprint
    assert parse("\n" + path.read_text() + "\n") == [first, second]
    assert parse("") == []


@pytest.mark.parametrize("text", ["{", "{}", "null", "[]", '{"samples": []}'])
def test_history_rejects_malformed_records(text: str) -> None:
    with pytest.raises(ValueError, match="line 2"):
        parse("\n" + text)


def test_history_rejects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    append(path, [record()])
    value = json.loads(path.read_text())
    value["host_fingerprint"] = "other"
    with pytest.raises(ValueError, match="fingerprint"):
        parse(json.dumps(value))
    value["host_fingerprint"] = HOST.fingerprint
    value["median"] = 99
    with pytest.raises(ValueError, match="summary"):
        parse(json.dumps(value))


@pytest.mark.parametrize("samples", [(), (-1.0,), (float("nan"),), (float("inf"),)])
def test_history_rejects_invalid_samples(samples: tuple[float, ...]) -> None:
    with pytest.raises(ValueError, match="samples"):
        replace(record(), samples=samples)


def test_delta_matches_host_and_exact_key() -> None:
    current = record(median=1.0)
    old = record(median=2.0, run_id="old")
    other_host = replace(HOST, cpu="different")
    history = [old, record(median=50.0, run_id="other", host=other_host),
               record(median=50.0, system="msb", run_id="other"),
               record(median=50.0, mode="agent", run_id="other"), current]
    assert previous(current, history) == old
    assert delta(current, history) == -50.0
    assert delta(current, []) is None
    assert delta(current, [record(median=0.0, run_id="old")]) is None
    assert delta(current, [old, record(median=4.0, run_id="latest")]) == -75.0


def test_render_table_and_history_delta() -> None:
    records = [record(median=2.0), record(median=0.5, mode="agent"),
               record(median=0.25, system="msb", mode="default")]
    targets = {("silo", "arch-30g", "image", "start"): Target(1.0, True, "30g"),
               ("silo", "arch-30g", "agent", "start"): Target(0.5)}
    table = render(records, [record(median=4.0, run_id="old")], targets)
    assert "Silo image s" in table and "Silo agent s" in table and "msb s" in table
    assert "1 NOT YET" in table and "0.5 PASS" in table
    assert "8.00x / 2.00x" in table and "-50.0% / - / -" in table
    assert "\x1b" not in table
    assert "FAIL" in render([record()], [], {("silo", "arch-30g", "image", "start"): Target(1.0)})
    assert "Silo image s" in render([], [], {})
    assert "-" in render([record()], [], {})
    extended = render([*records, record(median=0.5, system="boxd", mode="default")], [], targets)
    assert "boxd s" in extended and "Silo/boxd" in extended


def test_trend_reports_every_history_entry() -> None:
    text = trend([record(median=4.0, run_id="old"), record(median=2.0)])
    assert len(text.splitlines()) == 3
    assert "-50.0%" in text and HOST.fingerprint[:12] in text


@pytest.mark.parametrize(("first", "second", "expected"), [
    (1.0, 1.2, True), (1.0, 1.31, False), (0.01, 0.10, True), (0.01, 0.12, False),
    (0.0, 0.0, True),
])
def test_disk_invariance_noise(first: float, second: float, expected: bool) -> None:
    cohort = Cohort("disk", "alpine", 2, 2)
    assert invariant(first, second, cohort) is expected
    assert invariant(second, first, cohort) is expected


def test_catalog_observer_decodes_real_alias(tmp_path: Path) -> None:
    # A real SQLite catalog exercises the observer's encoding contract, not a product double.
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE image_alias(name TEXT PRIMARY KEY, snapshot_id TEXT, image_id TEXT)")
        connection.execute("INSERT INTO image_alias VALUES ('chosen', 'sha256:abc', NULL)")
    rows = observe(path)["image_alias"]
    assert rows == [("text:63686F73656E", "text:7368613235363A616263", "null:")]
    assert snapshot_id(path, "chosen") == "sha256:abc"
    assert snapshot_id(path, "absent") is None
    assert snapshot_id(tmp_path / "absent.db", "chosen") is None
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO image_alias VALUES ('not-snapshot', NULL, 'sha256:def')")
    with pytest.raises(ValueError, match="not a snapshot"):
        snapshot_id(path, "not-snapshot")


def test_explicit_distribution_binary_never_acquires(tmp_path: Path) -> None:
    binary = Path(sys.executable).resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    release = DistributionRelease("unit", "amd64", "file:///unavailable", "0" * 64, 0,
                                  digest, binary.stat().st_size)
    cache = tmp_path / "cache"
    installed = install_distribution(cache, release, binary_path=binary)
    assert installed.binary == binary and installed.release == release
    assert not cache.exists()
    for supplied in (tmp_path / "missing", tmp_path):
        with pytest.raises(SmokeEnvironmentError, match="Explicit"):
            install_distribution(cache, release, binary_path=supplied)
    with pytest.raises(SmokeEnvironmentError, match="Explicit"):
        install_distribution(cache, replace(release, binary_sha256="0" * 64), binary_path=binary)
    assert not cache.exists()
