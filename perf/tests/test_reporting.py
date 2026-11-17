from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
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
           run_id: str = "current", host: Host = HOST, target: Target | None = None) -> Record:
    verdict = None if target is None else target.evaluate(median)
    return Record(system, "arch-30g", mode, "start", (median,), median, median, median,
                  "commit", "silo test", "msb test", host, "2026-11-15T00:00:00Z", run_id,
                  verdict, None if target is None else target.tolerance)


@pytest.mark.parametrize("expected_fail", [False, True])
@pytest.mark.parametrize(("seconds", "verdict"), [
    (0.0, Verdict.PASS), (0.5, Verdict.PASS), (1.0, Verdict.PASS),
    (1.001, Verdict.WITHIN_TOLERANCE), (1.0 * 1.10, Verdict.WITHIN_TOLERANCE),
    (math.nextafter(1.0 * 1.10, math.inf), Verdict.FAIL), (1.11, Verdict.FAIL),
])
def test_target_evaluation(seconds: float, expected_fail: bool, verdict: Verdict) -> None:
    expected = Verdict.NOT_YET if expected_fail and verdict == Verdict.FAIL else verdict
    assert Target(1.0, 0.10, expected_fail, "30g").evaluate(seconds) == expected


@pytest.mark.parametrize("tolerance", [0.0, 0.10, 0.25, math.nextafter(1.0, 0.0)])
def test_target_tolerance_boundary(tolerance: float) -> None:
    target = Target(0.5, tolerance)
    bound = target.seconds * (1 + tolerance)
    assert target.evaluate(target.seconds) == Verdict.PASS
    expected = Verdict.PASS if tolerance == 0 else Verdict.WITHIN_TOLERANCE
    assert target.evaluate(bound) == expected
    assert target.evaluate(math.nextafter(bound, math.inf)) == Verdict.FAIL


@pytest.mark.parametrize("tolerance", [-0.01, 1.0, float("nan"), float("inf"), -float("inf")])
def test_invalid_tolerance(tolerance: float) -> None:
    with pytest.raises(ValueError, match="tolerance"):
        Target(1.0, tolerance)


@pytest.mark.parametrize(("tolerance", "label"), [(0.10, "10"), (0.125, "12.5"), (0.25, "25")])
def test_verdict_rendering(tolerance: float, label: str) -> None:
    assert Verdict.WITHIN_TOLERANCE.render(tolerance) == f"PASS (within {label}%)"
    for verdict in (Verdict.PASS, Verdict.FAIL, Verdict.NOT_YET):
        assert verdict.render(tolerance) == verdict.value


@pytest.mark.parametrize("seconds", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_target(seconds: float) -> None:
    with pytest.raises(ValueError):
        Target(seconds, 0.10)


@pytest.mark.parametrize("seconds", [-1.0, float("nan"), float("inf")])
def test_invalid_measurement(seconds: float) -> None:
    with pytest.raises(ValueError):
        Target(1.0, 0.10).evaluate(seconds)


def test_expected_failure_requires_slice() -> None:
    with pytest.raises(ValueError, match="slice"):
        Target(1.0, 0.10, expected_fail=True)


def test_checked_in_targets_and_cohorts() -> None:
    cohorts = load_cohorts()
    assert {"alpine-2g", "alpine-8g", "alpine-30g", "arch-30g", "disk-invariance"} <= cohorts.keys()
    assert cohorts["arch-30g"].cpus == 10
    assert cohorts["arch-30g"].disks == ("100gb",)
    assert cohorts["disk-invariance"].disks == ("30gib", "500gib")
    targets = load_targets()
    assert targets
    for (system, cohort, mode, metric), target in targets.items():
        assert system and cohort in cohorts and mode in {"image", "agent", "default"} and metric
        assert math.isfinite(target.seconds) and target.seconds > 0
        assert math.isfinite(target.tolerance) and 0 <= target.tolerance < 1
        assert not target.expected_fail or target.slice


def test_load_targets_inherits_and_overrides_tolerance(tmp_path: Path) -> None:
    path = tmp_path / "targets.toml"
    path.write_text('tolerance = 0.10\n'
                    '[silo.unit.image.start]\nseconds = 1.0\n'
                    '[silo.unit.image.exec]\nseconds = 0.1\ntolerance = 0.25\n'
                    '[silo.unit.image.restore_first]\nseconds = 0.5\ntolerance = 0.0\n')
    targets = load_targets(path)
    assert targets[("silo", "unit", "image", "start")] == Target(1.0, 0.10)
    assert target_for(targets, "silo", "unit", "image", "restore_first_exec") == Target(0.1, 0.25)
    assert targets[("silo", "unit", "image", "restore_first")] == Target(0.5, 0.0)
    assert target_for(targets, "msb", "unit", "default", "start") is None


@pytest.mark.parametrize("value", ["-0.01", "1.0", "nan", "inf", "-inf", "true", '"invalid"'])
@pytest.mark.parametrize("override", [False, True])
def test_load_targets_rejects_invalid_tolerance(tmp_path: Path, value: str, override: bool) -> None:
    path = tmp_path / "targets.toml"
    path.write_text(f"tolerance = {'0.10' if override else value}\n"
                    "[silo.unit.image.start]\nseconds = 1.0\n"
                    + (f"tolerance = {value}\n" if override else ""))
    with pytest.raises(ValueError, match="tolerance"):
        load_targets(path)


@pytest.mark.parametrize("text", ["", "[silo.unit.image.start]\nseconds = 1.0\n"])
def test_load_targets_requires_default_tolerance(tmp_path: Path, text: str) -> None:
    path = tmp_path / "targets.toml"
    path.write_text(text)
    with pytest.raises(ValueError, match="tolerance"):
        load_targets(path)


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
    assert value["verdict"] is None and value["tolerance"] is None
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
    targets = {("silo", "arch-30g", "image", "start"): Target(1.0, 0.10, True, "30g"),
               ("silo", "arch-30g", "agent", "start"): Target(0.5, 0.10)}
    table = render(records, [record(median=4.0, run_id="old")], targets)
    assert "Silo image s" in table and "Silo agent s" in table and "msb s" in table
    assert "1 NOT YET" in table and "0.5 PASS" in table
    assert "8.00x / 2.00x" in table and "-50.0% / - / -" in table
    assert "\x1b" not in table
    assert "FAIL" in render([record()], [], {("silo", "arch-30g", "image", "start"): Target(1.0, 0.10)})
    assert "Silo image s" in render([], [], {})
    assert "-" in render([record()], [], {})
    extended = render([*records, record(median=0.5, system="boxd", mode="default")], [], targets)
    assert "boxd s" in extended and "Silo/boxd" in extended


def test_trend_reports_every_history_entry() -> None:
    text = trend([record(median=4.0, run_id="old", target=Target(1.0, 0.25)),
                  record(median=2.0, target=Target(2.0, 0.10))])
    assert len(text.splitlines()) == 3
    assert "verdict" in text and "FAIL" in text and "PASS" in text
    assert "-50.0%" in text and HOST.fingerprint[:12] in text


@pytest.mark.parametrize("expected_fail", [False, True])
@pytest.mark.parametrize(("median", "verdict", "label"), [
    (0.5, Verdict.PASS, "PASS"), (0.504, Verdict.WITHIN_TOLERANCE, "PASS (within 10%)"),
    (0.5 * 1.10, Verdict.WITHIN_TOLERANCE, "PASS (within 10%)"),
    (0.5 * 1.11, Verdict.FAIL, "FAIL"),
])
def test_history_preserves_gate_verdict(tmp_path: Path, expected_fail: bool, median: float,
                                      verdict: Verdict, label: str) -> None:
    target = Target(0.5, 0.10, expected_fail, "30a")
    current = replace(record(median=median, target=target), metric="restore_first")
    if expected_fail and verdict == Verdict.FAIL:
        verdict, label = Verdict.NOT_YET, "NOT YET"
    assert current.verdict == verdict
    path = tmp_path / "history.jsonl"
    append(path, [current])
    value = json.loads(path.read_text())
    assert value["verdict"] == verdict.value and value["tolerance"] == 0.10
    restored = load(path)
    assert restored == [current]
    assert label in trend(restored)
    assert label in render(restored, [], {("silo", "arch-30g", "image", "restore_first"): target})


def test_history_preserves_tolerance_override(tmp_path: Path) -> None:
    current = record(median=1.2, target=Target(1.0, 0.25))
    path = tmp_path / "history.jsonl"
    append(path, [current])
    assert load(path) == [current]
    assert "PASS (within 25%)" in trend(load(path))


@pytest.mark.parametrize(("verdict", "tolerance"), [
    (Verdict.PASS.value, None), (None, 0.10), ("unknown", 0.10),
    (Verdict.PASS.value, -0.1), (Verdict.PASS.value, 1.0),
    (Verdict.PASS.value, "invalid"),
])
def test_history_rejects_invalid_gate_fields(tmp_path: Path, verdict: str | None,
                                           tolerance: float | str | None) -> None:
    path = tmp_path / "history.jsonl"
    append(path, [record()])
    value = json.loads(path.read_text())
    value.update(verdict=verdict, tolerance=tolerance)
    with pytest.raises(ValueError, match="line 1"):
        parse(json.dumps(value))


@pytest.mark.parametrize("field", ["verdict", "tolerance"])
def test_history_requires_gate_fields(tmp_path: Path, field: str) -> None:
    path = tmp_path / "history.jsonl"
    append(path, [record()])
    value = json.loads(path.read_text())
    del value[field]
    with pytest.raises(ValueError, match="line 1"):
        parse(json.dumps(value))


@pytest.mark.parametrize(("first", "second", "expected"), [
    (1.0, 1.10, True), (1.0, 1.11, False), (0.01, 0.06, True), (0.01, 0.07, False),
    (0.0, 0.0, True),
])
def test_disk_invariance_noise(first: float, second: float, expected: bool) -> None:
    cohort = Cohort("disk", "alpine", 2, 2)
    assert invariant(first, second, cohort, "fork_first") is expected
    assert invariant(second, first, cohort, "fork_first") is expected


def test_disk_invariance_accepted_residual_applies_to_its_metric_only() -> None:
    cohort = load_cohorts()["disk-invariance"]
    assert invariant(0.595, 0.716, cohort, "snapshot_full")
    assert not invariant(0.595, 0.716, cohort, "snapshot_incremental")
    assert not invariant(0.595, 0.760, cohort, "snapshot_full")


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


def test_informational_history_and_reporting(tmp_path: Path) -> None:
    current = replace(record(median=1000), cohort="alpine-2g-raw",
                      informational=True, image_source="remote")
    path = tmp_path / "history.jsonl"
    append(path, [current])
    assert load(path) == [current]
    table = render([current], [], {("silo", "alpine-2g-raw", "image", "start"): Target(0.01, 0.10)})
    assert "alpine-2g-raw (informational)" in table
    assert "remote" in table
    assert "FAIL" not in table
    assert "(informational)" in trend([current])
    with pytest.raises(ValueError, match="informational"):
        replace(current, verdict=Verdict.FAIL, tolerance=0.10)


def test_disk_invariance_rule_is_visible() -> None:
    cohort = Cohort("disk-invariance", "alpine", 2, 2, disks=("30gib", "500gib"))
    current = replace(record(), cohort="disk-invariance/30gib")
    table = render([current], [], {}, {cohort.name: cohort})
    assert "max(0.05s, 10% of smaller median)" in table
    accepted = replace(cohort, metric_noise_absolute_seconds={"snapshot_full": 0.15})
    assert render([current], [], {}, {accepted.name: accepted}).endswith("; snapshot_full accepted up to 0.15s")


def test_create_and_run_clock_labels() -> None:
    records = [replace(record(), metric=metric, informational=metric == "create_first")
               for metric in ("create_first", "create", "run_true")]
    table = render(records, [], {})
    assert "first create, includes image pull and preparation" in table
    assert "repeated create" in table
    assert "warm run" in table


def test_fork_identity_cost_rows_are_informational_and_follow_existing_clocks() -> None:
    from silo_perf.drivers import Action, INFORMATIONAL_METRICS
    from silo_perf.scenario import SCENARIO

    added = (Action.SNAPSHOT_SOURCE_AFTER_FORKS, Action.SNAPSHOT_FORK_CHILD_FIRST,
             Action.SNAPSHOT_FORK_CHILD_SECOND)
    assert SCENARIO[-3:] == added
    assert SCENARIO.index(Action.SNAPSHOT_AFTER_RESTART) < SCENARIO.index(added[0])
    assert {action.value for action in added} <= INFORMATIONAL_METRICS
    assert not {action.value for action in added} & {key[-1] for key in load_targets()}
