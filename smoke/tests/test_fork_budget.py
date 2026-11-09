"""ADR 0021 budget cohorts: full capture interruption, restore and 4-child fork.

Exact fixture, cohorts, cache method and boundaries are documented in
`silo_smoke/fork_budget.py`. Each test writes its reference-host record,
per-sample text and median/min/max summary under `SILO_SMOKE_BUDGET_EVIDENCE`
before asserting, so a failing budget still leaves its measured evidence.
Admission comes only from the isolated `capture_candidate --restore --fork`
build; a budget failure blocks qualification, it never relaxes a target.
"""
from __future__ import annotations

from collections.abc import Iterator
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import UUID

import pytest

from silo_smoke import fork, fork_budget, overlay, restore, shutdown, stopped
from silo_smoke import restore_lifecycle as lifecycle
from silo_smoke.cli import Silo, TIMINGS_PROPERTY, release
from silo_smoke.config import RUN_ROOT_PARENT, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.restore import restore_image  # noqa: F401, pytest fixture
from silo_smoke.workspace import Workspace

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]

SOURCE = "budget-source"
GIB = fork_budget.GIB


@pytest.fixture(name="silo")
def budget_silo(config: SmokeConfig, registry: LoopbackRegistry,
                request: pytest.FixtureRequest) -> Iterator[Silo]:
    supplied = os.environ.get("SILO_SMOKE_BUDGET_DIR")
    parent = Path(supplied) if supplied else None
    if parent is not None:
        assert parent.is_absolute() and parent.is_dir(), "SILO_SMOKE_BUDGET_DIR must name an existing mounted directory"
    workspace = Workspace(config, registry.ca_path, parent=parent,
                          runtime_parent=Path(RUN_ROOT_PARENT) if parent is not None else None)
    try:
        yield Silo(workspace)
    finally:
        release(workspace, failed=request.session.testsfailed > 0,
                publish=lambda summary: request.node.user_properties.append((TIMINGS_PROPERTY, summary)))


@pytest.fixture
def budget_host(silo: Silo) -> dict:
    """Probe the selected budget workspace once, before any timed operation."""
    return fork_budget.reference_host(silo)


def budget_source(silo: Silo, image: str, name: str = SOURCE) -> dict:
    """The exact cohort fixture: 4 GiB RAM, 2 GiB layered upper, witness running."""
    silo.create(name, image, "--cpus", "2", "--memory", fork_budget.RAM, "--disk-size", fork_budget.UPPER,
                "--vsock", "--network", "private")
    assert stopped.record(silo, name)["root"]["kind"] == "linux-overlay", "budget fixture is the default layered root"
    silo.start(name)
    info = silo.wait_ready(name)
    restore.require_restore_candidate(info)
    live = info["lifecycle"]["report"]["live"]
    assert live["fork"]["availability"] == {"status": "supported"}, live["fork"]
    initial = restore.start_witness(silo, name)
    upper = overlay.upper(silo, name)
    return {"name": name, "info": info, "initial": initial, "upper": upper}


def fixture_proof(silo: Silo, name: str, upper) -> dict:
    """Guest-written 1 GiB random payload, proven independently in the host upper."""
    payload = fork_budget.write_payload(silo, name)
    proof = fork_budget.upper_proof(upper)
    assert proof["logicalBytes"] == 2 * GIB, proof
    assert proof["allocatedBytes"] >= GIB and proof["nonzeroBytes"] >= GIB, proof
    return {"payload": payload, "upper": proof, "ramConfigured": fork_budget.RAM,
            "upperCapacity": fork_budget.UPPER, "network": "private", "cpus": 2,
            "image": "restore-execution (BASIC Alpine + static restore_execution.c)"}


def witness_continues(silo: Silo, name: str, initial: dict) -> None:
    current = restore.witness(silo, name)
    assert current["pid"] == initial["pid"], "child restarted the witness instead of resuming it"
    restore.advances(silo, name, current)


def ready(silo: Silo, name: str) -> bool:
    state = silo.info(name)
    return state["state"] == "running" and state["ready"] is True


def restart_source(silo: Silo, name: str) -> tuple[dict, dict]:
    """Fresh run of the same stopped source, outside any timed window.

    The populated upper (and its 1 GiB payload) is preserved. The previous
    run's witness socket, log and error file live on the persistent root; they
    are removed so a new witness process recreates them and the previous run's
    records can never be mistaken for this run's.
    """
    silo.start(name)
    info = silo.wait_ready(name)
    silo.exec(name, "rm", "-f", "/restore-execution.sock", "/restore-execution.records",
              "/restore-execution.error", user="root")
    return info, restore.start_witness(silo, name)


def test_fork_budget_full_capture_interruption_and_four_child_fork(
    silo: Silo, restore_image: str, budget_host: dict,  # noqa: F811
) -> None:
    """One source, payload written once; every sample ends with its children
    and the source stopped, removed/pruned, so at most one 4 GiB cut exists.

    A running source keeps its accepted capture baseline, so a cut is retired
    only after that exact source run ends. The source is restarted with a new
    witness before the next sample and the observer is rebuilt on that run.
    """
    host = budget_host
    reflink = host["reflinkProbe"]["reflink"]
    evidence = fork_budget.Evidence("fork4-capture", host)
    source = budget_source(silo, restore_image)
    info, initial, upper = source["info"], source["initial"], source["upper"]
    fixture = fixture_proof(silo, SOURCE, upper)
    rate = fork_budget.sequential_copy_rate(silo, upper)
    evidence.record("fixture.json", {**fixture, "sequentialCopy": rate})
    try:
        for position, (cohort, index) in enumerate(fork_budget.SCHEDULE):
            if position:
                info, initial = restart_source(silo, SOURCE)
            # Source RAM cut, four worst-case non-CoW private uppers and a margin.
            space = fork_budget.headroom(silo, 4 * GIB + fork_budget.CHILDREN * 2 * GIB + 2 * GIB)
            upper_now = fork_budget.upper_proof(upper)
            assert upper_now["nonzeroBytes"] >= GIB, "restarted source lost its payload"
            names = [f"bf-{cohort}-{index}-{child}" for child in range(fork_budget.CHILDREN)]
            # This run's own witness records; never a previous run's inode or bytes.
            observer = fork.WorkloadObserver(upper, initial["records"])
            try:
                cache = fork_budget.cache_state(silo, cohort)
                allocated = upper.stat().st_blocks * 512
                call = fork.run(silo, SOURCE, names, expect=0)
                exited = call.exited_ns
                result = call.result
                assert result is not None and result["stage"] == "finished", call.stderr
                assert result["capture"]["kind"] == "sealed" and result["source"] == {"kind": "resumed"}, result
                assert UUID(result["sourceRunId"]) == UUID(info["run_id"]), (result, info)
                assert fork.outcomes(result) == ["running"] * fork_budget.CHILDREN, result
                stamps = fork.events(silo, call.operation)
                fork.ordered_events(call, stamps, running=list(range(fork_budget.CHILDREN)))
                running = max(stamps[(child, "running")] for child in range(fork_budget.CHILDREN))
                found = fork.capture_events(silo, info["id"], result["captureId"])
                product = fork.product_interruption(found)
                observer.wait_beyond(exited)
                observed = observer.gap(call.dispatched_ns, exited)
                # The host must have seen at least the monitor's own vCPU pause.
                assert observed["hostGapSeconds"] + 0.1 >= product["vcpuPausedSeconds"], (observed, product)
            finally:
                observer.close()
            directory = fork.cut_directory(silo, call.operation)
            sealed_uppers = list((directory / "disks").glob("*.raw"))
            assert len(sealed_uppers) == 1, "root-only fixture must seal exactly one upper"
            sealed_allocated = sealed_uppers[0].stat().st_blocks * 512
            fork_seconds = (running - call.dispatched_ns) / 1e9
            fork_timing = fork_budget.gated_timing(
                fork_seconds, allocated_bytes=sealed_allocated, bytes_per_second=rate["bytesPerSecond"],
                reflink=reflink, copies=fork_budget.CHILDREN)
            interruption = max(product["conservativeSeconds"], observed["hostGapSeconds"])
            capture_timing = fork_budget.gated_timing(
                interruption, allocated_bytes=allocated, bytes_per_second=rate["bytesPerSecond"],
                reflink=reflink)
            evidence.allowance("fork4", fork_timing)
            evidence.allowance("captureInterruption", capture_timing)
            pause_stamp = found[fork.PAUSE_ESTABLISHED][0][0]
            disk_seal = [(stamp - pause_stamp) / 1e9 for stamp, _ in found[fork.DISK_SEALED]]
            ram = (directory / "memory.ram").stat()
            for child in names:
                witness_continues(silo, child, initial)
            payload = silo.exec(names[0], "sha256sum", fork_budget.PAYLOAD, user="root",
                                timeout=300).stdout.split()[0]
            assert payload == fixture["payload"]["sha256"], "child upper lacks the exact payload"
            witness_continues(silo, SOURCE, initial)
            evidence.sample({
                "cohort": cohort, "index": index, "operation": call.operation, "sourceRun": info["run_id"],
                "gates": ["fork4", "captureInterruption"], "cache": cache, "space": space, "upper": upper_now,
                "fork4": {
                    "dispatchToRunningSeconds": fork_seconds, **fork_timing,
                    "apiEntryToRunningSeconds": (running - stamps[(None, "api_entered")]) / 1e9,
                    "admissionSeconds": (stamps[(None, "admission_committed")]
                                         - stamps[(None, "api_entered")]) / 1e9,
                    "sealToRunningSeconds": (running - stamps[(None, "seal_authenticated")]) / 1e9,
                    "callerEndToEndSeconds": call.caller_seconds,
                    "phases": {f"{key[0]}:{key[1]}": value for key, value in stamps.items()},
                },
                "capture": {
                    "captureId": result["captureId"], "product": product, "hostObserved": observed,
                    "interruptionSeconds": interruption, "reflink": reflink,
                    "upperAllocatedBytes": allocated, **capture_timing,
                    "pauseToDiskSealedSeconds": disk_seal,
                    "monitorLines": {key: [line for _, line in values] for key, values in found.items()},
                    "ram": {"logicalBytes": ram.st_size, "allocatedBytes": ram.st_blocks * 512},
                },
            })
            fork.stop_and_remove(silo, names)
            stopped.stop(silo, SOURCE, require_clean=False)
            shutdown.storage_tool(silo, "prune")
            assert not directory.parent.exists(), "completed sample left its local cut"
    finally:
        # Text only: the source trace is the product-side boundary record.
        trace = fork.source_trace(silo, info["id"])
        if trace.is_file():
            (evidence.directory / "source-vm.trace.log").write_text(trace.read_text(errors="replace"))
    summary = evidence.finish()
    silo.ws.record("fork-budget-summary", json.dumps(summary, sort_keys=True) + "\n")
    assert all(summary["pass"].values()), (
        f"budget median over ADR target blocks admission; evidence: {evidence.directory}", summary["pass"])


def test_fork_budget_restore_to_running(
    silo: Silo, restore_image: str, budget_host: dict,  # noqa: F811
) -> None:
    host = budget_host
    reflink = host["reflinkProbe"]["reflink"]
    evidence = fork_budget.Evidence("restore", host)
    source = budget_source(silo, restore_image)
    initial = source["initial"]
    fixture = fixture_proof(silo, SOURCE, source["upper"])
    created = silo.run("snapshot", "create", SOURCE, "--live", "--name", "budget-checkpoint", timeout=600)
    value = json.loads(created.stdout)
    assert value["snapshot"]["captureKind"] == "live-execution", value
    assert value["capture"]["sourceOutcome"] == "resumed", value
    reference = "image:" + value["snapshot"]["id"]
    relative = Path(value["capture"]["staging"])
    assert not relative.is_absolute() and ".." not in relative.parts
    directory = silo.ws.silo_home / relative
    sealed_uppers = list((directory / "disks").glob("*.raw"))
    assert len(sealed_uppers) == 1, "root-only fixture must seal exactly one upper"
    sealed_upper = sealed_uppers[0]
    sealed_proof = fork_budget.upper_proof(sealed_upper)
    rate = fork_budget.sequential_copy_rate(silo, sealed_upper)
    evidence.record("fixture.json", {**fixture, "checkpoint": value, "sealedUpper": sealed_proof,
                                     "sequentialCopy": rate})
    for cohort, index in fork_budget.SCHEDULE:
        name = f"br-{cohort}-{index}"
        space = fork_budget.headroom(silo, 2 * GIB + 2 * GIB)
        cache = fork_budget.cache_state(silo, cohort)
        silo.ws.register_machine(name)
        args = restore.restore_argv(reference, name)
        dispatched = time.monotonic_ns()
        completed = subprocess.run([str(silo.ws.config.silo), *args], env=silo.ws.env(),
                                   capture_output=True, text=True, timeout=600)
        exited = time.monotonic_ns()
        silo.ws.record("restore", json.dumps({"args": args, "exit": completed.returncode,
                                              "stdout": completed.stdout, "stderr": completed.stderr}) + "\n")
        assert completed.returncode == 0, completed.stderr[-4000:]
        running = exited
        if not ready(silo, name):
            # Conservative: the first later Running+ready observation ends the window.
            shutdown.until(lambda: ready(silo, name), timeout=60, description=f"{name} never became Running")
            running = time.monotonic_ns()
        machine = UUID(silo.info(name)["id"]).hex
        trace = silo.ws.silo_home / "logs/machines" / machine / "vm.trace.log"
        found = lifecycle.events(trace.read_text(errors="replace"))
        prepared = lifecycle.first(found, lifecycle.PREPARED).realtime_ns
        started = lifecycle.first(found, lifecycle.STARTED).realtime_ns
        witness_continues(silo, name, initial)
        timing = fork_budget.gated_timing(
            (running - dispatched) / 1e9, allocated_bytes=sealed_proof["allocatedBytes"],
            bytes_per_second=rate["bytesPerSecond"], reflink=reflink)
        evidence.allowance("restore", timing)
        evidence.sample({
            "cohort": cohort, "index": index, "machine": machine,
            "gates": ["restore"] if cohort != "cold" or reflink else [],
            "cache": cache, "space": space,
            "restore": {"dispatchToRunningSeconds": (running - dispatched) / 1e9, **timing,
                        "callerEndToEndSeconds": (exited - dispatched) / 1e9,
                        "runningAtExit": running == exited,
                        "monitorPreparedToStartedSeconds": (started - prepared) / 1e9},
        })
        fork.stop_and_remove(silo, [name])
    summary = evidence.finish()
    silo.ws.record("restore-budget-summary", json.dumps(summary, sort_keys=True) + "\n")
    stopped.stop(silo, SOURCE, require_clean=False)
    assert all(summary["pass"].values()), (
        f"restore median over ADR target blocks admission; evidence: {evidence.directory}", summary["pass"])


@pytest.mark.parametrize(
    ("reflink", "copies", "allocated", "seconds", "expected_allowance", "expected_gated"),
    [
        (False, 1, 1024, 6.0, 4.0, 2.0),
        (False, 4, 1024, 25.0, 16.0, 9.0),
        (True, 1, 1024, 6.0, 0.0, 6.0),
        (True, 4, 1024, 25.0, 0.0, 25.0),
        (False, 1, 0, 1.0, 0.0, 1.0),
        (False, 1, 1024, 1.0, 4.0, -3.0),
    ],
)
def test_copy_allowance_arithmetic(reflink: bool, copies: int, allocated: int, seconds: float,
                                   expected_allowance: float, expected_gated: float) -> None:
    timing = fork_budget.gated_timing(
        seconds, allocated_bytes=allocated, bytes_per_second=256.0,
        reflink=reflink, copies=copies)
    assert timing["nonCowAllowanceSeconds"] == expected_allowance
    assert timing["gatedExcessSeconds"] == expected_gated
    assert timing["copyAllowance"] == {
        "lane": "reflink" if reflink else "non-reflink", "reflink": reflink,
        "upperAllocatedBytes": allocated, "privateCopies": copies,
        "copyBytes": allocated * copies, "bytesPerSecond": 256.0,
    }


@pytest.mark.parametrize("reflink", [False, True], ids=["ext4", "btrfs"])
def test_copy_allowance_summary_gates(reflink: bool) -> None:
    samples = []
    for cohort in ("cold", "warm-up", "warm"):
        for index in range(fork_budget.SAMPLES if cohort != "warm-up" else 1):
            # Raw restore exceeds 2 s; one non-CoW copy leaves exactly 2 s.
            restore_timing = fork_budget.gated_timing(
                6.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=reflink)
            # Four private copies leave 9 s against the 10 s fork4 target.
            fork_timing = fork_budget.gated_timing(
                25.0, allocated_bytes=1024, bytes_per_second=256.0,
                reflink=reflink, copies=fork_budget.CHILDREN)
            samples.append({
                "cohort": cohort, "index": index, "cache": {"label": cohort},
                "gates": ["fork4", "captureInterruption", "restore"]
                if cohort != "cold" or reflink else ["fork4", "captureInterruption"],
                "restore": {"dispatchToRunningSeconds": 6.0, **restore_timing},
                "fork4": {"dispatchToRunningSeconds": 25.0, **fork_timing},
                "capture": {"interruptionSeconds": 6.0, **restore_timing},
            })
    summary = fork_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        restored = summary["metrics"]["restore"][cohort]
        forked = summary["metrics"]["fork4"][cohort]
        captured = summary["metrics"]["captureInterruption"][cohort]
        assert restored["samples"] == fork_budget.SAMPLES
        assert restored["median"] == 6.0
        assert restored["gatedMedian"] == (6.0 if reflink else 2.0)
        assert forked["median"] == 25.0
        assert forked["gatedMedian"] == (25.0 if reflink else 9.0)
        assert captured["gatedMedian"] == (6.0 if reflink else 2.0)
        assert restored["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 4.0)
        assert forked["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 16.0)
        assert captured["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 4.0)
        assert restored["allowanceInputs"] == [restore_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert forked["allowanceInputs"] == [fork_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert captured["allowanceInputs"] == [restore_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert summary["pass"][f"fork4/{cohort}"] is (not reflink)
        assert summary["pass"][f"captureInterruption/{cohort}"] is (not reflink)
        assert restored["budgeted"] is (cohort != "cold" or reflink)
    assert summary["pass"]["restore/warm"] is (not reflink)
    if reflink:
        assert summary["pass"]["restore/cold"] is False
    else:
        assert "restore/cold" not in summary["pass"]


def test_reflink_probe_and_reference_host_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the real filesystem as the oracle, not the capture request contract."""
    source = tmp_path / "source"
    source.write_bytes(b"\xa5" * 4096)
    expected_errno = None
    with source.open("rb") as src, (tmp_path / "destination").open("wb") as dst:
        try:
            fcntl.ioctl(dst.fileno(), 0x40049409, src.fileno())
        except OSError as error:
            assert error.errno in {errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL}
            expected_errno = error.errno
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    probe = fork_budget.reflink_probe(workspace)
    assert probe == {
        "method": "FICLONE", "directory": str(workspace),
        "reflink": expected_errno is None, "errno": expected_errno,
    }
    assert list(workspace.iterdir()) == [], "probe left files in the budget workspace"
    monkeypatch.setenv(fork_budget.EVIDENCE_VARIABLE, str(tmp_path))
    evidence = fork_budget.Evidence("probe", {"reflinkProbe": probe})
    record = json.loads((evidence.directory / "reference-host.json").read_text())
    assert record["reflinkProbe"] == probe


def test_reflink_probe_rejects_missing_workspace(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fork_budget.reflink_probe(tmp_path / "missing")
