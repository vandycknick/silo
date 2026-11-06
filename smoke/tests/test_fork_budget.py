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


def budget_source(silo: Silo, image: str, name: str = SOURCE) -> dict:
    """The exact cohort fixture: 4 GiB RAM, 2 GiB flat upper, witness running."""
    silo.create(name, image, "--cpus", "2", "--memory", fork_budget.RAM, "--disk-size", fork_budget.UPPER,
                "--root-profile", overlay.PROFILE, "--vsock", "--network", "private")
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
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    """One source, payload written once; every sample ends with its children
    and the source stopped, removed/pruned, so at most one 4 GiB cut exists.

    A running source keeps its accepted capture baseline, so a cut is retired
    only after that exact source run ends. The source is restarted with a new
    witness before the next sample and the observer is rebuilt on that run.
    """
    host = fork_budget.reference_host(silo)
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
            plan = json.loads((directory / "request.json").read_bytes())
            copies = sorted({disk["copy"] for disk in plan["disks"]})
            assert copies and set(copies) <= {"clone", "copy"}, plan["disks"]
            clone = copies == ["clone"]
            allowance = 0.0 if clone else allocated / rate["bytesPerSecond"]
            interruption = max(product["conservativeSeconds"], observed["hostGapSeconds"])
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
                    "dispatchToRunningSeconds": (running - call.dispatched_ns) / 1e9,
                    "apiEntryToRunningSeconds": (running - stamps[(None, "api_entered")]) / 1e9,
                    "admissionSeconds": (stamps[(None, "admission_committed")]
                                         - stamps[(None, "api_entered")]) / 1e9,
                    "sealToRunningSeconds": (running - stamps[(None, "seal_authenticated")]) / 1e9,
                    "callerEndToEndSeconds": call.caller_seconds,
                    "phases": {f"{key[0]}:{key[1]}": value for key, value in stamps.items()},
                },
                "capture": {
                    "captureId": result["captureId"], "product": product, "hostObserved": observed,
                    "interruptionSeconds": interruption, "diskCopy": copies, "cloneContract": clone,
                    "upperAllocatedBytes": allocated, "nonCowAllowanceSeconds": allowance,
                    "gatedExcessSeconds": interruption - allowance,
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


def test_fork_budget_restore_to_running(silo: Silo, restore_image: str) -> None:  # noqa: F811
    host = fork_budget.reference_host(silo)
    evidence = fork_budget.Evidence("restore", host)
    source = budget_source(silo, restore_image)
    initial = source["initial"]
    fixture = fixture_proof(silo, SOURCE, source["upper"])
    created = silo.run("snapshot", "create", SOURCE, "--live", "--name", "budget-checkpoint", timeout=600)
    value = json.loads(created.stdout)
    assert value["snapshot"]["captureKind"] == "live-execution", value
    assert value["capture"]["sourceOutcome"] == "resumed", value
    reference = "image:" + value["snapshot"]["id"]
    evidence.record("fixture.json", {**fixture, "checkpoint": value})
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
        evidence.sample({
            "cohort": cohort, "index": index, "machine": machine, "gates": ["restore"],
            "cache": cache, "space": space,
            "restore": {"dispatchToRunningSeconds": (running - dispatched) / 1e9,
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
