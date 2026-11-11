"""ADR 0021 live-operation and ADR 0014 prepared-create/layered-boot budgets.

Exact fixture, cohorts, cache method and boundaries are documented in
`silo_smoke/fork_budget.py` and `smoke/README.md`. Each test writes its reference-host record,
per-sample text and median/min/max summary under `SILO_SMOKE_BUDGET_EVIDENCE`
before asserting, so a failing budget still leaves its measured evidence.
Live operations run directly against the staged runtime. A budget failure
never relaxes a target.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import UUID

import pytest

from silo_smoke import fork, fork_budget, incremental, overlay, reclaim, restore, shutdown, stopped
from silo_smoke import restore_lifecycle as lifecycle
from silo_smoke.cli import RootProfile, Silo, TIMINGS_PROPERTY, release
from silo_smoke.config import RUN_ROOT_PARENT, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.incremental import incremental_image  # noqa: F401, pytest fixture
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


def budget_source(silo: Silo, image: str, name: str = SOURCE, *, require_fork: bool = True) -> dict:
    """The exact cohort fixture: 4 GiB RAM, 2 GiB layered upper, witness running."""
    silo.create(name, image, "--cpus", "2", "--memory", fork_budget.RAM, "--disk-size", fork_budget.UPPER,
                "--vsock", "--network", "private")
    assert stopped.record(silo, name)["root"]["kind"] == "linux-overlay", "budget fixture is the default layered root"
    silo.start(name)
    info = silo.wait_ready(name)
    if require_fork:
        live = info["lifecycle"]["report"]["live"]
        assert live["fork"]["availability"] == {"status": "supported"}, live["fork"]
    initial = restore.start_witness(silo, name)
    upper = overlay.upper(silo, name)
    return {"name": name, "info": info, "initial": initial, "upper": upper}


def fixture_proof(silo: Silo, name: str, upper: Path) -> dict:
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
                reflink=reflink, sealed_allocated_bytes=sealed_allocated,
                hash_bytes_per_second=host["sequentialHash"]["bytesPerSecond"])
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
                "writeback": cache["writeback"],
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
            "cache": cache, "writeback": cache["writeback"], "space": space,
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


def budget_dispatch(silo: Silo, *args: str,
                    clock: Callable[[], int] = time.monotonic_ns,
                    stderr_path: Path | None = None,
                    env: dict[str, str] | None = None) -> tuple[str, int, int]:
    """Exact CLI dispatch/exit stamps in the selected host clock, excluding evidence."""
    command = [str(silo.ws.config.silo), *args]
    environment = silo.ws.env() if env is None else env
    dispatched = clock()
    completed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=240)
    exited = clock()
    if stderr_path is not None:
        stderr_path.write_text(completed.stderr)
    silo.ws.record("budget-dispatch", json.dumps({
        "args": args, "exit": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr}) + "\n")
    assert completed.returncode == 0, completed.stderr[-4000:]
    return completed.stdout, dispatched, exited


def checkpoint_value(silo: Silo, value: dict) -> tuple[Path, dict]:
    assert value["snapshot"]["captureKind"] == "live-execution", value
    assert value["capture"]["sourceOutcome"] == "resumed", value
    relative = Path(value["capture"]["staging"])
    assert not relative.is_absolute() and ".." not in relative.parts, relative
    directory = silo.ws.silo_home / relative
    seal = json.loads((directory / "vm.capture.json").read_text())
    assert seal["captureOutcome"] == "coherent" and seal["error"] is None, seal
    return directory, seal


def remove_checkpoint(silo: Silo, alias: str, value: dict) -> None:
    silo.run("image", "remove", "image:" + alias)
    silo.run("snapshot", "remove", "image:" + value["snapshot"]["id"])


def test_fork_budget_incremental_ten_percent_dirty(
    silo: Silo, incremental_image: str, budget_host: dict,  # noqa: F811
) -> None:
    host = budget_host
    evidence = fork_budget.Evidence("incremental", host)
    # Two complete RAM outputs (staging + immutable), a private upper and
    # its published stream, plus a margin. Previous baseline already exists.
    required = 2 * 4 * GIB + 2 * 2 * GIB + 2 * GIB
    fork_budget.headroom(silo, required)
    source = budget_source(silo, incremental_image, require_fork=False)
    info, initial, upper = source["info"], source["initial"], source["upper"]
    fixture = fixture_proof(silo, SOURCE, upper)
    fixture["image"] = "incremental-memory (BASIC Alpine + incremental and execution probes)"
    dirty_bytes = 410 * 1024 * 1024
    # The existing pinned-page probe controls 96 MiB, not an arbitrary size.
    # Preallocate 410 MiB in tmpfs before the baseline, then overwrite in place.
    dirty_command = ("dd if=/dev/urandom of=/budget-dirty/payload bs=1M count=410 "
                     "conv=notrunc 2>/dev/null; stat -c %s /budget-dirty/payload; "
                     "stat -f -c %T /budget-dirty")
    silo.exec(SOURCE, "sh", "-eu", "-c",
              "mkdir /budget-dirty; mount -t tmpfs -o size=512m tmpfs /budget-dirty; "
              + dirty_command, user="root", timeout=240)
    rate = fork_budget.sequential_copy_rate(silo, upper)
    alias = "budget-incremental-baseline"
    reclaim.settled(silo, SOURCE)
    previous = json.loads(silo.run(
        "snapshot", "create", SOURCE, "--live", "--capture-policy", "incremental",
        "--name", alias, timeout=240).stdout)
    previous_directory, previous_seal = checkpoint_value(silo, previous)
    assert previous_seal["memory"]["mode"] == "full", previous_seal["memory"]
    evidence.record("fixture.json", {**fixture, "sequentialCopy": rate,
                                    "dirtyWorkloadBytes": dirty_bytes, "baseline": previous})
    try:
        for position, (cohort, index) in enumerate(fork_budget.SCHEDULE):
            space = fork_budget.headroom(silo, required)
            dirty = silo.exec(SOURCE, "sh", "-eu", "-c", dirty_command,
                              user="root", timeout=240).stdout.split()
            assert dirty == [str(dirty_bytes), "tmpfs"], dirty
            current_alias = f"budget-incremental-{cohort}-{index}"
            upper_now = fork_budget.upper_proof(upper)
            assert upper_now["nonzeroBytes"] >= GIB, upper_now
            observer = fork.WorkloadObserver(upper, restore.witness(silo, SOURCE)["records"])
            try:
                cache = fork_budget.cache_state(silo, cohort)
                allocated = upper.stat().st_blocks * 512
                stdout, dispatched, exited = budget_dispatch(
                    silo, "snapshot", "create", SOURCE, "--live", "--capture-policy", "incremental",
                    "--name", current_alias)
                value = json.loads(stdout)
                directory, seal = checkpoint_value(silo, value)
                memory = seal["memory"]
                assert memory["mode"] == "incremental" and memory["fullReason"] is None, memory
                assert memory["baseline"] == previous_seal["memory"]["ramStream"], memory
                found = fork.capture_events(silo, info["id"], value["capture"]["captureId"])
                product = fork.product_interruption(found)
                observer.wait_beyond(exited)
                observed = observer.gap(dispatched, exited)
                assert observed["hostGapSeconds"] + 0.1 >= product["vcpuPausedSeconds"], (observed, product)
            finally:
                observer.close()
            interruption = max(product["conservativeSeconds"], observed["hostGapSeconds"])
            sealed_uppers = list((directory / "disks").glob("*.raw"))
            assert len(sealed_uppers) == 1, "root-only fixture must seal exactly one upper"
            sealed_allocated = sealed_uppers[0].stat().st_blocks * 512
            timing = fork_budget.gated_timing(
                interruption, allocated_bytes=allocated, bytes_per_second=rate["bytesPerSecond"],
                reflink=host["reflinkProbe"]["reflink"], sealed_allocated_bytes=sealed_allocated,
                hash_bytes_per_second=host["sequentialHash"]["bytesPerSecond"])
            evidence.allowance("incremental", timing)
            stats = memory["stats"]
            assert stats["seedMethod"] == (
                "clone" if host["reflinkProbe"]["reflink"] else "rebuild"), stats
            assert stats["wholeFileBytesHashed"] == 0, stats
            assert stats["overlayBytesWritten"] <= stats["liveBytesRead"] <= stats["identityBytesHashed"], stats
            if host["reflinkProbe"]["reflink"]:
                assert stats["liveBytesRead"] == stats["identityBytesHashed"], stats
                assert all(stats[field] == 0 for field in (
                    "baselineBytesRead", "baselineBytesWritten", "baselineHoleBytes", "extentQueries")), stats
            else:
                assert stats["liveBytesRead"] == stats["overlayBytesWritten"], stats
            dirty_fraction = stats["identityBytesHashed"] / stats["logicalBytes"]
            pause_stamp = found[fork.PAUSE_ESTABLISHED][0][0]
            witness_continues(silo, SOURCE, initial)
            evidence.sample({
                "cohort": cohort, "index": index, "gates": ["incremental"],
                "cache": cache, "space": space, "fixture": fixture, "upper": upper_now,
                "writeback": cache["writeback"],
                "sourceRun": info["run_id"], "checkpoint": value,
                "incremental": {
                    "interruptionSeconds": interruption, **timing,
                    "callerEndToEndSeconds": (exited - dispatched) / 1e9,
                    "product": product, "hostObserved": observed,
                    "dirtyWorkloadBytes": dirty_bytes,
                    "dirtyWorkloadFraction": dirty_bytes / (4096 * 1024 * 1024),
                    "dirtyMethod": "overwrite preallocated tmpfs with dd /dev/urandom bs=1M count=410",
                    "productDirtyFraction": dirty_fraction,
                    "productDirtyFractionBasis": "memory.stats.identityBytesHashed / logicalBytes (8 MiB chunks)",
                    "memory": memory,
                    "seedProbe": host["reflinkProbe"],
                    "pauseToDiskSealedSeconds": [(stamp - pause_stamp) / 1e9
                                                for stamp, _ in found[fork.DISK_SEALED]],
                    "monitorLines": {key: [line for _, line in values] for key, values in found.items()},
                },
            })
            # Source-run leases retain staging even after publication. End the
            # run before pruning, then inherit this cut's accepted baseline
            # through restore outside the next sample's timed window.
            stopped.stop(silo, SOURCE, require_clean=False)
            silo.rm(SOURCE)
            remove_checkpoint(silo, alias, previous)
            shutdown.storage_tool(silo, "prune")
            assert not previous_directory.exists() and not directory.exists(), (
                "ended source run retained incremental staging", previous_directory, directory)
            previous, previous_seal, alias = value, seal, current_alias
            previous_directory = directory
            if position + 1 < len(fork_budget.SCHEDULE):
                info = restore.restore_child(silo, "image:" + value["snapshot"]["id"], SOURCE)
                upper = overlay.upper(silo, SOURCE)
    finally:
        trace = fork.source_trace(silo, info["id"])
        if trace.is_file():
            (evidence.directory / "source-vm.trace.log").write_text(trace.read_text(errors="replace"))
    # The last successful sample already stopped and removed its source.
    remove_checkpoint(silo, alias, previous)
    shutdown.storage_tool(silo, "prune")
    summary = evidence.finish()
    assert all(summary["pass"].values()), (str(evidence.directory), summary["pass"])


def prepared_lower(silo: Silo, image: str, name: str) -> dict:
    """A stopped keeper pins the prepared lower across per-sample pruning."""
    silo.create(name, image, "--cpus", "2", "--memory", fork_budget.RAM,
                "--disk-size", fork_budget.UPPER, "--vsock", "--network", "private")
    record = stopped.record(silo, name)
    assert record["root"]["kind"] == "linux-overlay", record
    return {"image": image, "preparedLowerKeeper": record, "ramConfigured": fork_budget.RAM,
            "upperCapacity": fork_budget.UPPER, "network": "private", "cpus": 2}


def test_fork_budget_warm_create_stopped_machine(
    silo: Silo, restore_image: str, budget_host: dict,  # noqa: F811
) -> None:
    evidence = fork_budget.Evidence("warm-create", budget_host)
    fork_budget.headroom(silo, 4 * GIB)
    fixture = prepared_lower(silo, restore_image, "budget-lower-keeper")
    evidence.record("fixture.json", fixture)
    for cohort, index in fork_budget.SCHEDULE:
        # One worst-case 2 GiB upper and 2 GiB margin, no RAM cut.
        space = fork_budget.headroom(silo, 4 * GIB)
        name = f"bc-{cohort}-{index}"
        silo.ws.register_machine(name)
        cache = fork_budget.cache_state(silo, cohort)
        _, dispatched, exited = budget_dispatch(
            silo, "create", restore_image, "--name", name, "--cpus", "2",
            "--memory", fork_budget.RAM, "--disk-size", fork_budget.UPPER,
            "--vsock", "--network", "private")
        record = stopped.record(silo, name)
        assert record["root"]["kind"] == "linux-overlay", record
        assert silo.info(name)["state"] == "stopped", record
        evidence.sample({
            "cohort": cohort, "index": index, "gates": ["warmCreate"],
            "cache": cache, "writeback": cache["writeback"], "space": space, "fixture": fixture,
            "warmCreate": {"dispatchToExitSeconds": (exited - dispatched) / 1e9,
                           "marker": "create CLI exit, machine stopped", "machine": record,
                           "nonCowAllowanceSeconds": 0.0},
        })
        silo.rm(name)
        shutdown.storage_tool(silo, "prune")
    silo.rm("budget-lower-keeper")
    shutdown.storage_tool(silo, "prune")
    summary = evidence.finish()
    assert all(summary["pass"].values()), (str(evidence.directory), summary["pass"])


def test_fork_budget_boot_layered_within_raw(
    silo: Silo, restore_image: str, budget_host: dict,  # noqa: F811
) -> None:
    evidence = fork_budget.Evidence("boot-layered-raw", budget_host)
    fork_budget.headroom(silo, 6 * GIB)
    fixture = prepared_lower(silo, restore_image, "budget-boot-keeper")
    root_profiles: tuple[RootProfile, RootProfile] = ("raw", "layered")
    images: dict[RootProfile, str] = {
        profile: silo.root_image(restore_image, profile) for profile in root_profiles}
    fixture["rootImages"] = images
    evidence.record("fixture.json", fixture)
    for position, (cohort, index) in enumerate(fork_budget.SCHEDULE):
        # Two worst-case 2 GiB private roots plus 2 GiB margin.
        space = fork_budget.headroom(silo, 6 * GIB)
        profiles: tuple[RootProfile, RootProfile] = ("raw", "layered") if position % 2 == 0 else ("layered", "raw")
        names = {profile: f"bb-{profile}-{cohort}-{index}" for profile in profiles}
        roots: dict[RootProfile, dict] = {}
        for profile in profiles:
            name = names[profile]
            silo.create(name, images[profile], "--cpus", "2", "--memory", fork_budget.RAM,
                        "--disk-size", fork_budget.UPPER, "--vsock", "--network", "private")
            roots[profile] = stopped.record(silo, name)["root"]
        assert roots["layered"]["kind"] == "linux-overlay", roots
        assert roots["raw"]["kind"] == "opaque-raw", roots
        timings: dict[str, dict] = {}
        caches: dict[str, dict] = {}
        for profile in profiles:
            name = names[profile]
            # Cold eviction is repeated before both starts, so order alone
            # cannot warm the second profile's runtime/lower inputs.
            caches[profile] = fork_budget.cache_state(silo, cohort)
            start_trace = evidence.directory / f"{name}-start.trace.log"
            _, dispatched, exited = budget_dispatch(
                silo, "start", name, clock=time.time_ns, stderr_path=start_trace,
                env=silo.ws.env(RUST_LOG="info,libvm::runtime::start_timeline=debug"))
            # Liveness only: the timed endpoint is the product's own trace,
            # not this later CLI observation (nor its polling cadence).
            info = silo.wait_ready(name, poll_interval=0.02)
            assert silo.exec(name, "sh", "-eu", "-c",
                             "test -d /etc; test -r /etc/os-release; cat /etc/os-release").stdout
            stopped.stop(silo, name, require_clean=False)
            # Stop flushes the monitor's asynchronous trace appender before
            # reading it. Preserve the full trace before removing the machine.
            trace = fork.source_trace(silo, info["id"])
            text = trace.read_text(errors="replace")
            evidence_trace = evidence.directory / f"{name}-vm.trace.log"
            evidence_trace.write_text(text)
            timings[profile] = {
                **fork_budget.boot_timing(
                    text, trace=trace, machine_id=info["id"], run_id=info["run_id"],
                    dispatched_ns=dispatched, exited_ns=exited,
                    start_text=start_trace.read_text(errors="replace"), start_trace=start_trace),
                "runId": info["run_id"], "root": roots[profile],
                "writeback": caches[profile]["writeback"],
                "traceEvidence": str(evidence_trace),
                "startTraceEvidence": str(start_trace),
            }
        # Retain both full inventories; the aggregate label must not hide a
        # partially resident profile in a nominally cold pair.
        labels = {cache["label"] for cache in caches.values()}
        cache = {"label": "partial-cold" if cohort == "cold" and labels != {"cold"}
                 else caches[profiles[0]]["label"], "profiles": caches}
        evidence.sample({
            "cohort": cohort, "index": index, "gates": ["bootLayeredRatio"],
            "cache": cache, "space": space, "fixture": fixture, "order": profiles,
            "writeback": {profile: caches[profile]["writeback"] for profile in profiles},
            "bootLayered": timings["layered"], "bootRaw": timings["raw"],
        })
        for name in names.values():
            silo.rm(name)
        shutdown.storage_tool(silo, "prune")
    silo.rm("budget-boot-keeper")
    shutdown.storage_tool(silo, "prune")
    summary = evidence.finish()
    assert all(summary["pass"].values()), (str(evidence.directory), summary["pass"])


def test_quiesce_writeback_real_meminfo_record() -> None:
    record = fork_budget.quiesce_writeback(timeout_seconds=0)
    assert set(record) == {"dirtyBytesBefore", "dirtyBytesAtDispatch", "waitedSeconds"}
    assert isinstance(record["dirtyBytesBefore"], int) and record["dirtyBytesBefore"] >= 0
    assert isinstance(record["dirtyBytesAtDispatch"], int) and record["dirtyBytesAtDispatch"] >= 0
    assert isinstance(record["waitedSeconds"], float) and record["waitedSeconds"] >= 0
    assert fork_budget.writeback_bytes(Path("/proc/meminfo").read_text()) >= 0


@pytest.mark.parametrize(
    ("dirty_kib", "writeback_kib", "timeout", "waits"),
    [(15360, 0, 1.0, False), (15360, 1024, 0.01, True),
     (16384, 1, 0.01, True), (16384, 0, 0.0, True)],
    ids=["below-threshold", "at-threshold", "above-threshold", "at-timeout"],
)
def test_quiesce_writeback_threshold_and_timeout(
    tmp_path: Path, dirty_kib: int, writeback_kib: int, timeout: float, waits: bool,
) -> None:
    # A real file supplies a stable parsed counter, not a mocked clock or proc read.
    text = (f"MemTotal: 1048576 kB\nDirty: {dirty_kib} kB\n"
            f"Writeback: {writeback_kib} kB\nWritebackTmp: 999999 kB\n")
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(text)
    expected = (dirty_kib + writeback_kib) * 1024
    assert fork_budget.writeback_bytes(text) == expected
    record = fork_budget.quiesce_writeback(meminfo=meminfo, timeout_seconds=timeout)
    assert record["dirtyBytesBefore"] == record["dirtyBytesAtDispatch"] == expected
    if waits:
        assert record["waitedSeconds"] >= timeout
    else:
        assert record["waitedSeconds"] < timeout


@pytest.mark.parametrize("text", [
    "", "Dirty: 1 kB\n", "Dirty: -1 kB\nWriteback: 0 kB\n",
    "Dirty: 1 MB\nWriteback: 0 kB\n", "Dirty: invalid kB\nWriteback: 0 kB\n",
    "Dirty: 1 kB\nDirty: 2 kB\nWriteback: 0 kB\n",
], ids=["empty", "missing-counter", "negative", "wrong-unit", "not-integer", "duplicate"])
def test_quiesce_writeback_rejects_invalid_meminfo(text: str) -> None:
    with pytest.raises(ValueError):
        fork_budget.writeback_bytes(text)


def test_hash_rate_probe_uses_warm_second_pass(tmp_path: Path) -> None:
    size = 8 * 1024 * 1024 + 17
    probe = fork_budget.sequential_hash_rate(tmp_path / "hash-probe", size_bytes=size)
    assert probe["bytes"] == size
    assert probe["method"] == (
        "hashlib.sha256 (OpenSSL), 8 MiB reads twice, fresh /dev/urandom + fsync, "
        "no eviction; warm second pass")
    cold, warm = probe["passes"]
    assert [cold["label"], warm["label"]] == ["cold", "warm"]
    assert cold["sha256"] == warm["sha256"] == probe["sha256"]
    assert len(probe["sha256"]) == 64
    assert probe["seconds"] == warm["seconds"]
    assert probe["bytesPerSecond"] == warm["bytesPerSecond"] == size / warm["seconds"]
    assert probe["cache"] == warm["cache"]
    for measured in (cold, warm):
        assert measured["seconds"] > 0
        assert measured["bytesPerSecond"] == size / measured["seconds"]
        assert measured["cache"]["method"] == "mincore only, no eviction"
        assert measured["cache"]["logicalBytes"] == size
        assert measured["cacheAfter"]["residentBytesAfter"] == size
    assert warm["cache"]["residentBytesBefore"] == warm["cache"]["residentBytesAfter"] == size
    assert list(tmp_path.iterdir()) == [], "hash probe left scratch files behind"


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
    assert timing["diskSealAllowanceSeconds"] == 0.0
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
            capture_timing = fork_budget.gated_timing(
                6.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=reflink,
                sealed_allocated_bytes=512, hash_bytes_per_second=512.0)
            samples.append({
                "cohort": cohort, "index": index, "cache": {"label": cohort},
                "gates": ["fork4", "captureInterruption", "restore"]
                if cohort != "cold" or reflink else ["fork4", "captureInterruption"],
                "restore": {"dispatchToRunningSeconds": 6.0, **restore_timing},
                "fork4": {"dispatchToRunningSeconds": 25.0, **fork_timing},
                "capture": {"interruptionSeconds": 6.0, **capture_timing},
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
        assert captured["gatedMedian"] == (5.0 if reflink else 1.0)
        assert restored["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 4.0)
        assert forked["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 16.0)
        assert captured["nonCowAllowanceSeconds"]["median"] == (0.0 if reflink else 4.0)
        assert captured["diskSealAllowanceSeconds"]["median"] == 1.0
        assert captured["diskSealAllowanceInputs"] == [
            capture_timing["diskSealAllowance"]] * fork_budget.SAMPLES
        assert "diskSealAllowanceSeconds" not in restored
        assert "diskSealAllowanceSeconds" not in forked
        assert restored["allowanceInputs"] == [restore_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert forked["allowanceInputs"] == [fork_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert captured["allowanceInputs"] == [capture_timing["copyAllowance"]] * fork_budget.SAMPLES
        assert summary["pass"][f"fork4/{cohort}"] is (not reflink)
        assert summary["pass"][f"captureInterruption/{cohort}"] is True
        assert restored["budgeted"] is (cohort != "cold" or reflink)
    assert summary["pass"]["restore/warm"] is (not reflink)
    if reflink:
        assert summary["pass"]["restore/cold"] is False
    else:
        assert "restore/cold" not in summary["pass"]


@pytest.mark.parametrize("reflink", [False, True], ids=["copy", "reflink"])
@pytest.mark.parametrize("metric,record,target", [
    ("incremental", "incremental", 1.0), ("captureInterruption", "capture", 5.0),
])
@pytest.mark.parametrize("over", [0.0, 0.0000001], ids=["boundary", "over"])
def test_interruption_budget_gate_copy_allowance_and_disk_sealing(
    reflink: bool, metric: str, record: str, target: float, over: float,
) -> None:
    allowance = 0.0 if reflink else 4.0
    excess = target + over
    seconds = excess + allowance + 2.0
    timing = fork_budget.gated_timing(
        seconds, allocated_bytes=1024, bytes_per_second=256.0, reflink=reflink,
        sealed_allocated_bytes=1024, hash_bytes_per_second=512.0)
    samples = [{
        "cohort": cohort, "index": index, "cache": {"label": cohort}, "gates": [metric],
        record: {"interruptionSeconds": seconds, **timing},
    } for cohort, index in fork_budget.SCHEDULE]
    summary = fork_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        measured = summary["metrics"][metric][cohort]
        assert measured["samples"] == fork_budget.SAMPLES
        assert measured["median"] == seconds
        assert measured["gatedMedian"] == pytest.approx(excess)
        assert measured["nonCowAllowanceSeconds"]["median"] == allowance
        assert measured["allowanceInputs"] == [timing["copyAllowance"]] * fork_budget.SAMPLES
        assert measured["diskSealAllowanceSeconds"]["median"] == 2.0
        assert measured["diskSealAllowanceInputs"] == [
            timing["diskSealAllowance"]] * fork_budget.SAMPLES
        assert measured["budgeted"] is True
        assert summary["pass"][f"{metric}/{cohort}"] is (over == 0.0)


@pytest.mark.parametrize("reflink", [False, True], ids=["copy", "reflink"])
@pytest.mark.parametrize("sealed_bytes", [0, 1024], ids=["no-seal", "seal"])
@pytest.mark.parametrize("rate", [0.0, -1.0, float("nan")], ids=["zero", "negative", "nan"])
def test_hash_rate_rejects_invalid_rate(reflink: bool, sealed_bytes: int, rate: float) -> None:
    with pytest.raises(ValueError, match="hash_bytes_per_second must be positive"):
        fork_budget.gated_timing(
            5.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=reflink,
            sealed_allocated_bytes=sealed_bytes, hash_bytes_per_second=rate)


def test_hash_rate_required_for_disk_sealing() -> None:
    with pytest.raises(ValueError, match="sealed allocated bytes require hash_bytes_per_second"):
        fork_budget.gated_timing(
            5.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=True,
            sealed_allocated_bytes=1024)


def test_budget_gate_disk_seal_allowance_not_clamped() -> None:
    timing = fork_budget.gated_timing(
        1.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=False,
        sealed_allocated_bytes=512, hash_bytes_per_second=256.0)
    assert timing["nonCowAllowanceSeconds"] == 4.0
    assert timing["diskSealAllowanceSeconds"] == 2.0
    assert timing["gatedExcessSeconds"] == -5.0


@pytest.mark.parametrize("seconds", [2.0, 2.0000001], ids=["boundary", "over"])
def test_warm_create_budget_gate(seconds: float) -> None:
    samples = [{
        "cohort": cohort, "index": index, "cache": {"label": cohort}, "gates": ["warmCreate"],
        "warmCreate": {"dispatchToExitSeconds": seconds},
    } for cohort, index in fork_budget.SCHEDULE]
    summary = fork_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        metric = summary["metrics"]["warmCreate"][cohort]
        assert metric["median"] == metric["gatedMedian"] == seconds
        assert metric["budgeted"] is True
        assert summary["pass"][f"warmCreate/{cohort}"] is (seconds <= 2.0)


@pytest.mark.parametrize("ratio", [1.2, 1.2000001], ids=["boundary", "over"])
def test_boot_layered_ratio_budget_gate(ratio: float) -> None:
    samples = [{
        "cohort": cohort, "index": index, "cache": {"label": cohort}, "gates": ["bootLayeredRatio"],
        "bootLayered": {"dispatchToReadySeconds": ratio * 10.0},
        "bootRaw": {"dispatchToReadySeconds": 10.0},
    } for cohort, index in fork_budget.SCHEDULE]
    summary = fork_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        metric = summary["metrics"]["bootLayeredRatio"][cohort]
        assert metric["median"] == metric["gatedMedian"] == ratio
        assert metric["budgeted"] is True
        assert summary["pass"][f"bootLayeredRatio/{cohort}"] is (ratio <= 1.2)
        for raw_metric in ("bootLayered", "bootRaw"):
            assert summary["metrics"][raw_metric][cohort]["budgeted"] is False
            assert f"{raw_metric}/{cohort}" not in summary["pass"]


def test_boot_layered_ratio_budget_gate_uses_ratio_of_medians() -> None:
    raw = [1.0, 2.0, 10.0, 20.0, 100.0]
    layered = [1.0, 2.0, 12.0, 20.0, 100.0]
    samples = [{
        "cohort": cohort, "index": index, "cache": {"label": cohort}, "gates": ["bootLayeredRatio"],
        "bootLayered": {"dispatchToReadySeconds": layered[index]},
        "bootRaw": {"dispatchToReadySeconds": raw[index]},
    } for cohort in ("cold", "warm") for index in range(fork_budget.SAMPLES)]
    summary = fork_budget.summarize(samples)
    for cohort in ("cold", "warm"):
        metric = summary["metrics"]["bootLayeredRatio"][cohort]
        assert metric["median"] == 1.2
        assert sorted(metric["values"])[2] == 1.0, "paired-ratio median is not the ADR gate"
        assert summary["pass"][f"bootLayeredRatio/{cohort}"] is True


BOOT_MACHINE_ID = "4c6f6355-3a10-4b63-a606-fc6e47e6dd52"
BOOT_TRACE = "\n".join([
    "malformed line silo-vmm readiness changed ready=true",
    f"1970-01-01T00:00:01.100Z INFO silo-vmm generation started machine_id={BOOT_MACHINE_ID} run_id=run",
    f'1970-01-01T00:00:01.150Z INFO silo-vmm starting instance="a machine" machine_id={BOOT_MACHINE_ID}',
    '1970-01-01T00:00:01.200Z INFO starting primary VM after probe release event="primary_vm_spawn"',
    "1970-01-01T00:00:01.300Z INFO krun worker spawned worker_pid=42",
    f"1970-01-01T00:00:01.400Z INFO vm state changed machine_id={BOOT_MACHINE_ID} previous=Starting current=Running",
    f'1970-01-01T00:00:01.500Z INFO guest agent became responsive machine_id={BOOT_MACHINE_ID} agent_instance_id=Some("instance") agent_boot_id=Some("boot")',
    f"1970-01-01T00:00:01.600Z INFO guest agent status changed machine_id={BOOT_MACHINE_ID} current=Some(Ready)",
    f"1970-01-01T00:00:01.620Z INFO silo-vmm readiness changed machine_id={BOOT_MACHINE_ID} ready=false reason=GuestStarting",
    f"1970-01-01T00:00:01.650000001Z INFO silo-vmm readiness changed machine_id={BOOT_MACHINE_ID} ready=true reason=GuestReportedReady",
    f"1970-01-01T00:00:01.900Z INFO guest agent became responsive machine_id={BOOT_MACHINE_ID}",
])


# Verbatim excerpts from the Phase 24 deferred-ext4 runtime evidence:
# incremental-20261109T112106Z/source-vm.trace.log and
# boot-layered-raw-20261109T112408Z/bb-raw-cold-0-vm.trace.log.
BOOT_RESTORED_TRACE = """\
2026-11-09T11:22:39.200029Z  INFO silo-vmm generation started event="generation_start" machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 run_id=43d1e890-16ef-49d5-b836-3154c8581648
2026-11-09T11:22:39.222933Z  INFO silo-vmm starting instance=budget-source machine_id="4c6f6355-3a10-4b63-a606-fc6e47e6dd52" agent_enabled=true
2026-11-09T11:22:39.223891Z  INFO starting primary VM after probe release event="primary_vm_spawn"
2026-11-09T11:22:39.225309Z  INFO krun worker spawned worker_pid=3042461
2026-11-09T11:22:39.249981Z  INFO silo-vmm readiness changed instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 previous_ready=false ready=false previous_reason=VmRestoring reason=VmActivating
2026-11-09T11:22:39.261201Z  INFO guest agent became responsive instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 agent_instance_id=Some("4fb82f95-f2ee-4b68-87d9-69084e91f2bf") agent_version=Some("0.1.0") agent_boot_id=Some("0fe0fce4-c0b8-4ad7-81fc-95ebdf74a0b6")
2026-11-09T11:22:39.261209Z  INFO guest agent status changed instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 previous=None current=Some(Starting) code=Some("WORKLOAD_NOT_READY") Some("workload lifecycle is not ready")
2026-11-09T11:22:39.291091Z  INFO vm state changed instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 previous=Activating current=Running Some("vm running")
2026-11-09T11:22:39.302868Z  INFO guest agent status changed instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 previous=Some(Starting) current=Some(Ready) code=None None
2026-11-09T11:22:39.302879Z  INFO silo-vmm readiness changed instance=budget-source machine_id=4c6f6355-3a10-4b63-a606-fc6e47e6dd52 previous_ready=false ready=true previous_reason=GuestStarting reason=GuestReportedReady
"""
BOOT_FRESH_TRACE = """\
2026-11-09T11:24:12.703357Z  INFO silo-vmm generation started event="generation_start" machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f run_id=2906f38b-e12a-4cae-8391-c26fbb1a1b1f
2026-11-09T11:24:12.726124Z  INFO silo-vmm starting instance=bb-raw-cold-0 machine_id="5f1c868c-3e4a-4ea3-8de0-adc42eaae40f" agent_enabled=true
2026-11-09T11:24:12.726623Z  INFO starting primary VM after probe release event="primary_vm_spawn"
2026-11-09T11:24:12.727906Z  INFO krun worker spawned worker_pid=3044184
2026-11-09T11:24:12.748612Z  INFO vm state changed instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f previous=Starting current=Running Some("vm running")
2026-11-09T11:24:12.748622Z  INFO silo-vmm readiness changed instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f previous_ready=false ready=false previous_reason=VmStarting reason=AgentUnavailable
2026-11-09T11:24:12.957588Z  INFO guest agent became responsive instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f agent_instance_id=Some("533c0191-55ad-4fc0-a5f7-1af48679eb9a") agent_version=Some("0.1.0") agent_boot_id=Some("363c01f3-c913-4c07-97c8-d26ebe49931d")
2026-11-09T11:24:12.957600Z  INFO guest agent status changed instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f previous=None current=Some(Starting) code=Some("SSH_NOT_READY") Some("SSH listener verification pending")
2026-11-09T11:24:12.968507Z  INFO guest agent status changed instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f previous=Some(Starting) current=Some(Ready) code=None None
2026-11-09T11:24:12.968512Z  INFO silo-vmm readiness changed instance=bb-raw-cold-0 machine_id=5f1c868c-3e4a-4ea3-8de0-adc42eaae40f previous_ready=false ready=true previous_reason=GuestStarting reason=GuestReportedReady
"""


@pytest.mark.parametrize("compact_id", [True, False], ids=["cli-hex", "monitor-uuid"])
@pytest.mark.parametrize(("text", "machine_id", "run_id", "response_delta_ns"), [
    (BOOT_RESTORED_TRACE, BOOT_MACHINE_ID, "43d1e890-16ef-49d5-b836-3154c8581648", 61_172_000),
    (BOOT_FRESH_TRACE, "5f1c868c-3e4a-4ea3-8de0-adc42eaae40f",
     "2906f38b-e12a-4cae-8391-c26fbb1a1b1f", 254_231_000),
], ids=["restored-source", "fresh-boot"])
def test_boot_layered_trace_real_runtime_selects_machine_and_run(
    text: str, machine_id: str, run_id: str, response_delta_ns: int, compact_id: bool,
) -> None:
    generation = lifecycle.events(text, names=("silo-vmm generation started",))[0]
    assert generation.fields == {
        "event": "generation_start", "machine_id": machine_id, "run_id": run_id,
    }
    other_run = text.replace(run_id, "00000000-0000-0000-0000-000000000001")
    other_machine = text.replace(machine_id, "00000000-0000-0000-0000-000000000002")
    trace = Path("logs/machines") / UUID(machine_id).hex / "vm.trace.log"
    dispatched = generation.realtime_ns - 1_000_000
    timing = fork_budget.boot_timing(
        "\n".join([other_run, other_machine, text, other_run, other_machine]),
        trace=trace, machine_id=UUID(machine_id).hex if compact_id else machine_id,
        run_id=run_id, dispatched_ns=dispatched, exited_ns=generation.realtime_ns)
    assert timing["marker"]["line"] == next(
        line for line in text.splitlines() if "guest agent became responsive" in line)
    assert timing["marker"]["realtimeNs"] == generation.realtime_ns + response_delta_ns
    assert timing["dispatchToReadySeconds"] == (response_delta_ns + 1_000_000) / 1e9
    assert set(timing["availablePhases"]) == {phase for phase, _, _ in fork_budget.BOOT_PHASES}


def test_boot_layered_trace_marker_and_phase_deltas() -> None:
    timing = fork_budget.boot_timing(
        BOOT_TRACE, trace=Path("logs/machines/machine/vm.trace.log"),
        machine_id=BOOT_MACHINE_ID, run_id="run", dispatched_ns=1_000_000_000, exited_ns=1_250_000_000)
    assert timing["dispatchToReadySeconds"] == 0.5
    assert timing["callerEndToEndSeconds"] == 0.25
    marker = timing["marker"]
    assert marker["source"] == "logs/machines/machine/vm.trace.log"
    assert marker["realtimeNs"] == 1_500_000_000
    assert "guest agent became responsive" in marker["linePattern"]
    assert "CLOCK_REALTIME" in marker["clock"]
    assert timing["availablePhases"] == [phase for phase, _, _ in fork_budget.BOOT_PHASES]
    assert timing["unavailablePhases"] == ["kernelStart", "initramfs", "rootSwitch"]
    phases = timing["phases"]
    assert sum(phase["previousPhaseToPhaseSeconds"] for phase in phases) == pytest.approx(0.650000001)
    assert phases[-1]["previousPhase"] == "agentReportedReady"
    assert phases[-1]["previousPhaseToPhaseSeconds"] == 0.050000001
    assert phases[-1]["dispatchToPhaseSeconds"] == 0.650000001
    assert phases[-1]["line"].endswith("ready=true reason=GuestReportedReady")


def test_boot_layered_trace_selects_exact_generation() -> None:
    earlier = BOOT_TRACE.replace("run_id=run", "run_id=old")
    later = BOOT_TRACE.replace("run_id=run", "run_id=later")
    timing = fork_budget.boot_timing(
        earlier + "\n" + BOOT_TRACE + "\n" + later, trace=Path("vm.trace.log"),
        machine_id=BOOT_MACHINE_ID, run_id="run", dispatched_ns=1_000_000_000, exited_ns=1_250_000_000)
    assert timing["dispatchToReadySeconds"] == 0.5


def test_boot_layered_trace_lists_unavailable_phases() -> None:
    text = "\n".join(line for line in BOOT_TRACE.splitlines()
                     if "generation started" in line or "guest agent became responsive" in line)
    timing = fork_budget.boot_timing(
        text, trace=Path("vm.trace.log"), machine_id=BOOT_MACHINE_ID, run_id="run",
        dispatched_ns=1_000_000_000, exited_ns=1_250_000_000)
    assert timing["availablePhases"] == ["monitorGenerationStart", "agentResponsive"]
    assert "workerSpawn" in timing["unavailablePhases"]
    assert timing["phases"][-1]["previousPhase"] == "monitorGenerationStart"
    assert timing["phases"][-1]["previousPhaseToPhaseSeconds"] == 0.4


@pytest.mark.parametrize("text", [
    "", "not a trace",
    BOOT_TRACE.replace("guest agent became responsive", "guest agent connection lost"),
    BOOT_TRACE.replace("guest agent became responsive", "guest agent became responsive without fields"),
    BOOT_TRACE.replace("run_id=run", "run_id=other"),
    BOOT_TRACE.replace(f"machine_id={BOOT_MACHINE_ID}", "machine_id=other"),
    BOOT_TRACE.replace(f"guest agent became responsive machine_id={BOOT_MACHINE_ID}",
                       "guest agent became responsive machine_id=other"),
    BOOT_TRACE + "\n" + BOOT_TRACE,
    # A subsequent generation's serving event must not satisfy this run.
    BOOT_TRACE.replace("guest agent became responsive", "guest agent connection lost") + "\n"
    + BOOT_TRACE.replace("run_id=run", "run_id=later"),
], ids=["empty", "malformed", "not-serving", "malformed-serving", "wrong-run", "wrong-machine",
        "wrong-serving-machine", "duplicate-generation", "next-generation-serving"])
def test_boot_layered_trace_rejects_missing_or_ambiguous_marker(text: str) -> None:
    with pytest.raises(AssertionError):
        fork_budget.boot_timing(
            text, trace=Path("vm.trace.log"), machine_id=BOOT_MACHINE_ID, run_id="run",
            dispatched_ns=1_000_000_000, exited_ns=1_250_000_000)


def test_boot_layered_trace_rejects_wall_clock_reversal() -> None:
    with pytest.raises(AssertionError, match="CLOCK_REALTIME moved backwards"):
        fork_budget.boot_timing(
            BOOT_TRACE, trace=Path("vm.trace.log"), machine_id=BOOT_MACHINE_ID, run_id="run",
            dispatched_ns=2_000_000_000, exited_ns=2_250_000_000)


def test_evidence_budget_gate_custom_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(fork_budget.EVIDENCE_VARIABLE, str(tmp_path))

    def summary(samples: list[dict]) -> dict:
        return {"count": len(samples)}

    def markdown(value: dict, host: dict) -> str:
        return f"{host['name']}: {value['count']}\n"

    evidence = fork_budget.Evidence("custom", {"name": "host"}, summarize=summary, markdown=markdown)
    evidence.sample({"value": 1})
    assert evidence.finish() == {"count": 1}
    assert json.loads((evidence.directory / "summary.json").read_text()) == {"count": 1}
    assert (evidence.directory / "summary.md").read_text() == "host: 1\n"
    assert json.loads((evidence.directory / "samples.jsonl").read_text()) == {"value": 1}


def test_budget_gate_records_separate_allowances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(fork_budget.EVIDENCE_VARIABLE, str(tmp_path))
    host = {"sequentialHash": {"bytesPerSecond": 512.0}}
    evidence = fork_budget.Evidence("allowances", host)
    timing = fork_budget.gated_timing(
        7.0, allocated_bytes=1024, bytes_per_second=256.0, reflink=False,
        sealed_allocated_bytes=1024, hash_bytes_per_second=host["sequentialHash"]["bytesPerSecond"])
    evidence.allowance("incremental", timing)
    evidence.sample({"incremental": {"interruptionSeconds": 7.0, **timing}})
    record = json.loads((evidence.directory / "reference-host.json").read_text())
    assert record["sequentialHash"] == host["sequentialHash"]
    assert record["nonCowAllowances"]["incremental"] == {
        **timing["copyAllowance"], "nonCowAllowanceSeconds": 4.0,
    }
    assert record["diskSealAllowances"]["incremental"] == {
        **timing["diskSealAllowance"], "diskSealAllowanceSeconds": 2.0,
    }
    sample = json.loads((evidence.directory / "samples.jsonl").read_text())["incremental"]
    assert sample["interruptionSeconds"] == 7.0
    assert sample["nonCowAllowanceSeconds"] == 4.0
    assert sample["diskSealAllowanceSeconds"] == 2.0
    assert sample["gatedExcessSeconds"] == 1.0


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


# The production formatter's UTC, no-target, no-ANSI structured line shape.
# Timing values are a deterministic parser fixture, not benchmark measurements.
START_TIMELINE_SAMPLE = (
    f"1970-01-01T00:00:01.090000Z DEBUG machine start timeline machine_id={BOOT_MACHINE_ID} "
    'run_id="run" runtime_discovery_ms=10.25 catalog_open_recovery_ms=20.5 '
    "lifecycle_admission_ms=5.0 lower_resolve_authentication_ms=4.25 secrets_netd_ms=30.0 "
    "launch_publication_ms=5.0 durability_barrier_ms=10.0 admit_spawn_ms=4.0 total_ms=90.0"
)


def test_start_timeline_parser_selects_machine_and_run() -> None:
    other_run = START_TIMELINE_SAMPLE.replace('run_id="run"', 'run_id="old"')
    other_machine = START_TIMELINE_SAMPLE.replace(BOOT_MACHINE_ID, str(UUID(int=1)))
    timeline = fork_budget.start_timeline(
        "\n".join(["malformed", other_run, other_machine, START_TIMELINE_SAMPLE]),
        source=Path("start.trace.log"), machine_id=UUID(BOOT_MACHINE_ID).hex, run_id="run")
    assert timeline["machineId"] == BOOT_MACHINE_ID
    assert timeline["runId"] == "run"
    assert timeline["totalMilliseconds"] == 90.0
    assert timeline["stagesMilliseconds"] == {
        "runtime_discovery": 10.25, "catalog_open_recovery": 20.5,
        "lifecycle_admission": 5.0, "lower_resolve_authentication": 4.25,
        "secrets_netd": 30.0, "launch_publication": 5.0,
        "durability_barrier": 10.0, "admit_spawn": 4.0,
    }
    assert timeline["marker"]["line"] == START_TIMELINE_SAMPLE
    assert timeline["marker"]["source"] == "start.trace.log"


@pytest.mark.parametrize("text", [
    "", "not a trace", START_TIMELINE_SAMPLE + "\n" + START_TIMELINE_SAMPLE,
    START_TIMELINE_SAMPLE.replace("admit_spawn_ms=4.0 ", ""),
    START_TIMELINE_SAMPLE.replace("admit_spawn_ms=4.0", "admit_spawn_ms=invalid"),
    START_TIMELINE_SAMPLE.replace("admit_spawn_ms=4.0", "admit_spawn_ms=NaN"),
    START_TIMELINE_SAMPLE.replace("admit_spawn_ms=4.0", "admit_spawn_ms=inf"),
    START_TIMELINE_SAMPLE.replace("admit_spawn_ms=4.0", "admit_spawn_ms=-1"),
    START_TIMELINE_SAMPLE.replace("total_ms=90.0", "total_ms=1.0"),
], ids=["empty", "malformed", "duplicate", "missing-stage", "invalid", "nan", "infinite",
        "negative", "inconsistent-total"])
def test_start_timeline_parser_rejects_invalid_durations(text: str) -> None:
    with pytest.raises(AssertionError):
        fork_budget.start_timeline(
            text, source=Path("start.trace.log"), machine_id=BOOT_MACHINE_ID, run_id="run")


def test_start_timeline_boot_sample_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(fork_budget.EVIDENCE_VARIABLE, str(tmp_path))
    timing = fork_budget.boot_timing(
        BOOT_TRACE, trace=Path("vm.trace.log"), machine_id=BOOT_MACHINE_ID, run_id="run",
        dispatched_ns=1_000_000_000, exited_ns=1_250_000_000,
        start_text=START_TIMELINE_SAMPLE, start_trace=Path("start.trace.log"))
    evidence = fork_budget.Evidence("start-timeline", {})
    evidence.sample({"cohort": "warm", "index": 0, "bootRaw": timing, "bootLayered": timing})
    sample = json.loads((evidence.directory / "samples.jsonl").read_text())
    for profile in ("bootRaw", "bootLayered"):
        assert sample[profile]["startTimeline"]["stagesMilliseconds"]["secrets_netd"] == 30.0
        assert sample[profile]["startTimeline"]["marker"]["line"] == START_TIMELINE_SAMPLE
        assert sample[profile]["dispatchToReadySeconds"] == 0.5
