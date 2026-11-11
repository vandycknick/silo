"""Phase 20 functional gates against the staged runtime, not timing budgets."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from silo_smoke import capture, fork, incremental, overlay, pause, procs, reclaim, restore, shutdown, stopped
from silo_smoke.cli import Silo
from silo_smoke.config import REPO
from silo_smoke.incremental import incremental_image  # noqa: F401, pytest fixture

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]
SOURCE = "incremental-source"


def create(silo: Silo, image: str, *, start: bool = True) -> None:
    silo.create(SOURCE, image, "--cpus", "2", "--memory", "512mib", "--disk-size", "512mib",
                "--vsock", "--network", "none")
    if start:
        silo.start(SOURCE)
        silo.wait_ready(SOURCE)


def test_incremental_fork_preserves_pause_and_child_baseline(
    silo: Silo, incremental_image: str,  # noqa: F811
) -> None:
    create(silo, incremental_image)
    initial = incremental.witness(silo, SOURCE, "start")
    reclaim.settled(silo, SOURCE)
    baseline = restore.checkpoint(silo, SOURCE, alias="fork-baseline")
    baseline_map = incremental.authenticated_map(silo, baseline, mode="full", reason="no-baseline")["map"]
    source = silo.info(SOURCE)
    child = "incremental-fork-child"
    call = fork.run(silo, SOURCE, [child], "--preserve", expect=0)
    assert fork.outcomes(call.result) == ["running"]
    assert silo.info(SOURCE)["lifecycle"]["lifecycle"]["currentPause"] == source["lifecycle"]["lifecycle"]["currentPause"]
    cut = fork.cut(silo, call, source, baseline.boot_id, baseline.generation)
    memory = cut.seal["memory"]
    assert memory["mode"] == "incremental" and memory["fullReason"] is None
    assert memory["baseline"] == baseline.seal["memory"]["ramStream"]
    assert memory["ramStream"] == baseline.seal["memory"]["ramStream"]
    assert json.loads((cut.staging / "memory.map.json").read_bytes()) == baseline_map
    assert incremental.witness(silo, child, previous=initial) == initial
    changed = incremental.witness(silo, child, "first", previous=initial)
    saved = restore.checkpoint(silo, child, alias="fork-child-incremental")
    incremental.authenticated_map(silo, saved, mode="incremental", baseline=cut, baseline_map=baseline_map)
    incremental.pages_at_cut(silo, saved, changed)


def test_cpu_host_dma_zero_and_first_child_inherited_incremental(
    silo: Silo, incremental_image: str,  # noqa: F811
) -> None:
    create(silo, incremental_image)
    initial = incremental.witness(silo, SOURCE, "start")
    execution = restore.start_witness(silo, SOURCE)
    restore.witness(silo, SOURCE, "arm")
    reclaim.settled(silo, SOURCE)
    base = restore.checkpoint(silo, SOURCE, alias="incremental-base")
    incremental.authenticated_map(silo, base, mode="full", reason="no-baseline")
    incremental.pages_at_cut(silo, base, initial)
    silo.run("resume", SOURCE)

    first_pages = incremental.witness(silo, SOURCE, "first", previous=initial)
    first = restore.checkpoint(silo, SOURCE, alias="incremental-first")
    facts = incremental.authenticated_map(silo, first, mode="incremental", baseline=base)
    # CPU stores and O_DIRECT block DMA into the two exact pinned pages both
    # changed independently read RAM bytes, not merely receipt counters.
    changed = incremental.pages_at_cut(silo, first, {**first_pages, "pages": first_pages["pages"][:2]})
    assert changed <= facts["affected"]
    cut = restore.matched_cut(silo, first, execution, profile="layered")
    silo.run("resume", SOURCE)
    restore.resumed(silo, SOURCE, execution, cut)

    second_pages = incremental.witness(silo, SOURCE, "second", previous=initial)
    second = restore.checkpoint(silo, SOURCE, alias="incremental-second")
    facts = incremental.authenticated_map(silo, second, mode="incremental", baseline=first)
    assert incremental.pages_at_cut(silo, second, {**second_pages, "pages": second_pages["pages"][:2]}) <= facts["affected"]
    silo.run("resume", SOURCE)
    restore.witness(silo, SOURCE, "arm")
    zero_pages = incremental.witness(silo, SOURCE, "zero", previous=second_pages)
    zero = restore.checkpoint(silo, SOURCE, alias="incremental-zero")
    facts = incremental.authenticated_map(silo, zero, mode="incremental", baseline=second)
    zero_chunk = incremental.pages_at_cut(silo, zero, {**zero_pages, "pages": zero_pages["pages"][2:3]})
    assert zero_chunk <= facts["affected"]
    assert facts["stats"]["explicitZeroBytesWritten"] >= zero_pages["pageSize"]
    for index in zero_chunk:
        assert facts["map"]["chunks"][index] != "zero", "one page incorrectly zeroed its mixed 8MiB chunk"
    sealed = capture.inventory(zero.staging)

    # A fresh worker must inherit the verified complete map and a child-local
    # native token before restore/activation writes. Its first capture must not
    # be an unbased full capture or a concealed full live/identity scan.
    child = "incremental-child"
    restore.restore_child(silo, zero, child)
    inherited_pages = incremental.witness(silo, child, previous=initial)
    assert inherited_pages == zero_pages
    restore.advances(silo, child, restore.witness(silo, child))
    child_pages = incremental.witness(silo, child, "first", previous=zero_pages)
    recaptured = restore.checkpoint(silo, child, alias="incremental-child-first")
    child_facts = incremental.authenticated_map(silo, recaptured, mode="incremental", baseline=zero)
    changed = incremental.pages_at_cut(silo, recaptured, {**child_pages, "pages": child_pages["pages"][:2]})
    assert changed <= child_facts["affected"]
    incremental.pages_at_cut(silo, recaptured, child_pages)
    capture.unchanged(silo, zero.staging, sealed)
    restore.matched_cut(silo, recaptured, execution, profile="layered")


def test_observed_console_vsock_and_balloon_writes_match_frozen_full_ram(
    silo: Silo, incremental_image: str,  # noqa: F811
) -> None:
    create(silo, incremental_image)
    reclaim.settled(silo, SOURCE)
    base = restore.checkpoint(silo, SOURCE, alias="host-writers-baseline", policy="full")
    incremental.authenticated_map(silo, base, mode="full", reason="requested")
    baseline_reports = incremental.balloon_report_queue(silo, base)
    silo.run("resume", SOURCE)
    token = "incremental-console-" + uuid4().hex
    log = silo.ws.silo_home / "logs/machines" / silo.machine_id(SOURCE) / "serial.log"
    log_offset = log.stat().st_size
    device = silo.exec(SOURCE, "sh", "-eu", "-c",
        'test -c /dev/hvc0; printf "%s\\n" "$1" >/dev/hvc0; printf /dev/hvc0',
        "console-witness", token, user="root").stdout
    assert device == "/dev/hvc0"

    def emitted() -> bool:
        with log.open("rb") as serial:
            serial.seek(log_offset)
            return token.encode() in serial.read()

    shutdown.until(emitted, description="actual virtio console output never reached the host")
    # Byte-exact traffic in both directions crosses the real admitted vsock
    # transport and its host-owned used rings, not a fabricated native writer.
    payload = (uuid4().hex + "-vsock-bidirectional\\n") * 4096
    reply = silo.exec(SOURCE, "cat", stdin=payload, timeout=60)
    assert reply.stdout == payload, "vsock echo changed guest payload bytes"
    # CLI diagnostics share stderr with the guest stream. An active
    # capture/launch lease defers collection silently; no stderr at all,
    # including guest errors, is allowed in this byte-exact echo gate.
    assert reply.stderr == "", reply.stderr
    # The admitted workload kernel must actually negotiate free-page reporting.
    # Free previously allocated pages to make new reports, then allow its normal
    # delayed worker to return their real descriptor heads to the host.
    silo.exec(SOURCE, "sh", "-eu", "-c",
        "test -d /sys/bus/virtio/drivers/virtio_balloon; "
        "dd if=/dev/zero of=/dev/shm/incremental-balloon-report bs=1048576 count=64; "
        "rm /dev/shm/incremental-balloon-report; sleep 3", user="root")
    saved = restore.checkpoint(silo, SOURCE, alias="host-writers-incremental", policy="incremental")
    facts = incremental.authenticated_map(silo, saved, mode="incremental", baseline=base)
    reports = incremental.balloon_report_queue(silo, saved)
    assert reports["usedRing"] == baseline_reports["usedRing"]
    completed = (reports["nextUsed"] - baseline_reports["nextUsed"]) & 0xffff
    assert 0 < completed < 32768, "no real bounded balloon reporting completions after allocation/free"
    assert reports["usedIndexChunk"] in facts["affected"]
    entry = reports["usedRing"] + 4 + 8 * (baseline_reports["nextUsed"] % reports["size"])
    raw, offset = restore.sealed_ram(saved, entry, 8)
    assert int.from_bytes(raw[:4], "little") < reports["size"] and raw[4:] == b"\0" * 4
    assert offset // incremental.CHUNK in facts["affected"]
    incremental.frozen_full_oracle(silo, SOURCE, saved)
    silo.run("resume", SOURCE)
    child = "host-writers-restored"
    restore.restore_child(silo, saved, child)
    assert silo.exec(child, "cat", stdin=payload, timeout=60).stdout == payload
    silo.ws.record("incremental-host-writers", json.dumps({
        "consoleDevice": device, "consoleToken": token, "vsockBytesEachDirection": len(payload),
        "balloonReportCompletions": completed, "balloonQueue": reports,
        "snapshot": saved.snapshot, "frozenFullOracle": True}, sort_keys=True) + "\n")


@pytest.mark.parametrize("threshold", [0, 61, 255])
def test_incremental_threshold_refuses_before_freeze(silo: Silo, incremental_image: str, threshold: int) -> None:  # noqa: F811
    create(silo, incremental_image)
    before = incremental.no_child(silo)
    info = silo.info(SOURCE)
    result = silo.run("snapshot", "create", SOURCE, "--live", "--capture-policy", "incremental",
                      "--dirty-crossover-percent", str(threshold), expect=None)
    assert result.returncode != 0
    assert "dirty" in result.stderr.lower() and "60" in result.stderr
    assert incremental.no_child(silo) == before, "invalid selector allocated an operation or staging"
    after = silo.info(SOURCE)
    assert after["state"] == "running" and after["run_id"] == info["run_id"]
    assert after["lifecycle"]["lifecycle"]["currentPause"] is None


def test_full_request_lowered_crossover_and_new_worker_invalidate_baseline(
    silo: Silo, incremental_image: str,  # noqa: F811
) -> None:
    create(silo, incremental_image)
    initial = incremental.witness(silo, SOURCE, "start")
    reclaim.settled(silo, SOURCE)
    base = restore.checkpoint(silo, SOURCE, alias="selection-full", policy="full")
    incremental.authenticated_map(silo, base, mode="full", reason="requested")
    silo.run("resume", SOURCE)
    pages = incremental.witness(silo, SOURCE, "crossover", previous=initial)
    crossed = restore.checkpoint(silo, SOURCE, alias="selection-crossover",
                                 dirty_crossover_percent=1)
    incremental.authenticated_map(silo, crossed, mode="full", reason="dirty-crossover")
    incremental.pages_at_cut(silo, crossed, pages)
    silo.run("resume", SOURCE)
    # A subsequent small write must reuse the newly accepted FULL baseline.
    pages = incremental.witness(silo, SOURCE, "first", previous=pages)
    reused = restore.checkpoint(silo, SOURCE, alias="selection-reenabled")
    incremental.authenticated_map(silo, reused, mode="incremental", baseline=crossed)
    incremental.pages_at_cut(silo, reused, pages)
    stopped.stop(silo, SOURCE, require_clean=False)
    silo.start(SOURCE)
    silo.wait_ready(SOURCE)
    cold = restore.checkpoint(silo, SOURCE, alias="selection-new-worker")
    assert cold.source_info["run_id"] != reused.source_info["run_id"]
    incremental.authenticated_map(silo, cold, mode="full", reason="no-baseline")


@pytest.mark.parametrize("boundary", ["capture-ram-write", "capture-dirty-harvest"],
                         ids=["abandoned-union", "post-effect-coverage-lost"])
def test_capture_dirty_union_and_coverage_recovery(
    silo: Silo, incremental_image: str, boundary: str,  # noqa: F811
) -> None:
    """Cancel a real completed RAM attempt or fail a real harvested dirty log."""
    create(silo, incremental_image, start=False)
    target = stopped.writable_paths(silo, SOURCE)["root"]
    evidence = silo.ws.evidence
    driver_request = evidence / "incremental-driver.json"
    driver_request.write_text(json.dumps({"silo": str(silo.ws.config.silo), "name": SOURCE,
        "evidence": str(evidence), "preserve": True, "capturePolicy": "incremental",
        "dirtyCrossoverPercent": 60}) + "\n")
    trace_request = evidence / "incremental-boundary.json"
    release = evidence / "incremental-release"
    arm = evidence / "incremental-arm"
    trace_request.write_text(json.dumps({
        "command": [sys.executable, "-m", "silo_smoke.capture_process", str(driver_request)],
        "target": str(target), "boundary": boundary, "machines": str(silo.ws.silo_home / "machines"),
        "evidence": str(evidence), "release": str(release), "arm": str(arm)}) + "\n")
    cancel_process = None
    with (evidence / "incremental-controller.log").open("wb") as output:
        controller = subprocess.Popen([sys.executable, "-m", "silo_smoke.stopped_trace", str(trace_request)],
            env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")), stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.STDOUT)
        assert controller.stdin is not None
        try:
            def record(filename: str) -> dict | None:
                path = evidence / filename
                if path.exists():
                    return json.loads(path.read_text())
                assert controller.poll() is None, "incremental controller exited before boundary"
                return None

            started = shutdown.until(lambda: record("capture-traced-start.json"), timeout=90,
                                     description="traced incremental source did not start")
            assert started["code"] == 0
            silo.wait_ready(SOURCE)
            initial = incremental.witness(silo, SOURCE, "start")
            reclaim.settled(silo, SOURCE)
            baseline = restore.checkpoint(silo, SOURCE, alias="abandon-baseline", policy="incremental")
            incremental.authenticated_map(silo, baseline, mode="full", reason="no-baseline")
            silo.run("resume", SOURCE)
            written = incremental.witness(silo, SOURCE, "first", previous=initial)
            source_info = silo.info(SOURCE)
            generation = pause.generation(silo, SOURCE)
            captures = overlay.machine_dir(silo, SOURCE) / "captures"
            existing = set(captures.iterdir())
            arm.touch()
            controller.stdin.write(b"capture\n")
            controller.stdin.flush()
            held = shutdown.until(lambda: record("boundary-held.json"), timeout=90,
                                  description=f"incremental capture never reached {boundary}")
            attempts = set(captures.iterdir()) - existing
            assert len(attempts) == 1
            directory = attempts.pop()
            plan = json.loads((directory / "request.json").read_bytes())
            assert plan["policy"] == "incremental" and plan["runId"] == baseline.source_info["run_id"]
            if boundary == "capture-ram-write":
                assert held["injectedReturn"] is False
                assert Path(held["target"]).parent == directory
                cancel_id = str(uuid4())
                command = {"command": "cancelOperation", "envelope": {"machineId": plan["machineId"],
                    "runId": plan["runId"], "requestId": cancel_id}, "operationId": plan["captureId"]}
                request_path = evidence / "incremental-cancel.json"
                request_path.write_text(json.dumps(command) + "\n")
                cancel_process = subprocess.Popen([str(silo.ws.config.bin_dir / "examples/live_acceptance"),
                    SOURCE, str(request_path)], env=silo.ws.env(), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True)
                trace = silo.ws.silo_home / "logs/machines" / silo.machine_id(SOURCE) / "vm.trace.log"

                def admitted() -> bool:
                    assert cancel_process.poll() is None, "cancel ended before its admission evidence"
                    return any("live cancellation admitted" in line and cancel_id in line
                               and plan["captureId"] in line for line in trace.read_text().splitlines())

                shutdown.until(admitted, description="monitor did not admit incremental pre-seal cancel")
                release.touch()
                cancelled, errors = cancel_process.communicate(timeout=90)
                silo.ws.record("incremental-cancel-result", cancelled + "\n[stderr]\n" + errors)
                assert cancel_process.returncode == 0
                value = json.loads(cancelled)
                assert value["completed"]["effective"] is True
                assert value["completed"]["operation"]["outcome"]["failure"]["code"] == "cancelled"
            else:
                assert held["injectedReturn"] is True and held["afterEffect"] is True
                assert held["realReturn"] == 0 and held["ioctl"] == 0x4010AE42
                assert len(bytes.fromhex(held["dirtyBitmapPrefixHex"])) == 8
                release.touch()
            ended = shutdown.until(lambda: record("capture-manager-result.json"), timeout=90,
                                   description="incremental manager did not finish")
            assert silo.info(SOURCE)["state"] == "paused"
            if boundary == "capture-ram-write":
                assert ended["code"] != 0
                assert not procs.query(silo.ws.state_db(),
                    f"SELECT snapshot_id FROM snapshot_capture_provenance WHERE capture_id='{plan['captureId']}'")
                # No target writes after harvest: retry must retain the abandoned
                # union rather than depending on fresh dirty bits.
                silo.run("resume", SOURCE)
                retry = restore.checkpoint(silo, SOURCE, alias="abandon-retry", policy="incremental")
                facts = incremental.authenticated_map(silo, retry, mode="incremental", baseline=baseline)
            else:
                assert ended["code"] == 0, (evidence / "capture-manager.stderr").read_text()
                result = json.loads((evidence / "capture-manager.stdout").read_bytes())
                snapshot = result["snapshot"]["id"]
                seal = json.loads((directory / "vm.capture.json").read_bytes())
                retry = restore.Checkpoint("image:" + snapshot, snapshot, directory, seal,
                                           source_info, baseline.boot_id, generation)
                facts = incremental.authenticated_map(silo, retry, mode="full", reason="coverage-lost")
            targets = incremental.pages_at_cut(silo, retry, {**written, "pages": written["pages"][:2]})
            assert targets <= facts["affected"]
            if boundary == "capture-dirty-harvest":
                silo.run("resume", SOURCE)
                written = incremental.witness(silo, SOURCE, "second", previous=written)
                reenabled = restore.checkpoint(silo, SOURCE, alias="coverage-reenabled", policy="incremental")
                incremental.authenticated_map(silo, reenabled, mode="incremental", baseline=retry)
                incremental.pages_at_cut(silo, reenabled, written)
                retry = reenabled
            child = "abandon-restored"
            restore.restore_child(silo, retry, child)
            assert incremental.witness(silo, child, previous=initial) == written
            stopped.stop(silo, child, require_clean=False)
            controller.stdin.write(b"stop\n")
            controller.stdin.flush()
            assert controller.wait(timeout=90) == 0
        finally:
            release.touch(exist_ok=True)
            if cancel_process is not None and cancel_process.poll() is None:
                cancel_process.kill()
                cancel_process.communicate(timeout=10)
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
            controller.stdin.close()
