"""Real capture lifecycle faults: manager death, stop races, post-seal cancel,
absent continuation records and a genuine post-seal continuation failure.

Every case boots the source under the child-only syscall controller
(`silo_smoke.stopped_trace`) through the real CLI driver
(`silo_smoke.capture_process`) and holds one actual monitor/worker syscall.
Outcomes come only from the real CLI, monitor, worker, guest and libvm
reconciliation; nothing is injected, fabricated or shortened.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Iterator
from uuid import UUID, uuid4

import pytest

from silo_smoke import capture, images, procs, shutdown, stopped
from silo_smoke.cli import Silo
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry

# Explicit Phase14 candidate runtime only, like test_capture.py: production is
# lane-not-qualified until the capture/restore/fork admission milestone.
pytestmark = [pytest.mark.linux_only, pytest.mark.slow]
PROBE = "/usr/local/bin/capture-counter"
NAME = "capture-lifecycle"
FACTS = ("workloadsFrozen", "vcpusPaused", "devicesQuiesced", "hostWritersDrained",
         "hostFlushCompleted", "diskCopiesSealed", "memoryStateSealed")
POLICY = {"resume": "resume-if-acquired", "preserve": "preserve", "borrow": "preserve"}
CONTINUATION_STAGES = {"resume-native", "resume-clock", "resume-handshake", "resume-thaw",
                       "readiness", "recovery-freeze", "recovery-pause"}


@pytest.fixture(scope="session")
def lifecycle_image(config: SmokeConfig, registry: LoopbackRegistry,
                    tmp_path_factory: pytest.TempPathFactory) -> str:
    probe = capture.compile_probe(tmp_path_factory.mktemp("capture-lifecycle-probe") / "capture-counter")
    spec = replace(images.BASIC, name="capture-lifecycle", files={
        **images.BASIC.files, PROBE.lstrip("/"): images.GuestFile(probe.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "capture-lifecycle")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def acceptance_binary(silo: Silo) -> Path:
    binary = silo.ws.config.bin_dir / "examples/live_acceptance"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/live_acceptance"
    assert binary.is_file(), "build the real durable capture driver (live_acceptance example)"
    return binary


class Trace:
    """The child-only syscall controller owning the traced source run."""

    def __init__(self, silo: Silo, controller: subprocess.Popen[bytes]) -> None:
        self.silo = silo
        self.controller = controller

    def record(self, filename: str) -> dict | None:
        path = self.silo.ws.evidence / filename
        if path.exists():
            return json.loads(path.read_text())
        assert self.controller.poll() is None, f"capture tracer ended before {filename}"
        return None

    def wait(self, filename: str, timeout: float = 120) -> dict:
        return shutdown.until(lambda: self.record(filename), timeout=timeout,
                              description=f"capture trace did not produce {filename}")

    def command(self, line: str) -> None:
        assert self.controller.stdin is not None
        self.controller.stdin.write((line + "\n").encode())
        self.controller.stdin.flush()

    def release(self) -> None:
        (self.silo.ws.evidence / "boundary-release").touch(exist_ok=True)


@dataclass
class Run:
    silo: Silo
    trace: Trace
    running: dict
    counter: capture.Counter
    processes: dict[str, shutdown.Process]
    lease: Path
    manager: shutdown.Process
    held: dict
    directory: Path
    plan: dict
    borrowed: dict | None

    def envelope(self, request: str | None = None) -> dict:
        return {"machineId": self.plan["machineId"], "runId": self.plan["runId"],
                "requestId": request or str(uuid4())}

    def coherent(self, seal: dict) -> None:
        assert seal["captureOutcome"] == "coherent" and seal["error"] is None, seal
        assert seal["captureId"] == self.plan["captureId"], seal
        assert seal["runId"] == self.plan["runId"], seal
        assert all(seal[fact] is True for fact in FACTS), seal

    def logged(self, *needles: str) -> bool:
        path = (self.silo.ws.silo_home / "logs/machines" / UUID(self.plan["machineId"]).hex
                / "vm.trace.log")
        return path.is_file() and any(all(needle in line for needle in needles)
                                      for line in path.read_text(errors="replace").splitlines())

    def wait_logged(self, description: str, *needles: str, timeout: float = 90,
                    alive: subprocess.Popen | None = None) -> None:
        def observed() -> bool:
            if alive is not None:
                assert alive.poll() is None, f"{description}: request ended before its witness"
            return self.logged(*needles)

        shutdown.until(observed, timeout=timeout, description=description)

    def operation(self) -> dict:
        """GetOperation. Like every manager entry point it reconciles first."""
        result = run_request(self.silo, {
            "command": "getOperation", "envelope": self.envelope(),
            "operationId": self.plan["captureId"],
        })
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)
        assert value["outcome"] == "observation", value
        return value["observation"]

    def complete(self, *, expect: int | None = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(acceptance_binary(self.silo)), NAME, "complete-capture", self.plan["captureId"]],
            env=self.silo.ws.env(), capture_output=True, text=True, timeout=180,
        )
        self.silo.ws.record("capture-lifecycle-complete",
                            result.stdout + "\n[stderr]\n" + result.stderr + "\n")
        if expect is not None:
            assert result.returncode == expect, result.stderr
        return result

    def manager_snapshot(self) -> dict:
        result = self.trace.wait("capture-manager-result.json")
        errors = (self.silo.ws.evidence / "capture-manager.stderr").read_text(errors="replace")
        assert result["code"] == 0, errors
        return json.loads((self.silo.ws.evidence / "capture-manager.stdout").read_bytes())

    def resume_requests(self) -> int:
        rows = procs.query(self.silo.ws.state_db(),
                           "SELECT COUNT(*) FROM live_command WHERE replace(run_id,'-','')='"
                           + UUID(self.plan["runId"]).hex
                           + "' AND json_extract(input_json,'$.command.command')='resume'")
        return int(rows[0][0])

    def capture_record(self) -> dict | None:
        rows = procs.query(self.silo.ws.state_db(),
                           "SELECT json(record_json) FROM storage_operation WHERE kind='capture'"
                           " AND replace(operation_id,'-','')='" + UUID(self.plan["captureId"]).hex + "'")
        assert len(rows) <= 1
        return json.loads(rows[0][0]) if rows else None

    def provenance(self) -> list[tuple[str, ...]]:
        return procs.query(self.silo.ws.state_db(),
                           "SELECT snapshot_id,CAST(evidence_bytes AS TEXT) FROM snapshot_capture_provenance"
                           " WHERE replace(capture_id,'-','')='" + UUID(self.plan["captureId"]).hex + "'")

    def summary(self, value: dict, policy: str, source: str) -> dict:
        assert value["snapshot"]["captureKind"] == "live-execution", value
        summary = value["capture"]
        assert summary["captureId"] == self.plan["captureId"], summary
        assert summary["runId"] == self.plan["runId"], summary
        assert summary["resumePolicy"] == POLICY[policy], summary
        assert summary["pause"] == ("borrowed" if policy == "borrow" else "acquired"), summary
        assert summary["sourceOutcome"] == source, summary
        assert summary["released"] is True, summary
        return summary

    def published(self, seal: dict, value: dict) -> None:
        rows = self.provenance()
        assert len(rows) == 1, "sealed capture was not published exactly once"
        assert rows[0][0] == value["snapshot"]["id"]
        assert json.loads(rows[0][1]) == seal, "published evidence differs from the observed seal"

    def ended_silently(self) -> None:
        """The source run ended: its workload must not have run again."""
        output, _ = self.counter.process.communicate(timeout=30)
        assert b"COMMITTED=" not in self.counter.pending + output, (
            "the held capture pause was resumed or thawed before the source ended")

    def finish(self) -> None:
        self.trace.command("stop")
        assert self.trace.controller.wait(timeout=120) == 0, "trace owners did not finish"
        for process in self.processes.values():
            process.wait()
        assert not shutdown.lease_busy(self.lease)


def run_request(silo: Silo, command: dict) -> subprocess.CompletedProcess[str]:
    path = silo.ws.evidence / f"live-request-{uuid4().hex}.json"
    path.write_text(json.dumps(command) + "\n")
    result = subprocess.run([str(acceptance_binary(silo)), NAME, str(path)], env=silo.ws.env(),
                            capture_output=True, text=True, timeout=120)
    silo.ws.record("capture-lifecycle-request", json.dumps({
        "request": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
    }) + "\n")
    return result


@contextmanager
def captured(silo: Silo, image: str, boundary: str, policy: str,
             *, observe_syncs: bool = False) -> Iterator[Run]:
    """Boot a traced source, start the real CLI capture and hold `boundary`."""
    silo.create(NAME, image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib",
                "--vsock", "--network", "none")
    target = stopped.writable_paths(silo, NAME)["root"]
    evidence = silo.ws.evidence
    driver = evidence / "capture-process-request.json"
    driver.write_text(json.dumps({
        "silo": str(silo.ws.config.silo), "name": NAME, "evidence": str(evidence),
        "preserve": policy != "resume",
    }) + "\n")
    request = evidence / "boundary-request.json"
    request.write_text(json.dumps({
        "command": [sys.executable, "-m", "silo_smoke.capture_process", str(driver)],
        "target": str(target), "boundary": boundary,
        "machines": str(silo.ws.silo_home / "machines"),
        "evidence": str(evidence), "release": str(evidence / "boundary-release"),
        "observeCaptureSyncs": observe_syncs,
    }) + "\n")
    owned: list[shutdown.Process] = []
    counter = None
    with (evidence / "boundary-controller.log").open("wb") as output:
        controller = subprocess.Popen(
            [sys.executable, "-m", "silo_smoke.stopped_trace", str(request)],
            env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")),
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
        )
        trace = Trace(silo, controller)
        try:
            assert trace.wait("capture-traced-start.json")["code"] == 0
            running = silo.wait_ready(NAME)
            admitted = running["lifecycle"]["report"]["live"]["capture"]["availability"]
            assert admitted == {"status": "supported"}, "run this gate with the explicit isolated Phase14 candidate"
            counter = capture.Counter(silo, NAME, PROBE)
            counter.advances()
            borrowed = None
            if policy == "borrow":
                silo.run("pause", NAME)
                borrowed = silo.info(NAME)["lifecycle"]["lifecycle"]["currentPause"]
                assert borrowed["token"]["owner"] == {"kind": "user"}, borrowed
                counter.stationary()
            holders, lease = shutdown.holder(silo, NAME)
            processes = {entry["role"]: shutdown.Process(entry["pid"]) for entry in holders["holders"]}
            owned.extend(processes.values())
            trace.command("capture")
            manager = shutdown.Process(trace.wait("capture-manager-process.json")["pid"])
            owned.append(manager)
            held = trace.wait("boundary-held.json")
            assert held["injectedReturn"] is False, held
            assert held["pid"] in {process.pid for process in [*processes.values(), manager]}, held
            if "captureDirectory" in held:
                directory = Path(held["captureDirectory"])
            else:
                path = Path(held["target"])
                directory = (path.parent.parent if path.parent.name == "disks"
                             else path if path.parent.name == "captures" else path.parent)
            plan = json.loads((directory / "request.json").read_bytes())
            assert plan["runId"] == running["run_id"]
            assert plan["resumePolicy"] == POLICY[policy], plan
            yield Run(silo, trace, running, counter, processes, lease, manager, held,
                      directory, plan, borrowed)
        finally:
            trace.release()
            if counter is not None:
                counter.close()
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
            assert controller.stdin is not None
            controller.stdin.close()
            for process in owned:
                process.close()


@pytest.mark.parametrize("policy", ["resume", "preserve", "borrow"])
def test_capture_manager_death_leaves_the_recorded_policy_to_the_monitor(
    silo: Silo, lifecycle_image: str, policy: str,
) -> None:
    """Gap 3: the capture manager dies before the seal while monitor and
    worker survive. Without any manager the monitor seals and continues
    exactly under the recorded policy; a later manager only reconciles."""
    with captured(silo, lifecycle_image, "capture-execution-write", policy) as run:
        run.manager.send(signal.SIGKILL)
        run.manager.wait()
        assert run.trace.wait("capture-manager-result.json")["code"] == -signal.SIGKILL
        # From here until the monitor's completed continuation record no libvm
        # manager process exists: no CLI or live request is issued.
        run.trace.release()
        run.wait_logged("monitor did not finish the recorded continuation without its manager",
                        "capture continuation finished", run.plan["captureId"])
        seal_bytes = (run.directory / "vm.capture.json").read_bytes()
        seal = json.loads(seal_bytes)
        run.coherent(seal)
        source_bytes = (run.directory / "vm.capture-source.json").read_bytes()
        source = json.loads(source_bytes)
        assert source["captureId"] == run.plan["captureId"] and source["runId"] == run.plan["runId"]
        assert source["pauseToken"] == seal["pauseToken"] and source["error"] is None, source
        if policy == "resume":
            assert source["sourceOutcome"] == "resumed" and source["currentPause"] is None, source
            run.counter.advances()
        else:
            assert source["sourceOutcome"] == "preserved", source
            assert source["currentPause"]["owner"] == {"kind": "user"}, source
            if run.borrowed is not None:
                assert source["pauseToken"] == run.borrowed["token"] == source["currentPause"], (
                    "capture replaced the borrowed user authority")
            run.counter.stationary()
        assert run.resume_requests() == 0
        before = capture.inventory(run.directory)

        value = json.loads(run.complete().stdout)
        summary = run.summary(value, policy, source["sourceOutcome"])
        assert summary["sourceError"] is None, summary
        run.published(seal, value)
        observed = run.operation()
        assert observed["operation"]["outcome"]["status"] == "captureSealed", observed
        assert observed["operation"]["outcome"]["capture"]["evidenceSha256"] == digest(seal_bytes)
        assert observed["capture"]["continuation"]["status"] == source["sourceOutcome"], observed
        assert observed["capture"]["sourceRecordSha256"] == digest(source_bytes), observed
        release = observed["capture"]["release"]
        assert release["status"] == "released" and release["disposition"] == "published", release
        current = silo.info(NAME)
        assert current["run_id"] == run.running["run_id"]
        authority = current["lifecycle"]["lifecycle"]["currentPause"]
        if policy == "resume":
            assert current["state"] == "running" and authority is None, current
            run.counter.advances()
        else:
            assert current["state"] == "paused", current
            assert authority["token"] == source["currentPause"], authority
            if run.borrowed is not None:
                assert authority == run.borrowed, "a manager replaced the borrowed pause authority"
            else:
                assert authority["operationId"] == run.plan["captureId"], authority
            run.counter.stationary()
        assert run.resume_requests() == 0, "a manager resumed the source"
        capture.unchanged(silo, run.directory, before)
        if policy != "resume":
            silo.run("resume", NAME)
            run.counter.advances()
        run.finish()


@pytest.mark.parametrize("boundary", ["capture-execution-write", "capture-record-settle"])
def test_capture_stop_racing_unsealed_or_sealed_capture_never_resumes(
    silo: Silo, lifecycle_image: str, boundary: str,
) -> None:
    """Gap 3: an actual `silo stop` admitted while resume-if-acquired capture
    is held before the record (worker execution-state write) or after its
    link (monitor temporary-link removal). Stop never resumes or thaws; an
    unsealed capture never becomes coherent, a linked seal still publishes
    and its continuation is unknown."""
    sealed = boundary == "capture-record-settle"
    with captured(silo, lifecycle_image, boundary, "resume") as run:
        seal_bytes = None
        if sealed:
            seal_bytes = (run.directory / "vm.capture.json").read_bytes()
            run.coherent(json.loads(seal_bytes))
        run.counter.stationary()
        with (silo.ws.evidence / "capture-race-stop.stdout").open("wb") as output, \
                (silo.ws.evidence / "capture-race-stop.stderr").open("wb") as errors:
            stopper = silo.popen("stop", NAME, "--timeout", "60s", stdout=output, stderr=errors)
        try:
            # begin_stop sealed live admission and chose Terminate before release.
            run.wait_logged("stop was not admitted while capture was held",
                            "stopping a live-held machine without resuming it")
            run.trace.release()
            assert stopper.wait(timeout=120) == 0, (
                silo.ws.evidence / "capture-race-stop.stderr").read_text(errors="replace")
        finally:
            if stopper.poll() is None:
                stopper.kill()
                stopper.wait(timeout=10)
        for process in run.processes.values():
            process.wait()
        assert not shutdown.lease_busy(run.lease)
        run.ended_silently()
        assert silo.info(NAME)["state"] == "stopped"
        # The racing manager may be refused with monitor-stopping; recorded only.
        manager_result = run.trace.wait("capture-manager-result.json")
        assert not (run.directory / "vm.capture-source.json").exists(), (
            "a continuation record claims an outcome after stop took over")

        if seal_bytes is not None:
            if manager_result["code"] == 0:
                # The original manager may already publish and release the
                # operation before stop returns. Judge its exact retained seal.
                value = run.manager_snapshot()
            else:
                value = json.loads(run.complete().stdout)
            summary = run.summary(value, "resume", "unknown")
            assert summary["sourceError"] is None, summary
            run.published(json.loads(seal_bytes), value)
        else:
            recovered = run.complete(expect=None)
            assert recovered.returncode != 0, "stop-raced unsealed capture reconciled as success"
            assert run.provenance() == [], "stop-raced unsealed capture published a checkpoint"
            seal_path = run.directory / "vm.capture.json"
            if seal_path.exists():
                assert json.loads(seal_path.read_bytes())["captureOutcome"] == "failed"
            record = run.capture_record()
            assert record is None or record["state"]["state"] == "abandoned", record
        assert run.resume_requests() == 0
        run.finish()


def test_capture_cancel_joined_at_the_seal_never_interrupts_resume_handshake_or_thaw(
    silo: Silo, lifecycle_image: str,
) -> None:
    """Gap 3, resume-if-acquired: a real CancelOperation is admitted while the
    record is linked but not yet settled, so the capture's cancel token is set
    before ClockOnly release, handshake and Thaw. Cancel loses; the started
    continuation finishes normally and no sealed byte changes."""
    with captured(silo, lifecycle_image, "capture-record-settle", "resume") as run:
        seal_bytes = (run.directory / "vm.capture.json").read_bytes()
        seal = json.loads(seal_bytes)
        run.coherent(seal)
        before = capture.inventory(run.directory)
        assert "vm.capture-source.json" not in before
        run.counter.stationary()
        cancel_id = str(uuid4())
        request = silo.ws.evidence / "sealing-cancel-request.json"
        request.write_text(json.dumps({
            "command": "cancelOperation", "envelope": run.envelope(cancel_id),
            "operationId": run.plan["captureId"],
        }) + "\n")
        canceller = subprocess.Popen([str(acceptance_binary(silo)), NAME, str(request)],
                                     env=silo.ws.env(), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        try:
            run.wait_logged("monitor did not admit the cancel while sealing",
                            "live cancellation admitted", cancel_id, run.plan["captureId"],
                            alive=canceller)
            assert canceller.poll() is None, "joined cancel answered before record settlement"
            run.trace.release()
            output, errors = canceller.communicate(timeout=90)
        finally:
            if canceller.poll() is None:
                canceller.kill()
                canceller.communicate(timeout=10)
        silo.ws.record("capture-sealing-cancel", output + "\n[stderr]\n" + errors)
        assert canceller.returncode == 0, errors
        cancelled = json.loads(output)
        assert cancelled["outcome"] == "completed", cancelled
        assert cancelled["completed"]["effective"] is False, cancelled
        assert cancelled["completed"]["state"] == "capturing", cancelled
        outcome = cancelled["completed"]["operation"]["outcome"]
        assert outcome["status"] == "captureSealed", outcome
        assert outcome["capture"]["captureId"] == run.plan["captureId"]
        assert outcome["capture"]["evidenceSha256"] == digest(seal_bytes)
        assert outcome["capture"]["cutToken"] == seal["pauseToken"]

        value = run.manager_snapshot()
        summary = run.summary(value, "resume", "resumed")
        assert summary["sourceError"] is None, summary
        current = silo.info(NAME)
        assert current["run_id"] == run.running["run_id"]
        assert current["state"] == "running" and current["ready"] is True, current
        assert current["lifecycle"]["lifecycle"]["currentPause"] is None
        run.counter.advances()
        observed = run.operation()
        assert observed["operation"] == cancelled["completed"]["operation"], (
            "post-seal cancel changed the sealed operation outcome")
        assert observed["capture"]["continuation"] == {
            "status": "resumed", "consumedToken": seal["pauseToken"],
            "thawedEpoch": seal["freezeEpoch"],
        }, observed
        source = json.loads((run.directory / "vm.capture-source.json").read_bytes())
        assert source["sourceOutcome"] == "resumed" and source["pauseToken"] == seal["pauseToken"]
        capture.unchanged(silo, run.directory, before)
        run.published(seal, value)
        assert run.resume_requests() == 0
        run.finish()


def test_capture_absent_continuation_record_is_pending_while_run_lives_then_unknown(
    silo: Silo, lifecycle_image: str,
) -> None:
    """Gap 4: the monitor is held writing `vm.capture-source.json` after a
    coherent record and a completed native preserve. While the exact run lives,
    managers publish and stay Pending without inventing an outcome or
    resuming; once that run ends without the record, the outcome is unknown."""
    with captured(silo, lifecycle_image, "capture-source-write", "preserve") as run:
        assert Path(run.held["target"]).name == ".vm.capture-source.json.tmp", run.held
        seal_bytes = (run.directory / "vm.capture.json").read_bytes()
        seal = json.loads(seal_bytes)
        run.coherent(seal)
        final = run.directory / "vm.capture-source.json"
        assert not final.exists()
        run.counter.stationary()
        rows = shutdown.until(run.provenance, timeout=120,
                              description="manager did not publish the coherent cut while continuation was pending")
        assert len(rows) == 1 and json.loads(rows[0][1]) == seal
        record = run.capture_record()
        assert record["state"] == {"state": "published", "snapshot": rows[0][0]}, record
        assert record["sourceOutcome"] is None, record
        observed = run.operation()
        assert observed["state"] == "capturing", observed
        assert observed["operation"]["outcome"]["status"] == "captureSealed", observed
        assert observed["operation"]["outcome"]["capture"]["evidenceSha256"] == digest(seal_bytes)
        assert observed["capture"]["continuation"] == {"status": "pending"}, observed
        assert observed["capture"]["sourceRecordSha256"] is None, observed
        assert observed["capture"]["release"] == {"status": "retained"}, observed
        assert run.capture_record()["sourceOutcome"] is None, (
            "reconciliation invented a continuation outcome for a live run")
        assert not run.manager.terminal(), "manager stopped following the live exact run"
        run.counter.stationary()
        assert run.resume_requests() == 0

        # The exact run ends with only the unlinked temporary record: the
        # worker loses its monitor control endpoint and exits with it.
        run.processes["monitor"].send(signal.SIGKILL)
        run.processes["monitor"].wait()
        run.processes["krun-worker"].wait()
        value = run.manager_snapshot()
        summary = run.summary(value, "preserve", "unknown")
        assert summary["sourceError"] is None, summary
        run.published(seal, value)
        assert not final.exists()
        record = run.capture_record()
        assert record is None or record["sourceOutcome"] == {"kind": "unknown"}, record
        assert run.resume_requests() == 0, "a manager resumed a source with an unknown outcome"
        run.ended_silently()
        run.finish()


def test_checkpoint_publication_syncs_real_pool_fds_before_catalog_acknowledgment(
    silo: Silo, lifecycle_image: str,
) -> None:
    """Observe successful kernel barriers on the published inodes, not a mock."""
    with captured(silo, lifecycle_image, "capture-pool-directory-sync", "preserve",
                  observe_syncs=True) as run:
        seal_bytes = (run.directory / "vm.capture.json").read_bytes()
        seal = json.loads(seal_bytes)
        run.coherent(seal)
        assert "cut" not in seal and "cut" not in run.plan
        run.trace.release()
        value = run.manager_snapshot()
        run.published(seal, value)
        run.finish()
        observations = [json.loads(line) for line in
                        (silo.ws.evidence / "capture-syncs.jsonl").read_text().splitlines()]
        successful = [entry for entry in observations if entry["returned"] == 0]
        assert not [entry for entry in observations
                    if str(run.directory) in entry["path"]], observations
        pool = silo.ws.silo_home / "images"
        expected = []
        for entry in seal["inventory"]:
            stream = entry["role"] == "memory.ram" or entry["role"].endswith(".raw")
            identity = entry["identity"] if stream else entry["sha256"]
            expected.append(pool / ("streams" if stream else "objects") / "sha256" / identity[7:])
        expected.append(pool / "objects/sha256" / digest(seal_bytes)[7:])
        rows = procs.query(silo.ws.state_db(),
                           "SELECT record_digest FROM storage_snapshot WHERE id='"
                           + value["snapshot"]["id"] + "'")
        assert len(rows) == 1
        expected.append(pool / "objects/sha256" / rows[0][0][7:])
        for path in expected:
            metadata = path.stat()
            barriers = [entry for entry in successful
                        if (entry["device"], entry["inode"]) == (metadata.st_dev, metadata.st_ino)]
            assert barriers, f"published pool inode was never synced: {path}"
            parent = path.parent.stat()
            assert any(entry["directory"]
                       and (entry["device"], entry["inode"]) == (parent.st_dev, parent.st_ino)
                       and entry["startedNs"] >= barriers[-1]["finishedNs"]
                       for entry in successful), f"publication directory not synced after payload: {path}"
        assert any(entry["directory"] and Path(entry["path"]).parent == pool / "tmp"
                   for entry in successful), "relocation staging directory was not synced"
        assert any(Path(entry["path"]) in (silo.ws.silo_home / "state.db",
                                          silo.ws.silo_home / "state.db-wal")
                   and entry["startedNs"] > max(item["finishedNs"] for item in successful
                                               if item["directory"] and Path(item["path"]) in
                                               (pool / "objects/sha256", pool / "streams/sha256"))
                   for entry in successful), "catalog durability did not follow pool publication"


def test_capture_genuine_continuation_failure_keeps_seal_and_fences_source(
    silo: Silo, lifecycle_image: str,
) -> None:
    """Gap 4: after a coherent seal the worker's real libkrun vsock muxer thread
    is held, so the monitor's production handshake/Thaw/recovery deadlines
    expire. The checkpoint stays coherent and publishes, `resume-failed` is
    recorded separately, and the source stays fenced in Error until stop."""
    with captured(silo, lifecycle_image, "capture-guest-transport", "resume") as run:
        assert run.held["thread"] == "vsock muxer", run.held
        assert run.held["pid"] == run.processes["krun-worker"].pid, run.held
        seal_bytes = (run.directory / "vm.capture.json").read_bytes()
        seal = json.loads(seal_bytes)
        run.coherent(seal)
        before = capture.inventory(run.directory)
        assert "vm.capture-source.json" not in before
        # The ordinary OCI source is layered; its upper keeps the tree below /upper.
        source_disk = stopped.writable_paths(silo, NAME)["root"]
        assert stopped.record(silo, NAME)["root"]["kind"] == "linux-overlay"

        def disk_counter() -> bytes:
            result = subprocess.run(["debugfs", "-R", "cat /upper/capture-counter", str(source_disk)],
                                    check=True, capture_output=True, timeout=30)
            silo.ws.record("capture-fenced-counter-reader", result.stderr.decode(errors="replace"))
            assert len(result.stdout) == run.counter.page_size
            return result.stdout

        frozen_counter = disk_counter()
        run.counter.stationary()
        run.wait_logged("held guest transport did not end the real continuation",
                        "capture continuation finished", run.plan["captureId"], timeout=180)
        observed = run.operation()
        assert observed["state"] == "error", observed
        assert observed["currentPause"] is None, observed
        outcome = observed["operation"]["outcome"]
        assert outcome["status"] == "captureSealed", outcome
        assert outcome["capture"]["evidenceSha256"] == digest(seal_bytes)
        assert outcome["capture"]["cutToken"] == seal["pauseToken"]
        assert observed["capture"]["evidence"] == {"outcome": "coherent", "sha256": digest(seal_bytes)}
        continuation = observed["capture"]["continuation"]
        assert continuation["status"] == "resume-failed" and continuation["state"] == "error", continuation
        failure = continuation["failure"]
        assert failure["stage"] in CONTINUATION_STAGES, failure
        source_bytes = (run.directory / "vm.capture-source.json").read_bytes()
        source = json.loads(source_bytes)
        assert source["sourceOutcome"] == "resume-failed", source
        assert source["error"] and source["currentPause"] is None, source
        assert source["pauseToken"] == seal["pauseToken"], source
        assert observed["capture"]["sourceRecordSha256"] == digest(source_bytes)

        run.trace.release()
        value = run.manager_snapshot()
        summary = run.summary(value, "resume", "resume-failed")
        assert summary["sourceError"], summary
        run.published(seal, value)
        current = silo.info(NAME)
        assert current["run_id"] == run.running["run_id"]
        assert current["state"] == "error" and current["ready"] is False, current
        lifecycle = current["lifecycle"]["lifecycle"]
        assert lifecycle["currentPause"] is None and lifecycle["error"]["code"] == failure["code"], lifecycle
        # Error invalidates exec readiness, so its stream may close. Observe
        # the workload's actual durable counter instead of requiring that
        # failed-source sessions survive.
        time.sleep(0.5)
        assert disk_counter() == frozen_counter, "failed continuation let the workload write"
        intents = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command")
        refused = silo.run("snapshot", "create", NAME, "--live", "--name", "fenced", expect=None)
        assert refused.returncode != 0, "a fenced source admitted a new capture"
        assert procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command") == intents
        assert silo.info(NAME)["state"] == "error"
        capture.unchanged(silo, run.directory, before)
        assert run.resume_requests() == 0
        run.finish()
        run.ended_silently()
        assert disk_counter() == frozen_counter, "stop resumed the failed source"
