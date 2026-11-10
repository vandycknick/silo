from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import signal
import subprocess
import sys
import stat
from uuid import UUID, uuid4

import pytest

from silo_smoke import capture, images, overlay, pause, procs, shutdown, stopped
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]
PROBE = "/usr/local/bin/capture-counter"


@pytest.fixture(scope="session")
def capture_image(config: SmokeConfig, registry: LoopbackRegistry,
                  tmp_path_factory: pytest.TempPathFactory) -> str:
    probe = capture.compile_probe(tmp_path_factory.mktemp("capture-probe") / "capture-counter")
    spec = replace(images.BASIC, name="capture-counter", files={
        **images.BASIC.files, PROBE.lstrip("/"): images.GuestFile(probe.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "capture-counter")


@pytest.mark.parametrize("profile", ROOT_PROFILES)
@pytest.mark.parametrize("policy", ["resume", "preserve", "borrow"])
def test_capture_matched_cut_isolation_and_pause_authority(silo: Silo, capture_image: str,
                                                          profile: RootProfile, policy: str) -> None:
    name = "capture-source"
    silo.create(name, silo.root_image(capture_image, profile), "--cpus", "1", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")
    silo.start(name)
    running = silo.wait_ready(name)
    admitted = running["lifecycle"]["report"]["live"]["capture"]["availability"]
    assert admitted == {"status": "supported"}, admitted
    boot_id = silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout
    generation = pause.generation(silo, name)
    counter = capture.Counter(silo, name, PROBE)
    holders, lease = shutdown.holder(silo, name)
    processes = [shutdown.Process(entry["pid"]) for entry in holders["holders"]]
    try:
        counter.advances()
        borrowed = None
        if policy == "borrow":
            silo.run("pause", name)
            borrowed = silo.info(name)["lifecycle"]["lifecycle"]["currentPause"]
            counter.stationary()
            intents = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command")
            refused = silo.run("snapshot", "create", name, "--live", expect=None)
            assert refused.returncode != 0, "capture must not resume a borrowed user pause"
            assert procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command") == intents
        result = silo.run("snapshot", "create", name, "--live", "--name", "captured",
                          *(["--preserve"] if policy != "resume" else []), timeout=240)
        value = json.loads(result.stdout)
        summary = value["capture"]
        assert value["snapshot"]["captureKind"] == "live-execution"
        assert summary["released"] is True
        assert summary["sourceOutcome"] == ("resumed" if policy == "resume" else "preserved")
        assert summary["pause"] == ("borrowed" if policy == "borrow" else "acquired")
        relative = Path(summary["staging"])
        assert not relative.is_absolute() and ".." not in relative.parts
        directory = silo.ws.silo_home / relative
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        seal = json.loads((directory / "vm.capture.json").read_bytes())
        assert seal["captureOutcome"] == "coherent" and seal["error"] is None
        assert seal["captureId"] == summary["captureId"]
        assert seal["machineId"] == summary["machineId"]
        assert seal["runId"] == running["run_id"]
        facts = ("workloadsFrozen", "vcpusPaused", "devicesQuiesced", "hostWritersDrained",
                 "hostFlushCompleted", "diskCopiesSealed", "memoryStateSealed")
        assert all(seal[fact] is True for fact in facts), seal
        before = capture.inventory(directory)
        assert {"request.json", "execution.state", "devices.state", "memory.ram",
                "memory-layout.json", "vm.capture.json", "vm.capture-source.json"} <= set(before)
        assert all(item.mode == 0o600 for item in before.values())
        disks = list((directory / "disks").glob("*.raw"))
        assert len(disks) == 1, "root-only fixture must seal exactly one writable disk"
        capture.matched_cut(silo, directory, disks[0], counter, profile=profile)
        current = silo.info(name)
        assert current["run_id"] == running["run_id"]
        if policy != "resume":
            assert current["state"] == "paused"
            counter.stationary()
            token = current["lifecycle"]["lifecycle"]["currentPause"]
            assert token["token"]["owner"] == {"kind": "user"}
            if borrowed is not None:
                assert token == borrowed, "capture replaced borrowed Resume authority"
            silo.run("resume", name)
        counter.advances()
        assert silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout == boot_id
        after_generation = pause.generation(silo, name)
        assert after_generation["reseed_count"] == generation["reseed_count"]
        assert after_generation["completed_flags"] == "3", after_generation
        # Same live source continues mutating its original inode after the cut.
        # Neither the saved disk nor saved RAM/state bytes may change with it.
        silo.exec(name, "sh", "-eu", "-c", "printf post-cut >/capture-after; sync")
        counter.advances()
        capture.unchanged(silo, directory, before)
        ram = silo.ws.silo_home / "images/streams/sha256" / seal["memory"]["ramStream"][7:]
        assert ram.is_file() and not ram.samefile(directory / "memory.ram")
        silo.stop(name)
        for process in processes:
            process.wait()
        assert not shutdown.lease_busy(lease)
        shutdown.storage_tool(silo, "prune")
        assert not directory.exists(), "ended native baseline must permit staging reclamation"
        archive = silo.ws.silo_home / "capture-evidence" / str(UUID(summary["captureId"]))
        assert json.loads((archive / "vm.capture.json").read_bytes()) == seal
        if policy == "resume":
            retained_capture_survives_source_removal_and_relocation(
                silo, name, value["snapshot"]["id"], directory, seal)
    finally:
        counter.close()
        for process in processes:
            process.close()


def retained_capture_survives_source_removal_and_relocation(
    silo: Silo, source: str, snapshot: str, staging: Path, seal: dict,
) -> None:
    assert snapshot.startswith("sha256:") and len(snapshot) == 71
    assert all(character in "0123456789abcdef" for character in snapshot[7:])
    ram = silo.ws.silo_home / "images/streams/sha256" / seal["memory"]["ramStream"][7:]
    assert ram.is_file()
    paths: set[Path] = set()
    for table, column, kind in (
        ("snapshot_stream_dependency", "stream_id", "streams"),
        ("snapshot_object_dependency", "object_digest", "objects"),
        ("snapshot_capture_provenance", "evidence_digest", "objects"),
    ):
        rows = procs.query(silo.ws.state_db(),
                           f"SELECT {column} FROM {table} WHERE snapshot_id='{snapshot}'")
        for row in rows:
            digest = row[0]
            assert digest.startswith("sha256:") and len(digest) == 71
            assert all(character in "0123456789abcdef" for character in digest[7:])
            paths.add(Path("images") / kind / "sha256" / digest[7:])
    assert ram.relative_to(silo.ws.silo_home) in paths
    before = {str(path): replace(stopped.read_bytes(silo.ws.silo_home / path), path=str(path))
              for path in paths}
    source_dir = staging.parent.parent
    silo.rm(source)
    assert not source_dir.exists()
    silo.run("image", "remove", "image:captured")
    immutable = "image:" + snapshot
    assert json.loads(silo.run("snapshot", "inspect", immutable).stdout)["retained"] is True
    original_home = silo.ws.silo_home
    relocated = silo.ws.root / "relocated-capture-home"
    original_home.rename(relocated)
    silo.ws.silo_home = relocated
    shutdown.storage_tool(silo, "prune")
    inspected = json.loads(silo.run("snapshot", "inspect", immutable).stdout)
    assert inspected["id"] == snapshot and inspected["captureKind"] == "live-execution"
    assert inspected["retained"] is True and inspected["aliases"] == []
    after = {str(path): replace(stopped.read_bytes(relocated / path), path=str(path))
             for path in paths}
    assert before == after, "source removal, relocation or GC changed retained execution closure"
    silo.ws.record("capture-retention", json.dumps({
        "snapshot": snapshot, "originalHome": str(original_home), "relocatedHome": str(relocated),
        "sourceRemoved": not source_dir.exists(), "closureFiles": sorted(after),
    }, sort_keys=True) + "\n")


def test_capture_rejects_readonly_virtiofs_before_freeze(silo: Silo, capture_image: str) -> None:
    name = "capture-unsupported-share"
    share = silo.ws.root / "capture-host-share"
    share.mkdir(mode=0o700)
    (share / "proof").write_text("real readonly host share\n")
    silo.create(name, capture_image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib",
                "--vsock", "--network", "none", "--mount", f"{share}:/capture-host:ro")
    silo.start(name)
    running = silo.wait_ready(name)
    assert silo.exec(name, "cat", "/capture-host/proof").stdout == "real readonly host share\n"
    availability = running["lifecycle"]["report"]["live"]["capture"]["availability"]
    assert availability == {"status": "unsupported", "reason": {
        "code": "device-profile-rejected", "subject": {"kind": "virtiofs"}}}
    counter = capture.Counter(silo, name, PROBE)
    try:
        counter.advances()
        before = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command")
        captures = overlay.machine_dir(silo, name) / "captures"
        staged_before = set(captures.iterdir())
        result = silo.run("snapshot", "create", name, "--live", "--name", "must-not-exist", expect=None)
        assert result.returncode != 0
        assert "device-profile-rejected" in result.stderr and "virtiofs" in result.stderr
        assert procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command") == before
        counter.advances()
        observed = silo.info(name)
        assert observed["run_id"] == running["run_id"]
        assert observed["state"] == "running" and observed["ready"] is True
        assert observed["lifecycle"]["lifecycle"]["currentPause"] is None
        assert set(captures.iterdir()) == staged_before, "refusal staged a capture"
    finally:
        counter.close()
        silo.stop(name)


@pytest.mark.parametrize(("boundary", "victim", "capture_policy"), [
    (boundary, victim, "full")
    for boundary in (
        "capture-disk-copy", "capture-execution-write", "capture-ram-write",
        "capture-seal-publish", "capture-record-settle", "capture-source-write",
        "capture-pool-sync", "capture-pool-rename", "capture-pool-directory-sync",
        "capture-catalog-commit",
    )
    for victim in ("manager", "monitor", "krun-worker")
] + [("capture-source-write", "cancel", "full")]
  + [("capture-execution-write", policy, "full") for policy in
     ("cancel-resume", "cancel-preserve", "cancel-borrow")]
  + [(boundary, "manager", "incremental") for boundary in (
      "capture-pool-sync", "capture-pool-rename", "capture-pool-directory-sync",
      "capture-catalog-commit",
  )])
def test_capture_process_boundary_preserves_only_coherent_closure(
    silo: Silo, capture_image: str, boundary: str, victim: str, capture_policy: str,
) -> None:
    name = "capture-crash"
    silo.create(name, capture_image, "--cpus", "1", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")
    target = stopped.writable_paths(silo, name)["root"]
    evidence = silo.ws.evidence
    driver_request = evidence / "capture-process-request.json"
    driver_request.write_text(json.dumps({
        "silo": str(silo.ws.config.silo), "name": name, "evidence": str(evidence),
        "preserve": victim != "cancel-resume",
        "capturePolicy": capture_policy, "dirtyCrossoverPercent": 60,
    }) + "\n")
    trace_request = evidence / "boundary-request.json"
    release = evidence / "boundary-release"
    arm = evidence / "publication-armed"
    excluded_captures = evidence / "publication-prior-captures.json"
    trace_request.write_text(json.dumps({
        "command": [sys.executable, "-m", "silo_smoke.capture_process", str(driver_request)],
        "target": str(target), "boundary": boundary,
        "machines": str(silo.ws.silo_home / "machines"),
        "evidence": str(evidence), "release": str(release),
        **({"arm": str(arm), "excludeCapturesFile": str(excluded_captures)}
           if capture_policy == "incremental" else {}),
    }) + "\n")
    owned: list[shutdown.Process] = []
    cancel_process = None
    counter = None
    borrowed = None
    observed_seal = None
    with (evidence / "boundary-controller.log").open("wb") as output:
        controller = subprocess.Popen(
            [sys.executable, "-m", "silo_smoke.stopped_trace", str(trace_request)],
            env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")),
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
        )
        assert controller.stdin is not None
        try:
            def record(filename: str) -> dict | None:
                path = evidence / filename
                if path.exists():
                    return json.loads(path.read_text())
                assert controller.poll() is None, "capture tracer ended before boundary"
                return None

            started = shutdown.until(lambda: record("capture-traced-start.json"),
                                     timeout=90, description="traced start did not finish")
            assert started["code"] == 0
            running = silo.wait_ready(name)
            if capture_policy == "incremental":
                baseline = json.loads(silo.run(
                    "snapshot", "create", name, "--live", "--name", "crash-baseline",
                    "--capture-policy", "incremental", timeout=120,
                ).stdout)
                assert baseline["capture"]["memory"]["mode"] == "full"
                excluded_captures.write_text(json.dumps([baseline["capture"]["captureId"]]) + "\n")
                arm.touch()
            if victim.startswith("cancel-"):
                counter = capture.Counter(silo, name, PROBE)
                counter.advances()
                if victim == "cancel-borrow":
                    silo.run("pause", name)
                    borrowed = silo.info(name)["lifecycle"]["lifecycle"]["currentPause"]
                    counter.stationary()
            holders, lease = shutdown.holder(silo, name)
            processes = {entry["role"]: shutdown.Process(entry["pid"]) for entry in holders["holders"]}
            owned.extend(processes.values())
            controller.stdin.write(b"capture\n")
            controller.stdin.flush()
            manager = shutdown.until(lambda: record("capture-manager-process.json"),
                                     description="capture manager did not launch")
            processes["manager"] = shutdown.Process(manager["pid"])
            owned.append(processes["manager"])
            held = shutdown.until(lambda: record("boundary-held.json"), timeout=90,
                                  description=f"capture did not reach actual {boundary}")
            assert held["pid"] in {process.pid for process in owned}
            assert held["injectedReturn"] is False
            held_path = Path(held["target"])
            directory = (Path(held["captureDirectory"]) if "captureDirectory" in held else
                         held_path.parent.parent if held_path.parent.name == "disks" else
                         held_path if held_path.parent.name == "captures" else held_path.parent)
            plan = json.loads((directory / "request.json").read_bytes())
            assert plan["runId"] == running["run_id"]
            if (boundary in {"capture-seal-publish", "capture-record-settle", "capture-source-write"}
                    or "captureDirectory" in held):
                seal_path = directory / (
                    ".vm.capture.json.tmp" if boundary == "capture-seal-publish" else "vm.capture.json")
                cut = json.loads(seal_path.read_bytes())
                assert cut["captureOutcome"] == "coherent", (
                    "crash gate reached failure diagnostics instead of a coherent cut")
                if boundary != "capture-seal-publish":
                    observed_seal = cut
                    if capture_policy == "incremental":
                        assert cut["memory"]["mode"] == "incremental", cut["memory"]
            if borrowed is not None:
                refused = pause.request(silo, name, {
                    "command": "resume",
                    "envelope": {"machineId": plan["machineId"], "runId": plan["runId"],
                                 "requestId": str(uuid4())},
                    "operationId": borrowed["operationId"], "token": borrowed["token"],
                })
                assert refused["outcome"] == "rejected", refused
                assert refused["rejection"]["reason"]["code"] == "invalidState", refused
                assert refused["rejection"]["state"] == "capturing", refused
            if victim == "cancel":
                cancelled = pause.request(silo, name, {
                    "command": "cancelOperation",
                    "envelope": {"machineId": plan["machineId"], "runId": plan["runId"],
                                 "requestId": str(uuid4())},
                    "operationId": plan["captureId"],
                })
                assert cancelled["outcome"] == "completed", cancelled
                assert cancelled["completed"]["effective"] is False, cancelled
                assert cancelled["completed"]["operation"]["outcome"]["status"] == "captureSealed"
            elif victim.startswith("cancel-"):
                cancel_id = str(uuid4())
                command = {
                    "command": "cancelOperation",
                    "envelope": {"machineId": plan["machineId"], "runId": plan["runId"],
                                 "requestId": cancel_id},
                    "operationId": plan["captureId"],
                }
                request_path = evidence / "cancel-request.json"
                request_path.write_text(json.dumps(command) + "\n")
                cancel_process = subprocess.Popen(
                    [str(silo.ws.config.bin_dir / "examples/live_acceptance"), name, str(request_path)],
                    env=silo.ws.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                trace = silo.ws.silo_home / "logs/machines" / silo.machine_id(name) / "vm.trace.log"

                def cancel_admitted() -> bool:
                    assert cancel_process.poll() is None, "cancel ended before its admission witness"
                    return any("live cancellation admitted" in line
                               and cancel_id in line and plan["captureId"] in line
                               for line in trace.read_text().splitlines())

                shutdown.until(cancel_admitted, description="monitor did not admit pre-seal cancel")
            else:
                processes[victim].send(signal.SIGKILL)
            release.touch()
            if victim.startswith("cancel-"):
                output, errors = cancel_process.communicate(timeout=90)
                silo.ws.record("capture-preseal-cancel", output + "\n[stderr]\n" + errors)
                assert cancel_process.returncode == 0, errors
                cancelled = json.loads(output)
                assert cancelled["outcome"] == "completed", cancelled
                assert cancelled["completed"]["effective"] is True, cancelled
                assert cancelled["completed"]["operation"]["outcome"]["status"] == "failed"
                assert cancelled["completed"]["operation"]["outcome"]["failure"]["code"] == "cancelled"
            elif victim != "cancel":
                processes[victim].wait()
            shutdown.until(lambda: record("capture-manager-result.json"), timeout=90,
                           description="capture waiter did not terminate after process death")
            if victim.startswith("cancel-"):
                current = silo.info(name)
                assert current["run_id"] == running["run_id"]
                if victim == "cancel-resume":
                    assert current["state"] == "running" and current["ready"] is True, current
                    assert current["lifecycle"]["lifecycle"]["currentPause"] is None
                    counter.advances()
                else:
                    assert current["state"] == "paused" and current["ready"] is False, current
                    authority = current["lifecycle"]["lifecycle"]["currentPause"]
                    assert authority["token"]["owner"] == {"kind": "user"}
                    if borrowed is not None:
                        assert authority == borrowed
                    counter.stationary()
                    silo.run("resume", name)
                    counter.advances()
            if capture_policy == "incremental":
                assert observed_seal is not None
                binary = silo.ws.config.bin_dir / "examples/live_acceptance"
                assert binary.is_file(), "build the staged runtime's durable capture driver"
                recovered_live = subprocess.run(
                    [str(binary), name, "complete-capture", plan["captureId"]],
                    env=silo.ws.env(), capture_output=True, text=True, timeout=120,
                )
                silo.ws.record("capture-live-publication-recovery",
                               recovered_live.stdout + "\n[stderr]\n" + recovered_live.stderr)
                assert recovered_live.returncode == 0, recovered_live.stderr
                retry = json.loads(silo.run(
                    "snapshot", "create", name, "--live", "--preserve", "--name", "crash-retry",
                    "--capture-policy", "incremental", timeout=120,
                ).stdout)
                memory = retry["capture"]["memory"]
                assert memory["mode"] == "incremental", memory
                assert memory["baseline"] == observed_seal["memory"]["ramStream"], memory
                assert memory["ramStream"] == observed_seal["memory"]["ramStream"], memory
            controller.stdin.write(b"stop\n")
            controller.stdin.flush()
            assert controller.wait(timeout=90) == 0, "trace owners did not finish"
            for process in owned:
                process.wait()
            assert not shutdown.lease_busy(lease)
            # New manager reconciles the retained exact operation, never requests Resume.
            binary = silo.ws.config.bin_dir / "examples/live_acceptance"
            if not binary.is_file():
                binary = REPO / "target/debug/examples/live_acceptance"
            assert binary.is_file(), "build the real durable capture driver"
            recovered = subprocess.run(
                [str(binary), name, "complete-capture", plan["captureId"]],
                env=silo.ws.env(), capture_output=True, text=True, timeout=90,
            )
            silo.ws.record("capture-crash-reconciliation",
                           recovered.stdout + "\n[stderr]\n" + recovered.stderr)
            rows = procs.query(silo.ws.state_db(),
                               f"SELECT snapshot_id,CAST(evidence_bytes AS TEXT) FROM snapshot_capture_provenance WHERE replace(capture_id,'-','')='{plan['captureId'].replace('-', '')}'")
            if observed_seal is not None:
                assert rows, (
                    "observed coherent seal was not published",
                    {"stagingExists": directory.exists(), "recoveryExit": recovered.returncode,
                     "recoveryStderr": recovered.stderr},
                )
                assert json.loads(rows[0][1]) == observed_seal
            if victim.startswith("cancel-"):
                assert not rows, "cancelled pre-seal capture published a checkpoint"
            if rows:
                assert len(rows) == 1
                sealed = json.loads(rows[0][1])
                assert sealed["captureOutcome"] == "coherent" and sealed["error"] is None
                assert all(sealed[fact] is True for fact in (
                    "workloadsFrozen", "vcpusPaused", "devicesQuiesced", "hostWritersDrained",
                    "hostFlushCompleted", "diskCopiesSealed", "memoryStateSealed"))
                inspected = json.loads(silo.run("snapshot", "inspect", "image:" + rows[0][0]).stdout)
                assert inspected["captureKind"] == "live-execution"
            else:
                assert recovered.returncode != 0, "successful reconciliation lost its capture"
                if (directory / "vm.capture.json").exists():
                    seal = json.loads((directory / "vm.capture.json").read_bytes())
                    assert seal["captureOutcome"] != "coherent", "valid seal was lost on reconciliation"
        finally:
            release.touch(exist_ok=True)
            if cancel_process is not None and cancel_process.poll() is None:
                cancel_process.kill()
                cancel_process.communicate(timeout=10)
            if counter is not None:
                counter.close()
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
            controller.stdin.close()
            for process in owned:
                process.close()


@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_capture_taken_alias_refuses_before_pause_and_new_name_succeeds(
    silo: Silo, capture_image: str, profile: RootProfile,
) -> None:
    for name in ("alias-owner", "alias-contender"):
        silo.create(name, silo.root_image(capture_image, profile), "--cpus", "1",
                    "--memory", "512mib", "--disk-size", "512mib", "--vsock",
                    "--network", "none")
        silo.start(name)
        silo.wait_ready(name)
    first = json.loads(silo.run("snapshot", "create", "alias-owner", "--live",
                               "--name", "taken", timeout=240).stdout)
    contender = silo.info("alias-contender")
    counter = capture.Counter(silo, "alias-contender", PROBE)
    try:
        counter.advances()
        before_generation = pause.generation(silo, "alias-contender")
        commands = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command")
        records = procs.query(silo.ws.state_db(),
                              "SELECT operation_id FROM storage_operation WHERE kind='capture'")
        machine = silo.ws.silo_home / "machines" / UUID(contender["id"]).hex
        before_staging = set((machine / "captures").glob("*"))
        refused = silo.run("snapshot", "create", "alias-contender", "--live",
                           "--name", "taken", expect=None)
        assert refused.returncode != 0
        assert "image alias taken already names a different artifact" in refused.stderr
        # No Capture intent can reach the monitor, so a freeze-and-resume
        # cannot hide behind an eventual Running state.
        assert procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM live_command") == commands
        assert procs.query(silo.ws.state_db(),
                           "SELECT operation_id FROM storage_operation WHERE kind='capture'") == records
        assert set((machine / "captures").glob("*")) == before_staging
        assert pause.generation(silo, "alias-contender") == before_generation
        counter.advances()
        current = silo.info("alias-contender")
        assert current["state"] == "running" and current["run_id"] == contender["run_id"]

        retry = json.loads(silo.run("snapshot", "create", "alias-contender", "--live",
                                   "--name", "available", timeout=240).stdout)
        assert retry["capture"]["released"] is True
        assert retry["capture"]["sourceOutcome"] == "resumed"
        assert UUID(retry["capture"]["machineId"]).hex == UUID(contender["id"]).hex
        assert retry["namingOutcome"] is None
        for _ in range(3):
            listed = silo.run("snapshot", "list")
            assert "retained uncertainty" not in listed.stderr
            by_id = {snapshot["id"]: snapshot for snapshot in json.loads(listed.stdout)}
            assert "taken" in by_id[first["snapshot"]["id"]]["aliases"]
            assert "available" in by_id[retry["snapshot"]["id"]]["aliases"]
        assert not procs.query(silo.ws.state_db(),
                               "SELECT operation_id FROM storage_operation "
                               "WHERE kind='capture' AND state='staging'")
    finally:
        counter.close()
