from __future__ import annotations

from dataclasses import replace
import errno
import json
import os
from pathlib import Path

import pytest

from silo_smoke import capture, capture_multidisk as multidisk, images, pause, procs, shutdown, stopped
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.registry import LoopbackRegistry

# These gates require the explicitly isolated Phase14 candidate, not a runtime
# grant. No restore/children or production host-lane qualification is implied.
pytestmark = [pytest.mark.linux_only, pytest.mark.slow]


@pytest.fixture(scope="session")
def multidisk_image(config: SmokeConfig, registry: LoopbackRegistry,
                    tmp_path_factory: pytest.TempPathFactory) -> str:
    probe = multidisk.compile_probe(tmp_path_factory.mktemp("capture-multidisk") / "capture-multidisk")
    spec = replace(images.BASIC, name="capture-multidisk", files={
        **images.BASIC.files,
        multidisk.PROBE.lstrip("/"): images.GuestFile(probe.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "capture-multidisk")


def create(silo: Silo, image: str, profile: RootProfile) -> tuple[str, list[str]]:
    name = "capture-multidisk"
    silo.create(name, silo.root_image(image, profile), "--cpus", "1", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")
    roles = multidisk.install_disks(silo, name)
    stopped.mount_evidence(silo, os.environ.get("SILO_SMOKE_CAPTURE_FS"))
    return name, roles


def running(silo: Silo, name: str, trace: multidisk.Trace) -> tuple[dict, str, dict]:
    assert trace.wait("capture-traced-start.json")["code"] == 0
    info = silo.wait_ready(name)
    availability = info["lifecycle"]["report"]["live"]["capture"]["availability"]
    assert availability == {"status": "supported"}, "use the isolated Phase14 candidate"
    multidisk.mount_sources(silo, name)
    boot_id = silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout
    return info, boot_id, pause.generation(silo, name)


def same_source(silo: Silo, name: str, original: dict, boot_id: str, generation: dict) -> None:
    current = silo.info(name)
    assert current["run_id"] == original["run_id"] and current["state"] == "running"
    assert current["ready"] is True
    assert current["lifecycle"]["lifecycle"]["currentPause"] is None
    assert silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout == boot_id
    after = pause.generation(silo, name)
    assert after["reseed_count"] == generation["reseed_count"]
    assert after["completed_flags"] == "3"


def finish(silo: Silo, name: str, trace: multidisk.Trace) -> None:
    holders, lease = shutdown.holder(silo, name)
    processes = [shutdown.Process(entry["pid"]) for entry in holders["holders"]]
    try:
        trace.command("stop")
        assert trace.controller.wait(timeout=90) == 0, "traced CLI owners did not finish"
        assert trace.wait("capture-traced-stop.json")["code"] == 0
        for process in processes:
            process.wait()
        assert not shutdown.lease_busy(lease)
    finally:
        for process in processes:
            process.close()


@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_capture_multidisk_dirty_matched_cut_and_independent_sealed_bytes(
    silo: Silo, multidisk_image: str, profile: RootProfile,
) -> None:
    name, roles = create(silo, multidisk_image, profile)
    source_paths = stopped.writable_paths(silo, name)
    with multidisk.traced_capture(silo, name, source_paths["root"], "capture-execution-write",
                                 preserve=False) as trace:
        original, boot_id, generation = running(silo, name, trace)
        workload = multidisk.Workload(silo, name)
        try:
            workload.advances()
            trace.command("capture")
            held = trace.wait("boundary-held.json")
            assert held["injectedReturn"] is False
            directory = Path(held["target"]).parent
            plan = json.loads((directory / "request.json").read_bytes())
            assert plan["runId"] == original["run_id"]
            assert len(plan["disks"]) == 3, "root and both managed Data disks must be included"
            expected_roles = {disk["name"] for disk in plan["disks"]}
            assert set(roles) < expected_roles
            multidisk.copy_evidence(silo, directory, plan, completed=sorted(expected_roles))
            trace.release()
            assert trace.wait("capture-manager-result.json")["code"] == 0
            result = json.loads((silo.ws.evidence / "capture-manager.stdout").read_text())
            assert result["snapshot"]["captureKind"] == "live-execution"
            summary = result["capture"]
            assert summary["sourceOutcome"] == "resumed" and summary["released"] is True
            seal = json.loads((directory / "vm.capture.json").read_bytes())
            assert seal["captureId"] == plan["captureId"]
            assert seal["captureOutcome"] == "coherent" and seal["error"] is None
            assert all(seal[fact] is True for fact in (
                "workloadsFrozen", "vcpusPaused", "devicesQuiesced", "hostWritersDrained",
                "hostFlushCompleted", "diskCopiesSealed", "memoryStateSealed"))
            sealed = capture.inventory(directory)
            assert {key.removeprefix("disks/").removesuffix(".raw")
                    for key in sealed if key.startswith("disks/")} == expected_roles
            assert all(value.mode == 0o600 for value in sealed.values())
            source_inodes = {(path.stat().st_dev, path.stat().st_ino) for path in source_paths.values()}
            sealed_inodes = {(value.device, value.inode) for key, value in sealed.items()
                             if key.startswith("disks/")}
            assert len(source_inodes) == len(sealed_inodes) == 3
            assert source_inodes.isdisjoint(sealed_inodes), "sealed writable roles alias source inodes"
            multidisk.matched_cut(silo, directory, roles, workload)
            same_source(silo, name, original, boot_id, generation)
            workload.advances()
            # The original writer keeps overwriting the exact same numbered and
            # cache offsets on BOTH source disks, not merely unrelated new files.
            observed = silo.exec(name, "sh", "-eu", "-c", '''
for d in /capture-a /capture-b; do
    od -An -tu8 -N8 "$d/numbered"
    printf post-cut >"$d/source-only"
done
sync
''', user="root").stdout
            values = [int(line.strip()) for line in observed.splitlines() if line.strip()]
            assert len(values) == 2
            baseline = json.loads(silo.ws.evidence_path("capture-multidisk-matched-cut").read_text())
            assert all(value > disk["numberedDisk"] for value, disk in zip(values, baseline["disks"]))
            capture.unchanged(silo, directory, sealed)
            finish(silo, name, trace)
        finally:
            workload.close()


@pytest.mark.parametrize("profile", ROOT_PROFILES)
@pytest.mark.parametrize("policy", ["resume", "preserve", "borrow"])
def test_capture_multidisk_included_copy_enospc_never_publishes_partial_checkpoint(
    silo: Silo, multidisk_image: str, profile: RootProfile, policy: str,
) -> None:
    name, roles = create(silo, multidisk_image, profile)
    target = stopped.writable_paths(silo, name)["root"]
    with multidisk.traced_capture(silo, name, target, "capture-disk-copy",
                                 preserve=policy != "resume", disk_name=f"{roles[1]}.raw",
                                 injected_errno=errno.ENOSPC) as trace:
        original, boot_id, generation = running(silo, name, trace)
        workload = multidisk.Workload(silo, name)
        try:
            workload.advances()
            borrowed = None
            if policy == "borrow":
                silo.run("pause", name)
                borrowed = silo.info(name)["lifecycle"]["lifecycle"]["currentPause"]
                workload.stationary()
            before_snapshots = procs.query(silo.ws.state_db(), "SELECT id FROM storage_snapshot ORDER BY id")
            before_provenance = procs.query(silo.ws.state_db(),
                                            "SELECT capture_id FROM snapshot_capture_provenance ORDER BY capture_id")
            trace.command("capture")
            held = trace.wait("boundary-held.json")
            assert held["injectedReturn"] is True
            assert Path(held["target"]).name == f"{roles[1]}.raw"
            assert held["syscall"] in (1, 16, 18, 20), "must fault actual copy, not fsync"
            directory = Path(held["target"]).parent.parent
            plan = json.loads((directory / "request.json").read_bytes())
            assert plan["runId"] == original["run_id"] and len(plan["disks"]) == 3
            completed = [disk["name"] for disk in plan["disks"] if disk["name"] != roles[1]]
            multidisk.copy_evidence(silo, directory, plan, completed=completed)
            assert not (directory / "vm.capture.json").exists()
            trace.release()
            assert trace.wait("capture-manager-result.json")["code"] != 0
            injected = trace.wait("boundary-injected.json")
            assert injected["errno"] == errno.ENOSPC
            assert injected["target"] == held["target"] and injected["syscall"] == held["syscall"]
            # Retain the producer's genuine diagnostic before owner retirement.
            failed = json.loads((directory / "vm.capture.json").read_bytes())
            assert failed["captureId"] == plan["captureId"]
            assert failed["captureOutcome"] == "failed" and failed["error"] is not None
            assert failed["diskCopiesSealed"] is False and failed["memoryStateSealed"] is False
            diagnostic = json.dumps(failed["error"]).lower()
            assert "no space left" in diagnostic or "os error 28" in diagnostic, failed
            source = json.loads((directory / "vm.capture-source.json").read_bytes())
            assert source["captureId"] == plan["captureId"]
            assert source["sourceOutcome"] == ("resumed" if policy == "resume" else "preserved")
            assert source["error"] is None
            silo.ws.record("capture-multidisk-enospc", json.dumps({
                "injected": injected, "failure": failed, "continuation": source,
            }, sort_keys=True) + "\n")
            assert procs.query(silo.ws.state_db(), "SELECT id FROM storage_snapshot ORDER BY id") == before_snapshots
            assert procs.query(silo.ws.state_db(),
                               "SELECT capture_id FROM snapshot_capture_provenance ORDER BY capture_id") == before_provenance
            current = silo.info(name)
            assert current["run_id"] == original["run_id"]
            if policy != "resume":
                assert current["state"] == "paused" and current["ready"] is False
                authority = current["lifecycle"]["lifecycle"]["currentPause"]
                assert authority["token"]["owner"] == {"kind": "user"}
                if borrowed is not None:
                    assert authority == borrowed, "failed copy replaced borrowed Resume authority"
                workload.stationary()
                silo.run("resume", name)
            workload.advances()
            same_source(silo, name, original, boot_id, generation)
            finish(silo, name, trace)
            shutdown.storage_tool(silo, "prune")
            assert not directory.exists(), "failed capture staging survived final owner retirement"
        finally:
            workload.close()
