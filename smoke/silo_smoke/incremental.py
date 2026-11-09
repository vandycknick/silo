"""Independent RAM/map authentication and actual CLI incremental witnesses.

Native live-byte savings and mandatory immutable-output authentication are
separate facts. Nothing here installs a capability, baseline or fake receipt.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from . import fork_budget, images, overlay, procs, restore, stopped
from .cli import Silo
from .config import REPO, SmokeConfig
from .registry import LoopbackRegistry

CHUNK = 8 * 1024 * 1024
PROBE = "/usr/local/bin/incremental-memory"


@pytest.fixture(scope="session")
def incremental_image(config: SmokeConfig, registry: LoopbackRegistry,
                      tmp_path_factory: pytest.TempPathFactory) -> str:
    """Use the existing execution oracle plus a pinned CPU/block-DMA witness."""
    directory = tmp_path_factory.mktemp("incremental-probes")
    files = dict(images.BASIC.files)
    for source, destination in ((REPO / "smoke/fixtures/incremental_memory.c", PROBE),
                                (REPO / "virt/vmm/tests/guest/restore_execution.c", restore.PROBE)):
        executable = directory / Path(destination).name
        command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2", "-pthread",
                   "-Wall", "-Wextra", "-Werror", "-std=c11", str(source), "-o", str(executable)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        files[destination.lstrip("/")] = images.GuestFile(executable.read_bytes(), mode=0o755)
    spec = replace(images.BASIC, name="incremental-memory", files=files)
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "incremental-memory")


def require_candidate(info: dict) -> None:
    restore.require_restore_candidate(info)
    capability = info["lifecycle"]["report"]["live"]["incremental"]
    assert capability == {"native": True, "availability": {"status": "supported"}}, (
        "select Main's exact-input --restore --incremental candidate", capability)


def witness(silo: Silo, name: str, operation: str = "read", *, previous: dict | None = None) -> dict:
    value = json.loads(silo.exec(name, PROBE, operation, user="root").stdout)
    assert value["pageSize"] > 0 and len(value["pages"]) == 4
    assert len({page["guestPhysicalAddress"] for page in value["pages"]}) == 4
    assert all(page["guestPhysicalAddress"] > 0
               and page["guestPhysicalAddress"] % value["pageSize"] == 0
               and 0 <= page["value"] < 256 for page in value["pages"])
    if previous is not None:
        assert value["pageSize"] == previous["pageSize"]
        assert [page["guestPhysicalAddress"] for page in value["pages"]] == [
            page["guestPhysicalAddress"] for page in previous["pages"]], "pinned GPA moved"
    prior = [page["value"] for page in previous["pages"]] if previous is not None else [0x51] * 4
    expected = {"start": [0x51] * 4, "first": [0x62, 0x63, *prior[2:]],
                "second": [0x73, 0x74, *prior[2:]], "zero": [*prior[:2], 0, prior[3]],
                "crossover": [0x84] * 4}
    if operation in expected:
        assert [page["value"] for page in value["pages"]] == expected[operation]
    silo.ws.record("incremental-guest-pages", json.dumps({"machine": name, "operation": operation,
                                                         "witness": value}, sort_keys=True) + "\n")
    return value


def pages_at_cut(silo: Silo, saved: restore.Checkpoint, expected: dict) -> set[int]:
    affected = set()
    for page in expected["pages"]:
        raw, offset = restore.sealed_ram(saved, page["guestPhysicalAddress"], expected["pageSize"])
        assert raw == bytes([page["value"]]) * expected["pageSize"], (
            "independent sealed bytes differ from guest CPU/DMA/zero page", page, offset)
        affected.add(offset // CHUNK)
    silo.ws.record("incremental-sealed-pages", json.dumps({"snapshot": saved.snapshot,
                                                         "witness": expected,
                                                         "chunks": sorted(affected)}, sort_keys=True) + "\n")
    return affected


def authenticated_map(silo: Silo, saved: restore.Checkpoint, *, mode: str,
                      baseline: restore.Checkpoint | None = None, reason: str | None = None,
                      baseline_map: dict | None = None) -> dict:
    """Decode the canonical complete map and hash every output byte independently.

    The oracle intentionally scans immutable output. That scan is not a live
    guest RAM read and is never included in the native savings assertion.
    """
    assert (saved.staging / "vm.capture.json").stat().st_size <= 1024 * 1024
    assert (saved.staging / "request.json").stat().st_size <= 1024 * 1024
    evidence = saved.seal["memory"]
    assert (evidence["mode"], evidence["fullReason"]) == (mode, reason), evidence
    expected_baseline = baseline.seal["memory"]["ramStream"] if baseline is not None else None
    assert evidence["baseline"] == expected_baseline, evidence
    path = saved.staging / "memory.map.json"
    length = (saved.staging / "memory.ram").stat().st_size
    chunks = (length + CHUNK - 1) // CHUNK
    assert path.stat().st_size <= chunks * 74 + 256
    encoded = path.read_bytes()
    complete = json.loads(encoded)
    assert set(complete) == {"schema", "kind", "length", "chunkSize", "chunks"}
    assert (complete["schema"], complete["kind"], complete["length"], complete["chunkSize"]) == (
        1, "stream", length, CHUNK)
    assert len(complete["chunks"]) == chunks
    assert encoded == json.dumps(complete, sort_keys=True, separators=(",", ":")).encode()
    stream = "sha256:" + hashlib.sha256(b"silo:stream:v1\n" + encoded).hexdigest()
    assert stream == evidence["ramStream"]
    bitmap = evidence["dirtyChunks"]
    assert len(bitmap) == (chunks + 7) // 8 and len(bitmap) <= 16384
    assert all(type(byte) is int and 0 <= byte < 256 for byte in bitmap)
    if chunks % 8:
        assert bitmap[-1] >> (chunks % 8) == 0
    affected = {index for index in range(chunks) if bitmap[index // 8] & (1 << (index % 8))}
    if mode == "full":
        assert affected == set(range(chunks))
    else:
        assert baseline is not None
        old = baseline_map if baseline_map is not None else catalog_map(
            silo, restore.snapshot_record(silo, baseline)["execution"]["memory"])
        assert old["length"] == length
        for index in set(range(chunks)) - affected:
            assert complete["chunks"][index] == old["chunks"][index], "clean identity was not reused"
    whole = hashlib.sha256()
    with (saved.staging / "memory.ram").open("rb") as ram:
        for index, expected in enumerate(complete["chunks"]):
            data = ram.read(CHUNK)
            assert len(data) == min(CHUNK, length - index * CHUNK)
            whole.update(data)
            actual = "zero" if not any(data) else "sha256:" + hashlib.sha256(data).hexdigest()
            assert expected == actual, (index, expected, actual)
        assert not ram.read(1)
    ram_inventory = [entry for entry in saved.seal["inventory"] if entry["role"] == "memory.ram"]
    assert len(ram_inventory) == 1 and ram_inventory[0]["length"] == length
    assert ram_inventory[0]["identity"] == stream and ram_inventory[0].get("sha256") is None
    map_inventory = [entry for entry in saved.seal["inventory"] if entry["role"] == "ram-map"]
    assert len(map_inventory) == 1 and map_inventory[0]["length"] == len(encoded)
    assert map_inventory[0]["sha256"] == "sha256:" + hashlib.sha256(encoded).hexdigest()
    stats = evidence["stats"]
    assert stats["logicalBytes"] == length and stats["wholeFileBytesHashed"] == 0
    coverage = sum(min(CHUNK, length - index * CHUNK) for index in affected)
    assert stats["identityBytesHashed"] == coverage
    probe = None
    if mode == "incremental":
        probe = fork_budget.reflink_probe(saved.staging)
        assert stats["seedMethod"] == ("clone" if probe["reflink"] else "rebuild"), (stats, probe)
        assert stats["fullBytesWritten"] == 0
        assert stats["overlayBytesWritten"] <= stats["liveBytesRead"] <= coverage <= length
        if probe["reflink"]:
            assert stats["liveBytesRead"] == coverage
            assert all(stats[field] == 0 for field in (
                "baselineBytesRead", "baselineBytesWritten", "baselineHoleBytes", "extentQueries"))
        else:
            assert stats["liveBytesRead"] == stats["overlayBytesWritten"]
    else:
        assert stats["seedMethod"] == "rebuild" and stats["liveBytesRead"] == length
    record = restore.snapshot_record(silo, saved)
    assert record["execution"]["memory"]["stream"] == stream
    dependencies = procs.query(silo.ws.state_db(),
        f"SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id='{saved.snapshot}'")
    assert (stream,) in dependencies
    assert catalog_map(silo, record["execution"]["memory"]) == complete
    immutable = silo.ws.silo_home / "images/streams/sha256" / stream[7:]
    assert immutable.stat().st_size == length and overlay.digest(immutable) == whole.hexdigest()
    assert not immutable.samefile(saved.staging / "memory.ram")
    silo.ws.record("incremental-authentication", json.dumps({"snapshot": saved.snapshot,
        "mapBytes": len(encoded), "chunks": chunks, "affectedChunks": sorted(affected),
        "memory": evidence, "seedProbe": probe}, sort_keys=True) + "\n")
    return {"map": complete, "affected": affected, "stats": stats}


def catalog_map(silo: Silo, binding: dict) -> dict:
    stream = binding["stream"]
    length, digest = binding["length"], binding["map"]

    def object_record(digest: str) -> tuple[bytes, dict]:
        path = silo.ws.silo_home / "images/objects/sha256" / digest.removeprefix("sha256:")
        assert path.stat().st_size <= 4 * 1024 * 1024
        encoded = path.read_bytes()
        assert "sha256:" + hashlib.sha256(encoded).hexdigest() == digest
        return encoded, json.loads(encoded)

    _, root = object_record(digest)
    assert set(root) == {"schema", "kind", "stream", "length", "pages"}
    assert (root["schema"], root["kind"], root["stream"], root["length"]) == (1, "stream-map", stream, int(length))
    count = (int(length) + CHUNK - 1) // CHUNK
    assert len(root["pages"]) == (count + 4095) // 4096
    chunks = []
    remaining = int(length)
    for digest in root["pages"]:
        encoded, page = object_record(digest)
        span = min(remaining, 4096 * CHUNK)
        assert set(page) == {"schema", "kind", "length", "chunkSize", "chunks"}
        assert (page["schema"], page["kind"], page["length"], page["chunkSize"]) == (1, "stream", span, CHUNK)
        assert len(page["chunks"]) == (span + CHUNK - 1) // CHUNK
        assert encoded == json.dumps(page, sort_keys=True, separators=(",", ":")).encode()
        chunks.extend(page["chunks"])
        remaining -= span
    assert remaining == 0 and len(chunks) == count
    value = {"schema": 1, "kind": "stream", "length": int(length), "chunkSize": CHUNK, "chunks": chunks}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert "sha256:" + hashlib.sha256(b"silo:stream:v1\n" + encoded).hexdigest() == stream
    return value


def device_state(silo: Silo, saved: restore.Checkpoint) -> dict:
    path = saved.staging / "devices.state"
    assert 0 < path.stat().st_size <= 32 * 1024 * 1024
    binary = silo.ws.config.bin_dir / "examples/native-live-api"
    assert binary.is_file(), "stage the matching read-only native device inspector"
    command = [str(binary), "inspect-devices", str(path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    silo.ws.record("incremental-device-state", json.dumps({
        "snapshot": saved.snapshot, "command": command, "exit": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True) + "\n")
    result.check_returncode()
    return json.loads(result.stdout)


def balloon_report_queue(silo: Silo, saved: restore.Checkpoint) -> dict:
    devices = [device for device in device_state(silo, saved)["devices"] if device["deviceType"] == 5]
    assert len(devices) == 1
    device = devices[0]
    assert device["ackedFeatures"] & (1 << 5), "guest did not negotiate real free-page reporting"
    queues = [queue for queue in device["queues"] if queue["index"] == 4]
    assert len(queues) == 1 and queues[0]["ready"] is True
    queue = queues[0]
    assert 0 < queue["size"] <= 256 and queue["usedRing"] > 0
    raw, offset = restore.sealed_ram(saved, queue["usedRing"] + 2, 2)
    assert int.from_bytes(raw, "little") == queue["nextUsed"]
    return {**queue, "usedIndexChunk": offset // CHUNK}


def frozen_full_oracle(silo: Silo, name: str, saved: restore.Checkpoint) -> restore.Checkpoint:
    """Capture full at the same borrowed pause, without an intervening guest call."""
    before = silo.info(name)
    authority = before["lifecycle"]["lifecycle"]["currentPause"]
    assert before["state"] == "paused" and authority is not None
    incremental_digest = overlay.digest(saved.staging / "memory.ram")
    incremental_layout = (saved.staging / "memory-layout.json").read_bytes()
    result = json.loads(silo.run("snapshot", "create", name, "--live", "--preserve",
        "--capture-policy", "full", "--dirty-crossover-percent", "60",
        "--name", "incremental-full-oracle", timeout=240).stdout)
    summary = result["capture"]
    assert summary["pause"] == "borrowed" and summary["sourceOutcome"] == "preserved"
    relative = Path(summary["staging"])
    assert not relative.is_absolute() and ".." not in relative.parts
    directory = silo.ws.silo_home / relative
    seal = json.loads((directory / "vm.capture.json").read_bytes())
    assert seal["captureOutcome"] == "coherent" and seal["error"] is None
    assert seal["freezeOperationId"] == saved.seal["freezeOperationId"]
    full = replace(saved, reference="image:" + result["snapshot"]["id"],
                   snapshot=result["snapshot"]["id"], staging=directory, seal=seal,
                   source_info=before)
    authenticated_map(silo, full, mode="full", reason="requested")
    assert seal["memory"]["ramStream"] == saved.seal["memory"]["ramStream"], (
        "incremental output differs from explicit full capture at the same frozen cut")
    assert overlay.digest(directory / "memory.ram") == incremental_digest
    assert (directory / "memory-layout.json").read_bytes() == incremental_layout
    assert silo.info(name)["lifecycle"]["lifecycle"]["currentPause"] == authority
    silo.ws.record("incremental-frozen-full-oracle", json.dumps({
        "incrementalSnapshot": saved.snapshot, "fullSnapshot": full.snapshot,
        "stream": seal["memory"]["ramStream"], "pause": authority}, sort_keys=True) + "\n")
    return full


def no_child(silo: Silo) -> dict:
    return {"catalog": stopped.catalog(silo), "directories": {
        str(root): sorted(str(path.relative_to(root)) for path in root.rglob("*")) if root.is_dir() else []
        for root in (silo.ws.silo_home / "machines", silo.ws.run_root)}}
