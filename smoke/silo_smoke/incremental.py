"""Independent RAM/map authentication and actual CLI incremental witnesses.

Native live-byte savings and mandatory immutable-output authentication are
separate facts. Nothing here installs a capability, baseline or fake receipt.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from . import images, overlay, procs, restore, stopped, stream_map
from .filesystem import reflink_probe
from .cli import Silo
from .config import REPO, SmokeConfig
from .registry import LoopbackRegistry

CHUNK = stream_map.RAM_CHUNK
PROBE = "/usr/local/bin/incremental-memory"


def disk_full_scan_reason(stats: dict) -> str | None:
    """Read the tagged disk reason; null denotes a reused identity baseline."""
    reason = stats["fullScanReason"]
    return None if reason is None else reason["kind"]


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
                      baseline_map: tuple[stream_map.Root, dict[int, str]] | None = None) -> dict:
    """Authenticate binary roots, sparse changes and every immutable output byte.

    This independent scan is outside native capture and all timing assertions.
    """
    assert (saved.staging / "vm.capture.json").stat().st_size <= 1024 * 1024
    assert (saved.staging / "request.json").stat().st_size <= 1024 * 1024
    evidence = saved.seal["memory"]
    binding = evidence["binding"]
    assert binding["liveStateSchema"] == "silo.live-state/1"
    layout = json.loads((saved.staging / "memory-layout.json").read_bytes())
    assert binding["architecture"] == layout["architecture"]
    assert layout["magic"] == "KRUNRAML" and layout["schema"] == 1
    assert (evidence["mode"], evidence["fullReason"]) == (mode, reason), evidence
    identity_mode = {"full": "full", "since-anchor": "incremental"}[evidence["identityPolicy"]]
    expected_baseline = baseline.seal["memory"]["ramStream"] if baseline is not None else None
    assert evidence["baseline"] == expected_baseline, evidence
    path = saved.staging / "memory.root"
    length = (saved.staging / "memory.ram").stat().st_size
    encoded = path.read_bytes()
    root = stream_map.decode_root(encoded)
    assert root.length == length and root.chunk_size == CHUNK
    stream = root.identity
    assert stream == evidence["ramStream"] and evidence["identityChunkBytes"] == CHUNK
    changes = stream_map.read_changes(saved.staging / "memory.changes", length)
    summary = evidence["changes"]
    assert (changes.mode, changes.byte_length, changes.identity, len(changes.records)) == (
        identity_mode, summary["byteLen"], summary["sha256"], summary["recordCount"])
    assert summary["coverage"] == identity_mode and summary["baselineStream"] == expected_baseline
    actual_root, leaves = stream_map.from_file(saved.staging / "memory.ram", CHUNK)
    assert actual_root == root, "native root differs from independent full-byte oracle"
    source = stream_map.object_source(silo.ws.silo_home)

    def node(identity: str) -> bytes:
        staged = saved.staging / "map-nodes" / identity[7:]
        return staged.read_bytes() if staged.is_file() else source(identity)

    assert dict(stream_map.present_chunks(root, node)) == leaves
    affected = changes.affected()
    for change in changes.records:
        for index in range(change.first, change.first + change.count):
            assert leaves.get(index) == change.value, ("change differs from output bytes", change, index)
    if identity_mode == "full":
        assert {change.first: change.value for change in changes.records} == leaves
    else:
        assert baseline is not None
        old_root, old_leaves = baseline_map if baseline_map is not None else catalog_map(
            silo, restore.snapshot_record(silo, baseline)["execution"]["memory"])
        assert old_root.length == length and old_root.chunk_size == CHUNK
        changed = {index for index in old_leaves.keys() | leaves.keys()
                   if old_leaves.get(index) != leaves.get(index)}
        assert changed <= affected, "clean identity was not reused"
    ram_inventory = [entry for entry in saved.seal["inventory"] if entry["role"] == "memory.ram"]
    assert len(ram_inventory) == 1 and ram_inventory[0]["length"] == length
    assert ram_inventory[0]["identity"] == stream and ram_inventory[0].get("sha256") is None
    map_inventory = [entry for entry in saved.seal["inventory"] if entry["role"] == "ram-map"]
    assert len(map_inventory) == 1 and map_inventory[0]["length"] == len(encoded)
    assert map_inventory[0]["sha256"] == stream_map.digest(encoded)
    change_inventory = [entry for entry in saved.seal["inventory"] if entry["role"] == "memory.changes"]
    assert len(change_inventory) == 1
    assert (change_inventory[0]["length"], change_inventory[0]["sha256"]) == (changes.byte_length, changes.identity)
    stats = evidence["stats"]
    assert stats["logicalBytes"] == length and stats["wholeFileBytesHashed"] == 0
    coverage = sum(min(CHUNK, length - index * CHUNK) for index in affected)
    hashed = sum(min(CHUNK, length - change.first * CHUNK)
                 for change in changes.records if change.value is not None)
    assert stats["identityBytesHashed"] == hashed
    probe = None
    if mode == "incremental":
        probe = reflink_probe(saved.staging)
        assert stats["seedMethod"] == ("clone" if probe["reflink"] else "rebuild"), (stats, probe)
        assert stats["fullBytesWritten"] == 0
        assert stats["overlayBytesWritten"] <= stats["liveBytesRead"] <= coverage <= length
        if probe["reflink"]:
            # Every selected identity-unit byte is either read or proven absent.
            # Output zero runs/punches overlap those bytes and are not read savings.
            assert stats["liveBytesRead"] + stats["knownZeroBytesSkipped"] == coverage, stats
            launch = procs.query(silo.ws.state_db(),
                "SELECT json_type(record_json,'$.restore') FROM storage_operation "
                f"WHERE kind='launch' AND json_extract(record_json,'$.machineId')='{saved.source_info['id']}' "
                f"AND json_extract(record_json,'$.runId')='{saved.source_info['run_id']}'")
            assert len(launch) == 1 and launch[0][0] in {"null", "object"}, launch
            if launch[0][0] == "object":
                # Restore/fork RAM can expose nonzero file bytes after a discard.
                assert stats["knownZeroBytesSkipped"] == 0, stats
                assert stats["liveBytesRead"] == coverage, stats
            assert all(stats[field] == 0 for field in (
                "baselineBytesRead", "baselineBytesWritten", "baselineHoleBytes", "extentQueries"))
        else:
            assert stats["liveBytesRead"] == stats["overlayBytesWritten"]
    else:
        assert stats["seedMethod"] == "rebuild"
        assert stats["liveBytesRead"] + stats["knownZeroBytesSkipped"] == length
    record = restore.snapshot_record(silo, saved)
    assert record["execution"]["memory"]["stream"] == stream
    dependencies = procs.query(silo.ws.state_db(),
        f"SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id='{saved.snapshot}'")
    assert (stream,) in dependencies
    assert procs.query(silo.ws.state_db(),
        f"SELECT changes_digest FROM snapshot_capture_change WHERE snapshot_id='{saved.snapshot}'") == [(changes.identity,)]
    assert catalog_map(silo, record["execution"]["memory"]) == (root, leaves)
    immutable = silo.ws.silo_home / "images/streams/sha256" / stream[7:]
    assert immutable.stat().st_size == length
    assert overlay.digest(immutable) == overlay.digest(saved.staging / "memory.ram")
    assert not immutable.samefile(saved.staging / "memory.ram")
    silo.ws.record("incremental-authentication", json.dumps({"snapshot": saved.snapshot,
        "rootBytes": len(encoded), "changeRecords": len(changes.records), "affectedChunks": sorted(affected),
        "memory": evidence, "seedProbe": probe}, sort_keys=True) + "\n")
    return {"map": (root, leaves), "affected": affected, "stats": stats}


def full_file_oracle(silo: Silo, saved: restore.Checkpoint, *, full_identity: bool = False) -> dict:
    """Independently scan every RAM/disk byte and authenticate catalog map closures."""
    home = silo.ws.silo_home
    evidence = saved.seal["memory"]
    files = [(saved.staging / "memory.ram", stream_map.RAM_CHUNK)]
    files.extend((path, stream_map.DISK_CHUNK) for path in sorted((saved.staging / "disks").glob("*.raw")))
    for path, chunk in files:
        root, leaves = stream_map.from_file(path, chunk)
        members = [entry for entry in saved.seal["inventory"]
                   if entry["role"] == str(path.relative_to(saved.staging))]
        assert len(members) == 1 and members[0]["identity"] == root.identity, (path, members)
        binding = {"stream": root.identity, "map": root.identity,
                   "length": root.length, "chunkSize": chunk}
        assert stream_map.catalog_root(home, binding) == (root, leaves), path
        if path.name == "memory.ram":
            assert evidence["ramStream"] == root.identity
            if full_identity:
                assert evidence["identityPolicy"] == "full" and evidence["baseline"] is None, evidence
                assert evidence["identityFullReason"] == "unknown-anchor-after-fork", evidence
                expected_hash_bytes = sum(min(chunk, root.length - index * chunk) for index in leaves)
                assert evidence["stats"]["identityBytesHashed"] == expected_hash_bytes, evidence
    verified = silo.json("snapshot", "verify", saved.reference, timeout=240)
    assert verified["snapshot"] == saved.snapshot and verified["bytes"] > 0, verified
    return evidence["stats"]


def catalog_map(silo: Silo, binding: dict) -> tuple[stream_map.Root, dict[int, str]]:
    return stream_map.catalog_root(silo.ws.silo_home, binding)


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
        "--name", "incremental-full-oracle", "--format", "json", timeout=240).stdout)
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
