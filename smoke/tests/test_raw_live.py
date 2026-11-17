"""Default-selection live coverage for whole-disk roots and managed raw data.

Uses the session BASIC image, without compiling the slow capture witnesses.
The multidisk helper installs two small managed ext4 disks under the lifecycle
lock, so these exercise included writable storage, not external --disk grants.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from silo_smoke import capture_multidisk as multidisk, fork, procs, reclaim, restore, stopped, stream_map
from silo_smoke.cli import RootProfile, Silo

pytestmark = pytest.mark.linux_only


def create(silo: Silo, image: str, name: str, profile: RootProfile) -> None:
    silo.create(name, silo.root_image(image, profile), "--cpus", "1", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")


def live_snapshot(silo: Silo, name: str, alias: str) -> tuple[str, dict[str, Any]]:
    value = silo.json("snapshot", "create", name, "--live", "--name", alias, timeout=60)
    assert value["snapshot"]["captureKind"] == "live-execution"
    summary = value["capture"]
    assert summary["sourceOutcome"] == "resumed" and summary["released"] is True
    relative = Path(summary["staging"])
    assert not relative.is_absolute() and ".." not in relative.parts
    seal = json.loads((silo.ws.silo_home / relative / "vm.capture.json").read_bytes())
    assert seal["captureOutcome"] == "coherent" and seal["error"] is None
    return str(value["snapshot"]["id"]), seal


def snapshot_record(silo: Silo, snapshot: str) -> dict[str, Any]:
    rows = procs.query(silo.ws.state_db(),
                       f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{snapshot}'")
    assert len(rows) == 1
    return json.loads(rows[0][0])


def verify(silo: Silo, snapshot: str) -> None:
    # The CLI's default expectation is exit zero; never accept an error object.
    value = silo.json("snapshot", "verify", "image:" + snapshot, timeout=60)
    assert value["snapshot"] == snapshot
    assert value["streams"] > 0 and value["bytes"] > 0


def test_raw_root_live_snapshot_restore_fork_and_stopped(silo: Silo, basic_image: str) -> None:
    source = "raw-live-source"
    create(silo, basic_image, source, "raw")
    root = stopped.record(silo, source)["root"]
    assert root["kind"] == "opaque-raw" and root["layout"] == {"kind": "whole-disk"}
    silo.start(source)
    silo.wait_ready(source)
    silo.exec(source, "sh", "-eu", "-c", "printf 'first\\n' >/raw-live-marker; sync", user="root")
    # Boot free-page reporting dirties reclaimed RAM. Settle before establishing
    # the baseline so the second cut actually exercises incremental capture.
    reclaim.settled(silo, source)
    first, first_seal = live_snapshot(silo, source, "raw-live-first")
    assert first_seal["memory"]["mode"] == "full"
    silo.exec(source, "sh", "-eu", "-c", "printf 'changed\\n' >/raw-live-marker; sync", user="root")
    second, second_seal = live_snapshot(silo, source, "raw-live-second")
    assert first != second
    assert second_seal["memory"]["mode"] == "incremental"
    assert second_seal["memory"]["baseline"] == first_seal["memory"]["ramStream"]
    for snapshot in (first, second):
        record = snapshot_record(silo, snapshot)
        assert record["captureKind"] == "live-execution"
        assert record["root"]["profile"] == {"kind": "opaque-raw"}
        verify(silo, snapshot)

    restored = "raw-live-restored"
    restore.restore_child(silo, "image:" + first, restored)
    assert stopped.record(silo, restored)["root"]["kind"] == "opaque-raw"
    assert silo.exec(restored, "cat", "/raw-live-marker").stdout == "first\n"
    silo.stop(restored)

    live_child = "raw-live-fork"
    call = fork.run(silo, source, [live_child], expect=0, timeout=60)
    assert fork.outcomes(call.result) == ["running"]
    silo.wait_ready(live_child)
    assert stopped.record(silo, live_child)["root"]["kind"] == "opaque-raw"
    assert silo.exec(live_child, "cat", "/raw-live-marker").stdout == "changed\n"
    silo.stop(live_child)

    silo.stop(source)
    captured = silo.json("snapshot", "create", source, "--name", "raw-stopped", timeout=60)
    record = snapshot_record(silo, str(captured["id"]))
    assert record["captureKind"] == "stopped-storage"
    assert record["root"]["profile"] == {"kind": "opaque-raw"}
    stopped_child = "raw-stopped-fork"
    stopped.fork(silo, source, stopped_child)
    assert stopped.record(silo, stopped_child)["root"]["kind"] == "opaque-raw"
    silo.start(stopped_child)
    silo.wait_ready(stopped_child)
    assert silo.exec(stopped_child, "cat", "/raw-live-marker").stdout == "changed\n"


def test_layered_root_live_snapshot_restores_managed_raw_data(silo: Silo, basic_image: str) -> None:
    source = "raw-data-source"
    create(silo, basic_image, source, "layered")
    # Reuse the real multidisk fixture construction with BASIC: the slow
    # module's compiled, continuously dirtying workload is unnecessary here.
    roles = multidisk.install_disks(silo, source)
    storage = stopped.record(silo, source)
    assert storage["root"]["kind"] == "linux-overlay"
    assert len(roles) == len(storage["disks"]) == 2
    assert all(disk["storage"]["kind"] == "managed-writable" for disk in storage["disks"])
    silo.start(source)
    silo.wait_ready(source)
    multidisk.mount_sources(silo, source)
    silo.exec(source, "sh", "-eu", "-c", """
printf 'root-at-cut\\n' >/raw-live-marker
printf 'data-a-at-cut\\n' >/capture-a/raw-live-marker
printf 'data-b-at-cut\\n' >/capture-b/raw-live-marker
sync
""", user="root")
    snapshot, _ = live_snapshot(silo, source, "raw-data-live")
    verify(silo, snapshot)
    silo.exec(source, "sh", "-eu", "-c", """
for path in /raw-live-marker /capture-a/raw-live-marker /capture-b/raw-live-marker; do
    printf 'source-after-cut\\n' >\"$path\"
done
sync
""", user="root")
    restored = "raw-data-restored"
    restore.restore_child(silo, "image:" + snapshot, restored)
    assert silo.exec(restored, "cat", "/raw-live-marker", "/capture-a/raw-live-marker",
                     "/capture-b/raw-live-marker").stdout == "root-at-cut\ndata-a-at-cut\ndata-b-at-cut\n"


@pytest.mark.parametrize(("member", "unit", "role"), [
    ("memory", stream_map.RAM_CHUNK, "RAM"), ("root", stream_map.DISK_CHUNK, "root disk"),
])
def test_verify_localizes_flipped_payload_despite_warm_receipts(
    silo: Silo, basic_image: str, member: str, unit: int, role: str,
) -> None:
    source = "verify-localization"
    create(silo, basic_image, source, "raw")
    silo.start(source)
    silo.wait_ready(source)
    snapshot, _ = live_snapshot(silo, source, "verify-localization-cut")
    record = snapshot_record(silo, snapshot)
    binding = record["execution"]["memory"] if member == "memory" else record["root"]["stream"]
    root, _ = stream_map.catalog_root(silo.ws.silo_home, binding)
    assert root.chunk_size == unit
    path = silo.ws.silo_home / "images/streams/sha256" / binding["stream"][7:]
    assert stream_map.from_file(path, unit)[0] == root
    if member == "memory":
        child = "verify-root-restored"
        restore.restore_child(silo, "image:" + snapshot, child)
        # This is the actual file mapped into the restored guest, not a second
        # staging copy or a claimed stream ID from a CLI response.
        mapping = fork.ram_mapping(fork.worker(silo, child), path)
        assert mapping["inode"] == path.stat().st_ino and mapping["mappedBytes"] > 0
        assert stream_map.from_file(path, unit)[0].identity == binding["stream"]
        silo.stop(child)
    silo.stop(source)
    verify(silo, snapshot)
    offset = unit + 123
    index = offset // unit
    mode = path.stat().st_mode & 0o7777
    path.chmod(0o600)
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    original = os.pread(fd, 1, offset)
    assert len(original) == 1
    try:
        assert os.pwrite(fd, bytes([original[0] ^ 0x80]), offset) == 1
        os.fsync(fd)
        os.fchmod(fd, mode)
        failed = silo.run("snapshot", "verify", "image:" + snapshot, "--format", "json",
                          expect=1, timeout=120)
        error = json.loads(failed.stdout)["error"]
        assert (error["kind"], error["role"], error["stream"]) == ("chunkMismatch", role, binding["stream"])
        assert (error["chunkSize"], error["index"], error["start"], error["end"]) == (
            unit, index, index * unit, min((index + 1) * unit, binding["length"]))
        assert error["expected"] != error["actual"]
    finally:
        os.pwrite(fd, original, offset)
        os.fsync(fd)
        os.close(fd)
        path.chmod(mode)
    verify(silo, snapshot)


@pytest.mark.parametrize("height", range(5))
def test_verify_refuses_corrupt_map_node_closure(silo: Silo, basic_image: str, height: int) -> None:
    source = "verify-node"
    create(silo, basic_image, source, "raw")
    silo.start(source)
    silo.wait_ready(source)
    snapshot, _ = live_snapshot(silo, source, "verify-node-cut")
    binding = snapshot_record(silo, snapshot)["execution"]["memory"]
    root, _ = stream_map.catalog_root(silo.ws.silo_home, binding)
    source_bytes = stream_map.object_source(silo.ws.silo_home)
    node = root.tree
    assert node is not None
    for level in range(4, height, -1):
        node = next(iter(stream_map.decode_node(source_bytes(node), level).values()))
    path = silo.ws.silo_home / "images/objects/sha256" / node[7:]
    original = path.read_bytes()
    mode = path.stat().st_mode & 0o7777
    silo.stop(source)
    try:
        path.chmod(0o600)
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 0x80]))
        path.chmod(mode)
        failed = silo.run("snapshot", "verify", "image:" + snapshot, "--format", "json", expect=1, timeout=120)
        error = json.loads(failed.stdout)["error"]
        assert (error["kind"], error["role"], error["node"], error["height"]) == (
            "mapNode", "RAM", node, height)
        assert "index" not in error
    finally:
        path.chmod(0o600)
        path.write_bytes(original)
        path.chmod(mode)
