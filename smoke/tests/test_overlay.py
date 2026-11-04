from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

import pytest

from silo_smoke import images, overlay, procs, shutdown
from silo_smoke.cli import Silo
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


@pytest.fixture(scope="session")
def overlay_image(registry: LoopbackRegistry, overlay_image_bytes: images.OciImage) -> str:
    return registry.publish(overlay_image_bytes, "overlay")


@pytest.fixture(scope="session")
def overlay_large_image(config: SmokeConfig, registry: LoopbackRegistry, overlay_probe: Path) -> str:
    return registry.publish(overlay.image(config, overlay_probe, large=True), "overlay-large")


@pytest.fixture(scope="session")
def overlay_capacity_consumer(config: SmokeConfig) -> Path:
    binary = config.bin_dir / "examples/storage_acceptance"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/storage_acceptance"
    assert binary.is_file(), "Main must build cargo build -p libvm --example storage_acceptance"
    return binary


def test_overlay_production_persistence_index_metadata_whiteouts(silo: Silo, overlay_image: str) -> None:
    name = "overlay-persist"
    overlay.create(silo, name, overlay_image)
    observed = overlay.evidence(silo, name)
    first_frame = overlay.metrics(silo, name)["_observation"]
    first_run = procs.run_id(silo.ws, name)
    first_monitor = procs.vmm_pid(silo.ws, name)
    descriptor = overlay.machine_dir(silo, name) / "lower.vmdk"
    lower = overlay.records(descriptor)[0].path
    before = overlay.digest(lower)
    assert overlay.filesystem_magic(silo, name, "/") == overlay.OVERLAYFS_SUPER_MAGIC
    overlay.probe(silo, name, "lower-ro")
    overlay.probe(silo, name, "metadata")
    setup = silo.exec(name, "sh", "-eu", "-c", """
stat -c '%i' /run/silo/rootfs/upperfs/work/index
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
"$1" durable /root-committed
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
"$1" durable /tmp/tmp-committed
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
stat -c '%d' / /tmp
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
stat -c '%d' /tmp
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
""", "overlay-persist-setup", overlay.PROBE, user="root").stdout
    setup_parts = setup.split("SILO_OVERLAY_PERSIST_BOUNDARY\n")
    assert len(setup_parts) == 6 and setup_parts[-1] == "", setup
    index_lines = setup_parts[0].split("\n")
    assert len(index_lines) == 2 and index_lines[-1] == "", setup_parts[0]
    index_inode = index_lines[0].strip()
    devices = setup_parts[3].split("\n")
    tmp_device = setup_parts[4].split("\n")
    assert len(devices) == 3 and devices[-1] == "", setup_parts[3]
    assert len(tmp_device) == 2 and tmp_device[-1] == "", setup_parts[4]
    assert devices[0] == tmp_device[0].strip()
    overlay.orderly_guest_shutdown(silo, name)
    assert silo.info(name)["state"] == "stopped"
    assert overlay.digest(lower) == before
    stopped = overlay.ext4(overlay.upper(silo, name))
    assert stopped["incompat"] & 4 == 0, "orderly shutdown left RECOVER set"
    silo.start(name)
    silo.wait_ready(name)
    next_frame = overlay.metrics(silo, name)["_observation"]
    assert next_frame["agentInstanceId"] != first_frame["agentInstanceId"]
    assert procs.run_id(silo.ws, name) != first_run
    silo.ws.record("overlay-restart-identity", json.dumps({"before": first_frame, "after": next_frame, "oldRun": first_run, "newRun": procs.run_id(silo.ws, name), "oldMonitor": first_monitor, "newMonitor": procs.vmm_pid(silo.ws, name)}) + "\n")
    overlay.probe(silo, name, "persist-check")
    readback = silo.exec(name, "sh", "-eu", "-c", """
stat -c '%i' /run/silo/rootfs/upperfs/work/index
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
cat /root-committed
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
cat /tmp/tmp-committed
printf '%s\\n' SILO_OVERLAY_PERSIST_BOUNDARY
""", "overlay-persist-readback", user="root").stdout
    readback_parts = readback.split("SILO_OVERLAY_PERSIST_BOUNDARY\n")
    assert len(readback_parts) == 4 and readback_parts[-1] == "", readback
    index_lines = readback_parts[0].split("\n")
    assert len(index_lines) == 2 and index_lines[-1] == "", readback_parts[0]
    assert index_lines[0].strip() == index_inode
    assert readback_parts[1] == "committed\n"
    assert readback_parts[2] == "committed\n"
    assert overlay.observation(silo, name)["root"]["upper"]["filesystemUuid"] == observed["root"]["upper"]["filesystemUuid"]
    assert overlay.digest(lower) == before


def test_overlay_sized_tmpfs_and_policy_removal(silo: Silo, overlay_image: str) -> None:
    name = "overlay-tmpfs"
    overlay.create(silo, name, overlay_image, "--tmpfs-size", "8mib")
    assert overlay.filesystem_magic(silo, name, "/tmp") == overlay.TMPFS_MAGIC
    assert overlay.observation(silo, name)["root"]["temporaryDirectory"] == {"kind": "tmpfs", "capacityBytes": 8 * 1024**2}
    overlay.evidence(silo, name)
    assert silo.exec(name, "stat", "-c", "%a", "/tmp", user="root").stdout.strip() == "1777"
    silo.exec(name, overlay.PROBE, "durable", "/tmp/temporary", user="root")
    silo.stop(name)
    silo.start(name)
    silo.wait_ready(name)
    silo.exec(name, "test", "!", "-e", "/tmp/temporary", user="root")
    silo.stop(name)
    silo.run("set", name, "tmpfs-size=off")
    silo.start(name)
    silo.wait_ready(name)
    assert overlay.filesystem_magic(silo, name, "/tmp") == overlay.OVERLAYFS_SUPER_MAGIC
    assert overlay.observation(silo, name)["root"]["temporaryDirectory"] == {"kind": "disk-backed"}
    overlay.evidence(silo, name)
    silo.exec(name, overlay.PROBE, "durable", "/tmp/hidden-disk-sentinel", user="root")
    silo.stop(name)
    silo.run("set", name, "tmpfs-size=8mib")
    silo.start(name)
    silo.wait_ready(name)
    silo.exec(name, "test", "!", "-e", "/tmp/hidden-disk-sentinel", user="root")
    silo.stop(name)
    silo.run("set", name, "tmpfs-size=off")
    silo.start(name)
    silo.wait_ready(name)
    assert silo.exec(name, "cat", "/tmp/hidden-disk-sentinel", user="root").stdout == "committed\n"


@pytest.mark.linux_only
def test_overlay_actual_worker_readonly_handles(silo: Silo, overlay_image: str) -> None:
    name = "overlay-handles"
    overlay.create(silo, name, overlay_image)
    overlay.handle_evidence(silo, name, overlay.machine_dir(silo, name) / "lower.vmdk")


@pytest.mark.slow
@pytest.mark.linux_only
def test_vmdk_production_split_mapping_independent_oracles(silo: Silo, overlay_large_image: str) -> None:
    name = "vmdk-split"
    overlay.create(silo, name, overlay_large_image)
    descriptor = overlay.machine_dir(silo, name) / "lower.vmdk"
    records = overlay.records(descriptor)
    lower = records[0].path
    assert lower.stat().st_size > overlay.SPLIT
    assert len(records) >= 2 and records[1].offset == overlay.SPLIT // 512
    wrong_mismatches = 0
    zero_controls = 0
    for offset, length in overlay.probes(lower.stat().st_size):
        expected = overlay.linear_read([lower], offset, length)
        assert overlay.record_read(records, offset, length) == expected
        actual = bytes.fromhex(overlay.probe(silo, name, "read", str(offset), str(length))["hex"])
        assert actual == expected, f"production lower mismatch at {offset}+{length}"
        wrong = overlay.record_read(records, offset, length, wrong_bytes=True)
        if offset + length <= overlay.SPLIT:
            assert wrong == expected
            zero_controls += 1
        elif wrong != expected:
            wrong_mismatches += 1
    assert zero_controls and wrong_mismatches, "byte-offset negative control did not detect mapping defect"
    silo.ws.record("vmdk-negative-control", f"mutation=reader-offsets-as-bytes mismatches={wrong_mismatches} zero-offset-controls={zero_controls}\n")
    overlay.handle_evidence(silo, name, descriptor)
    overlay.probe(silo, name, "lower-ro")


def test_vmdk_home_spaces_and_relocation(silo: Silo, workspace: Workspace, overlay_image: str) -> None:
    old = workspace.silo_home
    spaced = workspace.root / "state with interior spaces"
    old.rename(spaced)
    workspace.silo_home = spaced
    overlay.create(silo, "overlay-moved", overlay_image)
    original_descriptor = overlay.machine_dir(silo, "overlay-moved") / "lower.vmdk"
    lower_digest = overlay.digest(overlay.records(original_descriptor)[0].path)
    silo.stop("overlay-moved")
    moved = workspace.root / "relocated state with spaces"
    spaced.rename(moved)
    workspace.silo_home = moved
    silo.start("overlay-moved")
    silo.wait_ready("overlay-moved")
    descriptor = overlay.machine_dir(silo, "overlay-moved") / "lower.vmdk"
    assert str(spaced) not in descriptor.read_text()
    assert str(moved) in descriptor.read_text()
    assert overlay.digest(overlay.records(descriptor)[0].path) == lower_digest
    overlay.probe(silo, "overlay-moved", "lower-ro")


@pytest.mark.parametrize("kind", ["blocks", "inodes", "copyup"])
def test_overlay_guest_enospc(silo: Silo, overlay_image: str, kind: str) -> None:
    name = "overlay-enospc"
    overlay.create(silo, name, overlay_image, capacity="64mib")
    lower = overlay.records(overlay.machine_dir(silo, name) / "lower.vmdk")[0].path
    before = overlay.digest(lower)
    host_before = shutil.disk_usage(silo.ws.silo_home).free
    assert host_before > 512 * 1024**2, "guest ENOSPC gate requires ample host space"
    result = overlay.probe(silo, name, "fill", kind, timeout=120)
    assert result["errno"] == 28
    exhausted = overlay.metrics(silo, name)
    if kind == "inodes":
        assert exhausted["upperFreeInodes"] == 0
        assert exhausted["upperFreeBytes"] > 0
    elif kind == "blocks":
        assert exhausted["upperAvailableBytes"] < 1024**2
        assert exhausted["upperFreeInodes"] > 0
    else:
        assert exhausted["upperFreeInodes"] > 0
        expected = overlay.PatternReader(512).read(512).hex()
        assert silo.exec(name, overlay.PROBE, "read-file", "/overlay-fixture/large", "0", user="root").stdout.strip() == expected
    overlay.evidence(silo, name)
    host_after = shutil.disk_usage(silo.ws.silo_home).free
    assert host_after > 256 * 1024**2
    assert overlay.digest(lower) == before
    if kind != "copyup":
        silo.exec(name, "rm", "-rf", "/fill", user="root")
        silo.exec(name, overlay.PROBE, "syncfs", user="root")
        recovered = overlay.metrics(silo, name)
        if kind == "inodes":
            assert recovered["upperFreeInodes"] > exhausted["upperFreeInodes"]
        else:
            assert recovered["upperAvailableBytes"] > exhausted["upperAvailableBytes"]
    silo.ws.record("overlay-enospc", json.dumps({"kind": kind, "errno": result["errno"], "host_free_before": host_before, "host_free_after": host_after}) + "\n")


def test_overlay_effective_index_downgrade_is_rejected(silo: Silo, overlay_image: str) -> None:
    name = "overlay-downgrade"
    overlay.create(silo, name, overlay_image)
    # Select by actual export-handle behavior, not a filesystem-name assumption.
    silo.exec(name, "sh", "-c", "set -eu\nmkdir -p /downgrade/lower /downgrade/merged /run/silo/rootfs/upperfs/downgrade-upper /run/silo/rootfs/upperfs/downgrade-work\nmount -t tmpfs -o size=1m tmpfs /downgrade/lower\necho source >/downgrade/lower/file\n", user="root")
    handle = overlay.probe(silo, name, "export-handle", "/downgrade/lower/file")
    if handle["errno"] != 95:
        silo.exec(name, "sh", "-c", "set -eu\numount /downgrade/lower\nmount -t ramfs ramfs /downgrade/lower\necho source >/downgrade/lower/file\n", user="root")
        handle = overlay.probe(silo, name, "export-handle", "/downgrade/lower/file")
    assert handle["errno"] == 95, "scratch lower must actually lack export handles"
    silo.exec(name, "sh", "-c", "set -eu\nmount -t overlay overlay -o lowerdir=/downgrade/lower,upperdir=/run/silo/rootfs/upperfs/downgrade-upper,workdir=/run/silo/rootfs/upperfs/downgrade-work,index=on,metacopy=off,redirect_dir=nofollow,xino=on,nfs_export=off,uuid=null /downgrade/merged\ncat /downgrade/merged/file\ncat /proc/self/mountinfo\n", user="root")
    assert overlay.probe(silo, name, "downgrade")["effective_index"] is False


@pytest.mark.slow
@pytest.mark.parametrize("dirty", [False, True], ids=["clean", "dirty"])
@pytest.mark.parametrize("capacity", [128 * 1024**2 + 4096, 16 * 1024**3 + 4096, 16 * 1024**3 + 4 * 1024**2, 1024**4])
@pytest.mark.linux_only
def test_overlay_replacement_growth_and_short_tails(silo: Silo, overlay_image: str, overlay_capacity_consumer: Path, capacity: int, dirty: bool) -> None:
    name = "overlay-growth"
    if capacity >= 16 * 1024**3:
        host_fs = int(subprocess.run(["stat", "-f", "-c", "%t", str(silo.ws.root)], capture_output=True, text=True, check=True, timeout=15).stdout.strip(), 16)
        assert host_fs != overlay.TMPFS_MAGIC, "large growth/copy gates require TMPDIR on a short durable /home path, not /tmp tmpfs"
    overlay.create(silo, name, overlay_image, capacity="64mib")
    silo.exec(name, overlay.PROBE, "durable", "/committed", user="root")
    before = overlay.observation(silo, name)
    lower = overlay.records(overlay.machine_dir(silo, name) / "lower.vmdk")[0].path
    lower_digest = overlay.digest(lower)
    if dirty:
        writer = silo.popen("exec", name, "--user", "root", "--", overlay.PROBE, "write-loop", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            import selectors
            assert writer.stdout is not None
            with selectors.DefaultSelector() as ready:
                ready.register(writer.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), "guest mutator never made observable write/fsync progress"
                assert writer.stdout.readline().strip() == b"SILO_DIRTY_WRITER_STARTED"
            silo.ws.record("overlay-dirty-writer", "observed >=17 guest file mutations with actual fsync progress before forced worker kill\n")
            time.sleep(0.05)
            from uuid import UUID
            killed_worker = overlay.worker_pid(silo, name)
            killed_monitor = procs.vmm_pid(silo.ws, name)
            killed_run = procs.run_id(silo.ws, name)
            assert killed_monitor is not None and killed_run is not None
            terminal_path = silo.ws.silo_home / "logs/machines" / silo.machine_id(name) / "vm.exit.json"
            os.kill(killed_worker, signal.SIGKILL)
            deadline = time.monotonic() + 60
            terminal = None
            while time.monotonic() < deadline:
                if terminal_path.is_file():
                    observed = json.loads(terminal_path.read_text())
                    if UUID(observed["runId"]) == UUID(killed_run):
                        terminal = observed
                        break
                time.sleep(0.05)
            assert terminal is not None, "forced recovery source needs an exact current-run terminal artifact"
            silo.ws.record("overlay-dirty-terminal", json.dumps(terminal, sort_keys=True) + "\n")
            assert UUID(terminal["machineId"]) == UUID(silo.machine_id(name)) and terminal["pid"] == killed_monitor
            assert terminal["backend"]["process"]["pid"] == killed_worker and terminal["backend"]["process"]["signal"] == signal.SIGKILL
            procs.wait_gone(killed_worker, timeout=20)
            procs.wait_gone(killed_monitor, timeout=20)
        finally:
            try:
                writer.wait(timeout=20)
            except subprocess.TimeoutExpired:
                writer.kill()
                writer.wait(timeout=10)
            if writer.stdout is not None:
                writer.stdout.close()
    else:
        overlay.orderly_guest_shutdown(silo, name)
    old = overlay.upper(silo, name)
    old_length = old.stat().st_size
    prefix = overlay.digest(old)
    old_uuid = overlay.ext4(old)["uuid"]
    if dirty:
        assert overlay.ext4(old)["incompat"] & 4
    else:
        assert not overlay.ext4(old)["incompat"] & 4, "clean source must have cleared RECOVER"
    source = silo.ws.evidence / "immutable-upper-source.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(old), str(source)], check=True, timeout=120)
    source.chmod(0o400)
    second_source = silo.ws.evidence / "second-unreplayed-upper.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(source), str(second_source)], check=True, timeout=120)
    second_source.chmod(0o400)
    if capacity % (1024**2) == 0:
        silo.run("set", name, f"disk={capacity // (1024**2)}mib")
    else:
        result = subprocess.run([str(overlay_capacity_consumer), "set-root-capacity", name, str(capacity)], env=silo.ws.env(), capture_output=True, text=True, timeout=250)
        silo.ws.record("overlay-exact-capacity-rust", result.stdout + "\n" + result.stderr)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["capacityBytes"] == capacity
    replacement = overlay.upper(silo, name)
    assert replacement != old and replacement.stat().st_size == capacity
    assert overlay.digest(replacement, old_length) == prefix
    assert overlay.ext4(replacement)["uuid"] == old_uuid
    silo.ws.record("overlay-growth-allocation", json.dumps({"stage": "replacement-before-boot", "originalPrefixBytesCompared": old_length, "files": [{"path": str(path), "logicalBytes": path.stat().st_size, "allocatedBytes": path.stat().st_blocks * 512} for path in (source, second_source, replacement)]}) + "\n")
    silo.start(name)
    silo.wait_ready(name, timeout=240)
    after = overlay.evidence(silo, name)
    assert after["root"]["upper"]["filesystemUuid"] == before["root"]["upper"]["filesystemUuid"]
    assert after["upperFilesystemBytes"] + after["unusableTailBytes"] == capacity
    assert after["unusableTailBytes"] == (4096 if capacity in {128 * 1024**2 + 4096, 16 * 1024**3 + 4096} else 0)
    assert silo.exec(name, "cat", "/committed", user="root").stdout == "committed\n"
    silo.exec(name, overlay.PROBE, "durable", "/first-private-only", user="root")
    overlay.orderly_guest_shutdown(silo, name, timeout=240)
    inspected = subprocess.run(["e2fsck", "-fn", str(replacement)], capture_output=True, text=True, timeout=240)
    silo.ws.record("overlay-recovered-e2fsck", inspected.stdout + inspected.stderr)
    assert inspected.returncode == 0
    assert not overlay.ext4(replacement)["incompat"] & (0x10 | 4), "META_BG or dirty state after orderly stop"
    achieved = overlay.ext4(replacement)
    descriptors = ((achieved["filesystem_bytes"] + 128 * 1024**2 - 1) // (128 * 1024**2) + 127) // 128
    assert achieved["reserved_gdt"] == 64 - descriptors
    assert overlay.digest(source) == prefix
    first_recovered = silo.ws.evidence / "first-recovered-private.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(replacement), str(first_recovered)], check=True, timeout=120)
    first_prefix = overlay.digest(first_recovered, old_length)
    silo.ws.record("overlay-growth-allocation", json.dumps({"stage": "first-recovery-copy", "originalPrefixBytesCompared": old_length, "files": [{"path": str(path), "logicalBytes": path.stat().st_size, "allocatedBytes": path.stat().st_blocks * 512} for path in (source, first_recovered, replacement)]}) + "\n")
    # A second independent recovery starts from the original dirty/clean bytes,
    # copied before either recovery, not a public snapshot or writable hardlink.
    shutil.copyfile(second_source, replacement)
    replacement.chmod(0o600)
    with replacement.open("r+b") as stream:
        stream.truncate(capacity)
    silo.start(name)
    silo.wait_ready(name, timeout=240)
    silo.exec(name, "test", "!", "-e", "/first-private-only", user="root")
    assert silo.exec(name, "cat", "/committed", user="root").stdout == "committed\n"
    silo.exec(name, overlay.PROBE, "durable", "/second-private-only", user="root")
    assert overlay.digest(source) == prefix
    assert overlay.digest(first_recovered, old_length) == first_prefix
    overlay.orderly_guest_shutdown(silo, name, timeout=240)
    inspected = subprocess.run(["e2fsck", "-fn", str(replacement)], capture_output=True, text=True, timeout=240)
    silo.ws.record("overlay-second-recovered-e2fsck", inspected.stdout + inspected.stderr)
    assert inspected.returncode == 0
    assert overlay.digest(lower) == lower_digest


@pytest.mark.slow
def test_overlay_directory_scale_dir_nlink_htree(silo: Silo, overlay_image: str) -> None:
    name = "overlay-directories"
    overlay.create(silo, name, overlay_image, capacity="2gib")
    assert overlay.probe(silo, name, "dirs", timeout=240)["directories"] == 66000
    overlay.orderly_guest_shutdown(silo, name, timeout=240)
    upper = overlay.upper(silo, name)
    assert not overlay.ext4(upper)["incompat"] & 4, "host directory inspection requires RECOVER cleared by guest shutdown"
    result = subprocess.run(["debugfs", "-R", "stat /upper/directory-scale", str(upper)], capture_output=True, text=True, check=True, timeout=30)
    silo.ws.record("overlay-directory-inode", result.stdout + result.stderr)
    import re
    flags = re.search(r"\bFlags:\s*(0x[0-9a-fA-F]+)", result.stdout)
    links = re.search(r"\bLinks:\s*(\d+)", result.stdout)
    assert flags is not None and int(flags.group(1), 16) & 0x1000, "directory has no independently observed EXT4_INDEX_FL"
    assert links is not None and int(links.group(1)) == 1, "DIR_NLINK sentinel was not exercised"
    silo.start(name)
    silo.wait_ready(name)
    silo.exec(name, "sh", "-c", "set -eu\nfor n in 00000 32000 64999 65999; do test -d /directory-scale/d$n; done\nrmdir /directory-scale/d65999\ntest ! -e /directory-scale/d65999\n", user="root")


@pytest.mark.parametrize("reserved", ["trusted.overlay.opaque", "user.overlay.opaque", "char-zero"])
def test_overlay_reserved_oci_encodings_reject_before_machine_publication(silo: Silo, config: SmokeConfig, registry: LoopbackRegistry, overlay_probe: Path, overlay_image_bytes: images.OciImage, reserved: str) -> None:
    from uuid import UUID
    admitted = registry.publish(overlay_image_bytes, "overlay-reserved-positive-control")
    silo.create("reserved-control", admitted, "--root-profile", overlay.PROFILE, "--disk-size", "64mib", "--network", "none")
    before = {UUID(machine["id"]) for machine in silo.ls()}
    image = overlay.image(config, overlay_probe, reserved=reserved)
    reference = registry.publish(image, "overlay-forbidden-" + reserved.replace(".", "-"))
    result = silo.run("create", reference, "--name", "forbidden-overlay", "--root-profile", overlay.PROFILE, expect=None)
    assert result.returncode != 0
    assert {UUID(machine["id"]) for machine in silo.ls()} == before, "rejected metadata published a machine"
    artifacts = procs.query(silo.ws.state_db(), "SELECT COUNT(*) FROM image_rootfs_artifact WHERE manifest_digest='" + image.manifest_digest + "'")
    assert artifacts == [("0",)], "rejected metadata published a failed rootfs artifact"
    silo.ws.record("overlay-reserved-refusal", json.dumps({"mutation": reserved, "manifestDigest": image.manifest_digest, "positiveControlMachineIds": sorted(str(value) for value in before), "publishedRejectedRootfsArtifacts": 0}) + "\n" + result.stdout + result.stderr)


def test_overlay_raw_default_regression(silo: Silo, basic_image: str) -> None:
    name = "overlay-raw-regression"
    silo.create(name, basic_image, "--network", "none", "--vsock")
    assert (overlay.machine_dir(silo, name) / "root.raw").is_file()
    silo.start(name)
    silo.wait_ready(name)
    assert overlay.filesystem_magic(silo, name, "/") != overlay.OVERLAYFS_SUPER_MAGIC
    silo.exec(name, "sh", "-c", "set -eu\necho raw >/raw-sentinel\nsync\n", user="root")
    silo.stop(name)
    silo.start(name)
    silo.wait_ready(name)
    assert silo.exec(name, "cat", "/raw-sentinel", user="root").stdout == "raw\n"


def test_vmdk_historical_occurrences_independent_negative_control(workspace: Workspace) -> None:
    # Exact retained experiment layout: a=4.5GiB, empty, b=1MiB, b repeated.
    a = workspace.root / "a.bin"
    b = workspace.root / "b.bin"
    empty = workspace.root / "empty.bin"
    with a.open("wb") as stream:
        stream.truncate(4_831_838_208)
    b.write_bytes(bytes(range(256)) * 4096)
    empty.touch()
    records = [overlay.Record(4_194_304, a, 0), overlay.Record(4_194_304, a, 4_194_304), overlay.Record(1_048_576, a, 8_388_608), overlay.Record(2048, b, 0), overlay.Record(2048, b, 0)]
    occurrences = [a, empty, b, b]
    total = sum(path.stat().st_size for path in occurrences)
    assert total == 4_833_935_360
    import random
    rng = random.Random(14)
    with a.open("r+b") as stream:
        for offset in [0, overlay.SPLIT - 4096, overlay.SPLIT, overlay.SPLIT + 4096, 2 * overlay.SPLIT - 4096, 2 * overlay.SPLIT, a.stat().st_size - 4096]:
            stream.seek(offset)
            stream.write(rng.randbytes(4096))
    mismatches = 0
    for offset, length in [*overlay.probes(total), (a.stat().st_size - 2048, 4096), (a.stat().st_size, 4096), (a.stat().st_size + b.stat().st_size - 2048, 4096)]:
        expected = overlay.linear_read(occurrences, offset, length)
        assert overlay.record_read(records, offset, length) == expected
        wrong = overlay.record_read(records, offset, length, wrong_bytes=True)
        if offset + length <= overlay.SPLIT:
            assert wrong == expected
        elif wrong != expected:
            mismatches += 1
    assert mismatches > 0
    workspace.record("vmdk-historical-oracle", f"seed=14 bytes={total} sectors=9441280 records=5 mutation=reader-offsets-as-bytes mismatches={mismatches}\n")


def test_overlay_candidate_qualification(silo: Silo, overlay_image: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_image)
    try:
        candidate.start()
        text = candidate.wait()
        metadata = json.loads((silo.ws.config.runtime_dir / "runtime-manifest.json").read_text())["managedOverlayCandidate"]
        assert metadata["kernelDigest"] == "sha256:" + candidate.identities["kernelSha256"]
        assert metadata["baseInitramfsDigest"] == "sha256:" + candidate.identities["initramfsSha256"]
        assert metadata["nativeExecutableDigest"] == "sha256:" + candidate.identities["monitorWorkerSha256"]
        config_input = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
        if config_input:
            config_digest = candidate.identities["resolvedConfigDigest"]
        else:
            artifact = metadata["kernelArtifact"]
            assert artifact is not None, "supply actual resolved Kconfig via SILO_SMOKE_KERNEL_CONFIG for local kernel"
            config_digest = artifact["resolvedConfig"]["digest"]
            assert artifact["kernel"]["digest"] == metadata["kernelDigest"]
        candidate.identities["resolvedConfigDigest"] = config_digest
        candidate.identities["guestArchitecture"] = metadata["guestArchitecture"]
        candidate.identities["observedVerifierAccepted"] = True
        version = next(line.strip() for line in text.split("GUEST_KERNEL_VERSION", 1)[1].splitlines() if line.strip().startswith("Linux version "))
        assert version.startswith("Linux version ")
        candidate.identities["observedGuestKernelVersion"] = version
        silo.ws.record("overlay-candidate-tuple", json.dumps(candidate.identities, sort_keys=True) + "\n")
        silo.ws.record("overlay-candidate-proof", text)
    finally:
        candidate.close()


@pytest.mark.parametrize("fault", ["uuid", "length", "magic", "journal-inode", "upper-symlink", "missing-bootstrap", "malformed-bootstrap"])
def test_overlay_candidate_guest_rejection(silo: Silo, overlay_image: str, fault: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_image, fault=fault)
    upper_before = overlay.digest(candidate.upper) if fault == "journal-inode" else None
    try:
        candidate.start()
        candidate.wait(rejected=True)
        if fault == "journal-inode":
            assert overlay.digest(candidate.upper) == upper_before, "invalid active journal must fail before replay/write"
    finally:
        candidate.close()


@pytest.mark.slow
@pytest.mark.linux_only
def test_overlay_actual_host_enospc_isolated_upper(silo: Silo, overlay_image: str) -> None:
    name = "overlay-host-enospc"
    overlay.create(silo, name, overlay_image, capacity="256mib")
    lower = overlay.records(overlay.machine_dir(silo, name) / "lower.vmdk")[0].path
    lower_before = overlay.digest(lower)
    silo.stop(name)
    request = silo.ws.evidence / "host-enospc-request.json"
    request.write_text(json.dumps({"silo": str(silo.ws.config.silo), "name": name, "machine_id": silo.machine_id(name), "upper": str(overlay.upper(silo, name)), "scratch": str(silo.ws.root / "bounded-upper"), "evidence": str(silo.ws.evidence), "exit_path": str(silo.ws.silo_home / "logs/machines" / silo.machine_id(name) / "vm.exit.json"), "outer_uid": str(os.getuid()), "outer_user_namespace": os.readlink("/proc/self/ns/user"), "log_directories": [str(silo.ws.silo_home / "logs/machines" / silo.machine_id(name))]}))
    environment = silo.ws.env(PYTHONPATH=str(REPO / "smoke"))
    import sys
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", sys.executable, "-m", "silo_smoke.overlay_host_enospc", str(request)], env=environment, capture_output=True, text=True, timeout=240)
    silo.ws.record("overlay-host-namespace", result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    assert overlay.digest(lower) == lower_before
    assert json.loads((silo.ws.evidence / "actual-host-enospc.json").read_text())["errno"] == 28


@pytest.mark.slow
@pytest.mark.parametrize("operation", ["discard", "zero"])
@pytest.mark.parametrize("region", ["middle", "tail", "whole", "middle-sector", "tail-sector"])
def test_overlay_scratch_discard_zero_length_invariants(silo: Silo, overlay_image: str, operation: str, region: str) -> None:
    name = "overlay-discard"
    scratch = silo.ws.root / "scratch-data.raw"
    size = 8 * 1024**2
    original = b"\xa5" * size
    scratch.write_bytes(original)
    overlay.create(silo, name, overlay_image, "--disk", str(scratch))
    device = silo.exec(name, "sh", "-c", 'set -eu\nfor p in /sys/block/*; do if test "$(cat "$p/serial" 2>/dev/null)" = silo-data-0; then echo /dev/${p##*/}; fi; done\n', user="root").stdout.strip()
    assert device.startswith("/dev/") and "\n" not in device
    offset, length = {"middle": (size // 2, 4096), "tail": (size - 4096, 4096), "whole": (0, size), "middle-sector": (size // 2 + 512, 512), "tail-sector": (size - 512, 512)}[region]
    silo.ws.record("overlay-scratch-range", json.dumps({"operation": operation, "region": region, "offset": offset, "length": length, "logicalBytesBefore": scratch.stat().st_size, "allocatedBytesBefore": scratch.stat().st_blocks * 512, "requiresActualZeroReads": True}) + "\n")
    silo.exec(name, overlay.PROBE, "durable", "/upper-trim-sentinel", user="root")
    overlay.probe(silo, name, "discard", device, operation, str(offset), str(length))
    silo.stop(name)
    assert scratch.stat().st_size == size
    expected = original[:offset] + b"\0" * length + original[offset + length:]
    assert scratch.read_bytes() == expected
    silo.start(name)
    silo.wait_ready(name)
    assert silo.exec(name, "cat", f"/sys/block/{device.removeprefix('/dev/')}/size", user="root").stdout.strip() == str(size // 512)
    assert silo.exec(name, overlay.PROBE, "read-file", device, str(offset), user="root").stdout.strip() == "00" * 512
    upper_length = overlay.upper(silo, name).stat().st_size
    silo.exec(name, "fstrim", "/run/silo/rootfs/upperfs", user="root")
    assert overlay.upper(silo, name).stat().st_size == upper_length
    silo.stop(name)
    assert overlay.upper(silo, name).stat().st_size == upper_length
    silo.start(name)
    silo.wait_ready(name)
    assert silo.exec(name, "cat", "/upper-trim-sentinel", user="root").stdout == "committed\n"


@pytest.mark.linux_only
@pytest.mark.parametrize("fault", ["missing", "truncated", "swapped", "duplicate", "writable-lower", "readonly-upper"])
def test_overlay_native_serial_and_access_fail_closed(silo: Silo, overlay_image: str, fault: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    import re
    candidate = Candidate(silo, overlay_image, fault=fault)
    try:
        candidate.start()
        text = candidate.wait(rejected=True)
        expected = {
            "missing": "missing lower serial",
            "truncated": "missing lower serial",
            "swapped": "mismatch",
            "duplicate": "duplicate lower serial",
            "writable-lower": "read-only mismatch",
            "readonly-upper": "read-only mismatch",
        }[fault]
        assert expected in text
        candidate.close()
        logs = candidate.native_diagnostic()
        responses = re.findall(r"SILO_SMOKE_GET_ID device=(0x[0-9a-f]+) sectors=([0-9]+) reply=([^\s]+)", logs)
        assert responses, "missing actual native virtqueue GET_ID request/response evidence"
        if fault == "duplicate":
            devices = {address for address, sectors, reply in responses if reply == "silo-root-lower"}
            assert len(devices) == 2, "must observe two distinct attached devices returning duplicate GET_ID, not missing/replaced native key"
            assert any(reply == "silo-root-upper" for _, _, reply in responses)
        silo.ws.record("overlay-native-get-id", json.dumps({"fault": fault, "actualResponses": responses}) + "\n")
    finally:
        candidate.close()


@pytest.mark.linux_only
def test_overlay_native_reordered_devices_keep_exact_serial_discovery(silo: Silo, overlay_image: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_image, fault="reordered")
    try:
        candidate.start()
        text = candidate.wait()
        assert "init: overlay: verified managed root" in text
        # The candidate workload reports actual /sys/block names/serials, so the
        # reordered native attachments are observed, not inferred from a flag.
        assert "DEVICE:/sys/block/vda" in text and "DEVICE:/sys/block/vdb" in text
        first = text.index("DEVICE:/sys/block/vda")
        second = text.index("DEVICE:/sys/block/vdb")
        assert "silo-root-upper" in text[first:second]
        assert "silo-root-lower" in text[second:]
    finally:
        candidate.close()


def test_overlay_capacity_refusal_is_nonmutating(silo: Silo, overlay_image: str, overlay_capacity_consumer: Path) -> None:
    name = "overlay-capacity-refusal"
    overlay.create(silo, name, overlay_image, capacity="64mib")
    current = overlay.upper(silo, name)
    assert silo.run("set", name, "disk=128mib", expect=None).returncode != 0, "hot upper resize accepted"
    silo.stop(name)
    environment = silo.ws.env()
    calibrated = subprocess.run([str(overlay_capacity_consumer), "set-root-capacity", name, str(64 * 1024**2)], env=environment, capture_output=True, text=True, timeout=250)
    silo.ws.record("overlay-capacity-rust-control", calibrated.stdout + "\n" + calibrated.stderr)
    assert calibrated.returncode == 0, calibrated.stderr
    assert json.loads(calibrated.stdout)["capacityBytes"] == 64 * 1024**2
    assert current.stat().st_size == 64 * 1024**2
    before = overlay.digest(current)
    entries = set(current.parent.iterdir())
    for size in [str(64 * 1024**2 - 4096), str(1024**4 + 4096), str(64 * 1024**2 + 1)]:
        result = subprocess.run([str(overlay_capacity_consumer), "set-root-capacity", name, size], env=environment, capture_output=True, text=True, timeout=250)
        silo.ws.record("overlay-capacity-rust-refusal", json.dumps({"requestedBytes": int(size), "returncode": result.returncode}) + "\n" + result.stdout + result.stderr)
        assert result.returncode != 0
        assert overlay.upper(silo, name) == current
        assert current.stat().st_size == 64 * 1024**2
        assert overlay.digest(current) == before
        assert set(current.parent.iterdir()) == entries


@pytest.mark.linux_only
def test_vmdk_production_preflight_limits_before_any_lower_open(silo: Silo, overlay_image: str) -> None:
    import ctypes
    import resource
    import struct
    name = "vmdk-preflight"
    overlay.create(silo, name, overlay_image)
    lower = overlay.records(overlay.machine_dir(silo, name) / "lower.vmdk")[0].path
    silo.stop(name)
    native = ctypes.CDLL(None, use_errno=True)
    native.inotify_init1.argtypes = [ctypes.c_int]
    native.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    fd = native.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0, os.strerror(ctypes.get_errno())
    try:
        assert native.inotify_add_watch(fd, os.fsencode(lower), 0x20 | 0x10) >= 0, os.strerror(ctypes.get_errno())
        def events() -> list[int]:
            masks = []
            while True:
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    return masks
                at = 0
                while at < len(data):
                    _, mask, _, length = struct.unpack_from("iIII", data, at)
                    masks.append(mask)
                    at += 16 + length
        # Independent real open-and-close positive control: FD snapshots alone
        # cannot prove that an attempted verification open did not occur.
        with lower.open("rb"):
            pass
        assert any(mask & 0x20 for mask in events())
        result = overlay.limited_start(silo, name, 256, 256)
        assert result.returncode != 0
        assert "file descriptor budget requires" in result.stderr
        assert "soft limit is 256" in result.stderr and "hard limit is 256" in result.stderr
        assert not any(mask & 0x20 for mask in events()), "production start opened lower before FD admission"
        assert silo.info(name)["state"] == "stopped"
        hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        assert hard == resource.RLIM_INFINITY or hard >= 512, "host hard limit cannot qualify raise-to-hard gate"
        raised = overlay.limited_start(silo, name, 256, 512)
        assert raised.returncode == 0, raised.stderr
        silo.wait_ready(name)
        assert any(mask & 0x20 for mask in events()), "positive production start never opened watched lower"
        limits = Path(f"/proc/{overlay.worker_pid(silo, name)}/limits").read_text()
        fields = next(line.split() for line in limits.splitlines() if line.startswith("Max open files"))
        assert fields[3:5] == ["512", "512"], limits
        silo.ws.record("vmdk-worker-limits", limits)
    finally:
        os.close(fd)


def test_overlay_shutdown_rejects_real_maintenance_path_replacement(silo: Silo, overlay_image: str) -> None:
    name = "overlay-shutdown-path"
    overlay.create(silo, name, overlay_image)
    silo.exec(name, overlay.PROBE, "durable", "/before-path-replacement", user="root")
    watched = overlay.shutdown_watch(silo, name)
    silo.exec(name, "mount", "-t", "tmpfs", "-o", "size=1m", "tmpfs", "/run/silo/rootfs/upperfs", user="root")
    monitor, worker = watched["monitorPid"], overlay.worker_pid(silo, name)
    silo.run("stop", name, "--timeout", "75s", expect=None, timeout=120)
    terminal = shutdown.exit_record(silo, name, watched["runId"])
    overlay.assert_unforced_native_exit(terminal, machine_id=silo.machine_id(name), run_id=watched["runId"], monitor=monitor, worker=worker)
    assert terminal["outcome"] == "error" and terminal["error"]
    assert terminal["storageShutdown"]["guestProtocolCompleted"] is False
    assert terminal["storageShutdown"]["hostFlushCompleted"] is False
    assert shutdown.outcome(silo, name) != "clean"
    shutdown.assert_failed_completion(silo.ws.silo_home / "logs/machines" / silo.machine_id(name), watched["runId"])


def test_overlay_injected_request_is_rejected_before_workload(silo: Silo, overlay_image: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_image, fault="effective-index-off")
    try:
        candidate.start()
        text = candidate.wait(rejected=True)
        assert "init: overlay: effective persistence profile downgraded" in text
        silo.ws.record("overlay-injected-request-proof", "mutation=copied-init-mount-request-index-off; verifier=byte-identical-production; not-a-spontaneous-kernel-downgrade\n" + text)
    finally:
        candidate.close()


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_overlay_nested_mount_source_rejected_before_workload(silo: Silo, workspace: Workspace, overlay_image: str, kind: str) -> None:
    parent = workspace.root / "nested-parent"
    child = workspace.root / "nested-child"
    parent.mkdir()
    child.mkdir()
    if kind == "file":
        (parent / "child").write_text("not a directory")
    else:
        (parent / "child").symlink_to(child, target_is_directory=True)
    name = "overlay-bad-nested"
    workspace.register_machine(name)
    result = silo.run("run", overlay_image, "--name", name, "--root-profile", overlay.PROFILE, "--network", "none", "--mount", f"{child}:/parent/child", "--mount", f"{parent}:/parent", "--", "/bin/sh", "-c", "echo SILO_USER_MOUNT_WORKLOAD_REACHED; echo reached >/parent/workload-sentinel", expect=None, timeout=90)
    assert result.returncode != 0
    serial = workspace.silo_home / "logs/machines" / silo.machine_id(name) / "serial.log"
    text = serial.read_text(errors="replace")
    assert "required nested mount source preflight failed" in text
    assert "SILO_USER_MOUNT_WORKLOAD_REACHED" not in text
    assert not (parent / "workload-sentinel").exists()


def test_overlay_nested_mounts_parent_before_child(silo: Silo, workspace: Workspace, overlay_image: str) -> None:
    parent = workspace.root / "valid-parent"
    child = workspace.root / "valid-child"
    (parent / "child").mkdir(parents=True)
    child.mkdir()
    (parent / "parent-proof").write_text("parent")
    (child / "child-proof").write_text("child")
    name = "overlay-valid-nested"
    overlay.create(silo, name, overlay_image, "--mount", f"{child}:/parent/child", "--mount", f"{parent}:/parent")
    assert silo.exec(name, "cat", "/parent/parent-proof", user="root").stdout == "parent"
    assert silo.exec(name, "cat", "/parent/child/child-proof", user="root").stdout == "child"


def test_overlay_switch_root_rejects_symlinked_maintenance_destination(silo: Silo, config: SmokeConfig, registry: LoopbackRegistry, overlay_probe: Path) -> None:
    from silo_smoke.overlay_candidate import Candidate
    reference = registry.publish(overlay.image(config, overlay_probe, root_run_symlink=True), "overlay-unsafe-run")
    candidate = Candidate(silo, reference)
    try:
        candidate.start()
        text = candidate.wait(rejected=True)
        assert "init: overlay: verified managed root" in text
        assert "init: switch_root failed" in text
    finally:
        candidate.close()


@pytest.mark.linux_only
def test_vmdk_native_attachment_reserve_edge(silo: Silo, workspace: Workspace, overlay_image: str) -> None:
    import resource
    import re
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    assert hard == resource.RLIM_INFINITY or hard >= 512
    data: list[Path] = []
    flags: list[str] = []
    for index in range(14):
        path = workspace.root / f"data-{index}.raw"
        with path.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        path.chmod(0o600)
        data.append(path)
        flags.extend(["--disk", str(path)])
    name = "vmdk-sixteen-attachments"
    silo.create(name, overlay_image, "--root-profile", overlay.PROFILE, "--disk-size", "64mib", "--network", "none", "--vsock", *flags)
    started = overlay.limited_start(silo, name, 256, 512)
    assert started.returncode == 0, started.stderr
    silo.wait_ready(name)
    overlay.handle_evidence(silo, name, overlay.machine_dir(silo, name) / "lower.vmdk")
    observed = silo.exec(name, "sh", "-c", 'set -eu\nfor p in /sys/block/*; do if test -f "$p/serial"; then printf "%s " "${p##*/}"; printf "%s " "$(cat "$p/serial")"; printf "%s " "$(cat "$p/size")"; cat "$p/ro"; fi; done\n', user="root").stdout.splitlines()
    devices = {fields[1]: (fields[0], int(fields[2]) * 512, int(fields[3])) for fields in (line.split() for line in observed)}
    assert set(devices) == {"silo-root-lower", "silo-root-upper", *(f"silo-data-{index}" for index in range(14))}
    assert devices["silo-root-lower"][2] == 1 and devices["silo-root-upper"][2] == 0
    assert all(devices[f"silo-data-{index}"][1:] == (8 * 1024**2, 0) for index in range(14))
    pid = overlay.worker_pid(silo, name)
    seen: set[Path] = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            path = Path(os.readlink(fd))
            info = Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text()
        except FileNotFoundError:
            continue
        if path in data:
            mode = int(next(line.split()[1] for line in info.splitlines() if line.startswith("flags:")), 8)
            assert mode & os.O_ACCMODE == os.O_RDWR
            seen.add(path)
    assert seen == set(data)
    limits = Path(f"/proc/{pid}/limits").read_text()
    assert next(line.split()[3:5] for line in limits.splitlines() if line.startswith("Max open files")) == ["512", "512"]
    workspace.record("vmdk-sixteen-attachment-proof", json.dumps({"workerPid": pid, "actualDevices": devices, "actualWritableDataHandles": sorted(str(path) for path in seen)}) + "\n" + limits)
    descriptor = overlay.machine_dir(silo, name) / "lower.vmdk"
    lower = overlay.records(descriptor)[0].path
    lower_before = overlay.digest(lower)
    overlay.probe(silo, name, "lower-ro")
    data_devices = [devices[f"silo-data-{index}"][0] for index in range(len(data))]
    transport_output = silo.exec(name, "sh", "-eu", "-c", """
for device do
    printf '%s\\t' "$device"
    readlink -f "/sys/block/$device/device"
done
""", "overlay-data-transports", *data_devices, user="root").stdout
    transport_lines = transport_output.split("\n")
    assert len(transport_lines) == len(data_devices) + 1 and transport_lines[-1] == "", transport_output
    data_virtio = {}
    for index, device_name in enumerate(data_devices):
        observed_device, separator, target = transport_lines[index].partition("\t")
        assert separator == "\t" and observed_device == device_name, transport_lines[index]
        data_virtio[f"silo-data-{index}"] = Path(target).name
        assert re.fullmatch(r"virtio[0-9]+", data_virtio[f"silo-data-{index}"]), target

    def interrupts() -> tuple[str, dict]:
        text = silo.exec(name, "cat", "/proc/interrupts", user="root").stdout
        routes = {}
        for line in text.splitlines():
            number, separator, body = line.partition(":")
            if not separator or not number.strip().isdecimal():
                continue
            count = 0
            for field in body.split():
                if not field.isdecimal():
                    break
                count += int(field)
            routes[int(number.strip())] = {"count": count, "devices": set(re.findall(r"\bvirtio[0-9]+\b", body))}
        return text, routes

    before_interrupts, before_routes = interrupts()
    shared = {irq: sorted(set(data_virtio.values()) & route["devices"]) for irq, route in before_routes.items() if len(set(data_virtio.values()) & route["devices"]) > 1}
    assert shared, "bounded attachment gate did not observe multiple real Data transports on one routed IRQ"
    written = overlay.probe(silo, name, "data-io", "write-read", timeout=120)
    assert written["completedDevices"] == len(data) and written["verifiedBytes"] == len(data) * 8 * 65536
    after_interrupts, after_routes = interrupts()
    assert any(after_routes[irq]["count"] > before_routes[irq]["count"] for irq in shared), "shared routed IRQ did not deliver actual I/O interrupts"
    workspace.record("vmdk-shared-irq", json.dumps({"dataVirtioDevices": data_virtio, "sharedRoutes": shared, "writeFlushReadReceipt": written}) + "\n[before]\n" + before_interrupts + "\n[after]\n" + after_interrupts)

    def check_backings() -> list[dict]:
        observed = []
        for index, path in enumerate(data):
            expected = bytearray(8 * 1024**2)
            for round_index in range(8):
                start = 1024**2 + round_index * 512 * 1024 + index * 4096
                expected[start:start + 65536] = bytes((index * 17 + round_index * 29 + position) & 255 for position in range(65536))
            assert path.stat().st_size == len(expected), "Data logical length changed"
            assert path.read_bytes() == expected, f"Data-{index} write/read range or untouched outside bytes changed"
            observed.append({"blockId": f"silo-data-{index}", "lengthBytes": path.stat().st_size, "sha256": overlay.digest(path)})
        assert overlay.digest(lower) == lower_before, "Data I/O changed immutable lower"
        return observed

    silo.stop(name)
    after_write = check_backings()
    silo.start(name)
    silo.wait_ready(name)
    overlay.handle_evidence(silo, name, descriptor)
    overlay.probe(silo, name, "lower-ro")
    reopened = overlay.probe(silo, name, "data-io", "read", timeout=120)
    assert reopened["completedDevices"] == len(data) and reopened["verifiedBytes"] == len(data) * 8 * 65536
    silo.stop(name)
    after_reopen = check_backings()
    workspace.record("vmdk-concurrent-data-io", json.dumps({"guestWriteFlushRead": written, "guestColdReopenRead": reopened, "afterStop": after_write, "afterReopenStop": after_reopen, "lowerSha256": lower_before}) + "\n")


@pytest.mark.slow
@pytest.mark.linux_only
def test_vmdk_controlled_historical_occurrences_native_mapping(silo: Silo, overlay_large_image: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_large_image, historical=True)
    try:
        assert candidate.logical_lower_bytes == 4_833_935_360
        records = overlay.records(candidate.descriptor)
        assert len(records) == 5
        candidate.start()
        text = candidate.wait()
        responses = [json.loads(line.split("SILO_MAP_RESULT ", 1)[1]) for line in text.splitlines() if "SILO_MAP_RESULT " in line]
        assert len(responses) == len(candidate.mapping_probes)
        seen: set[tuple[int, int]] = set()
        mismatches = 0
        controls = 0
        for response in responses:
            actual = bytes.fromhex(response["hex"])
            offset = response["offset"]
            seen.add((offset, len(actual)))
            expected = overlay.linear_read(candidate.occurrences, offset, len(actual))
            assert actual == expected
            assert overlay.record_read(records, offset, len(actual)) == expected
            wrong = overlay.record_read(records, offset, len(actual), wrong_bytes=True)
            if offset + len(actual) <= overlay.SPLIT:
                assert wrong == expected
                controls += 1
            elif wrong != expected:
                mismatches += 1
        assert seen == set(candidate.mapping_probes)
        assert mismatches > 0 and controls > 0
        assert candidate.process is not None
        overlay.readonly_handle_evidence(silo.ws, overlay.worker_pid_of_monitor(candidate.process.pid), candidate.descriptor, candidate.upper)
        silo.ws.record("vmdk-controlled-native-historical-proof", json.dumps({"seed": 14, "logicalBytes": candidate.logical_lower_bytes, "records": 5, "actualGuestComparisons": len(responses), "offsetAsBytesMismatches": mismatches, "offsetZeroControls": controls, "candidateOnly": True, "notProductionSemanticRepeatedClosure": True}) + "\n")
    finally:
        candidate.close()


def test_overlay_actual_journal_inode_ignores_wrong_superblock_backup(silo: Silo, overlay_image: str) -> None:
    from silo_smoke.overlay_candidate import Candidate
    candidate = Candidate(silo, overlay_image, fault="journal-backup")
    try:
        candidate.start()
        text = candidate.wait()
        assert "init: overlay: verified managed root" in text
        assert "SILO_OVERLAY_WORKLOAD_REACHED" in text
    finally:
        candidate.close()


@pytest.mark.slow
@pytest.mark.linux_only
@pytest.mark.parametrize("backing", ["tmpfs", "ramfs"])
@pytest.mark.parametrize("operation", ["discard", "zero", "zero-unmap"])
@pytest.mark.parametrize("region", ["middle", "tail", "whole", "middle-sector", "tail-sector"])
def test_overlay_native_range_opcode_and_real_fallback(silo: Silo, config: SmokeConfig, registry: LoopbackRegistry, overlay_image: str, backing: str, operation: str, region: str) -> None:
    from dataclasses import asdict
    import sys
    request = silo.ws.evidence / "native-range-request.json"
    evidence = silo.ws.evidence / "native-range"
    request.write_text(json.dumps({"config": asdict(config), "registry_ca": str(registry.ca_path), "image": overlay_image, "backing": backing, "operation": operation, "region": region, "evidence": str(evidence), "outer_uid": str(os.getuid()), "outer_user_namespace": os.readlink("/proc/self/ns/user")}, default=str))
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", sys.executable, "-m", "silo_smoke.overlay_range", str(request)], env=silo.ws.env(PYTHONPATH=str(REPO / "smoke"), TMPDIR=str(silo.ws.root.parent), SILO_SMOKE_FAULT_MONITORS=os.environ.get("SILO_SMOKE_FAULT_MONITORS", "")), capture_output=True, text=True, timeout=240)
    silo.ws.record("overlay-native-range-namespace", result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    complete = (evidence / "overlay-range-complete.log").read_text()
    assert f'"backing": "{backing}"' in complete
    assert '"nativeRequests": [' in complete


@pytest.mark.linux_only
def test_overlay_qualified_stage_replacement_uses_retained_triplet(silo: Silo, overlay_image: str) -> None:
    from silo_smoke.overlay_stage import replacement
    replacement(silo, overlay_image)


@pytest.mark.linux_only
def test_overlay_native_symlink_4095_and_flat_4096_refusal(silo: Silo, config: SmokeConfig, registry: LoopbackRegistry, overlay_probe: Path) -> None:
    from uuid import UUID
    valid = registry.publish(overlay.image(config, overlay_probe, symlink_target_length=4095), "overlay-symlink-4095")
    name = "overlay-symlink-4095"
    overlay.create(silo, name, valid, capacity="128mib")
    target = silo.exec(name, "readlink", "-n", "/overlay-fixture/long-symlink", user="root").stdout
    assert target == "t" * 4095
    silo.stop(name)
    before = {UUID(machine["id"]) for machine in silo.ls()}
    invalid = registry.publish(overlay.image(config, overlay_probe, symlink_target_length=4096), "overlay-symlink-4096")
    refused = silo.run("create", invalid, "--name", "overlay-symlink-4096", "--root-profile", overlay.PROFILE, expect=None)
    assert refused.returncode != 0, "one-byte-overflow symlink must fail flat materialization"
    assert {UUID(machine["id"]) for machine in silo.ls()} == before, "failed flat materialization published a machine"
    silo.ws.record("overlay-symlink-boundary", json.dumps({"nativeReadlinkBytes": len(target), "refusedTargetBytes": 4096, "publishedMachineIds": sorted(str(value) for value in before)}) + "\n" + refused.stdout + refused.stderr)
