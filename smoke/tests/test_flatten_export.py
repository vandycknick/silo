"""Real kernel-upper flatten/export gates, run once per qualified staged kernel.

The oracle is the existing independent containerd extractor's read-only collector,
executed inside both guests. Only /overlay-fixture is compared: it is the complete
controlled persistent namespace, not runtime-generated /proc, /run or machine
identity files. Collector rows are compared verbatim, including directory rows,
nanosecond mtimes, raw xattrs, symlink targets and surviving hardlink groups.
No flattener output or source-derived expected metadata is used as the oracle.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
from uuid import UUID

import pytest

from silo_smoke import cloud_disk, image_cache, images, overlay, procs, shutdown, stopped
from silo_smoke.cli import Result, Silo, timed
from silo_smoke.config import REPO
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace

pytestmark = pytest.mark.linux_only


@pytest.fixture
def silo(workspace: Workspace, overlay_image_caches: dict[str, Path]) -> Silo:
    with timed(workspace, "image_cache.seed"):
        seeded = image_cache.seed(overlay_image_caches["overlay"], workspace.silo_home)
    assert len(seeded) == 1, seeded
    return Silo(workspace)


@pytest.fixture(scope="session")
def overlay_image(registry: LoopbackRegistry, overlay_image_bytes: images.OciImage) -> str:
    return registry.publish(overlay_image_bytes, "overlay")


@pytest.fixture(scope="session")
def filesystem_observer() -> Path:
    observer = Path(os.environ.get("SILO_SMOKE_FILESYSTEM_OBSERVER", str(REPO / "target/changeset-tools/extractor"))).resolve()
    assert observer.is_file() and os.access(observer, os.X_OK), (
        "Build the existing pinned independent collector for the guest's architecture: "
        "CGO_ENABLED=0 make changeset-extractor; set SILO_SMOKE_FILESYSTEM_OBSERVER "
        "for another target directory. The binary must run on the Alpine guest."
    )
    return observer


def _install_observer(silo: Silo, name: str, observer: Path) -> None:
    # Keep both executable and report on /run's private tmpfs, outside the
    # persistent tree. Upload uses the production CLI, not a host mount.
    silo.run("cp", str(observer), f"{name}:/run/flatten-observer", "--mode", "755")


def _collect(silo: Silo, name: str, stage: str) -> list[dict]:
    silo.exec(name, "/run/flatten-observer", "collect", "--root", "/overlay-fixture",
              "--out", "/run/flatten-observation.json", user="root", timeout=120)
    report = json.loads(silo.exec(name, "cat", "/run/flatten-observation.json", user="root").stdout)
    silo.ws.record("flatten-namespace", json.dumps({"stage": stage, "machine": name, "report": report}, sort_keys=True) + "\n")
    assert report["schema"] == 1
    assert report["collector"] == "silo-independent-filesystem-observer-v1"
    assert report["problems"] == []
    assert report["rows"], "an empty observation cannot qualify an export"
    return report["rows"]


def _source_files(silo: Silo, name: str) -> dict[Path, cloud_disk.Fingerprint]:
    descriptor = overlay.machine_dir(silo, name) / "lower.vmdk"
    paths = [overlay.upper(silo, name), descriptor, *overlay.lower_occurrences(descriptor)]
    return {path: cloud_disk.fingerprint(path) for path in dict.fromkeys(paths)}


def _export_args(name: str, destination: Path, *, flatten: bool = True) -> tuple[str, ...]:
    return ("storage", "export", name, str(destination), "--disk-format", "raw",
            *(["--flatten-filesystem"] if flatten else []))


def _refuse(silo: Silo, name: str, destination: Path, *, flatten: bool = True) -> Result:
    before = {path: cloud_disk.fingerprint(path) for path in destination.parent.iterdir()}
    # Startup may retire closed read leases from a prior successful export.
    # Retained catalog entries, machine files and source bytes must stay exact.
    result = cloud_disk.refuse_before_publication(
        silo, *_export_args(name, destination, flatten=flatten),
        sources=tuple(_source_files(silo, name)),
    )
    after = {path: cloud_disk.fingerprint(path) for path in destination.parent.iterdir()}
    assert after == before, "refusal changed an output or left disk/sidecar staging behind"
    return result


def _raw_base64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _assert_fixture(rows: list[dict]) -> None:
    by_path = {_raw_base64(row["path"]): row for row in rows}
    assert b"" in by_path and by_path[b""]["kind"] == "directory"
    assert not ({b"a", b"deleted", b"opaque/old"} & by_path.keys()), "whiteout/opacity fixture was not applied"
    survivor = by_path[b"b"]
    assert survivor["content"] == "sha256:" + hashlib.sha256(b"changedl-hardlink\n").hexdigest()
    attributes = {_raw_base64(item["name"]): _raw_base64(item["value"]) for item in survivor["xattrs"]}
    assert attributes[b"user.near-limit"] == b"x" * 2750
    assert b"system.posix_acl_access" in attributes
    capability = by_path[b"capability"]["xattrs"]
    assert any(_raw_base64(item["name"]) == b"security.capability" for item in capability)
    assert by_path[b"opaque/new"]["content"] == "sha256:" + hashlib.sha256(b"new").hexdigest()
    assert by_path[b"new-content"]["content"] == "sha256:" + hashlib.sha256(b"flatten\x00new\n").hexdigest()
    for path in (b"new-content", b"new-alias"):
        assert _raw_base64(by_path[path]["group"]) == b"new-alias"
        assert by_path[path]["links"] == 2
        assert (by_path[path]["mode"], by_path[path]["uid"], by_path[path]["gid"]) == (0o640, 1234, 2345)
    assert _raw_base64(by_path[b"new-symlink"]["target"]) == b"new-content"
    assert _raw_base64(by_path[b"dangling-symlink"]["target"]) == b"missing-target"
    assert any(row["mtimeNanos"] != 0 for row in rows), "fixture must exercise subsecond metadata"


@pytest.mark.parametrize("output_format", ["plain", "json"])
def test_flatten_export_kernel_upper_namespace_and_boot(silo: Silo, overlay_image: str,
                                                       filesystem_observer: Path, output_format: str) -> None:
    name = "flatten-source"
    overlay.create(silo, name, overlay_image, "--cpus", "1", "--memory", "512mib", capacity="512mib")
    initial = overlay.observation(silo, name)
    assert initial["root"]["kind"] == overlay.PROFILE
    assert overlay.filesystem_magic(silo, name, "/") == overlay.OVERLAYFS_SUPER_MAGIC
    kernel_version = silo.exec(name, "cat", "/proc/version", user="root").stdout
    _install_observer(silo, name, filesystem_observer)
    # This existing probe opens a lower hardlink for writing, checks both aliases
    # and their ACL/xattrs, then removes the copied-up name. The remaining b
    # lower alias must obtain its modified bytes through the real OverlayFS index.
    assert overlay.probe(silo, name, "metadata") == {"hardlinks": True, "metadata": True, "rename_errno": 18}
    silo.exec(name, "sh", "-eu", "-c", """
printf 'flatten\\000new\\n' >/overlay-fixture/new-content
ln /overlay-fixture/new-content /overlay-fixture/new-alias
chmod 0640 /overlay-fixture/new-content
chown 1234:2345 /overlay-fixture/new-content
ln -s new-content /overlay-fixture/new-symlink
ln -s missing-target /overlay-fixture/dangling-symlink
test ! -e /run/silo/rootfs/upperfs/upper/overlay-fixture/b
sync
""", user="root")
    expected = _collect(silo, name, "source-running")
    _assert_fixture(expected)
    outputs = silo.ws.root / "flatten-exports"
    outputs.mkdir(mode=0o700)
    running_destination = outputs / "running.raw"
    run_id = procs.run_id(silo.ws, name)
    lower_before = overlay.lower_digests(overlay.machine_dir(silo, name) / "lower.vmdk")
    refused = silo.run(*_export_args(name, running_destination), expect=None, timeout=60)
    assert refused.returncode != 0, refused
    assert list(outputs.iterdir()) == [], "running export published output or staging"
    assert silo.info(name)["state"] == "running" and procs.run_id(silo.ws, name) == run_id
    assert _collect(silo, name, "after-running-refusal") == expected
    assert overlay.lower_digests(overlay.machine_dir(silo, name) / "lower.vmdk") == lower_before
    overlay.orderly_guest_shutdown(silo, name)
    upper = overlay.ext4(overlay.upper(silo, name))
    assert upper["incompat"] & 4 == 0, "qualification requires a truly clean on-disk upper"
    source_files = _source_files(silo, name)
    source_record = stopped.record(silo, name)
    source_config = stopped.configuration(silo, name)
    refused = _refuse(silo, name, outputs / "no-opt-in.raw", flatten=False)
    assert "overlay roots require flatten_filesystem" in refused.stderr, refused.stderr
    for collision in ("disk", "sidecar"):
        destination = outputs / f"existing-{collision}.raw"
        occupied = destination if collision == "disk" else Path(str(destination) + ".json")
        occupied.write_bytes(b"pre-existing output must survive\x00\n")
        _refuse(silo, name, destination)
        assert occupied.read_bytes() == b"pre-existing output must survive\x00\n"
        assert not (Path(str(destination) + ".json") if collision == "disk" else destination).exists()
    destination = outputs / "flattened.raw"
    result = silo.run(*_export_args(name, destination), *(["--format", "json"] if output_format == "json" else []), timeout=240)
    sidecar = Path(str(destination) + ".json")
    report = json.loads(sidecar.read_bytes())
    if output_format == "json":
        assert json.loads(result.stdout) == report
    else:
        assert result.stdout == str(destination) + "\n"
    assert bytes(report["path"]) == os.fsencode(destination)
    assert bytes(report["metadataPath"]) == os.fsencode(sidecar)
    assert report["geometry"] == {"length": destination.stat().st_size, "logicalSectorSize": 512}
    assert report["kind"]["kind"] == "flattened-filesystem"
    output_uuid = UUID(report["kind"]["filesystemUuid"])
    assert output_uuid.int != 0
    assert output_uuid not in {UUID(hex=upper["uuid"]), UUID(initial["root"]["lower"]["filesystemUuid"])}
    assert UUID(hex=overlay.ext4(destination)["uuid"]) == output_uuid
    boot = report["boot"]
    assert boot["kind"] == "linux-direct"
    assert boot["rootSelector"] == {"kind": "whole-disk"} and boot["rootFilesystem"] == "ext4"
    assert boot["binding"] == source_record["boot"]["binding"]
    binding = boot["binding"]
    assert binding["kind"] == "pinned"
    cloud_disk.assert_pool_objects(silo, binding)
    assert _source_files(silo, name) == source_files, "flattening changed source bytes or inode identity"
    assert stopped.record(silo, name) == source_record
    assert stopped.configuration(silo, name) == source_config
    _refuse(silo, name, destination)
    exported = cloud_disk.fingerprint(destination)
    imported = cloud_disk.import_disk(silo, destination, root="whole-disk", name="flattened-export")
    child = "flatten-consumer"
    silo.create(child, "image:" + imported["id"], "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock")
    # Explicitly consume the sidecar's retained exact tuple, never silently pick
    # whichever boot assets happen to be packaged when the consumer starts.
    silo.run("set", child, "boot-assets=" + cloud_disk.bundle_digest(binding))
    assert stopped.record(silo, child)["boot"] == boot
    cloud_disk.boot(silo, child)
    assert overlay.filesystem_magic(silo, child, "/") == 0xEF53
    assert silo.exec(child, "cat", "/proc/version", user="root").stdout == kernel_version
    assert cloud_disk.guest_agent_sha256(silo, child) == binding["agent"]
    _install_observer(silo, child, filesystem_observer)
    actual = _collect(silo, child, "booted-export-consumer")
    _assert_fixture(actual)
    assert actual == expected, "exported guest changed namespace/content/metadata/hardlink groups"
    overlay.probe(silo, child, "persist-check")
    stopped.stop(silo, child)
    assert cloud_disk.fingerprint(destination) == exported, "import/consumer boot modified exported input"
    assert _source_files(silo, name) == source_files
    silo.ws.record("flatten-source-identities", json.dumps({str(path): asdict(value) for path, value in source_files.items()}, sort_keys=True) + "\n")


def test_flatten_export_dirty_kernel_upper_requires_recovery(silo: Silo, overlay_image: str) -> None:
    name = "flatten-dirty-source"
    overlay.create(silo, name, overlay_image, "--cpus", "1", "--memory", "512mib", capacity="512mib")
    bound, lease = shutdown.holder(silo, name)
    processes = {entry["role"]: shutdown.Process(entry["pid"]) for entry in bound["holders"]}
    writer = silo.popen("exec", name, "--user", "root", "--", overlay.PROBE, "write-loop",
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert writer.stdout is not None
        with selectors.DefaultSelector() as ready:
            ready.register(writer.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=20), "actual dirty writer made no fsync progress"
            assert writer.stdout.readline().strip() == b"SILO_DIRTY_WRITER_STARTED"
        processes["krun-worker"].send(signal.SIGKILL)
        for process in processes.values():
            process.wait()
        shutdown.exit_record(silo, name, bound["runId"])
        assert not shutdown.lease_busy(lease)
        silo.stop(name, timeout="45s")  # reconcile only, never replay or mount
        assert shutdown.outcome(silo, name) in {"forced", "unknown"}
    finally:
        if writer.poll() is None:
            writer.kill()
        writer.wait(timeout=10)
        if writer.stdout is not None:
            writer.stdout.close()
        for process in processes.values():
            process.close()
    assert overlay.ext4(overlay.upper(silo, name))["incompat"] & 4 != 0
    before = _source_files(silo, name)
    outputs = silo.ws.root / "dirty-flatten-exports"
    outputs.mkdir(mode=0o700)
    refused = _refuse(silo, name, outputs / "dirty.raw")
    # RawExportRecoveryRequired's production CLI diagnostic is distinct from
    # unsupported index/layout rejection. No host replay/repair is permissible.
    assert "raw disk export requires a cleanly stopped source:" in refused.stderr, refused.stderr
    assert "raw disk export unsupported:" not in refused.stderr, refused.stderr
    assert _source_files(silo, name) == before
    assert overlay.ext4(overlay.upper(silo, name))["incompat"] & 4 != 0
