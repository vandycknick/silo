"""Phase 17 raw/qcow2 import, cloud-disk roots, boot pinning and conversion gates.

Every Linux test drives the staged CLI against real guests and real files.
Byte oracles are independent (SHA-256 of logical bytes, util-linux and
e2fsprogs readers); guest oracles are the guest kernel's own mount/sysfs view.
VZ refusal is a macOS lane and is not exercised on Linux.
"""
from __future__ import annotations

from dataclasses import replace
from functools import partial
import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

import pytest

from silo_smoke import cloud_disk, images, overlay, procs, shutdown, stopped, stream_map
from silo_smoke.cli import Silo
from silo_smoke.cloud_disk import Disk, Guids, Part, Roots

linux = pytest.mark.linux_only


def create_vm(silo: Silo, name: str, source: str, *flags: str) -> None:
    silo.create(name, source, "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock", *flags)


def gpt(silo: Silo, ext4: Path, name: str = "cloud.raw", guids: Guids | None = None, **options) -> tuple[Disk, Guids]:
    guids = guids or Guids.fresh()
    return cloud_disk.cloud_gpt(silo.ws.root / name, ext4, guids, **options), guids


def private_runtime(silo: Silo) -> Path:
    runtime = silo.ws.root / "private-runtime"
    overlay.copy_runtime(silo.ws.config.runtime_dir, runtime)
    silo.ws.config = replace(silo.ws.config, runtime_dir=runtime)
    return runtime / "assets"


def initialize(silo: Silo) -> None:
    silo.run("image", "list")
    assert silo.ws.state_db().is_file()


def selector(guid) -> dict:
    return {"kind": "gpt-partition", "guid": str(guid)}


@linux
def test_raw_and_qcow2_imports_share_decoded_identity_and_aliases(silo: Silo, cloud_roots: Roots) -> None:
    disk, guids = gpt(silo, cloud_roots.root)
    cloud_disk.verify_esp(disk, 1, silo.ws.root)
    raw_sha = overlay.digest(disk.path)
    size = disk.path.stat().st_size
    q2, q3 = silo.ws.root / "cloud-v2.qcow2", silo.ws.root / "cloud-v3.qcow2"
    kinds = {2: cloud_disk.qcow2(disk.path, q2, version=2, cluster_bits=12), 3: cloud_disk.qcow2(disk.path, q3, version=3, cluster_bits=16)}
    silo.ws.record("phase17-qcow2-kinds", json.dumps(kinds, sort_keys=True) + "\n")
    assert all(kinds[2][kind] > 0 for kind in ("allocated", "compressed", "unallocated")), kinds
    assert all(kinds[3][kind] > 0 for kind in ("allocated", "compressed", "unallocated", "zero")), kinds
    for encoded in (q2, q3):
        cloud_disk.qemu_img_cross_check(disk.path, encoded, partial(silo.ws.record, "phase17-qemu-img"))
    sources = {path: cloud_disk.fingerprint(path) for path in (disk.path, q2, q3)}

    raw = cloud_disk.import_disk(silo, disk.path, root="auto", name="cloud-raw")
    record = raw["record"]
    assert record["schema"] == 2 and record["kind"] == "image"
    assert record["root"]["profile"] == {"kind": "opaque-raw"}
    assert record["root"]["geometry"] == {"length": size, "logicalSectorSize": 512}
    assert record["root"]["layout"] == {"kind": "partitioned", "table": "gpt"}
    assert record["root"]["stream"]["length"] == size
    imported_root, _ = stream_map.catalog_root(silo.ws.silo_home, record["root"]["stream"])
    assert imported_root.chunk_size == stream_map.DISK_CHUNK
    assert stream_map.from_file(disk.path, stream_map.DISK_CHUNK)[0] == imported_root
    boot = record["boot"]
    assert boot["kind"] == "linux-direct" and boot["rootSelector"] == selector(guids.root), boot
    assert boot["rootFilesystem"] == "ext4" and boot["translation"] == "none"
    assert boot["userspacePlatform"] == {"architecture": cloud_disk.host_arch(), "variant": None}
    assert boot["kernelArchitecture"] == cloud_disk.host_arch()
    assert boot["binding"]["kind"] == "pinned" and boot["binding"]["abi"] == "silo-direct-v2"
    assert record["process"] == {"entrypoint": None, "command": None, "environment": {}, "workingDirectory": "/", "user": None}
    assert raw["names"] == ["cloud-raw"]
    assert raw["provenance"] == [{
        "container": "raw", "sourceDigest": "sha256:" + raw_sha, "sourceSpelling": str(disk.path.parent.resolve() / disk.path.name),
        "sourceManifest": None, "sourceConfig": None,
        "disk": {"sourceLength": size, "decodedLength": size, "selectedRoot": {
            "selector": selector(guids.root), "firstLba": disk.root.first_lba, "lengthLbas": disk.root.sectors,
            "gptType": str(cloud_disk.DPS_ROOT[cloud_disk.host_arch()]), "mbrType": None, "attributes": "0000000000000000"}}}]
    cloud_disk.assert_pool_objects(silo, boot["binding"])

    # `auto` is a request only: the concrete GUID is the persisted identity.
    explicit = cloud_disk.import_disk(silo, disk.path, root=f"gpt:{guids.root}")
    assert explicit["id"] == raw["id"] and explicit["record"] == record
    # Decoded bytes, not the container encoding, carry identity.
    for encoded, alias in ((q2, "cloud-q2"), (q3, "cloud-q3")):
        decoded = cloud_disk.import_disk(silo, encoded, root="auto", name=alias)
        assert decoded["id"] == raw["id"] and decoded["recordDigest"] == raw["recordDigest"] and decoded["record"] == record
        qcow2_facts = [entry for entry in decoded["provenance"] if entry["container"] == "qcow2" and entry["sourceDigest"] == "sha256:" + sources[encoded].sha256]
        assert len(qcow2_facts) == 1, decoded["provenance"]
        assert qcow2_facts[0]["disk"]["sourceLength"] == encoded.stat().st_size and qcow2_facts[0]["disk"]["decodedLength"] == size
    copy = cloud_disk.sparse_clone(disk.path, silo.ws.root / "elsewhere.raw")
    assert cloud_disk.import_disk(silo, copy, root="auto")["id"] == raw["id"], "a host path never salts image identity"
    inspected = cloud_disk.inspect(silo, "cloud-q3")
    assert inspected["kind"] == "stored" and inspected["info"]["id"] == raw["id"]
    assert set(inspected["info"]["names"]) == {"cloud-raw", "cloud-q2", "cloud-q3"}
    assert len(stopped.catalog(silo)["storage_image"]) == 1

    # One changed byte outside the root partition is a different stream and image.
    mutated = cloud_disk.sparse_clone(disk.path, silo.ws.root / "mutated.raw")
    with mutated.open("r+b") as stream:
        stream.seek(cloud_disk.FOREIGN_FIRST * 512 + 4096)
        stream.write(b"\x5a")
    changed = cloud_disk.import_disk(silo, mutated, root="auto")
    assert changed["id"] != raw["id"] and changed["record"]["root"]["stream"]["stream"] != record["root"]["stream"]["stream"]

    # Same bytes, another concrete root selector: same stream, new image identity.
    second = uuid4()
    parts = [*cloud_disk.cloud_gpt_parts(cloud_roots.root, guids),
             Part(5, disk.root.last_lba + 1, disk.root.sectors, cloud_disk.LINUX_DATA_TYPE, second, "second-root", content=cloud_roots.root)]
    two = cloud_disk.write_gpt(silo.ws.root / "two-roots.raw", parts, disk_guid=guids.disk, root_slot=4)
    cloud_disk.verify_table(two)
    first_root = cloud_disk.import_disk(silo, two.path, root=f"gpt:{guids.root}")
    second_root = cloud_disk.import_disk(silo, two.path, root=f"gpt:{second}")
    assert first_root["record"]["root"]["stream"] == second_root["record"]["root"]["stream"]
    assert first_root["id"] != second_root["id"]

    # Independent decoded-byte oracle: the never-booted private root is the raw source.
    for alias in ("cloud-q2", "cloud-q3"):
        name = f"from-{alias}"
        create_vm(silo, name, alias)
        root = cloud_disk.root_disk(silo, name)
        assert root.stat().st_size == size and overlay.digest(root) == raw_sha
        storage = stopped.record(silo, name)
        assert storage["root"]["initialContent"] == record["root"]["stream"]["stream"]
        assert storage["root"]["layout"] == record["root"]["layout"] and storage["boot"] == boot
    assert {path: cloud_disk.fingerprint(path) for path in sources} == sources, "imports modified a source"

    # Removing one of several names keeps the record and its other names.
    removed = silo.json("image", "rm", "cloud-raw")
    assert removed == {"id": raw["id"], "names": ["cloud-raw"], "recordRemoved": False}, removed
    after = cloud_disk.inspect(silo, raw["id"])["info"]
    assert set(after["names"]) == {"cloud-q2", "cloud-q3"}


@linux
def test_same_bundle_boots_whole_disk_gpt_and_mbr_roots_and_stops_clean(silo: Silo, cloud_roots: Roots) -> None:
    whole = cloud_disk.sparse_clone(cloud_roots.root, silo.ws.root / "whole.raw")
    disk, guids = gpt(silo, cloud_roots.root)
    mbr = cloud_disk.cloud_mbr(silo.ws.root / "cloud-mbr.raw", cloud_roots.root)
    cloud_disk.verify_esp(disk, 1, silo.ws.root)
    cloud_disk.verify_esp(mbr, 1, silo.ws.root)
    cloud_disk.import_disk(silo, whole, root="whole-disk", name="phase17-whole")
    cloud_disk.import_disk(silo, disk.path, root="auto", name="phase17-gpt")
    mbr_source = cloud_disk.fingerprint(mbr.path)
    create_vm(silo, "whole-vm", "phase17-whole")
    create_vm(silo, "gpt-vm", "phase17-gpt")
    # One-shot disk: creation with explicit original MBR slot 4 (slots 2-3 empty).
    create_vm(silo, "mbr-vm", f"disk:{mbr.path}", "--root", "mbr:4")
    assert cloud_disk.fingerprint(mbr.path) == mbr_source

    expected = cloud_disk.packaged_binding(silo.ws.config.runtime_dir / "assets")
    cases = {"whole-vm": (None, "whole-disk"), "gpt-vm": (disk.root, f"gpt:{guids.root}"), "mbr-vm": (mbr.root, "mbr:4")}
    for name, (partition, spelling) in cases.items():
        storage = stopped.record(silo, name)
        assert storage["boot"]["binding"] == expected, "every root shape pins the identical kernel/initramfs/agent tuple"
        view = silo.info(name)["boot"]
        assert view["bundle"] == cloud_disk.bundle_digest(expected) and view["root"] == spelling and view["rootFilesystem"] == "ext4"
    cloud_disk.assert_pool_objects(silo, expected)
    esp = disk.part(1)
    esp_before = overlay.digest(cloud_disk.extract(cloud_disk.root_disk(silo, "gpt-vm"), esp.first_lba, esp.sectors, silo.ws.root / "esp-before.img"))

    for name, (partition, _) in cases.items():
        root = cloud_disk.root_disk(silo, name)
        boot = cloud_disk.boot(silo, name)
        assert boot["guest"]["boot"]["agent_is_pid1"] is True
        record = cloud_disk.guest_probe(silo, name)
        cloud_disk.assert_root(record, partition=partition, parent_sectors=root.stat().st_size // 512)
        assert record["disks"] == {record["parent"]: "silo-root"}, record
        cloud_disk.durable_marker(silo, name, "/phase17-durable", name)
        # Partition-backed and whole-disk ext4 roots, ESP never mounted.
        stopped.stop(silo, name)
        first, sectors = (0, root.stat().st_size // 512) if partition is None else (partition.first_lba, partition.sectors)
        image = cloud_disk.extract(root, first, sectors, silo.ws.root / f"{name}-root.img")
        cloud_disk.e2fsck_clean(image)
        assert cloud_disk.debugfs_cat(image, "/phase17-durable") == name.encode()
        assert cloud_disk.debugfs_cat(image, cloud_disk.IDENTITY) == b"root\n"
    esp_after = cloud_disk.extract(cloud_disk.root_disk(silo, "gpt-vm"), esp.first_lba, esp.sectors, silo.ws.root / "esp-after.img")
    assert overlay.digest(esp_after) == esp_before, "an unmounted ESP must be untouched"


DPS_CASES = ("ambiguous", "missing", "wrong-isa", "foreign-platform", "no-auto", "read-only")


@linux
@pytest.mark.parametrize("case", DPS_CASES)
def test_dps_auto_selection_refuses_before_publication(silo: Silo, cloud_roots: Roots, case: str) -> None:
    host, foreign = cloud_disk.DPS_ROOT[cloud_disk.host_arch()], cloud_disk.DPS_ROOT[cloud_disk.foreign_arch()]
    options = {
        "ambiguous": {"foreign_type": host},
        "missing": {"root_type": cloud_disk.LINUX_DATA_TYPE, "foreign_type": cloud_disk.LINUX_DATA_TYPE},
        "wrong-isa": {"root_type": foreign, "foreign_type": cloud_disk.LINUX_DATA_TYPE},
        "foreign-platform": {"root_type": foreign, "foreign_type": cloud_disk.LINUX_DATA_TYPE},
        "no-auto": {"root_attributes": cloud_disk.DPS_NO_AUTO},
        "read-only": {"root_attributes": cloud_disk.DPS_READ_ONLY},
    }[case]
    disk, guids = gpt(silo, cloud_roots.root, **options)
    initialize(silo)
    platform_spelling = f"linux/{cloud_disk.foreign_arch()}" if case == "foreign-platform" else cloud_disk.host_platform()
    result = cloud_disk.refuse_before_publication(silo, "image", "import", str(disk.path), "--platform", platform_spelling, "--root", "auto",
                                                  "--boot", "linux-direct", "--name", "never-dps", sources=(disk.path,))
    if case != "foreign-platform":
        assert "root selection" in result.stderr.lower(), result.stderr
    if case == "ambiguous":
        # The typed refusal lists every candidate rather than choosing one.
        assert str(guids.root) in result.stderr.lower() and str(guids.foreign) in result.stderr.lower(), result.stderr
    if case == "read-only":
        cloud_disk.refuse_before_publication(silo, "image", "import", str(disk.path), "--platform", platform_spelling,
                                             "--root", f"gpt:{guids.root}", "--boot", "linux-direct", sources=(disk.path,))
    if case in {"foreign-platform", "no-auto", "wrong-isa"}:
        # Positive control: the same bytes are admitted with an explicit host-native
        # selection, so the refusal above is the selection/platform rule itself.
        admitted = cloud_disk.import_disk(silo, disk.path, root=f"gpt:{guids.root}")
        assert admitted["record"]["boot"]["rootSelector"] == selector(guids.root)
        if case == "no-auto":
            attributes = admitted["provenance"][0]["disk"]["selectedRoot"]["attributes"]
            assert int(attributes, 16) == cloud_disk.DPS_NO_AUTO


@linux
def test_trusted_init_override_is_rejected_before_machine_publication(silo: Silo, cloud_roots: Roots) -> None:
    source = cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name="trusted-init")
    before = cloud_disk.inspect(silo, "trusted-init")
    for argument in ("rdinit=/agent/silo-agent", 'rdinit="/agent/silo-agent"', '"rdinit=/agent/silo-agent"'):
        cloud_disk.refuse_before_publication(
            silo, "create", "trusted-init", "--name", "never-bypass",
            "--network", "none", f"--kernel-arg={argument}",
        )
    assert cloud_disk.inspect(silo, "trusted-init") == before
    create_vm(silo, "trusted-init", source["id"])
    cloud_disk.boot(silo, "trusted-init")
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "trusted-init"), partition=None)
    stopped.stop(silo, "trusted-init")


@linux
def test_unsupported_inputs_refuse_before_any_operation(silo: Silo, cloud_roots: Roots) -> None:
    whole = cloud_disk.sparse_clone(cloud_roots.root, silo.ws.root / "whole.raw")
    cloud_disk.import_disk(silo, whole, root="whole-disk", name="initialized")
    link = silo.ws.root / "whole-link.raw"
    link.symlink_to(whole)
    directory = silo.ws.root / "not-a-file"
    directory.mkdir()
    odd = silo.ws.root / "odd.raw"
    with odd.open("xb") as stream:
        stream.truncate(cloud_disk.MIB + 1)
    tiny = silo.ws.root / "tiny.raw"
    tiny.write_bytes(os.urandom(cloud_disk.MIB))
    host = cloud_disk.host_platform()

    def import_args(path: Path, root: str = "whole-disk", platform_spelling: str = host) -> tuple[str, ...]:
        return ("image", "import", str(path), "--platform", platform_spelling, "--root", root, "--boot", "linux-direct")

    cases: list[tuple[str, tuple[str, ...], tuple[Path, ...]]] = [
        ("symlink-import", import_args(link), (link, whole)),
        ("symlink-create", ("create", f"disk:{link}", "--name", "never-link"), (link, whole)),
        ("character-device", import_args(Path("/dev/null")), ()),
        ("directory", import_args(directory), ()),
        ("odd-length", import_args(odd), (odd,)),
        ("mbr-slot-5", import_args(whole, "mbr:5"), (whole,)),
        ("nil-gpt-guid", import_args(whole, "gpt:00000000-0000-0000-0000-000000000000"), (whole,)),
        ("malformed-gpt-guid", import_args(whole, "gpt:not-a-guid"), (whole,)),
        ("unsupported-platform", import_args(whole, platform_spelling="linux/riscv64"), (whole,)),
        ("unsupported-variant", import_args(whole, platform_spelling=f"linux/{cloud_disk.host_arch()}/v7"), (whole,)),
    ]
    for kind in cloud_disk.FOREIGN_CONTAINERS:
        path = cloud_disk.foreign_container(silo.ws.root / f"foreign.{kind}", kind)
        cases.append((f"container-{kind}", import_args(path), (path,)))
    for feature in cloud_disk.QCOW2_FORBIDDEN:
        path = cloud_disk.qcow2_forbidden(tiny, silo.ws.root / f"forbidden-{feature}.qcow2", feature)
        cases.append((f"qcow2-{feature}", import_args(path), (path,)))
    # All fixture writes are complete. Only serial early rejections and evidence
    # logging follow, so the verified after-state is the next request's before.
    refusals = cloud_disk.EarlyRefusals(silo)
    for label, args, sources in cases:
        result = refusals.refuse(*args, sources=sources)
        silo.ws.record("phase17-early-refusal-case", json.dumps({"case": label, "stderr": result.stderr[-2000:]}) + "\n")
        if label.startswith("qcow2-"):
            assert "qcow2" in result.stderr.lower(), (label, result.stderr)
        if label.startswith("container-"):
            assert "convert" in result.stderr.lower(), (label, result.stderr)


LAYOUT_REFUSALS = (
    "whole-disk-on-gpt", "absent-gpt-guid", "mbr-selector-on-gpt", "gpt-selector-on-mbr", "empty-mbr-slot",
    "gpt-entry-size-256", "corrupt-primary-array", "backup-not-at-capacity", "root-not-ext4", "whole-disk-not-ext4",
    "disk-create-partitioned-without-root",
)


@linux
@pytest.mark.parametrize("case", LAYOUT_REFUSALS)
def test_incompatible_layouts_refuse_before_publication(silo: Silo, cloud_roots: Roots, case: str) -> None:
    guids = Guids.fresh()
    root = cloud_roots.root
    path = silo.ws.root / f"{case}.raw"
    if case in {"gpt-selector-on-mbr", "empty-mbr-slot"}:
        disk = cloud_disk.cloud_mbr(path, root)
    elif case == "gpt-entry-size-256":
        disk = cloud_disk.write_gpt(path, cloud_disk.cloud_gpt_parts(root, guids), disk_guid=guids.disk, root_slot=4, entry_size=256)
    elif case == "corrupt-primary-array":
        disk = cloud_disk.write_gpt(path, cloud_disk.cloud_gpt_parts(root, guids), disk_guid=guids.disk, root_slot=4, corrupt_primary_array=True)
    elif case == "root-not-ext4":
        zero = silo.ws.root / "zero.ext4"
        with zero.open("xb") as stream:
            stream.truncate(root.stat().st_size)
        disk = cloud_disk.cloud_gpt(path, zero, guids)
    elif case == "whole-disk-not-ext4":
        with path.open("xb") as stream:
            stream.truncate(64 * cloud_disk.MIB)
        disk = None
    else:
        disk = cloud_disk.cloud_gpt(path, root, guids)
    if case == "backup-not-at-capacity":
        # Import is strict: an expanded GPT is only a guest-boot state, never an input.
        with path.open("r+b") as stream:
            stream.truncate(path.stat().st_size + cloud_disk.MIB)
    initialize(silo)
    root_spelling = {
        "whole-disk-on-gpt": "whole-disk", "absent-gpt-guid": f"gpt:{uuid4()}", "mbr-selector-on-gpt": "mbr:4",
        "gpt-selector-on-mbr": f"gpt:{guids.root}", "empty-mbr-slot": "mbr:2", "whole-disk-not-ext4": "whole-disk",
    }.get(case, "auto")
    if case == "disk-create-partitioned-without-root":
        # The disk: shorthand means whole-disk; it never guesses a partition.
        args = ("create", f"disk:{path}", "--name", "never-guessed", "--network", "none")
    else:
        args = ("image", "import", str(path), "--platform", cloud_disk.host_platform(), "--root", root_spelling, "--boot", "linux-direct", "--name", "never-layout")
    cloud_disk.refuse_before_publication(silo, *args, sources=(path,))
    if disk is not None and case not in {"gpt-entry-size-256", "corrupt-primary-array", "backup-not-at-capacity"}:
        cloud_disk.verify_table(disk)


@linux
def test_cloned_gpt_on_attached_disk_never_replaces_the_root_serial(silo: Silo, cloud_roots: Roots) -> None:
    disk, guids = gpt(silo, cloud_roots.root)
    clone, _ = gpt(silo, cloud_roots.clone, "clone.raw", guids)
    # The clone repeats the disk GUID, every unique partition GUID and both tables.
    metadata = 34 * 512
    assert cloud_disk.read_at(disk.path, 0, metadata) == cloud_disk.read_at(clone.path, 0, metadata)
    tail = disk.path.stat().st_size - 33 * 512
    assert cloud_disk.read_at(disk.path, tail, 33 * 512) == cloud_disk.read_at(clone.path, tail, 33 * 512)
    cloud_disk.import_disk(silo, disk.path, root=f"gpt:{guids.root}", name="cloned-root")
    create_vm(silo, "cloned", "cloned-root", "--disk", str(clone.path))
    cloud_disk.boot(silo, "cloned")
    record = cloud_disk.guest_probe(silo, "cloned")
    cloud_disk.assert_root(record, partition=disk.root)
    data = [name for name, serial in record["disks"].items() if serial == "silo-data-0"]
    assert len(data) == 1 and data[0] != record["parent"], record
    observed = silo.exec("cloned", "sh", "-eu", "-c", 'for f in partition start size; do cat "/sys/block/$1/$1$2/$f"; done', "child", data[0], str(disk.root_slot), user="root").stdout.split()
    assert [int(value) for value in observed] == [disk.root.slot, disk.root.first_lba, disk.root.sectors], "the duplicate GUID partition is really visible"
    stopped.stop(silo, "cloned", require_clean=False)


@linux
def test_init_selects_root_serial_under_shuffled_order_and_fails_closed(silo: Silo, cloud_roots: Roots) -> None:
    """Controlled candidate: a cloned GPT occupies the first attachment, root the second."""
    disk, guids = gpt(silo, cloud_roots.root)
    clone, _ = gpt(silo, cloud_roots.clone, "clone.raw", guids)
    length = disk.path.stat().st_size
    shuffled = [cloud_disk.candidate_disk(clone.path, role="root", block_id="silo-data-0"),
                cloud_disk.candidate_disk(disk.path, role="data", block_id="silo-root")]
    with cloud_disk.RawCandidate(silo, disks=shuffled, bootstrap=cloud_disk.raw_bootstrap(length, selector(guids.root))) as candidate:
        candidate.start()
        record = cloud_disk.probe_record(candidate.wait())
    cloud_disk.assert_root(record, partition=disk.root, parent_sectors=length // 512)
    first = min(record["disks"])
    assert record["disks"][first] == "silo-data-0" and record["parent"] != first, ("order was not shuffled", record)

    invalid = {
        "absent-guid": cloud_disk.raw_bootstrap(length, selector(uuid4())),
        "whole-disk-on-gpt": cloud_disk.raw_bootstrap(length, {"kind": "whole-disk"}),
        "mbr-on-gpt": cloud_disk.raw_bootstrap(length, {"kind": "mbr-partition", "number": 4}),
        "wrong-length": cloud_disk.raw_bootstrap(length + 512, selector(guids.root)),
    }
    # Each candidate is stopped and reaped before the next request; rejected
    # bootstrap contracts never mount a root and there are no host disk writes.
    before = {path: overlay.digest(path) for path in (disk.path, clone.path)}
    for label, bootstrap in invalid.items():
        with cloud_disk.RawCandidate(silo, disks=shuffled, bootstrap=bootstrap) as candidate:
            candidate.start()
            text = candidate.wait(rejected=True)
        silo.ws.record("phase17-candidate-refusal", json.dumps({"case": label, "tail": text[-2000:]}) + "\n")
        # No root was mounted, so no ext4 superblock or journal byte changed.
        after = {path: overlay.digest(path) for path in (disk.path, clone.path)}
        assert after == before, label
        before = after


@linux
def test_vfat_esp_mounts_from_fstab_and_late_mount_is_not_clean(silo: Silo, cloud_roots: Roots) -> None:
    disk, _ = gpt(silo, cloud_roots.root)
    cloud_disk.verify_esp(disk, 1, silo.ws.root)
    cloud_disk.import_disk(silo, disk.path, root="auto", name="esp-root")
    create_vm(silo, "esp", "esp-root")
    cloud_disk.boot(silo, "esp")
    # The guest's own fstab entry (LABEL=, explicit codepage/iocharset) drives mount.
    observed = silo.exec("esp", "sh", "-eu", "-c", """
mount "$1"
device=$(mountpoint -d "$1")
node=$(readlink -f "/sys/dev/block/$device")
cat "$node/partition"
printf '%s\\n' "$(cat "$(readlink -f "$node/..")/serial")"
awk -v target="$1" '$2 == target { print $3; print $4 }' /proc/mounts
cat "$1/SILO.TXT"
printf late-esp-write >"$1/LATE.TXT"
sync
""", "esp-mount", cloud_disk.ESP_MOUNT, user="root").stdout.split("\n", 5)
    partition, serial, fstype, options, content = observed[0], observed[1], observed[2], observed[3], observed[4]
    assert (int(partition), serial, fstype) == (1, "silo-root", "vfat"), observed
    assert {"codepage=437", "iocharset=utf8"} <= set(options.split(",")), options
    assert (content + "\n").encode() == cloud_disk.ESP_CONTENT, content
    # Mounted after agent capture: retained-before-write authority is absent.
    cloud_disk.stop_not_clean(silo, "esp")


@linux
def test_expanded_gpt_keeps_tables_partition_and_filesystem_size(silo: Silo, cloud_roots: Roots) -> None:
    disk, _ = gpt(silo, cloud_roots.root)
    cloud_disk.import_disk(silo, disk.path, root="auto", name="grow-root")
    create_vm(silo, "grow", "grow-root")
    root = cloud_disk.root_disk(silo, "grow")
    old = root.stat().st_size
    assert old % cloud_disk.MIB == 0
    primary = cloud_disk.read_at(root, 0, 34 * 512)
    backup = cloud_disk.read_at(root, old - 33 * 512, 33 * 512)
    blocks = cloud_disk.ext4_blocks(root, disk.root.first_lba * 512)
    new = old + 64 * cloud_disk.MIB
    silo.run("set", "grow", f"disk={new // cloud_disk.MIB}mib")
    assert stopped.record(silo, "grow")["root"]["geometry"] == {"length": new, "logicalSectorSize": 512}

    cloud_disk.boot(silo, "grow")
    assert root.stat().st_size == new
    record = cloud_disk.guest_probe(silo, "grow")
    # Opaque length reaches the guest; the selected partition is not grown.
    cloud_disk.assert_root(record, partition=disk.root, parent_sectors=new // 512)
    cloud_disk.durable_marker(silo, "grow", "/phase17-grown", "expanded")
    stopped.stop(silo, "grow")

    assert cloud_disk.read_at(root, 0, 34 * 512) == primary, "primary GPT was rewritten"
    assert cloud_disk.read_at(root, old - 33 * 512, 33 * 512) == backup, "backup GPT was relocated or rewritten"
    assert cloud_disk.all_zero(root, old, new), "expanded tail was written"
    assert cloud_disk.ext4_blocks(root, disk.root.first_lba * 512) == blocks, "root filesystem was grown automatically"
    image = cloud_disk.extract(root, disk.root.first_lba, disk.root.sectors, silo.ws.root / "grown-root.img")
    cloud_disk.e2fsck_clean(image)
    assert cloud_disk.debugfs_cat(image, "/phase17-grown") == b"expanded"


@linux
def test_pinned_bundle_survives_removal_and_changes_only_by_explicit_update(silo: Silo, cloud_roots: Roots) -> None:
    assets = private_runtime(silo)
    saved = silo.ws.root / "saved-assets"
    saved.mkdir()
    for name in ("kernel-default", "initramfs", "agent"):
        shutil.copyfile(assets / name, saved / name)
    original = cloud_disk.packaged_binding(assets)
    disk, _ = gpt(silo, cloud_roots.root)
    image = cloud_disk.import_disk(silo, disk.path, root="auto", name="pinned")
    assert image["record"]["boot"]["binding"] == original
    create_vm(silo, "pinned-a", "pinned")
    assert stopped.record(silo, "pinned-a")["boot"]["binding"] == original

    # Neither the caller's source nor the packaged assets are boot authority.
    disk.path.unlink()
    cloud_disk.break_assets(assets)
    create_vm(silo, "pinned-b", "pinned")
    assert stopped.record(silo, "pinned-b")["boot"]["binding"] == original
    cloud_disk.assert_pool_objects(silo, original)
    cloud_disk.boot(silo, "pinned-a")
    assert cloud_disk.guest_agent_sha256(silo, "pinned-a") == original["agent"]
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "pinned-a"), partition=disk.root)
    assert silo.info("pinned-a")["boot"]["bundle"] == cloud_disk.bundle_digest(original)
    stopped.stop(silo, "pinned-a")

    cloud_disk.valid_replacement_assets(assets, saved)
    replacement = cloud_disk.packaged_binding(assets)
    assert replacement["kernel"] == original["kernel"]
    assert replacement["baseInitramfs"] != original["baseInitramfs"] and replacement["agent"] != original["agent"]
    view = silo.info("pinned-a")["boot"]
    assert view["bundle"] == cloud_disk.bundle_digest(original)
    assert view["packagedReplacement"] is None, "unimported installed bytes are not an admitted bundle"
    create_vm(silo, "replacement-admission", "pinned")
    silo.run("set", "replacement-admission", "boot-assets=packaged")
    assert stopped.record(silo, "replacement-admission")["boot"]["binding"] == replacement
    view = silo.info("pinned-a")["boot"]
    assert view["bundle"] == cloud_disk.bundle_digest(original)
    assert view["packagedReplacement"] == cloud_disk.bundle_digest(replacement), "a locally admitted replacement is visible, not applied"

    # Start never upgrades implicitly; a running machine refuses the update.
    cloud_disk.boot(silo, "pinned-a")
    assert cloud_disk.guest_agent_sha256(silo, "pinned-a") == original["agent"]
    refused = silo.run("set", "pinned-a", "boot-assets=packaged", expect=None)
    assert refused.returncode != 0
    assert stopped.record(silo, "pinned-a")["boot"]["binding"] == original
    stopped.stop(silo, "pinned-a")
    mixed = silo.run("set", "pinned-a", "boot-assets=packaged", "cpus=2", expect=None)
    assert mixed.returncode != 0 and stopped.record(silo, "pinned-a")["boot"]["binding"] == original

    silo.run("set", "pinned-a", "boot-assets=packaged")
    storage = stopped.record(silo, "pinned-a")
    assert storage["boot"]["binding"] == replacement, "explicit update replaces the complete tuple"
    view = silo.info("pinned-a")["boot"]
    assert (view["bundle"], view["kernel"], view["baseInitramfs"], view["agent"]) == (
        cloud_disk.bundle_digest(replacement), replacement["kernel"], replacement["baseInitramfs"], replacement["agent"])
    assert view["packagedReplacement"] is None
    cloud_disk.assert_pool_objects(silo, replacement)
    cloud_disk.boot(silo, "pinned-a")
    assert cloud_disk.guest_agent_sha256(silo, "pinned-a") == replacement["agent"]
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "pinned-a"), partition=disk.root)
    stopped.stop(silo, "pinned-a")
    # Source image and sibling machine keep their own immutable tuple.
    assert cloud_disk.inspect(silo, "pinned")["info"]["record"] == image["record"]
    assert stopped.record(silo, "pinned-b")["boot"]["binding"] == original


@linux
def test_image_creation_and_snapshot_restore_preserve_semantics_and_every_disk(silo: Silo, cloud_roots: Roots) -> None:
    disk, _ = gpt(silo, cloud_roots.root)
    image = cloud_disk.import_disk(silo, disk.path, root="auto", name="snap-image")
    create_vm(silo, "snap-source", "snap-image", "--label", "owner=phase17")
    storage = stopped.record(silo, "snap-source")
    assert storage["boot"] == image["record"]["boot"] and storage["root"]["layout"] == image["record"]["root"]["layout"]
    assert storage["root"]["initialContent"] == image["record"]["root"]["stream"]["stream"]
    stopped.install_managed_fixture(silo, "snap-source", custom_boot=False)
    expected = stopped.configured_semantics(stopped.configuration(silo, "snap-source"))
    cloud_disk.boot(silo, "snap-source")
    cloud_disk.durable_marker(silo, "snap-source", "/phase17-snapshot", "captured-root")
    shutdown.write_raw_data(silo, "snap-source")
    stopped.stop(silo, "snap-source", require_clean=False)
    source = stopped.backing(silo, "snap-source", "phase17-before-snapshot")
    assert set(source) == {"root", "data:1"}
    captured = silo.json("snapshot", "create", "snap-source", "--name", "cloud-snap", timeout=240)
    assert captured["capture"] is None and captured["snapshot"]["names"] == ["cloud-snap"]

    # A snapshot is not an image: create refuses it and names restore instead.
    refused = cloud_disk.refuse_before_publication(silo, "create", "cloud-snap", "--name", "never-created")
    assert "silo restore cloud-snap" in refused.stderr, refused.stderr
    stopped.restore(silo, "cloud-snap", "from-snap")
    copy = stopped.backing(silo, "from-snap", "phase17-created-from-snapshot")
    stopped.same_content(source, copy)
    stopped.independent(source, copy)
    assert stopped.configured_semantics(stopped.configuration(silo, "from-snap")) == expected
    created = stopped.record(silo, "from-snap")
    assert created["boot"] == storage["boot"] and created["root"]["layout"] == storage["root"]["layout"]
    cloud_disk.boot(silo, "from-snap")
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "from-snap"), partition=disk.root)
    assert silo.exec("from-snap", "cat", "/phase17-snapshot", user="root").stdout == "captured-root"
    data = silo.exec("from-snap", "sh", "-eu", "-c", 'for p in /sys/block/*; do if test "$(cat "$p/serial" 2>/dev/null)" = silo-data-0; then dd if=/dev/${p##*/} bs=1 count=20 2>/dev/null; fi; done', user="root").stdout
    assert data == "raw-data-before-stop"
    stopped.stop(silo, "from-snap", require_clean=False)
    stopped.same_content(source, stopped.backing(silo, "snap-source", "phase17-source-unchanged"))


@linux
def test_image_and_snapshot_named_hello_coexist_and_resolve_by_command(silo: Silo, cloud_roots: Roots) -> None:
    image = cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name="hello")
    create_vm(silo, "hello-source", "hello", "--label", "origin=snapshot")
    snapshot = silo.json("snapshot", "create", "hello-source", "--name", "hello", timeout=240)["snapshot"]
    assert snapshot["names"] == ["hello"]
    # Each kind has its own name table: neither name shadows or refuses the other.
    database = silo.ws.state_db()
    assert procs.query(database, "SELECT name, stored_image_id FROM image_name WHERE stored_image_id IS NOT NULL") == [("hello", image["id"])]
    assert procs.query(database, "SELECT name, snapshot_id FROM snapshot_name") == [("hello", snapshot["id"])]
    assert cloud_disk.inspect(silo, "hello")["info"]["id"] == image["id"]
    assert silo.json("snapshot", "inspect", "hello")["id"] == snapshot["id"]

    # create resolves images only, restore snapshots only.
    create_vm(silo, "from-image", "hello")
    assert "origin" not in stopped.configuration(silo, "from-image")["labels"]
    assert stopped.record(silo, "from-image")["root"]["initialContent"] == image["record"]["root"]["stream"]["stream"]
    stopped.restore(silo, "hello", "from-snapshot")
    assert stopped.configuration(silo, "from-snapshot")["labels"] == {"origin": "snapshot"}
    assert stopped.configured_semantics(stopped.configuration(silo, "from-snapshot")) == \
        stopped.configured_semantics(stopped.configuration(silo, "hello-source"))

    # A name of only the other kind is refused with the right command, before any pull.
    silo.json("snapshot", "create", "hello-source", "--name", "snapshot-only", timeout=240)
    refused = cloud_disk.refuse_before_publication(silo, "create", "snapshot-only", "--name", "never-created")
    assert "silo restore snapshot-only" in refused.stderr, refused.stderr
    cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name="image-only")
    refused = cloud_disk.refuse_before_publication(silo, "restore", "image-only", "--name", "never-restored")
    assert "silo create image-only" in refused.stderr, refused.stderr


@linux
def test_image_rm_follows_names_and_prune_keeps_images_machines_use(silo: Silo, cloud_roots: Roots) -> None:
    used = cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk")
    disk, _ = gpt(silo, cloud_roots.root)
    unused = cloud_disk.import_disk(silo, disk.path, root="auto")
    assert used["names"] == [] and unused["names"] == [] and used["id"] != unused["id"]
    create_vm(silo, "uses-image", used["id"])
    database = silo.ws.state_db()

    # Prune removes only unnamed images that no machine uses.
    pruned = silo.json("image", "prune")
    assert pruned["imagesRemoved"] == 1, pruned
    assert procs.query(database, "SELECT id FROM storage_image") == [(used["id"],)]
    stored = [entry["info"]["id"] for entry in silo.json("image", "list") if entry["kind"] == "stored"]
    assert stored == [used["id"]], stored

    # rm NAME removes that name; the record goes with its last name.
    for name in ("tag-a", "tag-b", "tag-c"):
        assert cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name=name)["id"] == used["id"]
    removed = silo.json("image", "rm", "tag-a")
    assert removed == {"id": used["id"], "names": ["tag-a"], "recordRemoved": False}, removed
    assert set(cloud_disk.inspect(silo, used["id"])["info"]["names"]) == {"tag-b", "tag-c"}
    removed = silo.json("image", "rm", "tag-b")
    assert removed == {"id": used["id"], "names": ["tag-b"], "recordRemoved": False}, removed
    removed = silo.json("image", "rm", "tag-c")
    assert removed == {"id": used["id"], "names": ["tag-c"], "recordRemoved": True}, removed
    assert procs.query(database, "SELECT id FROM storage_image") == []
    assert procs.query(database, "SELECT name FROM image_name WHERE stored_image_id IS NOT NULL") == []

    # rm ID removes the record and all its names.
    again = cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name="tag-d")
    assert again["id"] == used["id"]
    cloud_disk.import_disk(silo, cloud_roots.root, root="whole-disk", name="tag-e")
    removed = silo.json("image", "rm", used["id"])
    assert removed["id"] == used["id"] and set(removed["names"]) == {"tag-d", "tag-e"} and removed["recordRemoved"] is True, removed
    assert procs.query(database, "SELECT id FROM storage_image") == []

    # A removed record never breaks a machine: its bytes stay until nothing references them.
    silo.json("image", "prune")
    cloud_disk.boot(silo, "uses-image")
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "uses-image"), partition=None)
    stopped.stop(silo, "uses-image")


CONVERTED_PROCESS = {
    "entrypoint": ["/bin/sleep"], "command": ["3600"],
    "environment": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PHASE17_CONVERTED": "exact value"},
    "workingDirectory": "/srv", "user": "root",
}


@linux
def test_explicit_conversion_is_cached_preserves_defaults_and_boots(silo: Silo, convert_image: tuple[str, images.OciImage]) -> None:
    reference, oci = convert_image
    assets = private_runtime(silo)
    saved = silo.ws.root / "saved-assets"
    saved.mkdir()
    for name in ("kernel-default", "initramfs", "agent"):
        shutil.copyfile(assets / name, saved / name)
    packaged = cloud_disk.packaged_binding(assets)
    converted = silo.json("image", "convert", reference, "--disk-format", "raw", "--name", "conv-a", timeout=600)
    record = converted["record"]
    assert record["root"]["layout"] == {"kind": "whole-disk"} and record["root"]["profile"] == {"kind": "opaque-raw"}
    assert record["boot"]["rootSelector"] == {"kind": "whole-disk"} and record["boot"]["rootFilesystem"] == "ext4"
    assert record["boot"]["binding"] == packaged
    assert record["process"] == CONVERTED_PROCESS
    assert converted["provenance"] == [{"container": "oci", "sourceDigest": oci.manifest_digest, "sourceSpelling": reference,
                                        "sourceManifest": oci.manifest_digest, "sourceConfig": oci.config_digest, "disk": None}]
    assert converted["names"] == ["conv-a"]

    repeated = silo.json("image", "convert", reference, "--disk-format", "raw", timeout=600)
    assert repeated["id"] == converted["id"] and repeated["record"] == record
    # A packaged upgrade never re-keys or re-pins a cached conversion.
    cloud_disk.valid_replacement_assets(assets, saved)
    aliased = silo.json("image", "convert", reference, "--disk-format", "raw", "--name", "conv-b", timeout=600)
    assert aliased["id"] == converted["id"] and aliased["record"]["boot"]["binding"] == packaged
    assert set(aliased["names"]) == {"conv-a", "conv-b"}
    catalog = stopped.catalog(silo)
    assert len(catalog["storage_image"]) == 1 and len(catalog["raw_conversion_result"]) == 1

    create_vm(silo, "converted", "conv-b")
    assert stopped.configuration(silo, "converted")["process"] == CONVERTED_PROCESS
    assert stopped.record(silo, "converted")["boot"]["binding"] == packaged
    cloud_disk.boot(silo, "converted")
    assert cloud_disk.guest_agent_sha256(silo, "converted") == packaged["agent"]
    cloud_disk.assert_root(cloud_disk.guest_probe(silo, "converted"), partition=None)
    stopped.stop(silo, "converted")


@pytest.mark.macos_only
def test_vz_refuses_oci_and_layered_roots_and_boots_converted_raw(silo: Silo, basic_image: str) -> None:
    """pending-lane:macos until exercised on VZ; never substituted by a Linux run."""
    if silo.ws.config.backend != "vz":
        pytest.skip("requires --backend vz")
    initialize(silo)
    # Ordinary OCI creation is layered; VZ refuses it and names explicit raw conversion.
    refused = cloud_disk.refuse_before_publication(silo, "create", basic_image, "--name", "vz-oci", "--network", "none")
    assert "boot admission rejected" in refused.stderr and "Conversion" in refused.stderr, refused.stderr
    krun = silo.ws.env(SILO_VIRT_BACKEND="krun")
    silo.run("create", basic_image, "--name", "krun-layered", "--network", "none", env=krun)
    silo.ws.register_machine("krun-layered")
    before = stopped.record(silo, "krun-layered")
    assert before["root"]["kind"] == "linux-overlay", before["root"]
    assert silo.run("start", "krun-layered", expect=None).returncode != 0
    assert stopped.record(silo, "krun-layered") == before and silo.info("krun-layered")["state"] == "stopped"
    silo.run("image", "convert", basic_image, "--disk-format", "raw", "--name", "vz-raw", timeout=600)
    create_vm(silo, "vz-raw-vm", "vz-raw")
    cloud_disk.boot(silo, "vz-raw-vm")
    silo.exec("vz-raw-vm", "test", "-f", "/etc/proof", user="root")
    silo.stop("vz-raw-vm")


@linux
@pytest.mark.parametrize("location", ("home", "input"))
def test_early_refusal_batch_detects_same_size_byte_changes(silo: Silo, location: str) -> None:
    """A verified after-state is retained, never silently re-baselined."""
    initialize(silo)
    root = silo.ws.silo_home if location == "home" else silo.ws.root
    source = root / "refusal-byte-oracle.raw"
    source.write_bytes(b"\0" * 512)
    metadata = source.stat()
    sources = (source,) if location == "input" else ()
    args = ("image", "import", str(source), "--platform", "linux/riscv64",
            "--root", "whole-disk", "--boot", "linux-direct")
    refusals = cloud_disk.EarlyRefusals(silo)
    refusals.refuse(*args, sources=sources)

    # Deliberately violate the batch's no-writer contract. Same length, mode and
    # mtime cannot substitute for reading complete bytes after the next request.
    with source.open("r+b") as stream:
        stream.write(b"\x01")
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    message = "refusal had catalog or file effects" if location == "home" else "refused input was modified"
    with pytest.raises(AssertionError, match=message):
        refusals.refuse(*args, sources=sources)
