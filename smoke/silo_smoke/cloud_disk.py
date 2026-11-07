"""Phase 17 opaque raw, qcow2 and cloud-disk fixtures with independent oracles.

Every container and table here is produced by bounded smoke-only encoders and
checked by tools that share no code with Silo: `sfdisk --json` reads back each
GPT/MBR layout, `blkid` probes the vfat ESP, `e2fsck`/`debugfs` read ext4
partitions extracted by byte range, and SHA-256 over complete logical bytes is
the decoded-stream oracle. Nothing parses a Silo store format a second way.
Guest evidence comes from the guest kernel's own sysfs/mount view, printed by a
probe script that lives in the fixture root filesystem.

                 GPT cloud disk (512-byte sectors, 1 MiB aligned)
   LBA 0      1   2..33      2048         34816        36864           end-33  end
   +------+------+-------+-------------+------------+----------------+-------+---+
   | PMBR | GPT  | array | slot 1 ESP  | slot 2     | slot 4 root    | array |GPT|
   |      | hdr  | (128) | vfat 16 MiB | foreign-ISA| host DPS ext4  | copy  |bak|
   +------+------+-------+-------------+------------+----------------+-------+---+
   Slot 3 stays empty, so the guest must resolve a sparse slot number.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import time
from typing import Any
from uuid import UUID, uuid4
import zlib

from . import images, overlay, procs, shutdown, stopped
from .cli import Result, Silo
from .config import REPO
from .overlay_candidate import bounded_log, cpio

SECTOR = 512
MIB = 1024**2

ESP_TYPE = UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
LINUX_DATA_TYPE = UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
# Discoverable Partitions Specification root types, per userspace ISA.
DPS_ROOT = {
    "amd64": UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"),
    "arm64": UUID("b921b045-1df0-41c3-af44-4c6f280d3fae"),
}
DPS_READ_ONLY = 1 << 60
DPS_NO_AUTO = 1 << 63

ESP_FIRST, ESP_SECTORS = 2048, 32768
FOREIGN_FIRST, FOREIGN_SECTORS = 34816, 2048
ROOT_FIRST = 36864
TAIL_SECTORS = 2048

ESP_LABEL = "SILOESP"
ESP_VOLUME_ID = 0x51170E5F
ESP_FILE = "SILO.TXT"
ESP_CONTENT = b"silo-phase17-esp\n"
ESP_MOUNT = "/boot/efi"

PROBE = "/usr/local/bin/phase17-probe"
IDENTITY = "/etc/phase17-identity"
PROBE_MARK = "PHASE17_PROBE "
CANDIDATE_REJECTED = "boot failed; workload prohibited"

# Guest root-identity probe. `report` prints only; without arguments it is an
# agentless image init that prints and powers off. It reads the kernel's view:
# the mounted root's device number, its sysfs node and the parent attachment.
PROBE_SCRIPT = b"""#!/bin/sh
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
test -r /proc/self/mountinfo || mount -t proc proc /proc
test -d /sys/dev/block || mount -t sysfs sysfs /sys
device=$(mountpoint -d /)
node=$(readlink -f "/sys/dev/block/$device")
if test -r "$node/partition"; then
    parent=$(readlink -f "$node/..")
    partition=$(cat "$node/partition")
    start=$(cat "$node/start")
else
    parent=$node
    partition=0
    start=0
fi
disks=""
for path in /sys/block/*; do
    test -r "$path/serial" || continue
    disks="$disks${disks:+,}\\"${path##*/}\\":\\"$(cat "$path/serial")\\""
done
filesystem=$(awk '$2 == "/" { fs = $3 } END { print fs }' /proc/mounts)
printf 'PHASE17_PROBE {"identity":"%s","device":"%s","name":"%s","parent":"%s","parentSerial":"%s","partition":%s,"start":%s,"sectors":%s,"parentSectors":%s,"filesystem":"%s","disks":{%s}}\\n' \\
    "$(cat /etc/phase17-identity)" "$device" "${node##*/}" "${parent##*/}" "$(cat "$parent/serial")" \\
    "$partition" "$start" "$(cat "$node/size")" "$(cat "$parent/size")" "$filesystem" "$disks"
if test "${1:-}" != report; then
    sync
    poweroff -f
fi
"""

# A stock cloud image mounts its ESP from fstab. Explicit codepage/iocharset
# exercise the admitted kernel's NLS tables, not only the vfat driver.
FSTAB = f"LABEL={ESP_LABEL} {ESP_MOUNT} vfat noauto,umask=0077,codepage=437,iocharset=utf8 0 2\n".encode()


def host_arch() -> str:
    return images.oci_arch()


def foreign_arch() -> str:
    return {"amd64": "arm64", "arm64": "amd64"}[host_arch()]


def host_platform() -> str:
    return f"linux/{host_arch()}"


def root_image_spec(identity: str) -> images.ImageSpec:
    """BASIC plus the probe, identity marker, ESP mount point and fstab."""
    return replace(
        images.BASIC,
        name=f"phase17-{identity}",
        files={
            **images.BASIC.files,
            IDENTITY.lstrip("/"): identity.encode() + b"\n",
            PROBE.lstrip("/"): images.GuestFile(PROBE_SCRIPT, mode=0o755),
            "etc/fstab": FSTAB,
        },
        dirs={
            **images.BASIC.dirs,
            "boot": images.GuestDir(),
            "boot/efi": images.GuestDir(mode=0o700),
            "usr/local": images.GuestDir(),
            "usr/local/bin": images.GuestDir(),
        },
    )


def with_process_defaults(image: images.OciImage, defaults: dict[str, Any]) -> images.OciImage:
    """Same layer, a config carrying OCI execution defaults and a new manifest."""
    config = json.loads(image.config)
    config["config"] = defaults
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    manifest = json.loads(image.manifest)
    manifest["config"] = {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": _digest(config_bytes), "size": len(config_bytes)}
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
    return replace(image, config=config_bytes, config_digest=_digest(config_bytes), manifest=manifest_bytes, manifest_digest=_digest(manifest_bytes))


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Byte helpers


def data_extents(fd: int, length: int) -> Iterator[tuple[int, int]]:
    """Allocated byte ranges of a sparse file; holes read as zero."""
    offset = 0
    while offset < length:
        try:
            start = os.lseek(fd, offset, os.SEEK_DATA)
        except OSError as error:
            if error.errno == errno.ENXIO:
                return
            raise
        if start >= length:
            return
        end = min(os.lseek(fd, start, os.SEEK_HOLE), length)
        yield start, end
        offset = end


def copy_range(source: Path, source_offset: int, length: int, destination: int, destination_offset: int) -> None:
    """Copy allocated source bytes into an already sized sparse destination."""
    with source.open("rb") as stream:
        fd = stream.fileno()
        for start, end in data_extents(fd, source_offset + length):
            start = max(start, source_offset)
            while start < end:
                block = os.pread(fd, min(4 * MIB, end - start), start)
                assert block, (source, start)
                written = os.pwrite(destination, block, destination_offset + start - source_offset)
                assert written == len(block)
                start += len(block)


def extract(disk: Path, first_lba: int, sectors: int, output: Path) -> Path:
    """Exact private copy of one partition's byte range, for host-side readers."""
    fd = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, sectors * SECTOR)
        copy_range(disk, first_lba * SECTOR, sectors * SECTOR, fd, 0)
    finally:
        os.close(fd)
    return output


def read_at(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    assert len(data) == length, (path, offset, length)
    return data


def all_zero(path: Path, start: int, end: int) -> bool:
    with path.open("rb") as stream:
        for extent_start, extent_end in data_extents(stream.fileno(), end):
            low, high = max(extent_start, start), min(extent_end, end)
            while low < high:
                block = os.pread(stream.fileno(), min(4 * MIB, high - low), low)
                if block.strip(b"\0"):
                    return False
                low += len(block)
    return True


def sparse_clone(source: Path, destination: Path) -> Path:
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", str(source), str(destination)], check=True, capture_output=True, timeout=300)
    destination.chmod(0o600)
    return destination


@dataclass(frozen=True)
class Fingerprint:
    device: int
    inode: int
    mode: int
    length: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


def fingerprint(path: Path) -> Fingerprint:
    """Complete source identity: an input is never modified, replaced or touched."""
    metadata = path.lstat()
    digest = overlay.digest(path) if stat.S_ISREG(metadata.st_mode) else ""
    after = path.lstat()
    assert (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns), path
    return Fingerprint(metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, digest)


# ---------------------------------------------------------------------------
# vfat ESP encoder


def fat16(*, sectors: int, hidden: int, files: dict[str, bytes]) -> bytes:
    """Minimal FAT16 volume with an 8.3 root directory; returns the used prefix."""
    bytes_per_sector, per_cluster, reserved, fats, root_entries = SECTOR, 2, 4, 2, 512
    root_sectors = root_entries * 32 // bytes_per_sector
    fat_sectors = 1
    while True:
        clusters = (sectors - reserved - fats * fat_sectors - root_sectors) // per_cluster
        needed = -(-(clusters + 2) * 2 // bytes_per_sector)
        if needed <= fat_sectors:
            break
        fat_sectors = needed
    assert 4085 <= clusters < 65525 and sectors < 65536, "fixture must be FAT16"
    boot = bytearray(bytes_per_sector)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"SILOSMKE"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, bytes_per_sector, per_cluster, reserved, fats, root_entries, sectors, 0xF8, fat_sectors, 32, 64, hidden, 0)
    struct.pack_into("<BBBI", boot, 36, 0x80, 0, 0x29, ESP_VOLUME_ID)
    boot[43:54] = ESP_LABEL.encode().ljust(11)
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"
    fat = bytearray(fat_sectors * bytes_per_sector)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    root = bytearray(root_sectors * bytes_per_sector)
    date = ((2026 - 1980) << 9) | (11 << 5) | 6
    root[0:11] = ESP_LABEL.encode().ljust(11)
    root[11] = 0x08
    struct.pack_into("<HH", root, 22, 0, date)
    cluster_bytes = per_cluster * bytes_per_sector
    data = bytearray()
    next_cluster = 2
    for index, (name, content) in enumerate(sorted(files.items()), 1):
        stem, _, extension = name.partition(".")
        assert stem.isupper() and len(stem) <= 8 and len(extension) <= 3, name
        count = -(-len(content) // cluster_bytes)
        first = next_cluster if count else 0
        for cluster in range(next_cluster, next_cluster + count):
            struct.pack_into("<H", fat, cluster * 2, cluster + 1 if cluster + 1 < next_cluster + count else 0xFFFF)
        next_cluster += count
        entry = index * 32
        root[entry:entry + 11] = stem.encode().ljust(8) + extension.encode().ljust(3)
        root[entry + 11] = 0x20
        struct.pack_into("<HHHHHHHI", root, entry + 14, 0, date, date, 0, 0, date, first, len(content))
        data += content.ljust(count * cluster_bytes, b"\0")
    assert next_cluster - 2 <= clusters
    head = bytes(boot) + bytes((reserved - 1) * bytes_per_sector) + bytes(fat) * fats + bytes(root)
    assert len(head) == (reserved + fats * fat_sectors + root_sectors) * bytes_per_sector
    return head + bytes(data)


def esp_volume(hidden: int) -> bytes:
    return fat16(sectors=ESP_SECTORS, hidden=hidden, files={ESP_FILE: ESP_CONTENT})


# ---------------------------------------------------------------------------
# Partition table encoders


@dataclass(frozen=True)
class Part:
    slot: int
    first_lba: int
    sectors: int
    kind: UUID | int
    guid: UUID | None = None
    name: str = ""
    attributes: int = 0
    content: Path | bytes | None = None

    @property
    def last_lba(self) -> int:
        return self.first_lba + self.sectors - 1


@dataclass(frozen=True)
class Disk:
    path: Path
    table: str
    sectors: int
    disk_guid: UUID | None
    parts: tuple[Part, ...]
    root_slot: int | None

    def part(self, slot: int) -> Part:
        return next(part for part in self.parts if part.slot == slot)

    @property
    def root(self) -> Part:
        assert self.root_slot is not None
        return self.part(self.root_slot)


def _protective_mbr(last_lba: int) -> bytes:
    mbr = bytearray(SECTOR)
    struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, min(last_lba, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def _place(fd: int, parts: tuple[Part, ...]) -> None:
    for part in parts:
        if isinstance(part.content, Path):
            length = part.content.stat().st_size
            assert length <= part.sectors * SECTOR, (part, length)
            copy_range(part.content, 0, length, fd, part.first_lba * SECTOR)
        elif isinstance(part.content, bytes):
            assert len(part.content) <= part.sectors * SECTOR
            assert os.pwrite(fd, part.content, part.first_lba * SECTOR) == len(part.content)


def write_gpt(path: Path, parts: list[Part], *, disk_guid: UUID, root_slot: int | None, sectors: int | None = None,
              entry_size: int = 128, corrupt_primary_array: bool = False) -> Disk:
    """GPT with protective MBR, 128 entries and both header/array copies."""
    entry_count = 128
    array_sectors = max(entry_count * entry_size, 16384) // SECTOR
    total = sectors or max(part.last_lba for part in parts) + 1 + TAIL_SECTORS
    last_lba = total - 1
    first_usable = 2 + array_sectors
    backup_array = last_lba - array_sectors
    last_usable = backup_array - 1
    array = bytearray(entry_count * entry_size)
    for part in parts:
        assert isinstance(part.kind, UUID) and part.guid is not None
        assert first_usable <= part.first_lba and part.last_lba <= last_usable, part
        offset = (part.slot - 1) * entry_size
        name = part.name.encode("utf-16-le")
        assert len(name) <= 72
        array[offset:offset + 128] = part.kind.bytes_le + part.guid.bytes_le + struct.pack("<QQQ", part.first_lba, part.last_lba, part.attributes) + name.ljust(72, b"\0")
    array_crc = zlib.crc32(array)

    def header(my_lba: int, alternate: int, array_lba: int) -> bytes:
        value = bytearray(SECTOR)
        struct.pack_into("<8sIIIIQQQQ16sQIII", value, 0, b"EFI PART", 0x00010000, 92, 0, 0, my_lba, alternate, first_usable, last_usable, disk_guid.bytes_le, array_lba, entry_count, entry_size, array_crc)
        struct.pack_into("<I", value, 16, zlib.crc32(value[:92]))
        return bytes(value)

    primary_array = bytearray(array)
    if corrupt_primary_array:
        primary_array[-1] ^= 0xFF
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, total * SECTOR)
        _place(fd, tuple(parts))
        for offset, data in [(0, _protective_mbr(last_lba)), (SECTOR, header(1, last_lba, 2)), (2 * SECTOR, bytes(primary_array)),
                             (backup_array * SECTOR, bytes(array)), (last_lba * SECTOR, header(last_lba, 1, backup_array))]:
            assert os.pwrite(fd, data, offset) == len(data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return Disk(path, "gpt", total, disk_guid, tuple(sorted(parts, key=lambda part: part.slot)), root_slot)


def write_mbr(path: Path, parts: list[Part], *, signature: int, root_slot: int | None) -> Disk:
    """Primary-only MBR; empty slots stay all-zero so the original numbering survives."""
    total = max(part.last_lba for part in parts) + 1 + TAIL_SECTORS
    mbr = bytearray(SECTOR)
    struct.pack_into("<I", mbr, 440, signature)
    for part in parts:
        assert isinstance(part.kind, int) and 1 <= part.slot <= 4
        struct.pack_into("<B3sB3sII", mbr, 446 + 16 * (part.slot - 1), 0, b"\xfe\xff\xff", part.kind, b"\xfe\xff\xff", part.first_lba, part.sectors)
    mbr[510:512] = b"\x55\xaa"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, total * SECTOR)
        _place(fd, tuple(parts))
        assert os.pwrite(fd, bytes(mbr), 0) == SECTOR
        os.fsync(fd)
    finally:
        os.close(fd)
    return Disk(path, "mbr", total, None, tuple(sorted(parts, key=lambda part: part.slot)), root_slot)


def sfdisk_layout(disk: Disk) -> dict:
    """util-linux reads the table back; the Silo parser is never the oracle."""
    result = subprocess.run(["sfdisk", "--json", str(disk.path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["partitiontable"]


def verify_table(disk: Disk) -> None:
    table = sfdisk_layout(disk)
    observed = {}
    for entry in table["partitions"]:
        slot = int(re.search(r"(\d+)$", entry["node"]).group(1))
        observed[slot] = entry
    assert set(observed) == {part.slot for part in disk.parts}, (observed, disk.parts)
    if disk.table == "gpt":
        assert table["label"] == "gpt" and UUID(table["id"]) == disk.disk_guid
        assert table["firstlba"] == 34 and table["lastlba"] == disk.sectors - 34
    else:
        assert table["label"] == "dos"
    for part in disk.parts:
        entry = observed[part.slot]
        assert (entry["start"], entry["size"]) == (part.first_lba, part.sectors), (entry, part)
        if disk.table == "gpt":
            assert UUID(entry["type"]) == part.kind and UUID(entry["uuid"]) == part.guid, (entry, part)
        else:
            assert int(entry["type"], 16) == part.kind, (entry, part)


def verify_esp(disk: Disk, slot: int, directory: Path) -> None:
    """blkid independently identifies the encoded vfat label and volume ID."""
    part = disk.part(slot)
    image = extract(disk.path, part.first_lba, part.sectors, directory / f"{disk.path.name}-esp-{uuid4().hex[:8]}.img")
    try:
        result = subprocess.run(["blkid", "-p", "-o", "export", str(image)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        assert values.get("TYPE") == "vfat" and values.get("LABEL") == ESP_LABEL, values
        assert values.get("UUID") == f"{ESP_VOLUME_ID >> 16:04X}-{ESP_VOLUME_ID & 0xFFFF:04X}", values
    finally:
        image.unlink()


def e2fsck_clean(image: Path) -> None:
    """Read-only full check; a dirty journal or inconsistent metadata fails."""
    result = subprocess.run(["e2fsck", "-fn", str(image)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def debugfs_cat(image: Path, path: str) -> bytes:
    result = subprocess.run(["debugfs", "-R", f"cat {path}", str(image)], capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout


def ext4_blocks(image: Path, offset: int = 0) -> int:
    superblock = read_at(image, offset + 1024, 1024)
    assert superblock[56:58] == b"\x53\xef"
    low, high = struct.unpack_from("<I", superblock, 4)[0], struct.unpack_from("<I", superblock, 0x150)[0]
    incompat_64bit = struct.unpack_from("<I", superblock, 96)[0] & 0x80
    return low | (high << 32 if incompat_64bit else 0)


# ---------------------------------------------------------------------------
# Standard cloud layouts


@dataclass(frozen=True)
class Guids:
    disk: UUID
    esp: UUID
    foreign: UUID
    root: UUID

    @staticmethod
    def fresh() -> Guids:
        return Guids(uuid4(), uuid4(), uuid4(), uuid4())


def root_sectors(ext4: Path) -> int:
    length = ext4.stat().st_size
    assert length % MIB == 0, "fixture root filesystem must be MiB aligned"
    return length // SECTOR


def cloud_gpt_parts(ext4: Path, guids: Guids, *, root_type: UUID | None = None, root_attributes: int = 0,
                    foreign_type: UUID | None = None) -> list[Part]:
    return [
        Part(1, ESP_FIRST, ESP_SECTORS, ESP_TYPE, guids.esp, "EFI System", content=esp_volume(ESP_FIRST)),
        Part(2, FOREIGN_FIRST, FOREIGN_SECTORS, foreign_type or DPS_ROOT[foreign_arch()], guids.foreign, "foreign-root"),
        Part(4, ROOT_FIRST, root_sectors(ext4), root_type or DPS_ROOT[host_arch()], guids.root, "root", root_attributes, ext4),
    ]


def cloud_gpt(path: Path, ext4: Path, guids: Guids, **options: Any) -> Disk:
    disk = write_gpt(path, cloud_gpt_parts(ext4, guids, **options), disk_guid=guids.disk, root_slot=4)
    verify_table(disk)
    return disk


def cloud_mbr(path: Path, ext4: Path) -> Disk:
    disk = write_mbr(path, [
        Part(1, ESP_FIRST, ESP_SECTORS, 0xEF, content=esp_volume(ESP_FIRST)),
        Part(4, ROOT_FIRST, root_sectors(ext4), 0x83, content=ext4),
    ], signature=0x5117_0017, root_slot=4)
    verify_table(disk)
    return disk


# ---------------------------------------------------------------------------
# qcow2 fixture encoder (bounded, independent of the decoder under test)


QCOW2_HEADER = ">4sIQIIQIIQQIIQ"
QCOW2_V3_TAIL = ">QQQII"


def qcow2(raw: Path, output: Path, *, version: int, cluster_bits: int) -> dict[str, int]:
    """Encode raw logical bytes as a self-contained qcow2 v2/v3 image.

    Holes stay unallocated, every third full nonzero cluster is raw-DEFLATE
    compressed (4 KiB window, as QEMU writes it), the rest are allocated, and
    v3 additionally carries explicit all-zero entries. Refcounts are exact.
    Returns the observed cluster-kind counts so a fixture can prove coverage.
    """
    assert version in (2, 3) and 9 <= cluster_bits <= 16
    size = raw.stat().st_size
    cluster = 1 << cluster_bits
    count = -(-size // cluster)
    l2_entries = cluster // 8
    l1_size = -(-count // l2_entries)
    payload: dict[int, tuple[str, bytes | None]] = {}
    kinds = {"allocated": 0, "compressed": 0, "zero": 0, "unallocated": 0}
    with raw.open("rb") as stream:
        fd = stream.fileno()
        indices = sorted({index for start, end in data_extents(fd, size) for index in range(start // cluster, (end - 1) // cluster + 1)})
        for ordinal, index in enumerate(indices):
            block = os.pread(fd, cluster, index * cluster)
            full = len(block) == cluster
            if not block.strip(b"\0"):
                if version == 3:
                    payload[index] = ("zero", None)
                continue
            if full and ordinal % 3 == 1:
                compressor = zlib.compressobj(9, zlib.DEFLATED, -12)
                compressed = compressor.compress(block) + compressor.flush()
                if len(compressed) <= cluster - SECTOR:
                    payload[index] = ("compressed", compressed)
                    continue
            payload[index] = ("allocated", block.ljust(cluster, b"\0"))
    if version == 3:
        # Explicit zero entries over true holes, independent of extent layout.
        holes = (index for index in range(count) if index not in payload)
        for _, index in zip(range(64), holes):
            payload[index] = ("zero", None)
    for kind, _ in payload.values():
        kinds[kind] += 1
    kinds["unallocated"] = count - len(payload)

    next_cluster = 1
    l1_offset = next_cluster * cluster
    next_cluster += -(-l1_size * 8 // cluster)
    l2_offsets = {}
    for table in sorted({index // l2_entries for index in payload}):
        l2_offsets[table] = next_cluster * cluster
        next_cluster += 1
    data_offsets = {}
    for index, (kind, _) in sorted(payload.items()):
        if kind == "allocated":
            data_offsets[index] = next_cluster * cluster
            next_cluster += 1
    cursor = next_cluster * cluster
    compressed_offsets = {}
    host_ranges = []
    for index, (kind, data) in sorted(payload.items()):
        if kind == "compressed":
            assert data is not None
            compressed_offsets[index] = cursor
            end = ((cursor + len(data) - 1) // SECTOR + 1) * SECTOR
            host_ranges.append((cursor, end))
            cursor += len(data)
    # Sector-rounded compressed reads may reach into the next host cluster.
    base = -(-max([cursor, *(end for _, end in host_ranges)]) // cluster)
    per_block = cluster * 8 // 16
    table_clusters, blocks = 1, 1
    while True:
        needed_blocks = -(-(base + table_clusters + blocks) // per_block)
        needed_table = -(-needed_blocks * 8 // cluster)
        if (needed_blocks, needed_table) == (blocks, table_clusters):
            break
        blocks, table_clusters = needed_blocks, needed_table
    table_offset = base * cluster
    block_offset = (base + table_clusters) * cluster
    total = base + table_clusters + blocks
    refcounts = [0] * total
    for index in range(next_cluster):
        refcounts[index] = 1
    for start, end in host_ranges:
        for host in range(start // cluster, (end - 1) // cluster + 1):
            refcounts[host] += 1
    for index in range(base, total):
        refcounts[index] = 1

    image = bytearray()
    header = struct.pack(QCOW2_HEADER, b"QFI\xfb", version, 0, 0, cluster_bits, size, 0, l1_size, l1_offset, table_offset, table_clusters, 0, 0)
    if version == 3:
        header += struct.pack(QCOW2_V3_TAIL, 0, 0, 0, 4, 104)
    shift = 62 - (cluster_bits - 8)
    fd = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, total * cluster)
        # Header extensions end immediately: the zero bytes after the header.
        os.pwrite(fd, header, 0)
        l1 = bytearray(l1_size * 8)
        for table, offset in l2_offsets.items():
            struct.pack_into(">Q", l1, table * 8, offset | (1 << 63))
        os.pwrite(fd, bytes(l1), l1_offset)
        tables = {table: bytearray(cluster) for table in l2_offsets}
        for index, (kind, data) in payload.items():
            table, slot = divmod(index, l2_entries)
            if kind == "allocated":
                entry = data_offsets[index] | (1 << 63)
                assert data is not None
                os.pwrite(fd, data, data_offsets[index])
            elif kind == "compressed":
                assert data is not None
                offset = compressed_offsets[index]
                additional = (offset + len(data) - 1) // SECTOR - offset // SECTOR
                assert offset < 1 << shift and additional < 1 << (62 - shift)
                entry = (1 << 62) | (additional << shift) | offset
                os.pwrite(fd, data, offset)
            else:
                entry = 1
            struct.pack_into(">Q", tables[table], slot * 8, entry)
        for table, value in tables.items():
            os.pwrite(fd, bytes(value), l2_offsets[table])
        refcount_table = bytearray(table_clusters * cluster)
        for block in range(blocks):
            struct.pack_into(">Q", refcount_table, block * 8, block_offset + block * cluster)
        os.pwrite(fd, bytes(refcount_table), table_offset)
        refcount_blocks = bytearray(blocks * cluster)
        for index, value in enumerate(refcounts):
            struct.pack_into(">H", refcount_blocks, index * 2, value)
        os.pwrite(fd, bytes(refcount_blocks), block_offset)
        os.fsync(fd)
    finally:
        os.close(fd)
    return kinds


QCOW2_FORBIDDEN = ("encrypted", "backing-file", "external-data-file", "zstd", "unknown-incompatible")


def qcow2_forbidden(base_raw: Path, output: Path, feature: str) -> Path:
    """A valid encoding with exactly one forbidden header feature patched in."""
    version = 2 if feature == "encrypted" else 3
    qcow2(base_raw, output, version=version, cluster_bits=16)
    with output.open("r+b") as stream:
        def put(offset: int, form: str, value: int) -> None:
            stream.seek(offset)
            stream.write(struct.pack(form, value))
        if feature == "encrypted":
            put(32, ">I", 1)
        elif feature == "backing-file":
            name = b"phase17-missing-base.qcow2"
            stream.seek(4096)
            stream.write(name)
            put(8, ">Q", 4096)
            put(16, ">I", len(name))
        elif feature == "external-data-file":
            name = b"phase17-external.raw"
            put(72, ">Q", 1 << 2)
            stream.seek(104)
            stream.write(struct.pack(">II", 0x44415441, len(name)) + name.ljust(-(-len(name) // 8) * 8, b"\0") + bytes(8))
        elif feature == "zstd":
            put(72, ">Q", 1 << 3)
            put(100, ">I", 112)
            put(104, ">B", 1)
        elif feature == "unknown-incompatible":
            put(72, ">Q", 1 << 10)
        else:
            raise ValueError(feature)
    return output


FOREIGN_CONTAINERS = {
    "vmdk": (0, b"KDMV\x01\x00\x00\x00"),
    "vhdx": (0, b"vhdxfile"),
    "qed": (0, b"QED\x00"),
    "luks": (0, b"LUKS\xba\xbe\x00\x02"),
    "gzip": (0, b"\x1f\x8b\x08\x00"),
}


def foreign_container(output: Path, kind: str) -> Path:
    offset, magic = FOREIGN_CONTAINERS[kind]
    with output.open("xb") as stream:
        stream.truncate(MIB)
        stream.seek(offset)
        stream.write(magic)
    output.chmod(0o600)
    return output


def qemu_img_cross_check(raw: Path, encoded: Path, record) -> None:
    """Optional third-party oracle. Absent configuration is recorded, never passed."""
    tool = os.environ.get("SILO_SMOKE_QEMU_IMG")
    if not tool:
        record("SILO_SMOKE_QEMU_IMG unset: qemu-img cross-check not exercised\n")
        return
    for args in (["check", "-f", "qcow2", str(encoded)], ["compare", "-f", "raw", "-F", "qcow2", str(raw), str(encoded)]):
        result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=300)
        record(f"$ qemu-img {' '.join(args)}\nexit={result.returncode}\n{result.stdout}{result.stderr}\n")
        assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# CLI drivers and publication oracles


def import_disk(silo: Silo, path: Path, *, root: str, name: str | None = None, platform_spelling: str | None = None) -> dict:
    result = silo.run("image", "import", str(path), "--platform", platform_spelling or host_platform(), "--root", root,
                      "--boot", "linux-direct", *(["--name", name] if name else []), timeout=600, label="image-import")
    return json.loads(result.stdout)


def inspect(silo: Silo, reference: str) -> dict:
    return json.loads(silo.run("image", "inspect", reference, label="image-inspect").stdout)


PUBLISHED_TABLES = (
    "machine_config", "machine_state", "machine_storage", "machine_rootfs", "storage_image", "image_alias",
    "image_provenance", "image_stream_dependency", "image_object_dependency", "raw_conversion_result",
    "storage_snapshot",
)


def _published(silo: Silo) -> dict:
    catalog = stopped.catalog(silo)
    return {table: catalog[table] for table in PUBLISHED_TABLES}


def _operations(silo: Silo) -> dict[str, tuple[str, str]]:
    return {row[0]: (row[1], row[2]) for row in procs.query(silo.ws.state_db(), "SELECT operation_id, kind, state FROM storage_operation")}


def refuse_before_publication(silo: Silo, *args: str, sources: tuple[Path, ...] = (), timeout: float = 600) -> Result:
    """Refused import/create: no image, alias, provenance, snapshot or machine.

    Imports register their operation before reading protected bytes, so an
    abandoned operation (never committed) and its pool staging may remain for
    existing recovery. Catalog publication and every machine directory may not.
    """
    assert silo.ws.state_db().is_file(), "initialize the Home before a refusal oracle"
    before = (_published(silo), stopped.inventory(silo.ws.silo_home / "machines"), _operations(silo))
    inputs = [fingerprint(path) for path in sources]
    result = silo.run(*args, expect=None, timeout=timeout)
    after = (_published(silo), stopped.inventory(silo.ws.silo_home / "machines"), _operations(silo))
    silo.ws.record("phase17-refusal", json.dumps({"args": args, "exit": result.returncode, "stderr": result.stderr[-4000:],
                                                   "newOperations": {key: value for key, value in after[2].items() if key not in before[2]}}, sort_keys=True) + "\n")
    assert result.returncode != 0, (args, result.stdout, result.stderr)
    assert after[0] == before[0], ("catalog publication changed", args)
    assert after[1] == before[1], ("machine directories changed", args)
    for operation, (kind, state) in after[2].items():
        if operation not in before[2]:
            assert state != "committed", (operation, kind, state)
    assert [fingerprint(path) for path in sources] == inputs, "refused input was modified"
    return result


class EarlyRefusals:
    """Serialized early rejections with no intervening fixture or guest writes.

    Prepare every input before constructing this batch. Each request gets a
    fresh full catalog/Home/run-root inventory and full source fingerprints.
    Only a successfully verified after-state can become the next before-state;
    never retain a batch across a successful operation or other writer.
    Evidence logs are outside all three inventoried roots.
    """

    def __init__(self, silo: Silo) -> None:
        assert silo.ws.state_db().is_file(), "initialize the Home before a refusal oracle"
        self.silo = silo
        self.before = self._state()
        self.inputs: dict[Path, Fingerprint] = {}

    def _state(self) -> tuple:
        return (stopped.catalog(self.silo), stopped.inventory(self.silo.ws.silo_home), stopped.inventory(self.silo.ws.run_root))

    def refuse(self, *args: str, sources: tuple[Path, ...] = ()) -> Result:
        for path in sources:
            if path not in self.inputs:
                self.inputs[path] = fingerprint(path)
        inputs = [self.inputs[path] for path in sources]
        result = self.silo.run(*args, expect=None, timeout=60)
        after = self._state()
        after_inputs = [fingerprint(path) for path in sources]
        self.silo.ws.record("phase17-early-refusal", json.dumps({"args": args, "exit": result.returncode, "stderr": result.stderr[-4000:]}, sort_keys=True) + "\n")
        assert result.returncode != 0, (args, result.stdout, result.stderr)
        assert after == self.before, ("refusal had catalog or file effects", args)
        assert after_inputs == inputs, "refused input was modified"
        self.before = after
        self.inputs.update(zip(sources, after_inputs))
        return result


def refuse_without_effects(silo: Silo, *args: str, sources: tuple[Path, ...] = ()) -> Result:
    """Single early refusal; use EarlyRefusals only for a no-writer batch."""
    return EarlyRefusals(silo).refuse(*args, sources=sources)


def bundle_digest(binding: dict) -> str:
    """Independent canonical bytes of the complete pinned tuple (sorted, compact JSON)."""
    assert binding["kind"] == "pinned" and set(binding) == {"kind", "kernel", "baseInitramfs", "agent", "architecture", "abi"}
    return _digest(json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def packaged_binding(assets: Path) -> dict:
    return {"kind": "pinned", "kernel": "sha256:" + overlay.digest(assets / "kernel-default"),
            "baseInitramfs": "sha256:" + overlay.digest(assets / "initramfs"),
            "agent": "sha256:" + overlay.digest(assets / "agent"), "architecture": host_arch(), "abi": "silo-direct-v2"}


def assert_pool_objects(silo: Silo, binding: dict) -> None:
    """Every pinned member is retained as exact bytes in the pool, plus the bundle object."""
    objects = silo.ws.silo_home / "images/objects/sha256"
    for role in ("kernel", "baseInitramfs", "agent"):
        digest = binding[role]
        assert overlay.digest(objects / digest.removeprefix("sha256:")) == digest.removeprefix("sha256:"), role
    bundle = bundle_digest(binding)
    assert overlay.digest(objects / bundle.removeprefix("sha256:")) == bundle.removeprefix("sha256:")


def valid_replacement_assets(assets: Path, saved: Path) -> None:
    """Different but bootable packaged bytes: an extra trailing cpio member and an agent trailer."""
    initramfs = (saved / "initramfs").read_bytes()
    initramfs += b"\0" * (-len(initramfs) % 4) + cpio([("phase17-replacement", b"bundle-update\n", 0o100644)])
    for name, data, mode in (("initramfs", initramfs, 0o644), ("agent", (saved / "agent").read_bytes() + b"\0phase17-agent-trailer\0", 0o755),
                             ("kernel-default", (saved / "kernel-default").read_bytes(), 0o644)):
        target = assets / name
        target.unlink()
        target.write_bytes(data)
        target.chmod(mode)


def break_assets(assets: Path) -> None:
    for name, mode in (("kernel-default", 0o644), ("initramfs", 0o644), ("agent", 0o755)):
        target = assets / name
        target.unlink()
        target.write_bytes(b"not-the-pinned-boot-bytes\n")
        target.chmod(mode)


def guest_agent_sha256(silo: Silo, name: str) -> str:
    """PID 1 is the injected agent for BASIC-derived roots: hash its executing bytes."""
    output = silo.exec(name, "sha256sum", "/proc/1/exe", user="root").stdout.split()
    assert len(output) == 2, output
    return "sha256:" + output[0]


def probe_record(text: str) -> dict:
    lines = [line.strip("\r") for line in text.splitlines() if line.strip("\r").startswith(PROBE_MARK)]
    assert len(lines) == 1, text[-4000:]
    return json.loads(lines[0].removeprefix(PROBE_MARK))


def guest_probe(silo: Silo, name: str) -> dict:
    record = probe_record(silo.exec(name, PROBE, "report", user="root").stdout)
    silo.ws.record("phase17-guest-probe", json.dumps({"machine": name, "probe": record}, sort_keys=True) + "\n")
    return record


def assert_root(record: dict, *, identity: str = "root", partition: Part | None, parent_sectors: int | None = None) -> None:
    """The mounted root is exactly the selected child of the `silo-root` attachment."""
    assert record["identity"] == identity, record
    assert record["parentSerial"] == "silo-root", record
    assert record["filesystem"] == "ext4", record
    if partition is None:
        assert record["partition"] == 0 and record["name"] == record["parent"], record
    else:
        assert record["name"] != record["parent"], record
        assert (record["partition"], record["start"], record["sectors"]) == (partition.slot, partition.first_lba, partition.sectors), record
    if parent_sectors is not None:
        assert record["parentSectors"] == parent_sectors, record


def boot(silo: Silo, name: str) -> dict:
    silo.start(name)
    return silo.wait_ready(name, timeout=120)


def durable_marker(silo: Silo, name: str, path: str, content: str) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'printf "%s" "$2" >"$1"; sync', "phase17-marker", path, content, user="root")


def stop_not_clean(silo: Silo, name: str) -> str:
    """Orderly stop request whose storage evidence must not be certified clean."""
    result = silo.run("stop", name, "--timeout", "45s", expect=None, timeout=120)
    silo.ws.record("phase17-nonclean-stop", json.dumps({"exit": result.returncode, "stderr": result.stderr[-4000:]}) + "\n")
    if silo.info(name)["state"] != "stopped":
        silo.stop(name, timeout="20s", force=True)
    outcome = shutdown.outcome(silo, name)
    assert outcome in {"forced", "unknown"}, outcome
    assert silo.info(name)["storage_stop_outcome"] != "clean"
    return outcome


def root_disk(silo: Silo, name: str) -> Path:
    return stopped.writable_paths(silo, name)["root"]


# ---------------------------------------------------------------------------
# Controlled agentless candidate launch through the shipped monitor


class RawCandidate:
    """Disposable launch files for the staged monitor, kernel and base initramfs.

    It never inserts catalog, capability or qualification state and is not
    product acceptance: it exercises guest init against attachment orders the
    product never produces (root first is libvm's fixed order), which is how
    shuffled order and an identical GPT on a lower-numbered disk are proven.
    """

    def __init__(self, silo: Silo, *, disks: list[dict], bootstrap: dict) -> None:
        self.silo = silo
        self.root = silo.ws.root / ("raw-candidate-" + uuid4().hex[:8])
        self.root.mkdir(mode=0o700)
        self.serial = self.root / "serial.log"
        self.trace = self.root / "trace.log"
        self.process: subprocess.Popen | None = None
        self.lease_fd: int | None = None
        runtime = silo.ws.config.runtime_dir
        self.monitor = self.root / "silo-vmm"
        shutil.copyfile(runtime / "bin/silo-vmm", self.monitor)
        self.monitor.chmod(0o700)
        kernel = self.root / "kernel"
        shutil.copyfile(runtime / "assets/kernel-default", kernel)
        base = (runtime / "assets/initramfs").read_bytes()
        payload = json.dumps(bootstrap, separators=(",", ":")).encode()
        composite = self.root / "initramfs"
        composite.write_bytes(base + b"\0" * (-len(base) % 4) + cpio([("silo", b"", 0o040700), ("silo/rootfs.json", payload, 0o100600)]))
        composite.chmod(0o600)
        self.identities = {"kernelSha256": overlay.digest(kernel), "baseInitramfsSha256": hashlib.sha256(base).hexdigest(),
                           "monitorSha256": overlay.digest(self.monitor), "bootstrap": bootstrap,
                           "disks": [{key: disk[key] for key in ("role", "blockId", "geometry")} | {"sha256": overlay.digest(Path(disk["path"]))} for disk in disks],
                           "candidateOnly": True, "agentInjected": False}
        self.spec = {"specVersion": "0.2.0",
                     "boot": {"kernel": {"path": str(kernel), "initramfs": str(composite), "cmdline": ["loglevel=6", f"init={PROBE}"]}},
                     "hardware": {"cpus": 1, "memory": 512, "rosetta": False, "nestedVirtualization": False},
                     "storage": {"disks": disks}}
        self.config = self.root / "spec.json"
        self.config.write_text(json.dumps(self.spec))
        silo.ws.record("phase17-candidate-inputs", json.dumps(self.identities, sort_keys=True) + "\n")

    def __enter__(self) -> RawCandidate:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def start(self) -> None:
        machine_id, run_id, operation_id = str(uuid4()), str(uuid4()), str(uuid4())
        self.lease_fd = os.open(self.root / (operation_id + ".lease"), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.lease_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        metadata = os.fstat(self.lease_fd)
        context = {"version": 1, "machineId": machine_id, "runId": run_id, "manifest": {"kind": "complete", "attachments": [
            {"kind": "block", **{key: disk[key] for key in ("blockId", "role", "format", "geometry", "readOnly")}, "exclusiveWriter": True}
            for disk in self.spec["storage"]["disks"]]}}
        request = {"version": 1, "machineId": machine_id, "machineRunId": run_id, "startupCommand": None,
                   "storageLease": {"operationId": operation_id, "fileDevice": metadata.st_dev, "fileInode": metadata.st_ino},
                   "storageShutdown": context}
        reader, writer = os.pipe()
        environment = self.silo.ws.env()
        environment.update(_VM_STARTPIPE=str(reader), _VM_STORAGE_LEASES=json.dumps([self.lease_fd]))
        args = [str(self.monitor), "--foreground", "--id", machine_id, "--run-id", run_id, "--name", "phase17-candidate"]
        for flag, path in [("--data-dir", self.root), ("--runtime-dir", self.root), ("--config", self.config), ("--socket", self.root / "vm.sock"),
                           ("--pidfile", self.root / "vm.pid"), ("--exit-status", self.root / "vm.exit.json"),
                           ("--serial-log", self.serial), ("--trace-log", self.trace)]:
            args.extend([flag, str(path)])
        try:
            with (self.root / "monitor-output.log").open("ab") as sink:
                self.process = subprocess.Popen(args, env=environment, pass_fds=(reader, self.lease_fd), stdin=subprocess.DEVNULL, stdout=sink, stderr=sink, start_new_session=True)
            os.close(reader)
            reader = -1
            with os.fdopen(writer, "wb") as stream:
                writer = -1
                stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        finally:
            if reader >= 0:
                os.close(reader)
            if writer >= 0:
                os.close(writer)

    def wait(self, *, rejected: bool = False, timeout: float = 90) -> str:
        deadline = time.monotonic() + timeout
        while True:
            text = bounded_log(self.serial) if self.serial.exists() else ""
            if rejected:
                assert PROBE_MARK not in text, "image code ran after a bootstrap contract failure"
                assert "starting rescue shell" not in text
                if CANDIDATE_REJECTED in text:
                    return text
            elif PROBE_MARK in text and "\n" in text.split(PROBE_MARK, 1)[1]:
                assert "init: raw: verified bootstrap-selected root" in text
                return text
            if self.process is None or self.process.poll() is not None:
                if not rejected and PROBE_MARK in text:
                    return text
                raise AssertionError(f"candidate monitor exited before guest evidence; serial={text[-4000:]}")
            if time.monotonic() >= deadline:
                raise AssertionError(f"candidate produced no {'refusal' if rejected else 'probe'} evidence: {text[-4000:]}")
            time.sleep(0.05)

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=10)
        for label, path in [("phase17-candidate-serial", self.serial), ("phase17-candidate-trace", self.trace), ("phase17-candidate-monitor", self.root / "monitor-output.log")]:
            if path.exists():
                self.silo.ws.record(label, bounded_log(path))
        if self.lease_fd is not None:
            os.close(self.lease_fd)
            self.lease_fd = None


def candidate_disk(path: Path, *, role: str, block_id: str) -> dict:
    return {"path": str(path), "role": role, "format": "raw", "geometry": {"length": path.stat().st_size, "logicalSectorSize": SECTOR},
            "blockId": block_id, "readOnly": False}


def raw_bootstrap(length: int, selector: dict) -> dict:
    """Schema-2 bootstrap from rootfs-spec's own fixture, not a second codec."""
    value = json.loads((REPO / "specs/rootfs-spec/fixtures/raw-gpt.json").read_text())
    value["rosetta"] = "disabled"
    value["root"]["device"]["lengthBytes"] = length
    value["root"]["selector"] = selector
    return value
