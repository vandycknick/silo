"""Real multiple-managed-disk capture witnesses and child-only trace driver.

Only fresh never-run fixture configuration is installed directly. Capture state,
copy results and checkpoint evidence are always produced by the real CLI/monitor.
Sealed ext4 readers never mount, fsck, or replay a captured journal.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import select
import shlex
import struct
import subprocess
import sys
from uuid import UUID, uuid4

from . import capture, overlay, procs, shutdown, stopped
from .cli import Silo
from .config import REPO

PROBE = "/usr/local/bin/capture-multidisk"
MOUNTS = ("/capture-a", "/capture-b")


def compile_probe(output: Path) -> Path:
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2",
               "-Wall", "-Wextra", "-Werror", "-std=c11",
               str(REPO / "virt/vmm/tests/guest/capture_multidisk.c"), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return output


def install_disks(silo: Silo, name: str) -> list[str]:
    """Use the stopped fixture's lifecycle-lock/current-schema construction pattern."""
    config = stopped.configuration(silo, name)
    lock = silo.ws.run_root / "locks" / str(config["lockId"])
    fd = os.open(lock, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = procs.machine_state_json(silo.ws, name)
        assert state["status"] == "stopped" and state.get("runId") is None
        assert state["vmmonPid"] is None
        machine_id = config["id"]
        assert not procs.query(silo.ws.state_db(),
                              f"SELECT operation_id FROM storage_operation WHERE machine_id='{machine_id}'")
        storage = stopped.record(silo, name)
        assert storage["disks"] == []
        directory = overlay.machine_dir(silo, name) / "disks"
        directory.mkdir(mode=0o700)
        roles = []
        for number in range(2):
            path = directory / f"data-{number}.raw"
            with path.open("xb") as output:
                output.truncate(32 * 1024**2)
            path.chmod(0o600)
            result = subprocess.run(["mkfs.ext4", "-F", "-q", "-E", "lazy_itable_init=0,lazy_journal_init=0",
                                     "-L", f"capture-{number}", str(path)],
                                    check=True, capture_output=True, text=True, timeout=60)
            silo.ws.record("capture-multidisk-mkfs", result.stdout + result.stderr)
            geometry = {"length": path.stat().st_size, "logicalSectorSize": 512}
            order = len(config["spec"]["storage"]["disks"])
            storage["disks"].append({"id": str(uuid4()), "role": "data", "order": order,
                                     "storage": {"kind": "managed-writable", "path": f"disks/{path.name}",
                                                 "geometry": geometry}})
            config["spec"]["storage"]["disks"].append({
                "path": str(path), "role": "data", "format": "raw", "geometry": geometry,
                "blockId": f"silo-data-{number}", "readOnly": False,
            })
            roles.append(f"silo-data-{order}")
        def literal(value: dict) -> str:
            return "'" + json.dumps(value).replace("'", "''") + "'"
        statement = (f"BEGIN IMMEDIATE; UPDATE machine_config SET config_json=jsonb({literal(config)}) "
                     f"WHERE id='{machine_id}'; UPDATE machine_storage SET record_json=jsonb({literal(storage)}) "
                     f"WHERE machine_id='{machine_id}'; COMMIT;")
        result = subprocess.run(["sqlite3", str(silo.ws.state_db()), statement],
                                check=True, capture_output=True, text=True, timeout=15)
        silo.ws.record("capture-multidisk-fixture", result.stdout + result.stderr)
        assert stopped.configuration(silo, name) == config
        assert stopped.record(silo, name) == storage
        return roles
    finally:
        os.close(fd)


def mount_sources(silo: Silo, name: str) -> None:
    # Mount only the original running source devices, never any sealed copy.
    for number, mount in enumerate(MOUNTS):
        result = silo.exec(name, "sh", "-eu", "-c", '''
found=
for p in /sys/block/*; do
    if test "$(cat "$p/serial" 2>/dev/null || true)" = "$1"; then
        test -z "$found"
        found=/dev/${p##*/}
    fi
done
test -n "$found"
mkdir "$2"
mount -t ext4 -o rw "$found" "$2"
cat /proc/self/mountinfo
''', "capture-mount", f"silo-data-{number}", mount, user="root")
        silo.ws.record("capture-multidisk-source-mount", result.stdout)


class Workload(capture.Counter):
    """Reuse progress/pause/session ownership checks with a multi-page identity."""

    def __init__(self, silo: Silo, name: str) -> None:
        self.silo = silo
        self.process = silo.popen("exec", name, "--user", "root", "--", PROBE, *MOUNTS)
        assert self.process.stdout is not None
        self.fd = self.process.stdout.fileno()
        self.pending = b""
        self.address: int | None = None
        self.page_size: int | None = None
        self.cache_addresses: list[int] = []
        self.values: list[int] = []

    def receive(self, timeout: float) -> bool:
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        data = os.read(self.fd, 65536)
        assert data, f"multidisk workload ended, CLI exit={self.process.poll()}"
        self.pending += data
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if self.address is None:
                identity = json.loads(line)
                self.address = identity["guestPhysicalAddress"]
                self.page_size = identity["pageSize"]
                self.cache_addresses = identity["cacheGuestPhysicalAddresses"]
                assert len(set([self.address, *self.cache_addresses])) == 3
                assert all(address > 0 and address % self.page_size == 0
                           for address in [self.address, *self.cache_addresses])
                self.silo.ws.record("capture-multidisk-address", json.dumps(identity) + "\n")
            else:
                assert line.startswith(b"COMMITTED="), line
                value = int(line.removeprefix(b"COMMITTED="))
                assert value == (self.values[-1] + 1 if self.values else 1)
                self.values.append(value)
        return True


def ram_at(directory: Path, address: int, length: int) -> bytes:
    layout_path = directory / "memory-layout.json"
    assert layout_path.stat().st_size <= 4 * 1024**2
    layout = json.loads(layout_path.read_bytes())
    regions = [region for region in layout["regions"]
               if region["guestPhysicalAddress"] <= address
               and address + length <= region["guestPhysicalAddress"] + region["length"]]
    assert len(regions) == 1, "pinned GPA must resolve uniquely in sealed RAM"
    region = regions[0]
    offset = region["streamOffset"] + address - region["guestPhysicalAddress"]
    fd = os.open(directory / "memory.ram", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        result = os.pread(fd, length, offset)
    finally:
        os.close(fd)
    assert len(result) == length
    return result


def disk_page(silo: Silo, path: Path, file: str) -> bytes:
    result = subprocess.run(["debugfs", "-R", f"cat /{file}", str(path)],
                            check=True, capture_output=True, timeout=30)
    silo.ws.record("capture-multidisk-debugfs", result.stderr.decode(errors="replace"))
    assert len(result.stdout) == 4096, (path, file, len(result.stdout))
    return result.stdout


def matched_cut(silo: Silo, directory: Path, roles: list[str], workload: Workload) -> None:
    assert workload.address is not None
    words = struct.unpack("<7Q", ram_at(directory, workload.address, 56))
    assert words[0] == 0x53494C4F4D554C31
    observations = []
    dirty_cache = False
    for index, role in enumerate(roles):
        committed, pending, writing = words[1 + index * 3:4 + index * 3]
        assert writing in (0, 1) and pending in (committed, committed + 1)
        assert committed >= workload.values[0]
        disk = directory / "disks" / f"{role}.raw"
        page = disk_page(silo, disk, "numbered")
        numbered = struct.unpack("<512Q", page)
        assert len(set(numbered)) == 1, "torn numbered block"
        assert numbered[0] in ({committed, pending} if writing else {committed})
        cache_ram = struct.unpack("<Q", ram_at(directory, workload.cache_addresses[index], 8))[0]
        cache_disk = struct.unpack("<Q", disk_page(silo, disk, "cached")[:8])[0]
        assert cache_ram in (committed, max(0, committed - 1))
        assert cache_disk <= cache_ram, "newer disk cache with older memory"
        dirty_cache |= cache_disk < cache_ram
        filesystem = overlay.ext4(disk)
        assert filesystem["compat"] & 4, "fixture must have an ext4 journal"
        assert filesystem["incompat"] & 4, "sealed mounted ext4 must still require recovery"
        observations.append({"role": role, "committed": committed, "pending": pending,
                             "writing": writing, "numberedDisk": numbered[0],
                             "cachedRam": cache_ram, "cachedDisk": cache_disk,
                             "filesystem": filesystem})
    assert words[1] in (words[4], words[4] + 1), "two-disk sequential writer cut is impossible"
    silo.ws.record("capture-multidisk-matched-cut", json.dumps({
        "disks": observations, "unsyncedCacheObserved": dirty_cache,
        "sealedDisksMounted": False, "journalReplayPerformed": False,
    }, sort_keys=True) + "\n")
    assert dirty_cache, "gate did not observe dirty unsynced cache at this cut"


class Trace:
    def __init__(self, silo: Silo, controller: subprocess.Popen[bytes]) -> None:
        self.silo = silo
        self.controller = controller

    def record(self, filename: str) -> dict | None:
        path = self.silo.ws.evidence / filename
        if path.exists():
            return json.loads(path.read_text())
        manager = self.silo.ws.evidence / "capture-manager-result.json"
        if filename == "boundary-held.json" and manager.exists():
            result = json.loads(manager.read_text())
            assert result["code"] == 0, (
                "capture failed before the requested boundary",
                (self.silo.ws.evidence / "capture-manager.stderr").read_text())
        assert self.controller.poll() is None, f"capture tracer ended before {filename}"
        return None

    def wait(self, filename: str, timeout: float = 90) -> dict:
        return shutdown.until(lambda: self.record(filename), timeout=timeout,
                              description=f"capture trace did not produce {filename}")

    def command(self, command: str) -> None:
        assert self.controller.stdin is not None
        self.controller.stdin.write((command + "\n").encode())
        self.controller.stdin.flush()

    def release(self) -> None:
        (self.silo.ws.evidence / "boundary-release").touch(exist_ok=True)


def copy_evidence(silo: Silo, directory: Path, plan: dict, *, completed: list[str]) -> None:
    """Separate logical sealed lengths from observed syscall transfer bytes."""
    observations = json.loads((silo.ws.evidence / "capture-copy.json").read_text())
    trace = silo.ws.silo_home / "logs/machines" / UUID(plan["machineId"]).hex / "vm.trace.log"
    method_lines = [line for line in trace.read_text().splitlines()
                    if "sealed writable disk role" in line]
    report = []
    for disk in plan["disks"]:
        path = directory / "disks" / f"{disk['name']}.raw"
        calls = [item for item in observations if item["path"] == str(path)]
        lines = [line for line in method_lines if f"disks/{disk['name']}.raw" in line]
        if disk["name"] in completed:
            assert len(lines) == 1, (disk, method_lines)
            assert "Clone" in lines[0] or "SparseCopy" in lines[0], lines
            assert sum(item["successfulCalls"] for item in calls) > 0, calls
        report.append({
            "role": disk["name"], "plannedCopy": disk["copy"],
            "logicalBytes": disk["length"], "methodLog": lines,
            "syscalls": calls,
            "observedWriteReturnedBytes": sum(item["returnedBytes"] for item in calls
                                               if item["ioctl"] is None),
            "clonePhysicalTransferBytes": None,
        })
    silo.ws.record("capture-multidisk-copy", json.dumps({
        "disks": report, "physicalTransferCaveat": "FICLONE return zero is not a physical-byte measurement",
        "productionQualified": False,
    }, sort_keys=True) + "\n")


@contextmanager
def traced_capture(silo: Silo, name: str, target: Path, boundary: str, *,
                   preserve: bool, disk_name: str | None = None,
                   injected_errno: int | None = None):
    evidence = silo.ws.evidence
    driver = evidence / "capture-process-request.json"
    driver.write_text(json.dumps({"silo": str(silo.ws.config.silo), "name": name,
                                 "evidence": str(evidence), "preserve": preserve}) + "\n")
    request = {"command": [sys.executable, "-m", "silo_smoke.capture_process", str(driver)],
               "target": str(target), "boundary": boundary,
               "machines": str(silo.ws.silo_home / "machines"), "evidence": str(evidence),
               "release": str(evidence / "boundary-release"), "observeCaptureCopies": True}
    if disk_name is not None:
        request["captureDiskName"] = disk_name
    if injected_errno is not None:
        request["errno"] = injected_errno
    request_path = evidence / "boundary-request.json"
    request_path.write_text(json.dumps(request) + "\n")
    with (evidence / "boundary-controller.log").open("wb") as output:
        controller = subprocess.Popen(
            [sys.executable, "-m", "silo_smoke.stopped_trace", str(request_path)],
            env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")), stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.STDOUT,
        )
        trace = Trace(silo, controller)
        try:
            yield trace
        finally:
            trace.release()
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
            assert controller.stdin is not None
            controller.stdin.close()
