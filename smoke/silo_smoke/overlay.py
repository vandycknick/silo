"""Phase 4 native helpers. Every VM goes through staged Silo or its real monitor.

The linear oracle consumes whole occurrences, and intentionally knows nothing
about the descriptor's splitting arithmetic. The second oracle independently
parses canonical records. Neither gives expected bytes to the guest.
"""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import random
import time
from uuid import UUID
import re
import struct
import subprocess
import tarfile
from collections import Counter
from dataclasses import dataclass

from . import images, procs, shutdown
from .cli import Silo, timed
from .config import REPO, SmokeConfig
from .workspace import Workspace

SPLIT = 2 * 1024**3
PROBE = "/usr/local/bin/overlay-probe"
PROFILE = "linux-flat-overlay-v1"
APPROVED_NATIVE_REVISION = "58253c00580bda34f5ea9fc4e0fccaf1e09a83d4"
OVERLAYFS_SUPER_MAGIC = 0x794C7630
TMPFS_MAGIC = 0x01021994


def native_capabilities(monitor: Path, *, diagnostic: Path | None = None) -> dict:
    result = subprocess.run([str(monitor), "capabilities", "--backend", "krun", "--json"], capture_output=True, text=True, timeout=30)
    if diagnostic is not None:
        diagnostic.write_text(f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    result.check_returncode()
    return json.loads(result.stdout)


@dataclass(frozen=True)
class NativeSourceIdentity:
    kind: str
    state: str
    revision: str
    content: str
    inputs: str


def native_source_identity(report: dict) -> NativeSourceIdentity:
    """Decode only the current truthful source binding, never an old pin label."""
    parts = report["buildIdentity"].split(":")
    if len(parts) != 6 or parts[0] != "v2" or not parts[4].startswith("content=") or not parts[5].startswith("inputs="):
        raise ValueError("Expected current native source/content build identity")
    _, kind, state, revision, content, inputs = parts
    if (kind == "path" and state not in {"clean", "dirty", "unknown"}) or (kind == "git" and state != "revision-bound") or kind not in {"path", "git"}:
        raise ValueError("Invalid native source kind/state")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) and not (revision == "unknown" and state == "unknown"):
        raise ValueError("Invalid native source revision observation")
    content, inputs = content.removeprefix("content="), inputs.removeprefix("inputs=")
    if not re.fullmatch(r"[0-9a-f]{64}", inputs) or (not re.fullmatch(r"[0-9a-f]{64}", content) and not (content == "unknown" and state == "unknown")):
        raise ValueError("Invalid native source/input content fingerprints")
    return NativeSourceIdentity(kind, state, revision, content, inputs)


def digest(path: Path, length: int | None = None) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        remaining = length
        while remaining is None or remaining:
            block = stream.read(min(1024**2, remaining) if remaining is not None else 1024**2)
            if not block:
                if remaining:
                    raise AssertionError(f"Short prefix {path}: {remaining} bytes missing")
                break
            value.update(block)
            if remaining is not None:
                remaining -= len(block)
    return value.hexdigest()


def copy_runtime(source: Path, destination: Path) -> None:
    """Copy a Linux fixture runtime with private inodes, reflinking where possible."""
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    subprocess.run(
        ["cp", "-RL", "--reflink=auto", "--preserve=mode,timestamps,xattr", "--no-target-directory", "--", str(source), str(destination)],
        check=True, capture_output=True, text=True, timeout=300,
    )


def compile_probe(destination: Path) -> Path:
    target = {"x86_64": "x86_64-unknown-linux-musl", "aarch64": "aarch64-unknown-linux-musl", "arm64": "aarch64-unknown-linux-musl"}[platform.machine()]
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    host_output = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, text=True, timeout=30).stdout
    host = next(line.removeprefix("host: ") for line in host_output.splitlines() if line.startswith("host: "))
    subprocess.run(["rustc", "--edition=2024", "--target", target, "-O", "-A", "dead_code", "-C", "link-self-contained=yes", "-C", f"linker={sysroot}/lib/rustlib/{host}/bin/rust-lld", str(REPO / "virt/vmm/tests/guest/overlay_probe.rs"), "-o", str(destination)], check=True, capture_output=True, text=True, timeout=120)
    return destination


class PatternReader:
    """Bounded streaming body, with different seed-14 bytes in each MiB."""
    def __init__(self, length: int) -> None:
        self.remaining = length
        self.position = 0
        self.seed = random.Random(14).randbytes(4096)

    def read(self, length: int = -1) -> bytes:
        length = min(self.remaining, 1024**2 if length < 0 else length)
        result = bytearray()
        while len(result) < length:
            sector, within = divmod(self.position, 4096)
            block = struct.pack("<Q", sector) + self.seed[8:]
            count = min(length - len(result), 4096 - within)
            result.extend(block[within:within + count])
            self.position += count
        self.remaining -= length
        return bytes(result)


def image(config: SmokeConfig, probe: Path, *, large: bool = False, reserved: str | None = None, root_run_symlink: bool = False, symlink_target_length: int | None = None) -> images.OciImage:
    """Reuse pinned Alpine fixture, stream large data rather than allocating GiBs."""
    base = images.build(images.BASIC, images.fetch_alpine(config.cache_dir))
    compressed = io.BytesIO()
    raw_digest = hashlib.sha256()
    class HashWriter:
        def __init__(self, output: gzip.GzipFile) -> None:
            self.output = output
        def write(self, data: bytes) -> int:
            raw_digest.update(data)
            return self.output.write(data)
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0, compresslevel=1) as gz:
        with tarfile.open(fileobj=HashWriter(gz), mode="w|", format=tarfile.PAX_FORMAT) as output:
            with tarfile.open(fileobj=io.BytesIO(base.layer), mode="r:gz") as source:
                for member in source:
                    if root_run_symlink and (member.name.rstrip("/") == "run" or member.name.startswith("run/")):
                        continue
                    if member.name.rstrip("/") in {"usr/local/bin", "usr/local/bin/overlay-probe", "sbin/candidate-init"} or member.name.startswith("overlay-fixture/") or member.name.rstrip("/") == "overlay-fixture":
                        continue
                    stream = source.extractfile(member) if member.isreg() else None
                    try:
                        output.addfile(copy.copy(member), stream)
                    finally:
                        if stream is not None:
                            stream.close()
            def member(name: str, data: bytes = b"", *, kind: bytes = tarfile.REGTYPE, link: str = "", attrs: dict[str, str] | None = None) -> None:
                header = tarfile.TarInfo(name)
                header.mode = 0o755 if kind == tarfile.DIRTYPE or name.endswith(("overlay-probe", "candidate-init")) else 0o644
                header.type, header.linkname, header.size = kind, link, len(data)
                header.pax_headers = attrs or {}
                output.addfile(header, io.BytesIO(data) if data else None)
            member("usr/local/bin", kind=tarfile.DIRTYPE)
            member("usr/local/bin/overlay-probe", probe.read_bytes())
            member("sbin/candidate-init", b"#!/bin/sh\nset -eu\nexec >/dev/console 2>&1\necho SILO_OVERLAY_CANDIDATE_BEGIN\necho GUEST_KERNEL_VERSION\ncat /proc/version\ncat /run/silo/rootfs/observation.json\ncat /proc/self/mountinfo\nfor p in /sys/module/overlay/parameters/*; do echo PARAM:$p; cat \"$p\"; done\nfor p in /sys/block/*; do test ! -f \"$p/serial\" || { echo DEVICE:$p; cat \"$p/serial\" \"$p/size\" \"$p/ro\" \"$p/queue/logical_block_size\"; }; done\nfor arg in $(cat /proc/cmdline); do case \"$arg\" in silo.smoke_probes=*) /usr/local/bin/overlay-probe mapping \"${arg#silo.smoke_probes=}\";; silo.smoke_range=*) /usr/local/bin/overlay-probe range-request \"${arg#silo.smoke_range=}\";; esac; done\necho SILO_OVERLAY_WORKLOAD_REACHED\nwhile true; do sleep 3600; done\n")
            if root_run_symlink:
                member("run", kind=tarfile.SYMTYPE, link="tmp")
            member("overlay-fixture/capability", b"capability", attrs={"LIBARCHIVE.xattr.security.capability": base64.b64encode(struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0)).decode()})
            member("overlay-fixture", kind=tarfile.DIRTYPE)
            member("overlay-fixture/a", b"original-hardlink\n", attrs={"SCHILY.xattr.user.near-limit": "x" * 2750, "SCHILY.acl.access": "user::rw-,user:1234:r--,group::r--,mask::r--,other::r--"})
            member("overlay-fixture/b", kind=tarfile.LNKTYPE, link="overlay-fixture/a")
            for directory in ("lower-dir", "opaque"):
                member(f"overlay-fixture/{directory}", kind=tarfile.DIRTYPE)
                member(f"overlay-fixture/{directory}/old", b"old")
            member("overlay-fixture/deleted", b"delete")
            if symlink_target_length is not None:
                assert symlink_target_length in (4095, 4096)
                member("overlay-fixture/long-symlink", kind=tarfile.SYMTYPE, link="t" * symlink_target_length)
            if reserved:
                if reserved == "char-zero":
                    member("overlay-fixture/forbidden", kind=tarfile.CHRTYPE)
                else:
                    member("overlay-fixture/forbidden", b"bad", attrs={f"SCHILY.xattr.{reserved}": "y"})
            header = tarfile.TarInfo("overlay-fixture/large")
            header.mode = 0o644
            header.size = 2304 * 1024**2 if large else 80 * 1024**2
            output.addfile(header, PatternReader(header.size))
    layer = compressed.getvalue()
    sha = lambda data: "sha256:" + hashlib.sha256(data).hexdigest()
    cfg = json.dumps({"architecture": images.oci_arch(), "os": "linux", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + raw_digest.hexdigest()]}, "config": {}}, separators=(",", ":")).encode()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(cfg), "size": len(cfg)}, "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(layer), "size": len(layer)}]}, separators=(",", ":")).encode()
    return images.OciImage(manifest, sha(manifest), cfg, sha(cfg), layer, sha(layer))


@dataclass(frozen=True)
class Record:
    sectors: int
    path: Path
    offset: int


def records(descriptor: Path) -> list[Record]:
    lines = descriptor.read_text().splitlines()
    result = []
    for line in lines:
        if not line.startswith("RW "):
            continue
        match = re.fullmatch(r'RW ([0-9]+) FLAT "([^"\\\x00-\x1f]+)" ([0-9]+)', line)
        assert match, f"Noncanonical descriptor line {line!r}"
        size, path, offset = match.groups()
        result.append(Record(int(size), Path(path), int(offset)))
    assert result
    return result


def linear_read(occurrences: list[Path], offset: int, length: int) -> bytes:
    result = bytearray()
    for path in occurrences:
        size = path.stat().st_size
        if offset >= size:
            offset -= size
            continue
        with path.open("rb") as stream:
            stream.seek(offset)
            result.extend(stream.read(min(length - len(result), size - offset)))
        offset = 0
        if len(result) == length:
            return bytes(result)
    raise AssertionError("Linear oracle read outside occurrence concatenation")


def record_read(extents: list[Record], offset: int, length: int, *, wrong_bytes: bool = False) -> bytes:
    result = bytearray()
    for extent in extents:
        size = extent.sectors * 512
        if offset >= size:
            offset -= size
            continue
        with extent.path.open("rb") as stream:
            stream.seek(extent.offset * (1 if wrong_bytes else 512) + offset)
            result.extend(stream.read(min(length - len(result), size - offset)))
        offset = 0
        if len(result) == length:
            return bytes(result)
    raise AssertionError("Record oracle read outside descriptor")


def probes(length: int) -> list[tuple[int, int]]:
    positions = {(0, 512), (4096, 4096), (length - 512, 512)}
    for boundary in range(SPLIT, length, SPLIT):
        positions.update((boundary + delta, size) for delta, size in [(-512, 512), (0, 512), (512, 512), (-2048, 4096)])
    rng = random.Random(14)
    positions.update((rng.randrange(0, (length - 4096) // 512) * 512, 4096) for _ in range(16))
    return sorted(positions)


def probe(silo: Silo, name: str, *args: str, timeout: float = 90) -> dict:
    return json.loads(silo.exec(name, PROBE, *args, user="root", timeout=timeout).stdout)


def machine_dir(silo: Silo, name: str) -> Path:
    return silo.ws.silo_home / "machines" / procs.machine_id(silo.ws, name)


def upper(silo: Silo, name: str) -> Path:
    machine_id = procs.machine_id(silo.ws, name)
    rows = procs.query(silo.ws.state_db(), "SELECT json(record_json) FROM machine_storage WHERE machine_id='" + machine_id + "'")
    assert len(rows) == 1
    root = json.loads(rows[0][0])["root"]
    assert root["kind"] == "linux-overlay"
    relative = Path(root["upper"])
    assert not relative.is_absolute() and ".." not in relative.parts
    return machine_dir(silo, name) / relative


def observation(silo: Silo, name: str) -> dict:
    return json.loads(silo.exec(name, "cat", "/run/silo/rootfs/observation.json", user="root").stdout)


def filesystem_magic(silo: Silo, name: str, path: str) -> int:
    return int(silo.exec(name, "stat", "-f", "-c", "%t", path, user="root").stdout.strip(), 16)


def metrics(silo: Silo, name: str) -> dict:
    binary = silo.ws.config.bin_dir / "examples/root_metrics"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/root_metrics"
    with timed(silo.ws, "overlay.metrics"):
        # Require a new post-effect report, not merely a previously fresh report.
        after = int(time.time() * 1000)
        machine_id = UUID(procs.machine_id(silo.ws, name))
        deadline = time.monotonic() + 20
        while True:
            with timed(silo.ws, "root_metrics"):
                result = subprocess.run([str(binary), name], env=silo.ws.env(), capture_output=True, text=True, timeout=30)
            silo.ws.record("overlay-metrics", result.stdout + result.stderr)
            assert result.returncode == 0, result.stderr
            snapshot = json.loads(result.stdout)
            assert UUID(snapshot["machineId"]) == machine_id
            assert snapshot["agentInstanceId"]
            root = snapshot["rootStorage"]
            temporary = root["temporaryDirectory"]
            if snapshot["freshness"] == "Fresh" and snapshot["observedAtUnixMillis"] >= after:
                # One guest stat invocation observes both real filesystems without
                # paying for a second CLI/transport/guest process round trip.
                lines = silo.exec(name, "stat", "-f", "-c", "%S %b %f %a %c %d", "/run/silo/rootfs/upperfs", "/tmp", user="root").stdout.splitlines()
                assert len(lines) == 2, lines
                def measured(line: str) -> dict:
                    fragment, blocks, free, available, inodes, free_inodes = map(int, line.split())
                    return {"usable": fragment * blocks, "used": fragment * (blocks - free), "free": fragment * free, "available": fragment * available, "inodes": inodes, "freeInodes": free_inodes}
                upper_actual, tmp_actual = map(measured, lines)
                if (root["upperUsableBytes"], root["upperUsedBytes"], root["upperFreeBytes"], root["upperAvailableBytes"], root["upperTotalInodes"], root["upperFreeInodes"]) == tuple(upper_actual[key] for key in ("usable", "used", "free", "available", "inodes", "freeInodes")) and (temporary["capacityBytes"], temporary["usedBytes"], temporary["freeBytes"], temporary["availableBytes"]) == tuple(tmp_actual[key] for key in ("usable", "used", "free", "available")):
                    silo.ws.record("overlay-independent-statvfs", json.dumps({"upper": upper_actual, "temporary": tmp_actual, "observedAtUnixMillis": snapshot["observedAtUnixMillis"], "agentInstanceId": snapshot["agentInstanceId"]}) + "\n")
                    break
            assert time.monotonic() < deadline, "no fresh post-effect capacity report matching independent guest statvfs"
            time.sleep(0.1)
    assert root["upperBackingBytes"] == root["upperFilesystemBytes"] + root["unusableTailBytes"]
    assert root["upperFilesystemBytes"] == root["upperUsableBytes"] + root["filesystemOverheadBytes"]
    assert root["upperUsedBytes"] + root["upperFreeBytes"] == root["upperUsableBytes"]
    assert root["upperAvailableBytes"] <= root["upperFreeBytes"]
    root["_observation"] = {key: snapshot[key] for key in ("machineId", "agentInstanceId", "freshness", "observedAtUnixMillis", "receivedAtUnixMillis", "staleAtUnixMillis")}
    return root


@dataclass(frozen=True)
class Evidence:
    """The guest's boot observation and the validated metrics frame checked against it."""

    observation: dict
    metrics: dict


def evidence(silo: Silo, name: str) -> Evidence:
    value = observation(silo, name)
    silo.ws.record("overlay-observation", json.dumps(value, sort_keys=True) + "\n")
    # The diagnostics below are read-only, so the fresh frame need not follow
    # them; sampling first keeps their guest sessions out of the cutoff wait.
    root_metrics = metrics(silo, name)
    # Keep every diagnostic and fail on any failed read, but use one real guest
    # exec rather than one SSH/CLI session per small procfs/sysfs file.
    silo.exec(name, "sh", "-eu", "-c", """
for path in /proc/self/mountinfo /proc/version /sys/module/overlay/parameters/index /sys/module/overlay/parameters/metacopy /sys/module/overlay/parameters/redirect_dir /sys/module/overlay/parameters/redirect_always_follow /sys/module/overlay/parameters/xino_auto /sys/module/overlay/parameters/nfs_export; do
    printf '\\n== %s ==\\n' "$path"
    cat "$path"
done
df -Pk / /tmp /run/silo/rootfs/upperfs
df -Pi /run/silo/rootfs/upperfs
""", user="root")
    assert root_metrics["upperBackingBytes"] == value["root"]["upper"]["lengthBytes"]
    assert root_metrics["sharedLowerLogicalBytes"] == value["root"]["lower"]["lengthBytes"]
    temporary = root_metrics["temporaryDirectory"]
    if value["root"]["temporaryDirectory"]["kind"] == "tmpfs":
        assert temporary["kind"] == "tmpfs" and temporary["memoryCharged"] is True and temporary["persistent"] is False
        assert temporary["capacityBytes"] == value["root"]["temporaryDirectory"]["capacityBytes"]
    else:
        assert temporary["kind"] == "upper" and temporary["memoryCharged"] is False and temporary["persistent"] is True
    return Evidence(value, root_metrics)


def worker_pid(silo: Silo, name: str) -> int:
    monitor = procs.vmm_pid(silo.ws, name)
    assert monitor is not None
    return worker_pid_of_monitor(monitor)


def worker_pid_of_monitor(monitor: int) -> int:
    children: set[str] = set()
    for task in Path(f"/proc/{monitor}/task").iterdir():
        try:
            children.update((task / "children").read_text().split())
        except FileNotFoundError:
            continue
    workers = [int(pid) for pid in children if Path(f"/proc/{pid}/comm").read_text().strip() == "krun"]
    assert len(workers) == 1, f"Expected actual krun worker child of {monitor}: {children}"
    return workers[0]


def handle_evidence(silo: Silo, name: str, descriptor: Path) -> None:
    readonly_handle_evidence(silo.ws, worker_pid(silo, name), descriptor, upper(silo, name))


def readonly_handle_evidence(ws: Workspace, pid: int, descriptor: Path, upper_file: Path) -> None:
    extents = records(descriptor)
    expected = Counter(str(item.path.resolve()) for item in extents)
    expected[str(descriptor.resolve())] += 1
    observed: Counter[str] = Counter()
    upper_path = str(upper_file.resolve())
    upper_seen = False
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            path = os.readlink(fd)
            info = Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text()
        except FileNotFoundError:
            continue
        flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith("flags:")), 8)
        if path in expected:
            assert flags & os.O_ACCMODE == os.O_RDONLY, (pid, fd, path, info)
            observed[path] += 1
        if path == upper_path:
            assert flags & os.O_ACCMODE == os.O_RDWR, (pid, fd, path, info)
            upper_seen = True
        if path in expected or path == upper_path:
            ws.record("overlay-worker-handles", f"worker={pid} fd={fd.name} path={path} {info}\n")
    assert observed == expected, (observed, expected)
    assert upper_seen


def create(silo: Silo, name: str, reference: str, *flags: str, capacity: str = "256mib") -> None:
    silo.create(name, reference, "--root-profile", PROFILE, "--disk-size", capacity, "--network", "none", "--vsock", *flags)
    silo.start(name)
    silo.wait_ready(name)


def ext4(path: Path) -> dict:
    with path.open("rb") as stream:
        stream.seek(1024)
        sb = stream.read(1024)
    assert len(sb) == 1024 and sb[56:58] == b"\x53\xef"
    blocks = struct.unpack_from("<I", sb, 4)[0]
    return {"uuid": sb[104:120].hex(), "filesystem_bytes": blocks * 4096, "incompat": struct.unpack_from("<I", sb, 96)[0], "compat": struct.unpack_from("<I", sb, 92)[0], "ro_compat": struct.unpack_from("<I", sb, 100)[0], "reserved_gdt": struct.unpack_from("<H", sb, 206)[0]}


def shutdown_watch(silo: Silo, name: str) -> dict:
    path = silo.ws.silo_home / "logs/machines" / procs.machine_id(silo.ws, name) / "serial.log"
    assert path.is_file()
    return {"path": str(path), "offset": path.stat().st_size, "runId": procs.run_id(silo.ws, name), "monitorPid": procs.vmm_pid(silo.ws, name)}


def shutdown_text(silo: Silo, watched: dict) -> str:
    text = Path(watched["path"]).read_bytes()[watched["offset"]:].decode(errors="replace")
    silo.ws.record("overlay-run-bound-shutdown", json.dumps(watched) + "\n" + text)
    return text


def assert_unforced_native_exit(terminal: dict, *, machine_id: str, run_id: str, monitor: int, worker: int) -> None:
    assert UUID(terminal["machineId"]) == UUID(machine_id) and UUID(terminal["runId"]) == UUID(run_id)
    assert terminal["pid"] == monitor
    backend = terminal["backend"]
    assert backend["forceReason"] is None, "host-forced shutdown is not guest PID1 evidence"
    process = backend["process"]
    assert process["pid"] == worker and process["rawStatus"] == 0 and process["code"] == 0
    assert process["signal"] is None and process["coreDumped"] is False


def orderly_guest_shutdown(silo: Silo, name: str, *, timeout: float = 90) -> dict:
    """Normal CLI/libvm shutdown with actual guest/native and storage evidence."""
    watched = shutdown_watch(silo, name)
    assert watched["runId"] is not None and watched["monitorPid"] is not None
    worker = worker_pid(silo, name)
    try:
        result = silo.run("stop", name, "--timeout", f"{int(timeout)}s", expect=None, timeout=timeout + 30)
        silo.ws.record("overlay-orderly-cli-stop", json.dumps({"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        terminal = shutdown.exit_record(silo, name, watched["runId"])
        assert_unforced_native_exit(terminal, machine_id=procs.machine_id(silo.ws, name), run_id=watched["runId"], monitor=watched["monitorPid"], worker=worker)
        procs.wait_gone(worker, timeout=20)
        procs.wait_gone(watched["monitorPid"], timeout=20)
        assert terminal["storageShutdown"]["guestProtocolCompleted"] is True
        if platform.system() == "Linux":
            shutdown.assert_clean(silo, name, terminal)
        return terminal
    finally:
        shutdown_text(silo, watched)


def limited_start(silo: Silo, name: str, soft: int, hard: int) -> subprocess.CompletedProcess[str]:
    import sys
    code = "import os,resource,sys; resource.setrlimit(resource.RLIMIT_NOFILE,(int(sys.argv[1]),int(sys.argv[2]))); os.execv(sys.argv[3],sys.argv[3:])"
    result = subprocess.run([sys.executable, "-c", code, str(soft), str(hard), str(silo.ws.config.silo), "start", name], env=silo.ws.env(), capture_output=True, text=True, timeout=90)
    silo.ws.record(f"vmdk-isolated-rlimit-{soft}-{hard}", result.stdout + result.stderr)
    return result
