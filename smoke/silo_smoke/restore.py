"""Real execution-restore smoke inputs and independent persistent witnesses.

No capability override or synthetic checkpoint is installed here. The caller
must select Main's isolated compiled capture+restore candidate through the
normal SILO_SMOKE_BIN_DIR and SILO_SMOKE_RUNTIME_DIR configuration.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
import copy
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import time
import uuid

import pytest

from . import images, overlay, pause, procs, stopped
from .cli import Result, Silo
from .config import REPO, SmokeConfig
from .registry import LoopbackRegistry

PROBE = "/usr/local/bin/restore-execution"
MAGIC = 0x53494C4F52535431
RECORD = struct.Struct("<8Q")
STATE = struct.Struct("<15Q")


@pytest.fixture(scope="session")
def restore_image(config: SmokeConfig, registry: LoopbackRegistry,
                  tmp_path_factory: pytest.TempPathFactory) -> str:
    output = tmp_path_factory.mktemp("restore-probe") / "restore-execution"
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2", "-pthread",
               "-Wall", "-Wextra", "-Werror", "-std=c11",
               str(REPO / "virt/vmm/tests/guest/restore_execution.c"), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    spec = replace(images.BASIC, name="restore-execution", files={
        **images.BASIC.files, PROBE.lstrip("/"): images.GuestFile(output.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "restore-execution")


def require_restore_candidate(info: dict) -> None:
    live = info["lifecycle"]["report"]["live"]
    for operation in ("capture", "restore"):
        assert live[operation]["availability"] == {"status": "supported"}, (
            "select the explicit isolated capture+restore candidate", operation, live[operation])


def create_source(silo: Silo, image: str, *flags: str, name: str = "restore-source",
                  profile: str = "raw", network: str = "none", cpus: int = 2) -> dict:
    assert profile in {"raw", "flat"} and cpus in (2, 4)
    silo.create(name, image, "--cpus", str(cpus), "--memory", "512mib", "--disk-size", "512mib",
                "--vsock", "--network", network,
                *(["--root-profile", overlay.PROFILE] if profile == "flat" else []), *flags)
    silo.start(name)
    info = silo.wait_ready(name)
    require_restore_candidate(info)
    return info


@dataclass(frozen=True)
class Checkpoint:
    reference: str
    snapshot: str
    staging: Path
    seal: dict
    source_info: dict
    boot_id: str
    generation: dict[str, str]


def checkpoint(silo: Silo, name: str, *, alias: str = "restore-checkpoint",
               borrowed: bool = False) -> Checkpoint:
    """Capture a real guest, preserving acquired or borrowed pause authority.

    This deliberately does not start or assume an execution witness, so the
    activation/network smoke can use the same path with its own image.
    """
    source = silo.info(name)
    boot_id = silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout
    generation = pause.generation(silo, name)
    original_pause = None
    if borrowed:
        silo.run("pause", name)
        original_pause = silo.info(name)["lifecycle"]["lifecycle"]["currentPause"]
    result = silo.run("snapshot", "create", name, "--live", "--preserve", "--name", alias,
                      timeout=240)
    value = json.loads(result.stdout)
    summary = value["capture"]
    assert value["snapshot"]["captureKind"] == "live-execution"
    assert summary["sourceOutcome"] == "preserved" and summary["released"] is True
    assert summary["pause"] == ("borrowed" if borrowed else "acquired")
    relative = Path(summary["staging"])
    assert not relative.is_absolute() and ".." not in relative.parts
    directory = silo.ws.silo_home / relative
    seal = json.loads((directory / "vm.capture.json").read_bytes())
    assert seal["captureOutcome"] == "coherent" and seal["error"] is None
    assert seal["runId"] == source["run_id"]
    preserved = silo.info(name)
    assert preserved["state"] == "paused" and preserved["run_id"] == source["run_id"]
    if original_pause is not None:
        assert preserved["lifecycle"]["lifecycle"]["currentPause"] == original_pause
        assert seal["freezeOperationId"] == original_pause["operationId"]
    assert seal["freezeOperationId"] and seal["freezeEpoch"] > 0
    snapshot = value["snapshot"]["id"]
    return Checkpoint("image:" + snapshot, snapshot, directory, seal, source, boot_id, generation)


def restore_argv(reference: str, child: str, *extra: str) -> list[str]:
    return ["restore", reference, "--name", child, *extra]


def restore(silo: Silo, reference: str, child: str, *extra: str,
            expect: int | None = None) -> Result:
    # Register even failure paths: ActivationFailed may still own a child.
    silo.ws.register_machine(child)
    return silo.run(*restore_argv(reference, child, *extra), expect=expect, timeout=240)


def restore_child(silo: Silo, saved: Checkpoint | str, name: str) -> dict:
    reference = saved.reference if isinstance(saved, Checkpoint) else saved
    restore(silo, reference, name, expect=0)
    child = silo.wait_ready(name)
    if isinstance(saved, Checkpoint):
        assert child["id"] != saved.source_info["id"]
        assert child["run_id"] and child["run_id"] != saved.source_info["run_id"]
        assert silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout == saved.boot_id
        generation = pause.generation(silo, name)
        assert generation["request_id"] != saved.generation["request_id"]
        assert generation["completed_sequence"] == generation["ack_sequence"] == generation["request_sequence"]
        assert generation["request_flags"] == generation["completed_flags"] == "1"
        assert int(generation["reseed_count"]) == int(saved.generation["reseed_count"]) + 1
        silo.ws.record("restore-generation", json.dumps({
            "machine": name, "source": saved.generation, "child": generation,
            "sourceIdentity": saved.source_info, "childIdentity": child,
            "bootId": saved.boot_id,
        }, sort_keys=True) + "\n")
    return child


def witness(silo: Silo, name: str, operation: str = "read", *, first: int = 0) -> dict:
    result = silo.exec(name, PROBE, operation, str(first), user="root")
    value = json.loads(result.stdout)
    assert value["errors"] == 0 and value["committed"] > 0
    assert value["guestPhysicalAddress"] > 0
    assert value["guestPhysicalAddress"] % value["pageSize"] == 0
    assert [record[0] for record in value["records"]] == list(
        range(first + 1, min(value["committed"], first + 32) + 1))
    return value


def start_witness(silo: Silo, name: str) -> dict:
    silo.exec(name, PROBE, "start", user="root")
    initial = witness(silo, name)
    return advances(silo, name, initial)


def advances(silo: Silo, name: str, before: dict, *, first: int = 0) -> dict:
    deadline = time.monotonic() + 20
    while True:
        value = witness(silo, name, first=first)
        assert value["pid"] == before["pid"], "restored witness was restarted instead of resumed"
        assert value["guestPhysicalAddress"] == before["guestPhysicalAddress"]
        assert value["avxEnabled"] == before["avxEnabled"]
        if (value["committed"] >= before["committed"] + 3
                and value["timers"] > before["timers"]
                and value["cpuSteps"] > before["cpuSteps"]
                and value["registerSteps"] > before["registerSteps"]):
            return value
        assert time.monotonic() < deadline, "restored disk/CPU/timer witness made no progress"
        time.sleep(0.05)


@dataclass(frozen=True)
class Cut:
    state: tuple[int, ...]
    records: tuple[tuple[int, ...], ...]
    disk: Path

    @property
    def committed(self) -> int:
        return self.state[1]

    @property
    def durable(self) -> int:
        return len(self.records)


def sealed_ram(saved: Checkpoint, address: int, length: int) -> tuple[bytes, int]:
    layout_path = saved.staging / "memory-layout.json"
    assert layout_path.stat().st_size <= 4 * 1024 * 1024
    layout = json.loads(layout_path.read_bytes())
    regions = [region for region in layout["regions"]
               if region["guestPhysicalAddress"] <= address
               and address + length <= region["guestPhysicalAddress"] + region["length"]]
    assert len(regions) == 1
    offset = regions[0]["streamOffset"] + address - regions[0]["guestPhysicalAddress"]
    fd = os.open(saved.staging / "memory.ram", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        assert 0 <= offset and offset + length <= os.fstat(fd).st_size
        raw = os.pread(fd, length, offset)
    finally:
        os.close(fd)
    assert len(raw) == length
    return raw, offset


def matched_cut(silo: Silo, saved: Checkpoint, identity: dict, *, profile: str) -> Cut:
    address = identity["guestPhysicalAddress"]
    raw, offset = sealed_ram(saved, address, STATE.size)
    state = STATE.unpack(raw)
    magic, committed, pending, writing = state[:4]
    assert magic == MAGIC and writing in (0, 1)
    assert pending in (committed, committed + 1) and committed >= identity["committed"]
    assert state[6:8] == (1, 1), "pending timer/signal were not retained at the cut"
    assert state[12] == 0, "source CPU/SIMD witness already failed"
    assert state[13] > 0 and state[14] in (0, 1), "live register workload did not reach the cut"
    disks = list((saved.staging / "disks").glob("*.raw"))
    assert len(disks) == 1
    path = "/upper/restore-execution.records" if profile == "flat" else "/restore-execution.records"
    result = subprocess.run(["debugfs", "-R", f"cat {path}", str(disks[0])],
                            capture_output=True, check=True, timeout=30)
    silo.ws.record("restore-independent-disk-reader", result.stderr.decode(errors="replace"))
    assert len(result.stdout) == 32768 * RECORD.size
    records = tuple(RECORD.iter_unpack(result.stdout))
    durable = next((index for index, record in enumerate(records) if record[0] == 0), len(records))
    assert all(not any(record) for record in records[durable:]), "noncontiguous durable disk log"
    records = records[:durable]
    assert [record[0] for record in records] == list(range(1, durable + 1))
    assert durable in ({committed, pending} if writing else {committed}), (state, durable)
    assert records and records[-1][1] <= state[4]
    silo.ws.record("restore-matched-cut", json.dumps({
        "snapshot": saved.snapshot, "guestPhysicalAddress": address, "streamOffset": offset,
        "ram": state, "diskRecords": records,
    }) + "\n")
    return Cut(state, records, disks[0])


def resumed(silo: Silo, name: str, identity: dict, cut: Cut) -> dict:
    baseline = {**identity, "committed": cut.durable, "timers": cut.state[4], "cpuSteps": cut.state[8],
                "registerSteps": cut.state[13], "avxEnabled": cut.state[14]}
    value = advances(silo, name, baseline, first=max(0, cut.durable - 2))
    # Include the last two independently read sealed records and the exact first
    # resumed append. Merely observing a larger last value could hide skipped or
    # repeated writes and would not prove the RAM/disk continuation boundary.
    first = max(0, cut.durable - 2)
    records = value["records"]
    prefix = cut.records[first:]
    assert tuple(tuple(record) for record in records[:len(prefix)]) == prefix
    assert len(records) >= len(prefix) + 3
    assert records[len(prefix)][0] == cut.durable + 1
    assert records[len(prefix)][0] in (cut.committed + 1, cut.committed + 2)
    assert all(later[6] >= earlier[6] for earlier, later in zip(records, records[1:]))
    assert value["timerPending"] == value["signalPending"] == 1
    delivered = witness(silo, name, "deliver", first=cut.durable)
    assert delivered["timerPending"] == delivered["signalPending"] == 0
    assert delivered["delivered"] == value["delivered"] + 1
    return advances(silo, name, delivered, first=cut.durable)


def snapshot_record(silo: Silo, saved: Checkpoint) -> dict:
    rows = procs.query(silo.ws.state_db(),
                       f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{saved.snapshot}'")
    assert len(rows) == 1
    return json.loads(rows[0][0])


def closure_paths(silo: Silo, saved: Checkpoint) -> list[Path]:
    paths = set()
    for table, column, kind in (
        ("snapshot_stream_dependency", "stream_id", "streams"),
        ("snapshot_object_dependency", "object_digest", "objects"),
        ("snapshot_capture_provenance", "evidence_digest", "objects"),
    ):
        for row in procs.query(silo.ws.state_db(),
                               f"SELECT {column} FROM {table} WHERE snapshot_id='{saved.snapshot}'"):
            digest = row[0]
            assert digest.startswith("sha256:") and len(digest) == 71
            assert all(character in "0123456789abcdef" for character in digest[7:])
            paths.add(silo.ws.silo_home / "images" / kind / "sha256" / digest[7:])
    assert paths
    return sorted(paths)


def exact_boot(silo: Silo, name: str, expected: dict[str, str]) -> None:
    pinned = stopped.record(silo, name)["boot"]["binding"]
    assert pinned["kind"] == "pinned"
    for role, digest in expected.items():
        path = silo.ws.silo_home / "images/objects/sha256" / pinned[role].removeprefix("sha256:")
        assert overlay.digest(path) == digest


def sql(silo: Silo, statement: str) -> None:
    result = subprocess.run(["sqlite3", "-bail", str(silo.ws.state_db())], input=statement,
                            capture_output=True, text=True, timeout=15)
    silo.ws.record("restore-fixture-sql", statement + "\n" + result.stdout + result.stderr)
    result.check_returncode()


def object_bytes(silo: Silo, content: bytes) -> tuple[str, Path]:
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    path = silo.ws.silo_home / "images/objects/sha256" / digest[7:]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
        os.fsync(fd)
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)
    return digest, path


@contextmanager
def incompatible_checkpoint(silo: Silo, saved: Checkpoint, mutation: str) -> Iterator[tuple[str, str]]:
    """Rebind a real captured negative closure, including local provenance.

    New object digests, snapshot identity and every dependency edge authenticate
    the altered envelope. Thus only an exact native refusal subject, not a hash
    error, satisfies the test. Original provenance is moved back on exit.
    """
    assert mutation in {"cpu", "producer", "profile", "xsave"}
    binary = silo.ws.config.bin_dir / "examples/native-live-api"
    assert binary.is_file(), "Main must stage cargo build -p silo-vmm --example native-live-api"
    original = snapshot_record(silo, saved)
    source_digest = original["execution"]["execution"]
    source = silo.ws.silo_home / "images/objects/sha256" / source_digest[7:]
    altered = silo.ws.evidence / ("restore-altered-" + mutation + ".state")
    command = [str(binary), "mutate-execution", str(source), str(altered), mutation]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    silo.ws.record("restore-native-mutation", json.dumps({
        "command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
    }) + "\n")
    result.check_returncode()
    changed = json.loads(result.stdout)
    content = altered.read_bytes()
    assert changed["length"] == len(content)
    assert bytes(changed["sha256"]).hex() == hashlib.sha256(content).hexdigest()
    record = copy.deepcopy(original)
    seal = copy.deepcopy(saved.seal)
    created: list[Path] = []
    execution_digest, path = object_bytes(silo, content)
    created.append(path)
    record["execution"]["execution"] = execution_digest
    if mutation == "producer":
        record["execution"]["compatibilityProfile"]["nativeProducer"] = changed["nativeProducer"]
        seal["memory"]["binding"]["nativeProducer"] = changed["nativeProducer"]
    inventory = [entry for entry in seal["inventory"] if entry["role"] == "execution.state"]
    assert len(inventory) == 1
    inventory[0]["length"] = len(content)
    inventory[0]["sha256"] = execution_digest
    # Closed schema keys are ASCII, all numbers are safe integers, and no float
    # is emitted. This is the RFC 8785 spelling of this real captured record.
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode()
    snapshot = "sha256:" + hashlib.sha256(b"silo:snapshot:v1\n" + canonical).hexdigest()
    record_digest, path = object_bytes(silo, canonical)
    created.append(path)
    seal_bytes = json.dumps(seal, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    evidence_digest, path = object_bytes(silo, seal_bytes)
    created.append(path)
    provenance = procs.query(silo.ws.state_db(),
        f"SELECT capture_id,evidence_digest,hex(evidence_bytes) FROM snapshot_capture_provenance WHERE snapshot_id='{saved.snapshot}'")
    assert len(provenance) == 1
    capture_id, old_evidence_digest, old_evidence_hex = provenance[0]
    assert capture_id == saved.seal["captureId"]
    old_record_digest = procs.query(silo.ws.state_db(),
        f"SELECT record_digest FROM storage_snapshot WHERE id='{saved.snapshot}'")[0][0]
    replacements = {source_digest: execution_digest, old_record_digest: record_digest}
    objects = {replacements.get(row[0], row[0]) for row in procs.query(silo.ws.state_db(),
        f"SELECT object_digest FROM snapshot_object_dependency WHERE snapshot_id='{saved.snapshot}'")}
    statements = [
        "PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;",
        f"INSERT INTO storage_snapshot(id,record_digest,record_bytes,retained,created_at) SELECT '{snapshot}','{record_digest}',X'{canonical.hex()}',1,created_at FROM storage_snapshot WHERE id='{saved.snapshot}';",
        f"INSERT INTO snapshot_stream_dependency SELECT '{snapshot}',stream_id FROM snapshot_stream_dependency WHERE snapshot_id='{saved.snapshot}';",
        *[f"INSERT INTO snapshot_object_dependency VALUES('{snapshot}','{digest}');" for digest in sorted(objects)],
        f"DELETE FROM snapshot_capture_provenance WHERE capture_id='{capture_id}';",
        f"INSERT INTO snapshot_capture_provenance VALUES('{capture_id}','{snapshot}','{evidence_digest}',X'{seal_bytes.hex()}');",
        "COMMIT;",
    ]
    installed = False
    try:
        sql(silo, "\n".join(statements))
        installed = True
        silo.ws.record("restore-incompatible-closure", json.dumps({
            "mutation": mutation, "sourceSnapshot": saved.snapshot, "negativeSnapshot": snapshot,
            "executionDigest": execution_digest, "recordDigest": record_digest,
            "provenanceDigest": evidence_digest, "expectedSubject": changed["subject"],
            "newObjects": [str(path) for path in created],
            "originalDeviceDigest": original["execution"]["devices"],
            "originalDeviceBinding": saved.seal["memory"]["binding"],
            "negativeExpectedBinding": seal["memory"]["binding"],
            "producerAdmissionPrecedesDeviceDecoding": mutation == "producer",
        }, sort_keys=True) + "\n")
        yield "image:" + snapshot, changed["subject"]
    finally:
        if installed:
            sql(silo, "\n".join([
                "PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;",
                f"DELETE FROM storage_snapshot WHERE id='{snapshot}';",
                f"INSERT INTO snapshot_capture_provenance VALUES('{capture_id}','{saved.snapshot}','{old_evidence_digest}',X'{old_evidence_hex}');",
                "COMMIT;",
            ]))


def execution_state(silo: Silo, saved: Checkpoint) -> dict:
    binary = silo.ws.config.bin_dir / "examples/native-live-api"
    assert binary.is_file(), "Main must stage the selected native-live-api example"
    command = [str(binary), "inspect-execution", str(saved.staging / "execution.state")]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    silo.ws.record("restore-native-execution", json.dumps({
        "snapshot": saved.snapshot, "command": command, "exit": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr,
    }) + "\n")
    result.check_returncode()
    return json.loads(result.stdout)


def irq_cut(silo: Silo, saved: Checkpoint, *, pending: bool) -> dict:
    """Independently inspect real AP2 IRR/ISR and its sealed guest RAM record."""
    state = execution_state(silo, saved)
    assert state["lane"] == "KvmX86" and state["pitProfile"] == 1
    assert [cpu["id"] for cpu in state["cpus"]] == [0, 1, 2, 3]
    cpu = state["cpus"][2]
    assert state["cpus"][3]["mpState"] == 1, "never-started AP3 did not remain parked"
    lapic = bytes(cpu["lapic"])
    assert len(lapic) >= 0x274
    irr = int.from_bytes(lapic[0x270:0x274], "little") & 1
    isr = int.from_bytes(lapic[0x170:0x174], "little") & 1
    assert bool(irr) is pending and isr == 0, "actual vector 224 pending/in-service state differs"
    assert cpu["deadline"] == 0, "consumed original comparator was recreated"
    assert cpu["registers"][12:14] == [0x13579BDF2468ACE0, 0xFEDCBA9876543210]
    xsave = bytes(cpu["xsave"])
    assert xsave[400:416] == b"\xff" * 16, "AP2 live SSE register was not retained"
    assert xsave[32:42] == bytes([0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F])
    raw, offset = sealed_ram(saved, 0x1C010000, 24 * 8)
    words = struct.unpack("<24Q", raw)
    assert words[0] == 0x53494C4F and words[1] == 1 and words[2] > 0
    assert words[23] % 2 == 0, "native cut interrupted the IRQ publication epoch"
    if words[21]:
        ymm = [component for component in cpu["xstate"] if component["id"] == 2]
        assert len(ymm) == 1
        start = ymm[0]["offset"] + 14 * 16
        assert xsave[start:start + 16] == b"\xff" * 16, "AP2 live upper YMM register was not retained"
    if pending:
        assert words[3] == words[4] == 2 and words[8] == 1
        assert cpu["registers"][17] & (1 << 9) == 0, "pending source IRQ was not held by real IF=0"
    proof = {"snapshot": saved.snapshot, "words": words, "guestPhysicalAddress": 0x1C010000,
             "streamOffset": offset, "pendingVector224": bool(irr), "inServiceVector224": bool(isr),
             "cpu": cpu}
    silo.ws.record("restore-hardware-irq-cut", json.dumps(proof, sort_keys=True) + "\n")
    return proof


@pytest.fixture(scope="session")
def restore_irq_fixture(config: SmokeConfig) -> Path:
    """Require Main's exact, separately compiled diagnostic-candidate inputs."""
    directory = config.runtime_dir / "assets/restore-irq-witness"
    manifest = json.loads((directory / "fixture-manifest.json").read_text())
    for field, filename in (("sourceSha256", "witness.S"), ("binarySha256", "witness.bin"),
                            ("symbolsSha256", "witness.nm")):
        assert overlay.digest(directory / filename) == manifest[field], (field, filename)
    assert 0 < (directory / "witness.bin").stat().st_size <= 0x3000
    assert 0 < (directory / "witness.nm").stat().st_size <= 65536
    monitor = config.runtime_dir / "bin/silo-vmm"
    assert overlay.digest(monitor) == manifest["candidateMonitorSha256"]
    capabilities = overlay.native_capabilities(monitor)
    assert capabilities["buildIdentity"] == manifest["nativeSourceIdentity"]
    return directory


def irq_probe(silo: Silo, name: str, request: dict, *, refused: str | None = None) -> dict:
    """Talk only to the owned candidate worker's compile-gated abstract socket."""
    info = silo.info(name)
    machine_id, run_id = uuid.UUID(info["id"]), uuid.UUID(info["run_id"])
    endpoint = f"\0silo-irq-probe/{machine_id}/{run_id}"
    message = json.dumps(request, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    assert len(message) <= 131072
    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(7)
        channel.connect(endpoint)
        channel.sendall(message)
        while True:
            chunk = channel.recv(16384)
            if not chunk:
                break
            response.extend(chunk)
            assert len(response) <= 131072, "oversized candidate IRQ probe response"
    silo.ws.record("restore-irq-probe", json.dumps({
        "machine": name, "machineId": info["id"], "runId": info["run_id"],
        "request": request, "rawResponse": response.decode(errors="replace"),
    }, sort_keys=True) + "\n")
    assert response.endswith(b"\n") and len(response.splitlines()) == 1
    value = json.loads(response)
    assert uuid.UUID(value["machine_id"]) == machine_id and uuid.UUID(value["run_id"]) == run_id
    assert value["pid"] == overlay.worker_pid(silo, name)
    if refused is not None:
        assert value["status"] == "refused" and value["reason"] == refused, value
        return value
    assert value["status"] == "ok", value
    observation = value["observation"]
    assert len(observation["words"]) == 23 and len(observation["irq_publication"]) == 2
    assert all(type(word) is int and 0 <= word < 2**64 for word in
               [*observation["words"], *observation["irq_publication"]])
    return observation


def initialize_irq_probe(silo: Silo, name: str, fixture: Path, *, refused: str | None = None) -> dict:
    silo.ws.record("restore-irq-fixture", (fixture / "fixture-manifest.json").read_text())
    silo.ws.record("restore-irq-source", (fixture / "witness.S").read_text())
    return irq_probe(silo, name, {
        "request": "initialize", "code": base64.b64encode((fixture / "witness.bin").read_bytes()).decode(),
        "symbols": (fixture / "witness.nm").read_text(),
    }, refused=refused)


def irq_wait(silo: Silo, name: str, predicate: Callable[[dict], bool], *, description: str) -> dict:
    deadline = time.monotonic() + 15
    while True:
        value = irq_probe(silo, name, {"request": "observe"})
        epoch = value["irq_publication"]
        if epoch[0] == epoch[1] and epoch[0] % 2 == 0 and predicate(value):
            return value
        assert time.monotonic() < deadline, description
        time.sleep(0.025)
