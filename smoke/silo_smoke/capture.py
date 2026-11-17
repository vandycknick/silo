"""Independent real-guest capture witnesses, not production seal generation."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import shlex
import struct
import subprocess
import time

from .cli import RootProfile, Silo
from .config import REPO
from . import stopped, stream_map


def compile_probe(output: Path) -> Path:
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2",
               "-Wall", "-Wextra", "-Werror", "-std=c11",
               str(REPO / "virt/vmm/tests/guest/capture_counter.c"), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return output


class Counter:
    """Retain the original writer session and its exact pinned guest address."""

    def __init__(self, silo: Silo, name: str, executable: str) -> None:
        self.silo = silo
        self.process = silo.popen("exec", name, "--user", "root", "--",
                                  executable, "/capture-counter")
        assert self.process.stdout is not None
        self.fd = self.process.stdout.fileno()
        self.pending = b""
        self.address: int | None = None
        self.page_size: int | None = None
        self.values: list[int] = []

    def receive(self, timeout: float) -> bool:
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        data = os.read(self.fd, 65536)
        assert data, f"capture writer session ended, CLI exit={self.process.poll()}"
        self.pending += data
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if self.address is None:
                identity = json.loads(line)
                self.address = identity["guestPhysicalAddress"]
                self.page_size = identity["pageSize"]
                assert self.address > 0 and self.address % self.page_size == 0
                self.silo.ws.record("capture-counter-address", json.dumps(identity) + "\n")
            else:
                assert line.startswith(b"COMMITTED="), line
                value = int(line.removeprefix(b"COMMITTED="))
                assert value == (self.values[-1] + 1 if self.values else 1), value
                self.values.append(value)
        return True

    def advances(self) -> None:
        initial = len(self.values)
        deadline = time.monotonic() + 20
        while len(self.values) < initial + 3:
            assert time.monotonic() < deadline, "capture writer did not make durable progress"
            self.receive(min(0.2, max(0, deadline - time.monotonic())))

    def stationary(self) -> None:
        deadline = time.monotonic() + 3
        while self.receive(0.2):
            assert time.monotonic() < deadline, "capture preserve left writer running"
        assert not self.receive(0.5), "capture preserve advanced existing writer"

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            output, errors = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            output, errors = self.process.communicate(timeout=10)
        self.silo.ws.record("capture-counter-session", json.dumps({
            "values": self.values, "partialHex": self.pending.hex(),
            "remainingHex": output.hex(), "stderr": errors.decode(errors="replace"),
            "exit": self.process.returncode,
        }) + "\n")


def matched_cut(silo: Silo, directory: Path, disk: Path, counter: Counter,
                *, profile: RootProfile) -> dict[str, int]:
    """Read sealed disk and exact RAM GPA without mounting or replaying a journal."""
    layout_path = directory / "memory-layout.json"
    assert layout_path.stat().st_size <= 4 * 1024 * 1024
    layout = json.loads(layout_path.read_bytes())
    assert counter.address is not None and counter.page_size is not None
    matches = [region for region in layout["regions"]
               if region["guestPhysicalAddress"] <= counter.address
               and counter.address + 32 <= region["guestPhysicalAddress"] + region["length"]]
    assert len(matches) == 1, "reported pinned GPA does not resolve uniquely in sealed RAM"
    region = matches[0]
    offset = region["streamOffset"] + counter.address - region["guestPhysicalAddress"]
    fd = os.open(directory / "memory.ram", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.pread(fd, 32, offset)
    finally:
        os.close(fd)
    assert len(raw) == 32
    magic, committed, pending, writing = struct.unpack("<QQQQ", raw)
    assert magic == 0x53494C4F43555431, "pinned witness address changed or RAM cut is corrupt"
    assert writing in (0, 1)
    assert pending in (committed, committed + 1)
    path = "/upper/capture-counter" if profile == "layered" else "/capture-counter"
    result = subprocess.run(["debugfs", "-R", f"cat {path}", str(disk)],
                            capture_output=True, check=True, timeout=30)
    silo.ws.record("capture-counter-disk-reader", result.stderr.decode(errors="replace"))
    assert len(result.stdout) == counter.page_size, "sealed disk witness file missing or wrong size"
    disk_counter = struct.unpack("<Q", result.stdout[:8])[0]
    assert disk_counter in ({committed, pending} if writing else {committed}), (
        "disk/RAM cut differs", disk_counter, committed, pending, writing)
    assert committed >= counter.values[0], "capture predates observed writer progress"
    proof = {"guestPhysicalAddress": counter.address, "streamOffset": offset,
             "committed": committed, "pending": pending, "writing": writing,
             "disk": disk_counter}
    silo.ws.record("capture-matched-cut", json.dumps(proof) + "\n")
    return proof


def pending_cut(directory: Path) -> dict:
    cut = json.loads((directory / "vm.capture-cut.json").read_bytes())
    assert cut["phase"] == "identity-pending" and cut["disks"], cut
    evidence = cut["evidence"]
    assert evidence["captureOutcome"] == "coherent" and evidence["error"] is None, evidence
    assert evidence["diskCopiesSealed"] is False, evidence
    assert all(evidence[fact] is True for fact in (
        "workloadsFrozen", "vcpusPaused", "devicesQuiesced", "hostWritersDrained",
        "hostFlushCompleted", "memoryStateSealed")), evidence
    assert not any(entry["role"].startswith("disks/") for entry in evidence["inventory"])
    assert not (directory / "vm.capture.json").exists(), "pending disk identities were sealed early"
    return evidence


def completed_cut(cut: dict, seal: dict) -> None:
    for field in ("captureId", "machineId", "runId", "pauseToken", "pauseDisposition", "freezeEpoch",
                  "freezeOperationId", "configurationDigest", "requestDigest"):
        assert seal[field] == cut[field], field
    before, after = cut["memory"], seal["memory"]
    assert {key: value for key, value in before.items() if key != "stats"} == {
        key: value for key, value in after.items() if key != "stats"}
    # RAM identities are already sealed in the pending record. Host map
    # publication later adds its node count without changing native work.
    assert before["stats"]["mapNodesWritten"] == 0
    assert after["stats"]["mapNodesWritten"] >= before["stats"]["mapNodesWritten"]
    assert {key: value for key, value in before["stats"].items() if key != "mapNodesWritten"} == {
        key: value for key, value in after["stats"].items() if key != "mapNodesWritten"}
    assert all(entry in seal["inventory"] for entry in cut["inventory"])


def inventory(directory: Path) -> dict[str, stopped.Bytes]:
    """Fingerprint staged files without synthesizing producer identities."""
    return {str(path.relative_to(directory)): stopped.read_bytes(path)
            for path in sorted(directory.rglob("*")) if path.is_file()}


def unchanged(silo: Silo, directory: Path, before: dict[str, stopped.Bytes],
              *, added: set[str] | None = None) -> None:
    after = inventory(directory)
    assert set(before) <= set(after), f"capture files disappeared: {sorted(set(before) - set(after))}"
    unexpected = set(after) - set(before) - {"vm.capture-source.json"} - (added or set())
    assert not unexpected, f"unexpected capture files: {sorted(unexpected)}"
    for name, original in before.items():
        observed = after[name]
        # Read-only faults can allocate tmpfs holes without changing file bytes.
        assert (observed.path, observed.device, observed.inode, observed.mode, observed.content()) == (
            original.path, original.device, original.inode, original.mode, original.content()
        ), f"sealed capture file mutated: {name}: {original!r} -> {observed!r}"
    silo.ws.record("capture-sealed-inventory", json.dumps({
        name: asdict(value) for name, value in after.items()}, sort_keys=True) + "\n")


def completed_disk_node_files(home: Path, directory: Path, seal: dict) -> set[str]:
    """Authenticate exactly the disk-node closure allowed after an identity-pending cut."""
    staged_nodes: set[str] = set()
    pool = stream_map.object_source(home)

    def source(identity: str) -> bytes:
        relative = "map-nodes/" + identity.removeprefix("sha256:")
        path = directory / relative
        if path.is_file():
            staged_nodes.add(relative)
            return path.read_bytes()
        return pool(identity)

    for entry in seal["inventory"]:
        role = entry["role"]
        if not role.startswith("disks/") or not role.endswith(".root"):
            continue
        encoded = (directory / role).read_bytes()
        root = stream_map.decode_root(encoded)
        assert len(encoded) == entry["length"] and root.identity == entry["sha256"]
        assert root.chunk_size == stream_map.DISK_CHUNK
        assert root.length == (directory / Path(role).with_suffix(".raw")).stat().st_size
        dict(stream_map.present_chunks(root, source))
    return staged_nodes
