"""Real hibernate CLI, saved-file and identity observers for ADR 0023.

Keep public info reporting fields in report(), so smoke and performance
qualification share one adapter for the CLI schema.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import select
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from silo_smoke import overlay, procs, restore_lifecycle, shutdown
from silo_smoke.cli import Result, RootProfile, Silo
from silo_smoke.config import REPO

IMAGE_MACHINE_ID = "aabbccddeeff00112233445566778899"


class MemoryMode(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"


@dataclass(frozen=True)
class MemoryCapture:
    mode: MemoryMode
    bytes_written: int
    full_reason: str | None


@dataclass(frozen=True)
class Report:
    hibernated_at: datetime
    saved_state_bytes: int
    memory_capture: MemoryCapture


def report(silo: Silo, name: str) -> Report:
    """Public CLI hibernation report, shared by smoke and performance drivers."""
    info = silo.info(name)
    assert info["state"] == "hibernated" and info["ready"] is False, info
    value = info["hibernation"]
    timestamp = datetime.fromtimestamp(value["hibernated_at"], tz=UTC)
    size = value["saved_state_bytes"]
    assert timestamp.tzinfo is not None and type(size) is int and size > 0, value
    memory = value["memory_capture"]
    stats = memory["stats"]
    written = sum(stats[key] for key in ("fullBytesWritten", "overlayBytesWritten",
                                        "baselineBytesWritten"))
    reason = memory["full_reason"]
    assert type(written) is int and written >= 0
    assert reason is None or isinstance(reason, str)
    capture = MemoryCapture(MemoryMode(memory["mode"]), written, reason)
    return Report(timestamp, size, capture)


def create(silo: Silo, image: str, name: str, *flags: str,
           profile: RootProfile = "layered", network: str = "none", start: bool = True,
           cpus: int = 1) -> None:
    silo.create(name, silo.root_image(image, profile), "--cpus", str(cpus), "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", network, *flags)
    if start:
        silo.start(name)
        silo.wait_ready(name)


def boot_id(silo: Silo, name: str) -> str:
    return silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout.strip()


@dataclass(frozen=True)
class BootProcess:
    pid: int
    start_ticks: int
    command: str


def boot_process(silo: Silo, name: str) -> BootProcess:
    """Observe the boot-started PID 1, not an OCI CMD ignored by idle start."""
    raw = silo.exec(name, "cat", "/proc/1/stat").stdout
    pid = int(raw.split(" ", 1)[0])
    start_ticks = int(raw.rsplit(") ", 1)[1].split()[19])
    command = silo.exec(name, "cat", "/proc/1/cmdline").stdout.rstrip("\0")
    assert pid == 1 and start_ticks >= 0 and command, (raw, command)
    return BootProcess(pid, start_ticks, command)


def holders(silo: Silo, name: str) -> list[shutdown.Process]:
    value, _ = shutdown.holder(silo, name)
    return [shutdown.Process(entry["pid"]) for entry in value["holders"]]


def save(silo: Silo, name: str) -> None:
    processes = holders(silo, name)
    try:
        result = silo.run("hibernate", name, timeout=240)
        assert result.stdout == "", result
        assert re.search(rf"✓ Hibernated\s+{re.escape(name)}\b", result.stderr), result
        for process in processes:
            process.wait()
        saved_files(silo, name)
        assert silo.info(name)["state"] == "hibernated"
    finally:
        for process in processes:
            process.close()


def wake(silo: Silo, name: str) -> str:
    silo.start(name)
    info = silo.wait_ready(name)
    run = info["run_id"]
    assert isinstance(run, str) and run, info
    return run


def no_wake_line(result: Result, name: str) -> None:
    """An access command wakes without leaving a line in its output.

    A wake slower than half a second may draw a spinner on a terminal, which
    clears itself; the plain `Waking NAME` line belongs to `silo start` only.
    """
    output = (result.stdout + result.stderr).replace("\r\n", "\n")
    assert f"Waking {name}" not in [line.strip() for line in output.splitlines()], result


def refused(result: Result, message: str) -> None:
    assert result.returncode != 0, result
    assert message in result.stderr, result


def unusable(name: str, reason: str) -> str:
    return (f"cannot wake `{name}`: its saved state cannot be used ({reason}); "
            f"run `silo stop {name}` to discard it, then `silo start {name}`")


def saved_directory(silo: Silo, name: str) -> Path:
    root = overlay.machine_dir(silo, name) / "hibernation"
    directories = [path for path in root.iterdir() if path.is_dir()]
    assert len(directories) == 1, directories
    return directories[0]


def saved_files(silo: Silo, name: str) -> tuple[Path, ...]:
    directory = saved_directory(silo, name)
    files = tuple(sorted(path for path in directory.rglob("*") if path.is_file()))
    assert files, f"no saved files in {directory}"
    assert all(not path.is_symlink() and path.stat().st_mode & 0o222 == 0 for path in files)
    return files


@dataclass(frozen=True)
class Identity:
    machine_id: str
    name: str
    network: restore_lifecycle.Identity
    hostname: str
    guest_machine_id: str
    ssh_fingerprint: str


def identity(silo: Silo, name: str) -> Identity:
    info = silo.info(name)
    host, guest_id = silo.exec(name, "sh", "-ec", "hostname; cat /etc/machine-id").stdout.splitlines()
    trust = silo.ws.known_host(procs.machine_id(silo.ws, name)).read_text().split()
    assert len(trust) == 2 and trust[0] == "ssh-ed25519", trust
    digest = hashlib.sha256(base64.b64decode(trust[1], validate=True)).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    return Identity(str(info["id"]), str(info["name"]), restore_lifecycle.guest_identity(silo, name),
                    host, guest_id, fingerprint)

@contextmanager
def workspace_processes(silo: Silo) -> Iterator[list[shutdown.Process]]:
    """Pin identity before reading ownership, so PID reuse cannot redirect a kill."""
    roots = (os.fsencode(silo.ws.root), os.fsencode(silo.ws.run_root))
    owned: list[shutdown.Process] = []
    try:
        for path in Path("/proc").glob("[0-9]*"):
            if int(path.name) == os.getpid():
                continue
            try:
                process = shutdown.Process(int(path.name))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            keep = False
            try:
                identity = (path / "cmdline").read_bytes() + (path / "environ").read_bytes()
                keep = any(root in identity for root in roots) and not process.terminal()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
            finally:
                if keep:
                    owned.append(process)
                else:
                    process.close()
        yield owned
    finally:
        for process in owned:
            process.close()



def read_line(process: subprocess.Popen[bytes], timeout: float = 30) -> bytes:
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    pending = bytearray()
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([process.stdout], [], [], remaining)[0], pending
        block = os.read(process.stdout.fileno(), 4096)
        assert block, f"session exited before its ready line: {process.poll()}"
        pending.extend(block)
    return bytes(pending)


def terminate(process: subprocess.Popen[bytes], silo: Silo, label: str) -> None:
    if process.poll() is None:
        process.kill()
    output, errors = process.communicate(timeout=15)
    silo.ws.record(label, f"exit={process.returncode}\nstdout={output!r}\nstderr={errors!r}\n")


@dataclass(frozen=True)
class Trace:
    silo: Silo
    evidence: Path
    controller: subprocess.Popen[bytes]

    def wait(self, name: str) -> dict:
        def observed() -> dict | None:
            path = self.evidence / name
            if path.exists():
                return json.loads(path.read_bytes())
            assert self.controller.poll() is None, f"tracer ended before {name}: {self.evidence}"
            return None
        return shutdown.until(observed, timeout=180, description=f"no trace receipt {name}")

    def command(self, command: str) -> None:
        assert self.controller.stdin is not None
        self.controller.stdin.write((command + "\n").encode())
        self.controller.stdin.flush()

    def release(self) -> None:
        (self.evidence / "release").touch(exist_ok=True)

    def held(self) -> dict:
        receipt = self.wait("boundary-held.json")
        assert receipt["injectedReturn"] is False, receipt
        return receipt


@contextmanager
def traced(silo: Silo, name: str, *, waking: bool, target: Path) -> Iterator[Trace]:
    """Trace only our own descendants; hold real RAM I/O before save/consume."""
    evidence = silo.ws.evidence / ("wake-trace" if waking else "hibernate-trace")
    evidence.mkdir()
    driver = evidence / "driver.json"
    driver.write_text(json.dumps({"silo": str(silo.ws.config.silo), "name": name,
                                  "evidence": str(evidence), "waking": waking}) + "\n")
    request = evidence / "request.json"
    request.write_text(json.dumps({
        "command": [sys.executable, "-m", "silo_smoke.hibernate", str(driver)],
        "target": str(target), "boundary": "wake-memory-map" if waking else "capture-ram-write",
        "captureDirectoryName": "hibernation", "machines": str(silo.ws.silo_home / "machines"),
        "evidence": str(evidence), "release": str(evidence / "release"),
    }) + "\n")
    with (evidence / "controller.log").open("wb") as output:
        controller = subprocess.Popen(
            [sys.executable, "-m", "silo_smoke.stopped_trace", str(request)],
            env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")), stdin=subprocess.PIPE,
            stdout=output, stderr=subprocess.STDOUT,
        )
    trace = Trace(silo, evidence, controller)
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
        if controller.stdin is not None:
            controller.stdin.close()


@dataclass(frozen=True)
class Drive:
    silo: str
    name: str
    evidence: str
    waking: bool


def drive(request: Drive) -> None:
    """A real CLI parent, kept alive so ptrace can own monitor descendants."""
    evidence = Path(request.evidence)

    def record(name: str, value: object) -> None:
        target = evidence / name
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(value) + "\n")
        temporary.replace(target)

    if not request.waking:
        result = subprocess.run([request.silo, "start", request.name], capture_output=True,
                                text=True, timeout=90, check=False)
        record("started.json", {"code": result.returncode, "stderr": result.stderr})
        assert result.returncode == 0, result.stderr
        assert sys.stdin.readline().strip() == "hibernate"
    with (evidence / "manager.stdout").open("wb") as output, (evidence / "manager.stderr").open("wb") as errors:
        process = subprocess.Popen([request.silo, "start" if request.waking else "hibernate", request.name],
                                   stdout=output, stderr=errors)
        record("manager.json", {"pid": process.pid})
        try:
            code = process.wait(timeout=230)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        record("result.json", {"code": code})
    # Do not end the trace owner before the test has observed and cleaned up
    # the surviving run; EXITKILL would otherwise turn success into a crash.
    assert sys.stdin.readline().strip() == "finish"


if __name__ == "__main__":
    drive(Drive(**json.loads(Path(sys.argv[1]).read_bytes())))
