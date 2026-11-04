"""Independent Linux process/inode/lease observables for production shutdown smoke.

No fact is synthesized here. JSON is the product under test, checked against
kernel process/FD state and durable storage contents. All signals use pidfds.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import time
from uuid import UUID

from . import procs
from .cli import Silo
from .config import REPO


def until(predicate, *, timeout: float = 30, description: str):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        assert time.monotonic() < deadline, description
        time.sleep(0.025)


class Process:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.fd = os.pidfd_open(pid)
        try:
            self.start_ticks = self.state()[1]
        except BaseException:
            os.close(self.fd)
            raise

    def state(self) -> tuple[str, int]:
        fields = Path(f"/proc/{self.pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[0], int(fields[19])

    def task_states(self) -> dict[int, str]:
        result = {}
        for task in Path(f"/proc/{self.pid}/task").iterdir():
            try:
                result[int(task.name)] = (task / "stat").read_text().rsplit(") ", 1)[1].split()[0]
            except FileNotFoundError:
                continue
        return result

    def stopped(self) -> bool:
        states = self.task_states()
        return bool(states) and all(value == "T" for value in states.values())

    def terminal(self) -> bool:
        return bool(select.select([self.fd], [], [], 0)[0])

    def send(self, value: signal.Signals) -> None:
        signal.pidfd_send_signal(self.fd, value)

    def wait(self, timeout: float = 30) -> None:
        until(self.terminal, timeout=timeout, description=f"process {self.pid}/{self.start_ticks} not terminal")

    def reap(self, *, code: int | None = None) -> None:
        self.wait()
        pid, status = os.waitpid(self.pid, 0)
        assert pid == self.pid
        if code is not None:
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == code, (pid, status)

    def close(self) -> None:
        os.close(self.fd)


@contextmanager
def subreaper():
    # The monitor daemon double-forks. Adopt only this test's descendants so
    # watchdog exit125 can be observed with waitpid rather than guessed from ps.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "child subreaper")
    try:
        yield
    finally:
        if libc.prctl(36, previous.value, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "restore child subreaper")


@contextmanager
def owned_processes(*processes: Process):
    try:
        yield
    finally:
        # Never kill a name/group or a reused PID, even on assertion failure.
        for process in reversed(processes):
            if not process.terminal():
                try:
                    process.send(signal.SIGCONT)
                    process.send(signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for process in reversed(processes):
            try:
                process.reap()
            except ChildProcessError:
                pass
            finally:
                process.close()


def holder(silo: Silo, name: str) -> tuple[dict, Path]:
    machine_id = procs.machine_id(silo.ws, name)
    run_id = procs.run_id(silo.ws, name)
    path = silo.ws.run_root / "machines" / machine_id / "vm.storage-holder.json"
    raw = path.read_bytes()
    assert len(raw) <= 4096
    value = json.loads(raw)
    assert value["schemaVersion"] == 1
    assert UUID(value["machineId"]) == UUID(machine_id)
    assert UUID(value["runId"]) == UUID(run_id)
    assert UUID(value["operationId"]).int != 0
    assert {entry["role"] for entry in value["holders"]} == {"monitor", "krun-worker"}
    assert len(value["holders"]) == 2 and all(entry["startedAt"] > 0 for entry in value["holders"])
    boot_seconds = int(next(line.split()[1] for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime ")))
    for entry in value["holders"]:
        fields = Path(f"/proc/{entry['pid']}/stat").read_text().rsplit(") ", 1)[1].split()
        assert fields[0] not in ("Z", "X")
        assert entry["startedAt"] == boot_seconds + int(fields[19]) // os.sysconf("SC_CLK_TCK")
    lease = silo.ws.silo_home / "images/locks/leases" / (value["operationId"] + ".lease")
    metadata = lease.stat()
    assert stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1 and metadata.st_uid == os.geteuid()
    rows = procs.query(silo.ws.state_db(), "SELECT file_device,file_inode FROM storage_operation WHERE replace(operation_id,'-','')='" + UUID(value["operationId"]).hex + "'")
    assert rows == [(str(metadata.st_dev), str(metadata.st_ino))], "stable lease inode differs from the original registered OFD"
    silo.ws.record("shutdown-holder", json.dumps(value, sort_keys=True) + "\n")
    return value, lease


def lease_busy(path: Path) -> bool:
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)  # close only; never unlock an inherited OFD


def handles(silo: Silo, pid: int, paths: list[Path]) -> dict[str, list[int]]:
    expected = {(path.stat().st_dev, path.stat().st_ino): str(path) for path in paths}
    found = {str(path): [] for path in paths}
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            metadata = fd.stat()
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in expected:
                found[expected[identity]].append(int(fd.name))
        except FileNotFoundError:
            continue
    assert all(found.values()), (pid, found)
    silo.ws.record("shutdown-inodes", json.dumps({"pid": pid, "identities": [list(key) for key in expected], "fds": found}) + "\n")
    return found


def exit_record(silo: Silo, name: str, run_id: str) -> dict:
    machine_id = procs.machine_id(silo.ws, name)
    path = silo.ws.silo_home / "logs/machines" / machine_id / "vm.exit.json"
    def current():
        if not path.is_file():
            return None
        value = json.loads(path.read_text())
        return value if UUID(value["runId"]) == UUID(run_id) else None
    value = until(current, timeout=90, description="no exact current-run exit record")
    assert UUID(value["machineId"]) == UUID(machine_id)
    silo.ws.record("shutdown-exit", json.dumps(value, sort_keys=True) + "\n")
    return value


def outcome(silo: Silo, name: str) -> str:
    machine_id = procs.machine_id(silo.ws, name)
    rows = procs.query(silo.ws.state_db(), "SELECT json_extract(record_json,'$.stopOutcome') FROM machine_storage WHERE machine_id='" + machine_id + "'")
    assert len(rows) == 1
    return rows[0][0]


def storage_tool(silo: Silo, *args: str) -> None:
    binary = silo.ws.config.bin_dir / "examples/storage_acceptance"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/storage_acceptance"
    assert binary.is_file(), "Main must build cargo build -p libvm --example storage_acceptance"
    result = subprocess.run([str(binary), *args], env=silo.ws.env(), capture_output=True, text=True, timeout=90)
    silo.ws.record("shutdown-storage-api", result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr


def assert_clean(silo: Silo, name: str, value: dict) -> None:
    assert value["outcome"] == "clean"
    assert value["storageShutdown"] == {"version": 1, "guestProtocolCompleted": True, "hostFlushCompleted": True, "attachmentsClosed": True}
    assert outcome(silo, name) == "clean"
    assert silo.info(name)["storage_stop_outcome"] == "clean"


def write_raw_data(silo: Silo, name: str) -> None:
    """Actual raw Data write, deliberately unsupported for clean certification."""
    silo.exec(name, "sh", "-c", 'set -eu; device=""; for p in /sys/block/*; do if test "$(cat "$p/serial" 2>/dev/null)" = silo-data-0; then device=/dev/${p##*/}; fi; done; test -n "$device"; printf "raw-data-before-stop\\n" | dd of="$device" bs=512 count=1 conv=sync,notrunc; sync', user="root")


def assert_failed_completion(log_directory: Path, run_id: str) -> None:
    """Require the host's exact-run FAILED receipt, not a guest terminal log."""
    import re

    expected = UUID(run_id)
    with (log_directory / "vm.trace.log").open(errors="replace") as stream:
        for raw in stream:
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            if "guest shutdown completion observed" not in line or "result=Some(2)" not in line:
                continue
            identity = re.search(r"\brun_id=([0-9a-f-]+)", line)
            if identity is not None and UUID(identity.group(1)) == expected:
                return
    raise AssertionError("no exact-run host-observed COMPLETED/FAILED receipt; timeout is not sticky-error proof")
