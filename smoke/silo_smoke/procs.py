from __future__ import annotations

from collections.abc import Iterator
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import time
from typing import Any
from uuid import UUID

from .errors import SmokeAssertion
from .workspace import Workspace


def alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_gone(pid: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while alive(pid):
        if time.monotonic() >= deadline:
            raise SmokeAssertion(f"Process {pid} did not exit and get reaped within {timeout}s")
        time.sleep(0.05)


def krun_workers(monitor: int) -> list[int]:
    """Find direct worker children independently of Silo's catalog."""
    if platform.system() == "Darwin":
        # Darwin has no PR_SET_NAME. Match the worker's exact argv, not the
        # executable name it shares with the monitor.
        result = subprocess.run(
            ["/usr/bin/pgrep", "-P", str(monitor), "-fx", "krun"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 1:
            return []
        result.check_returncode()
        return [int(pid) for pid in result.stdout.split()]

    children: set[str] = set()
    try:
        for task in Path(f"/proc/{monitor}/task").iterdir():
            try:
                children.update((task / "children").read_text().split())
            except FileNotFoundError:
                continue
    except FileNotFoundError:
        return []
    workers = []
    for pid in sorted(map(int, children)):
        try:
            if Path(f"/proc/{pid}/comm").read_text().strip() == "krun":
                workers.append(pid)
        except FileNotFoundError:
            continue
    return workers


def executable_path(pid: int) -> Path:
    """Executable selected by the kernel, not the process's mutable argv."""
    if platform.system() != "Darwin":
        return Path(f"/proc/{pid}/exe")
    proc_pidpath = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_pidpath
    proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    proc_pidpath.restype = ctypes.c_int
    path = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE
    if proc_pidpath(pid, path, len(path)) <= 0:
        error = ctypes.get_errno()
        if error == errno.ESRCH:
            raise FileNotFoundError(error, os.strerror(error), pid)
        raise OSError(error, os.strerror(error), pid)
    return Path(os.fsdecode(path.value))


def file_access_modes(pid: int) -> Iterator[tuple[int, str, int]]:
    """Yield numeric descriptors, their paths and read/write access modes."""
    if platform.system() == "Darwin":
        result = subprocess.run(
            ["/usr/sbin/lsof", "-n", "-P", "-p", str(pid), "-F0fan"],
            capture_output=True, check=True, timeout=10,
        )
        access = {b"r": os.O_RDONLY, b"w": os.O_WRONLY, b"u": os.O_RDWR}
        for record in result.stdout.split(b"\0\n"):
            fields = {field[:1]: field[1:] for field in record.split(b"\0") if field}
            fd, mode, path = fields.get(b"f", b""), fields.get(b"a"), fields.get(b"n")
            if fd.isdigit() and mode in access and path is not None:
                yield int(fd), os.fsdecode(path), access[mode]
        return

    process = Path(f"/proc/{pid}")
    for fd in (process / "fd").iterdir():
        try:
            path = os.readlink(fd)
            info = (process / "fdinfo" / fd.name).read_text()
        except FileNotFoundError:
            continue
        flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith("flags:")), 8)
        yield int(fd.name), path, flags & os.O_ACCMODE


def thread_states(ws: Workspace, command: str) -> str:
    """Capture thread scheduling evidence without logging process environments."""
    roots = (os.fsencode(ws.root), os.fsencode(ws.run_root))
    sample_threads = _darwin_thread_sample if platform.system() == "Darwin" else _linux_thread_sample
    lines = [f"$ silo {command} timed out"]
    for sample in range(2):
        lines.append(f"sample {sample}")
        try:
            lines.extend(sample_threads(roots))
        except (OSError, subprocess.SubprocessError) as error:
            lines.append(f"thread inspection unavailable: {error}")
        if sample == 0:
            time.sleep(1)
    return "\n".join(lines) + "\n"


def _darwin_thread_sample(roots: tuple[bytes, ...]) -> list[str]:
    listing = subprocess.run(
        ["/bin/ps", "-axwwE", "-o", "pid=,command="],
        capture_output=True, check=True, timeout=5,
    )
    pids = []
    for line in listing.stdout.splitlines():
        pid, _, identity = line.strip().partition(b" ")
        if pid.isdigit() and any(root in identity for root in roots):
            pids.append(os.fsdecode(pid))
    if not pids:
        return []
    threads = subprocess.run(
        ["/bin/ps", "-wwM", "-p", ",".join(pids)],
        capture_output=True, check=False, text=True, errors="replace", timeout=5,
    )
    # A process can exit between enumeration and thread sampling.
    return threads.stdout.splitlines() + threads.stderr.splitlines()


def _linux_thread_sample(roots: tuple[bytes, ...]) -> Iterator[str]:
    for process in sorted(Path("/proc").glob("[0-9]*"), key=lambda path: int(path.name)):
        try:
            cmdline = (process / "cmdline").read_bytes()
            identity = cmdline + (process / "environ").read_bytes()
            if not any(root in identity for root in roots):
                continue
            arguments = cmdline.replace(b"\0", b" ").decode(errors="replace")
            yield f"pid {process.name} {arguments[:200]}"
            for task in sorted((process / "task").iterdir(), key=lambda path: int(path.name)):
                fields = (task / "stat").read_text().rsplit(") ", 1)[1].split()
                yield (f"  {(task / 'comm').read_text().strip():<18} state={fields[0]} "
                       f"utime={fields[11]} stime={fields[12]} wchan={(task / 'wchan').read_text() or '-'}")
        except (OSError, IndexError, ValueError):
            continue


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def bound_port(status: bytes) -> int:
    """Read the port actually owned by a session forward that requested port zero."""
    match = re.search(rb"(?m)^Forwarding host:tcp:127\.0\.0\.1:([0-9]+) -> [^\n]+\n", status)
    assert match is not None, f"Missing bound forwarding address: {status!r}"
    port = int(match[1])
    assert 0 < port <= 65535, status
    return port


def query(db: Path, sql: str) -> list[tuple[str, ...]]:
    try:
        result = subprocess.run(
            ["sqlite3", "-readonly", "-cmd", ".timeout 5000", "-separator", "\x1f", str(db), sql],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeAssertion(f"Cannot query {db}: {error}") from error
    if result.returncode:
        raise SmokeAssertion(f"Query failed for {db}: {result.stderr}")
    return [tuple(row.split("\x1f")) for row in result.stdout.splitlines()]


def catalog(db: Path) -> dict[str, list[tuple[str, ...]]]:
    """Observe the complete catalog in one independent read transaction."""
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("catalog_observer.py")), str(db)],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeAssertion(f"Cannot observe {db}: {error}") from error
    if result.returncode:
        raise SmokeAssertion(f"Catalog observation failed for {db}: {result.stderr}")
    return {table: [tuple(row) for row in rows] for table, rows in json.loads(result.stdout).items()}


def _name(name: str) -> str:
    return "'" + name.replace("'", "''") + "'"


def machine_id(ws: Workspace, name: str) -> str:
    # Path lookup needs catalog identity, not live status reconciliation.
    # Keep this in the separate read-only process used by all catalog oracles.
    rows = query(ws.state_db(), f"SELECT id FROM machine_config WHERE name={_name(name)}")
    assert len(rows) == 1
    identity = UUID(rows[0][0]).hex
    assert identity == rows[0][0]
    return identity


def _state_value(ws: Workspace, name: str, expression: str) -> str | None:
    rows = query(ws.state_db(), f"SELECT {expression} FROM machine_state s JOIN machine_config c ON c.id=s.machine_id WHERE c.name={_name(name)}")
    return rows[0][0] or None if rows else None


def machine_state_json(ws: Workspace, name: str) -> dict[str, Any]:
    value = _state_value(ws, name, "json(state_json)")
    if value is None:
        raise SmokeAssertion(f"No machine state for {name}")
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise SmokeAssertion(f"Machine state for {name} is not a JSON object")
    return parsed


def vmm_pid(ws: Workspace, name: str) -> int | None:
    value = _state_value(ws, name, "json_extract(state_json,'$.vmmonPid')")
    return int(value) if value is not None else None


def run_id(ws: Workspace, name: str) -> str | None:
    return _state_value(ws, name, "json_extract(state_json,'$.runId')")


def netd_pid(ws: Workspace, name: str) -> int | None:
    rows = query(ws.state_db(), "SELECT json_extract(n.driver_state_json,'$.helper_pid') FROM network_instances n JOIN network_attachments a ON a.network_instance_id=n.id JOIN machine_config c ON c.id=a.machine_id WHERE c.name=" + _name(name))
    return int(rows[0][0]) if rows and rows[0][0] else None
