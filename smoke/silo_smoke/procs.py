from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any

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


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def query(db: Path, sql: str) -> list[tuple[str, ...]]:
    try:
        result = subprocess.run(["sqlite3", "-readonly", "-separator", "\x1f", str(db), sql], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeAssertion(f"Cannot query {db}: {error}") from error
    if result.returncode:
        raise SmokeAssertion(f"Query failed for {db}: {result.stderr}")
    return [tuple(row.split("\x1f")) for row in result.stdout.splitlines()]


def _name(name: str) -> str:
    return "'" + name.replace("'", "''") + "'"


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
