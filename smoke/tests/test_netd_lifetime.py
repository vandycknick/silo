from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import time

import pytest

from silo_smoke import procs
from silo_smoke.cli import Silo
from silo_smoke.workspace import Workspace

pytestmark = pytest.mark.linux_only


def _execute(db: Path, sql: str) -> None:
    result = subprocess.run(["sqlite3", str(db), sql], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def _pid(value: int | None) -> int:
    assert isinstance(value, int) and value > 0, value
    return value


def test_netd_lifetime(silo: Silo, workspace: Workspace, basic_image: str) -> None:
    broken, healthy = "lifetime-broken", "lifetime-healthy"
    for name in (broken, healthy):
        silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock")
        silo.start(name)
        silo.wait_ready(name)
    suspended = _pid(procs.vmm_pid(workspace, broken))
    os.kill(suspended, signal.SIGSTOP)
    try:
        started = time.monotonic()
        stalled = silo.show(broken)
        assert time.monotonic() - started < 5
        assert stalled["state"] == "running"
        assert stalled["ready"] is False
        assert any(issue["component"] == "telemetry" for issue in stalled["issues"])
        assert silo.show(healthy)["state"] == "running"
    finally:
        os.kill(suspended, signal.SIGCONT)
    before = procs.machine_state_json(workspace, broken)
    helper = _pid(procs.netd_pid(workspace, broken))
    os.kill(helper, signal.SIGKILL)
    procs.wait_gone(helper, timeout=20)
    snapshot = silo.show(broken)
    assert snapshot["state"] == "running"
    assert any(issue["component"] == "network" for issue in snapshot["issues"])
    assert procs.machine_state_json(workspace, broken) == before
    listing = silo.ls()
    assert len(listing) == 2
    assert {item["name"] for item in listing} == {broken, healthy}
    assert all(item["state"] == "running" for item in listing)
    assert "Details: silo show" not in silo.run("ls", "--format", "json").stdout
    assert silo.run("ls").returncode == 0
    assert "Issue (Network)" in silo.run("show", broken).stdout
    assert "generation started" in silo.run("logs", broken, "--stream", "network").stdout
    healthy_helper = _pid(procs.netd_pid(workspace, healthy))
    silo.stop(healthy)
    procs.wait_gone(healthy_helper, timeout=20)
    assert silo.show(healthy)["state"] == "stopped"
    assert procs.query(workspace.state_db(), "SELECT status FROM machine_state s JOIN machine_config c ON c.id=s.machine_id WHERE c.name='lifetime-healthy'") == [("stopped",)]
    silo.start(healthy)
    silo.wait_ready(healthy)
    healthy_helper = _pid(procs.netd_pid(workspace, healthy))
    monitor = _pid(procs.vmm_pid(workspace, healthy))
    os.kill(monitor, signal.SIGKILL)
    procs.wait_gone(healthy_helper, timeout=20)
    procs.wait_gone(monitor, timeout=20)
    assert silo.show(healthy)["state"] == "stopped"
    db = workspace.state_db()
    original = procs.query(db, "SELECT hex(state_json) FROM machine_state s JOIN machine_config c ON c.id=s.machine_id WHERE c.name='lifetime-healthy'")
    assert len(original) == 1
    try:
        _execute(db, "UPDATE machine_state SET state_json=x'00' WHERE machine_id=(SELECT id FROM machine_config WHERE name='lifetime-healthy')")
        unknown = silo.show(healthy)
        assert unknown["name"] == healthy
        assert unknown["state"] == "unknown"
        assert unknown["observation"] == "unavailable"
        listing = silo.ls()
        assert len(listing) == 2
        assert {item["name"] for item in listing} == {broken, healthy}
        assert next(item for item in listing if item["name"] == healthy)["observation"] == "unavailable"
        assert silo.run("logs", healthy, "--stream", "network").stdout != ""
    finally:
        _execute(db, f"UPDATE machine_state SET state_json=x'{original[0][0]}' WHERE machine_id=(SELECT id FROM machine_config WHERE name='lifetime-healthy')")
    missing = silo.run("start", healthy, "-v", env=workspace.env(NETD_BIN=str(workspace.root / "missing-netd")), expect=1, timeout=10)
    assert missing.returncode == 1
    assert "NETD_BIN" in missing.stderr
    assert str(workspace.root / "missing-netd") in missing.stderr
