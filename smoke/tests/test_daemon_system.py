from __future__ import annotations

from uuid import UUID

import pytest

from silo_smoke import procs
from silo_smoke.config import SmokeConfig
from silo_smoke.daemon import Silod
from silo_smoke.workspace import Workspace

pytestmark = [pytest.mark.daemon, pytest.mark.system]


def _identity(workspace: Workspace) -> tuple[str, str, str, str]:
    rows = procs.query(workspace.state_db(), "SELECT c.id, json_extract(s.state_json,'$.vmmonPid'), json_extract(s.state_json,'$.runId'), json_extract(n.driver_state_json,'$.helper_pid') FROM machine_config c JOIN machine_state s ON s.machine_id=c.id JOIN network_attachments a ON a.machine_id=c.id JOIN network_instances n ON n.id=a.network_instance_id WHERE s.status='running' ORDER BY c.id")
    assert len(rows) == 1, rows
    assert len(rows[0]) == 4, rows
    machine_id, vmm, run_id, netd = rows[0]
    assert UUID(machine_id).hex == machine_id
    assert str(UUID(run_id)) == run_id
    assert int(vmm) > 0
    assert int(netd) > 0
    return machine_id, vmm, run_id, netd


def test_graceful_restart_adopts_running_appliance(daemon: Silod, workspace: Workspace, config: SmokeConfig) -> None:
    if config.system_image is None:
        pytest.skip("SILO_SMOKE_SYSTEM_IMAGE not set")
    args = (
        "--system-enabled=true", "--system-image", config.system_image,
        "--system-backend", config.backend, "--system-cpus", "1",
        "--system-memory", "1GiB", "--system-root-size", "2GiB",
        "--system-data-size", "512MiB", "--system-home-share", "false",
        "--system-rosetta", "false",
    )
    try:
        daemon.start(*args)
        status = daemon.wait_system("ready", 150)
        before = _identity(workspace)
        _, vmm, _, netd = before
        restarts = status["system"]["restart_count"]
        assert daemon.terminate() == 0
        assert daemon.wait_core("stopped")["core"] == "stopped"
        assert procs.alive(int(vmm)) is True
        assert procs.alive(int(netd)) is True
        assert _identity(workspace) == before
        daemon.start(*args)
        restarted = daemon.wait_system("ready", 60)
        assert _identity(workspace) == before
        assert restarted["system"]["restart_count"] == restarts
        assert daemon.terminate() == 0
        assert daemon.wait_core("stopped")["core"] == "stopped"
        assert daemon.stop_installation().returncode == 0
        procs.wait_gone(int(vmm), timeout=20)
        procs.wait_gone(int(netd), timeout=20)
        assert procs.alive(int(vmm)) is False
        assert procs.alive(int(netd)) is False
    finally:
        daemon.terminate()
        daemon.stop_installation()
