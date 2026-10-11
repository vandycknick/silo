from __future__ import annotations

import shutil
import stat
import subprocess
import time
from uuid import UUID

import pytest

from silo_smoke.cli import Silo
from silo_smoke.daemon import Silod
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace

pytestmark = pytest.mark.daemon


def test_daemon_ready_status_and_cli_routing(
    daemon: Silod, silo: Silo, workspace: Workspace, registry: LoopbackRegistry,
) -> None:
    daemon.start()
    status = daemon.wait_core("ready")
    assert status["schema"] == 2
    assert status["pid"] == daemon.pid
    assert status["control_endpoint"] == str(daemon.control_sock)
    assert status["home"] == str(workspace.silo_home)
    assert status["system"] is None
    assert status["tailscale"]["state"] == "disabled"
    socket_stat = daemon.control_sock.stat()
    assert stat.S_ISSOCK(socket_stat.st_mode)
    assert stat.S_IMODE(socket_stat.st_mode) == 0o600
    routed = silo.json("daemon", "status")
    assert routed["state"] == "ready"
    assert routed["daemon"]["generation"] == status["generation"]
    second = Silod(workspace)
    started = time.monotonic()
    proc = second.start_raw("--system-enabled=false", "--tailscale-enabled=false", label="second-silod")
    assert proc.wait(timeout=10) == 1
    assert time.monotonic() - started < 10
    assert "another Silo system daemon owns this installation" in workspace.evidence_path("second-silod-1").read_text()
    requests = registry.requests
    assert silo.ls() == []
    assert registry.requests == requests
    assert workspace.state_db().is_file()
    assert not (workspace.user_home / ".silo" / "state.db").exists()
    assert daemon.terminate() == 0
    assert daemon.wait_core("stopped")["core"] == "stopped"
    assert not daemon.control_sock.exists()


def test_daemon_managed_vm_lifecycle(
    daemon: Silod, silo: Silo, workspace: Workspace,
    basic_image: str, registry: LoopbackRegistry,
) -> None:
    daemon.start()
    daemon.wait_core("ready")
    name = "daemon-vm"
    created = silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    assert created["state"] == "stopped"
    assert created["resources"] == {"cpus": 1, "memory_mib": 512}
    assert created["rootfs"]["source_kind"] == "oci"
    assert registry.requests > 0
    silo.start(name)
    first = silo.wait_ready(name)
    assert first["guest"]["boot"]["agent_is_pid1"] is True
    assert str(UUID(first["run_id"])) == first["run_id"]
    machine_id = first["id"]
    known_host = workspace.known_host(machine_id).read_bytes()
    secrets = workspace.machine_secrets(machine_id).read_bytes()
    assert stat.S_IMODE(workspace.machine_secrets(machine_id).stat().st_mode) == 0o600
    silo.stop(name)
    assert silo.show(name)["state"] == "stopped"
    silo.start(name)
    second = silo.wait_ready(name)
    assert second["run_id"] != first["run_id"]
    assert workspace.known_host(machine_id).read_bytes() == known_host
    assert workspace.machine_secrets(machine_id).read_bytes() == secrets
    proc = silo.popen("exec", name, "--", "sh", "-c", "sleep 3; echo survived", stdin=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        assert proc.poll() is None
        assert daemon.terminate() == 0
        stdout, stderr = proc.communicate(timeout=15)
        workspace.record("surviving-exec", f"{stdout.decode()}\n[stderr]\n{stderr.decode()}")
        assert proc.returncode == 0
        assert stdout == b"survived\n"
        assert stderr == b""
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    silo.stop(name)
    assert silo.show(name)["state"] == "stopped"
    silo.rm(name)
    assert silo.run("show", name, expect=1).returncode == 1
    assert silo.ls() == []


def test_cli_with_other_home_fails_closed(
    daemon: Silod, silo: Silo, workspace: Workspace, basic_image: str,
) -> None:
    daemon.start()
    daemon.wait_core("ready")
    other = workspace.root / "other-home"
    other.mkdir(mode=0o700)
    env = workspace.env(SILO_HOME=str(other))
    result = silo.run("ls", env=env, expect=1)
    assert result.returncode == 1
    assert "silod is bound to another Home/config root" in result.stderr
    dry_run = silo.run("create", basic_image, "--dry-run", "--format", "json", env=env)
    assert dry_run.returncode == 0


def test_daemon_managed_disk_create_update_remove(
    daemon: Silod, silo: Silo, workspace: Workspace, basic_image: str,
) -> None:
    daemon.start()
    daemon.wait_core("ready")
    source = silo.create(
        "disk-a", basic_image, "--cpus", "1", "--memory", "512mb",
        "--network", "none",
    )
    assert source["state"] == "stopped"
    disk = workspace.root / "disk.img"
    shutil.copyfile(source["rootfs"]["root_disk_path"], disk)
    created = silo.create(
        "disk-b", f"disk:{disk}", "--cpus", "2", "--no-agent",
        "--label", "k=v", "--network", "none",
    )
    assert created["state"] == "stopped"
    assert created["resources"]["cpus"] == 2
    assert created["labels"] == {"k": "v"}
    assert created["rootfs"]["source_kind"] == "disk"
    silo.run("set", "disk-b", "cpus=1")
    assert silo.show("disk-b")["resources"]["cpus"] == 1
    silo.rm("disk-b")
    assert silo.run("show", "disk-b", expect=1).returncode == 1
    assert [machine["name"] for machine in silo.ls()] == ["disk-a"]
