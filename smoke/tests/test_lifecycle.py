from __future__ import annotations

import platform
import stat
from uuid import UUID

from silo_smoke import overlay, shutdown
from silo_smoke.cli import Silo
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


def test_create_start_ready_stop_restart_rm(
    silo: Silo, workspace: Workspace, basic_image: str, registry: LoopbackRegistry,
) -> None:
    name = "lifecycle-vm"
    created = silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    assert created["state"] == "stopped"
    assert created["observation"] == "observed"
    assert created["ready"] is False
    assert created["run_id"] is None
    assert created["rootfs"]["source_kind"] == "oci"
    assert created["resources"] == {"cpus": 1, "memory_mib": 512}
    assert registry.requests > 0
    silo.start(name)
    running = silo.wait_ready(name)
    assert running["state"] == "running"
    assert running["ready"] is True
    assert running["guest"]["boot"]["agent_is_pid1"] is True
    run_id = running["run_id"]
    assert str(UUID(run_id)) == run_id
    known_host = workspace.known_host(created["id"])
    secrets = workspace.machine_secrets(created["id"])
    host_bytes = known_host.read_bytes()
    secret_bytes = secrets.read_bytes()
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o600
    processes = ()
    lease = None
    if platform.system() == "Linux":
        bound, lease = shutdown.holder(silo, name)
        identities = {entry["role"]: entry["pid"] for entry in bound["holders"]}
        monitor = shutdown.Process(identities["monitor"])
        worker = shutdown.Process(identities["krun-worker"])
        processes = (monitor, worker)
        assert overlay.worker_pid_of_monitor(monitor.pid) == worker.pid
        root = workspace.silo_home / "machines" / created["id"] / "root.raw"
        for process in processes:
            shutdown.handles(silo, process.pid, [root, lease])
    try:
        silo.stop(name, timeout="20s")
        if platform.system() == "Linux":
            terminal = shutdown.exit_record(silo, name, run_id)
            for process in processes:
                process.wait()
            assert lease is not None and not shutdown.lease_busy(lease)
            shutdown.assert_clean(silo, name, terminal)
            assert overlay.ext4(root)["incompat"] & 4 == 0
    finally:
        for process in processes:
            process.close()
    assert silo.info(name)["state"] == "stopped"
    silo.start(name)
    restarted = silo.wait_ready(name)
    assert restarted["state"] == "running"
    assert restarted["ready"] is True
    assert str(UUID(restarted["run_id"])) == restarted["run_id"]
    assert restarted["run_id"] != run_id
    assert known_host.read_bytes() == host_bytes
    assert secrets.read_bytes() == secret_bytes
    silo.stop(name, timeout="20s")
    silo.rm(name)
    removed = silo.run("info", name, expect=1)
    assert "not found" in removed.stderr
    assert silo.ls() == []


def test_info_unavailable_without_runtime(silo: Silo) -> None:
    result = silo.run("info", "never-created", expect=1)
    assert result.stderr != ""
    assert "not found" in result.stderr


def test_boot_failure_leaves_machine_stopped(
    silo: Silo, basic_image: str,
) -> None:
    name = "failed-boot"
    # Admission accepts positive memory; this cannot hold the packaged kernel.
    silo.create(name, basic_image, "--cpus", "1", "--memory", "1mib", "--vsock", "--network", "none")
    result = silo.run("start", name, expect=None)
    assert result.returncode != 0
    assert silo.info(name)["state"] == "stopped"
    assert silo.run("rm", name, "--force").returncode == 0
