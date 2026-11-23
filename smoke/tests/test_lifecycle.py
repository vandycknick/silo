from __future__ import annotations

import platform
import stat
from uuid import UUID

import pytest

from silo_smoke import fork, overlay, restore, shutdown, stopped
from silo_smoke.cli import Silo
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


def test_create_start_ready_stop_restart_rm(
    silo: Silo, workspace: Workspace, basic_image: str, registry: LoopbackRegistry,
) -> None:
    name = "lifecycle-vm"
    silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    created = silo.info(name)
    assert created["state"] == "stopped"
    assert created["observation"] == "observed"
    assert created["ready"] is False
    assert created["run_id"] is None
    assert created["rootfs"]["source_kind"] == "oci"
    assert created["resources"] == {"cpus": 1, "memory_mib": 512}
    assert registry.requests > 0
    # Ordinary OCI creation defaults to the layered EROFS root, never raw.
    storage = stopped.record(silo, name)
    assert storage["root"]["kind"] == "linux-overlay", storage["root"]
    assert storage["root"]["lower"]["kind"] == "erofs-composition", storage["root"]
    root = stopped.writable_paths(silo, name)["root"]
    silo.start(name)
    running = silo.wait_ready(name)
    assert running["state"] == "running"
    assert running["ready"] is True
    assert running["guest"]["boot"]["agent_is_pid1"] is True
    assert overlay.filesystem_magic(silo, name, "/") == overlay.OVERLAYFS_SUPER_MAGIC
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


@pytest.mark.linux_only
@pytest.mark.slow
def test_restart_after_live_lineage_snapshot_removal_and_prune(
    silo: Silo, basic_image: str,
) -> None:
    source = "restart-lineage"
    silo.create(source, basic_image, "--cpus", "1", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")
    silo.start(source)
    silo.wait_ready(source)
    silo.exec(source, "sh", "-ec", "echo before >/restart-marker; sync", user="root")
    first = restore.checkpoint(silo, source, alias="restart-first", policy="full")
    assert first.seal["memory"]["mode"] == "full"
    silo.run("resume", source)
    silo.exec(source, "sh", "-ec", "echo after >/restart-marker; sync", user="root")
    second = restore.checkpoint(silo, source, alias="restart-second")
    assert second.seal["memory"]["mode"] == "incremental"
    silo.run("resume", source)
    restore.restore_child(silo, second, "restart-restored")
    call = fork.run(silo, source, ["restart-fork"], expect=0)
    assert fork.outcomes(call.result) == ["running"]
    for child in ("restart-restored", "restart-fork"):
        assert silo.exec(child, "cat", "/restart-marker").stdout.strip() == "after"
    silo.rm("restart-fork", force=True)
    for alias in ("restart-first", "restart-second"):
        silo.run("snapshot", "rm", alias)
    shutdown.storage_tool(silo, "prune")
    # The restored child's cold boot must not depend on its removed snapshot
    # or the force-removed sibling's capture ownership.
    silo.stop("restart-restored")
    silo.start("restart-restored")
    silo.wait_ready("restart-restored")
    assert silo.exec("restart-restored", "cat", "/restart-marker").stdout.strip() == "after"
    silo.rm("restart-restored", force=True)
    shutdown.storage_tool(silo, "prune")
    silo.stop(source)
    silo.start(source)
    silo.wait_ready(source)
    assert silo.exec(source, "cat", "/restart-marker").stdout.strip() == "after"
    third = restore.checkpoint(silo, source, alias="restart-after-stop")
    assert third.seal["memory"]["mode"] == "full"
    silo.run("resume", source)

    # Machine-lifetime lower and boot ownership must also survive removal of
    # the original source and the final snapshot, not just a sibling.
    restore.restore_child(silo, third, "restart-orphan-restored")
    call = fork.run(silo, source, ["restart-orphan-fork"], expect=0)
    assert fork.outcomes(call.result) == ["running"]
    silo.rm(source, force=True)
    silo.run("snapshot", "rm", third.snapshot)
    shutdown.storage_tool(silo, "prune")
    for child in ("restart-orphan-restored", "restart-orphan-fork"):
        silo.stop(child)
        silo.start(child)
        silo.wait_ready(child)
        assert silo.exec(child, "cat", "/restart-marker").stdout.strip() == "after"
    silo.rm("restart-orphan-restored", force=True)
    shutdown.storage_tool(silo, "prune")
    silo.stop("restart-orphan-fork")
    silo.start("restart-orphan-fork")
    silo.wait_ready("restart-orphan-fork")
    assert silo.exec("restart-orphan-fork", "cat", "/restart-marker").stdout.strip() == "after"
