"""macOS krun live acceptance and early, typed VZ refusals."""
from __future__ import annotations

import time

import pytest

from silo_smoke import cloud_disk, hibernate, restore, stopped
from silo_smoke.cli import Result, Silo

pytestmark = pytest.mark.macos_only

VZ_HINT = "snapshots, forks and live operations need the krun backend"


def _running(silo: Silo, name: str, image: str) -> None:
    silo.create(name, image, "--cpus", "1", "--memory", "512mib", "--network", "none", "--vsock")
    silo.start(name)
    silo.wait_ready(name)


def _published(silo: Silo) -> tuple[dict, list[str]]:
    catalog = stopped.catalog(silo)
    machines = silo.ws.silo_home / "machines"
    return ({table: catalog[table] for table in cloud_disk.PUBLISHED_TABLES},
            sorted(path.name for path in machines.iterdir()) if machines.is_dir() else [])


def _refuse(silo: Silo, running: bool, *args: str) -> Result:
    """A running guest keeps writing its own disk, so its files cannot be compared byte for byte."""
    if not running:
        return cloud_disk.refuse_before_publication(silo, *args)
    before = _published(silo)
    result = silo.run(*args, expect=None)
    assert result.returncode != 0, (args, result.stdout, result.stderr)
    assert _published(silo) == before, ("catalog publication or machine set changed", args)
    return result


def _refused(silo: Silo, name: str, expected: str, hint: str, *args: str) -> None:
    before = silo.info(name)["state"]
    result = _refuse(silo, before == "running", *args)
    assert expected in result.stderr, (args, result.stderr)
    assert result.stderr.strip().endswith(hint), (args, result.stderr)
    assert result.stdout == "", (args, result.stdout)
    assert silo.info(name)["state"] == before, args


@pytest.mark.krun_live
def test_krun_memory_snapshot_restore_fork_hibernate_and_wake(silo: Silo, basic_image: str) -> None:
    source, restored, forked = "live-source", "live-restored", "live-forked"
    hibernate.create(silo, basic_image, source)
    original = silo.info(source)
    boot = hibernate.boot_id(silo, source)
    marker = "/dev/shm/macos-live-marker"
    silo.exec(source, "sh", "-ec", f"printf live-cut >{marker}", user="root")

    def check_running(name: str) -> dict:
        info = silo.wait_ready(name)
        assert info["state"] == "running"
        assert silo.exec(name, "cat", marker).stdout == "live-cut"
        assert hibernate.boot_id(silo, name) == boot
        before = time.time()
        guest = int(silo.exec(name, "date", "+%s").stdout)
        after = time.time()
        assert before - 3 <= guest <= after + 3, (name, before, guest, after)
        return info

    saved = silo.json("snapshot", "create", source, "--memory", "--name", "macos-live-cut", timeout=240)
    assert saved["snapshot"]["memory"] == "included"
    assert check_running(source)["run_id"] == original["run_id"]
    restore.restore(silo, "macos-live-cut", restored, expect=0)
    assert check_running(restored)["id"] != original["id"]

    silo.ws.register_machine(forked)
    fork = silo.json("fork", source, "--live", "--name", forked, timeout=240)
    assert fork["children"][0]["outcome"]["kind"] == "running"
    assert check_running(forked)["id"] != original["id"]
    assert check_running(source)["run_id"] == original["run_id"]

    silo.run("hibernate", source, timeout=240)
    assert silo.info(source)["state"] == "hibernated"
    silo.start(source)
    awake = check_running(source)
    assert awake["id"] == original["id"] and awake["run_id"] != original["run_id"]

    for name in (restored, forked, source):
        silo.stop(name)
        silo.rm(name)
    silo.run("snapshot", "rm", "macos-live-cut")


def test_vz_refuses_everything_beyond_the_basic_lifecycle(silo: Silo, basic_image: str) -> None:
    if silo.ws.config.backend != "vz":
        pytest.skip("requires --backend vz")
    name = "refusal-vz"
    silo.run("image", "convert", basic_image, "--disk-format", "raw", "--name", "refusal-vz-raw", timeout=600)
    _running(silo, name, "refusal-vz-raw")
    excluded = "backend-excluded (backend=vz, lane=not-applicable)"
    try:
        _refused(silo, name, f"pause unsupported: {excluded}", VZ_HINT, "pause", name)
        _refused(silo, name, f"capture unsupported: {excluded}", VZ_HINT, "snapshot", "create", name, "--memory", "--name", "refused-memory")
        _refused(silo, name, f"fork unsupported: {excluded}", VZ_HINT, "fork", name, "--live", "--name", "refused-live")
        _refused(silo, name, f"capture unsupported: {excluded}", VZ_HINT, "hibernate", name)
        assert silo.exec(name, "true").returncode == 0, "refusals must leave the guest reachable"
    finally:
        silo.stop(name, timeout="60s")
    _refused(silo, name, f"capture unsupported: {excluded}", VZ_HINT, "snapshot", "create", name, "--name", "refused-stopped")
    _refused(silo, name, f"fork unsupported: {excluded}", VZ_HINT, "fork", name, "--name", "refused-fork")
    for mode in ((), ("--without-memory",)):
        result = cloud_disk.refuse_before_publication(silo, "restore", "no-such-snapshot", "--name", "refused-restore", "--pull", "never", *mode)
        assert f"restore unsupported: {excluded}" in result.stderr, (mode, result.stderr)
        assert result.stderr.strip().endswith(VZ_HINT), (mode, result.stderr)
