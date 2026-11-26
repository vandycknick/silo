"""What a macOS host cannot do yet is refused early, typed, and without side effects.

krun on macOS runs pause and resume only; VZ runs neither. Every other live or
stopped-storage operation a backend lacks must fail before it changes the
catalog, a machine directory or the machine's state.
"""
from __future__ import annotations

import pytest

from silo_smoke import cloud_disk, stopped
from silo_smoke.cli import Result, Silo

pytestmark = pytest.mark.macos_only

KRUN_HINT = "use silo stop, then a snapshot without memory"
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


def test_krun_refuses_memory_operations_and_keeps_the_machine_running(silo: Silo, basic_image: str) -> None:
    if silo.ws.config.backend != "krun":
        pytest.skip("requires --backend krun")
    name = "refusal-krun"
    _running(silo, name, basic_image)
    try:
        reason = "build-excluded (backend=krun, lane=hvf-arm64)"
        _refused(silo, name, f"capture unsupported: {reason}", KRUN_HINT, "snapshot", "create", name, "--memory", "--name", "refused-memory")
        _refused(silo, name, f"fork unsupported: {reason}", KRUN_HINT, "fork", name, "--live", "--name", "refused-live")
        _refused(silo, name, f"capture unsupported: {reason}", KRUN_HINT, "hibernate", name)
        assert silo.exec(name, "true").returncode == 0, "refusals must leave the guest reachable"

        resumed = silo.run("resume", name, expect=None)
        assert resumed.returncode != 0
        assert resumed.stderr.strip() == f"error: machine `{name}` is not paused", resumed.stderr
        assert silo.info(name)["state"] == "running"
    finally:
        silo.stop(name)


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
