"""ADR 0023 item 8, real child-only syscall holds and pidfd process death.

These are expressible pre-durable and pre-consume boundaries, not power-loss
injection or an exhaustive test of every durable-row crash window.
"""
from __future__ import annotations

import platform
import signal

import pytest

from silo_smoke import hibernate, procs, shutdown, stopped
from silo_smoke import restore_lifecycle as lifecycle
from silo_smoke.cli import Silo

pytestmark = [pytest.mark.linux_only, pytest.mark.slow,
              pytest.mark.skipif(platform.machine() != "x86_64", reason="child-only syscall controller is x86_64")]
NAME = "hibernate-crash"


def finish(trace: hibernate.Trace, silo: Silo) -> None:
    trace.release()
    silo.stop(NAME, force=True)
    trace.command("finish")
    assert trace.controller.wait(timeout=120) == 0, trace.evidence


def test_manager_killed_before_memory_save_completes(silo: Silo, basic_image: str) -> None:
    hibernate.create(silo, basic_image, NAME, start=False)
    target = stopped.writable_paths(silo, NAME)["root"]
    with hibernate.traced(silo, NAME, waking=False, target=target) as trace:
        assert trace.wait("started.json")["code"] == 0
        silo.wait_ready(NAME)
        boot = hibernate.boot_id(silo, NAME)
        silo.exec(NAME, "sh", "-ec", "printf before-crash >/hibernate-crash-marker", user="root")
        trace.command("hibernate")
        receipt = trace.held()
        assert receipt["target"].endswith("/memory.ram"), receipt
        manager = shutdown.Process(trace.wait("manager.json")["pid"])
        try:
            manager.send(signal.SIGKILL)
            trace.release()
            manager.wait()
            assert trace.wait("result.json")["code"] != 0
            state = silo.info(NAME)["state"]
            assert state in {"running", "hibernated"}, state
            if state == "hibernated":
                hibernate.wake(silo, NAME)
            else:
                silo.wait_ready(NAME)
            assert hibernate.boot_id(silo, NAME) == boot
            assert silo.exec(NAME, "cat", "/hibernate-crash-marker").stdout == "before-crash"
            # A fresh save/wake proves recovery did not leave a wedged capture.
            hibernate.save(silo, NAME)
            hibernate.wake(silo, NAME)
            assert hibernate.boot_id(silo, NAME) == boot
            finish(trace, silo)
        finally:
            manager.close()


@pytest.mark.parametrize("victim", ["monitor", "krun-worker"])
def test_preconsume_wake_process_death_leaves_retryable_save(
    silo: Silo, basic_image: str, victim: str,
) -> None:
    hibernate.create(silo, basic_image, NAME)
    boot = hibernate.boot_id(silo, NAME)
    silo.exec(NAME, "sh", "-ec", "printf before-wake >/hibernate-crash-marker", user="root")
    hibernate.save(silo, NAME)
    memory = hibernate.saved_directory(silo, NAME) / "memory.ram"
    before = {str(path): stopped.read_bytes(path) for path in hibernate.saved_files(silo, NAME)}
    with hibernate.traced(silo, NAME, waking=True, target=memory) as trace:
        receipt = trace.held()
        assert receipt["syscall"] == 9 and receipt["target"] == str(memory), receipt
        child = lifecycle.ChildProcesses.observe(silo, procs.machine_id(silo.ws, NAME))
        try:
            assert receipt["pid"] == child.processes["krun-worker"].pid, receipt
            child.processes[victim].send(signal.SIGKILL)
            trace.release()
            assert trace.wait("result.json")["code"] != 0
            child.reaped()
            assert silo.info(NAME)["state"] == "hibernated"
            assert {str(path): stopped.read_bytes(path) for path in hibernate.saved_files(silo, NAME)} == before
            assert procs.vmm_pid(silo.ws, NAME) is None
            hibernate.wake(silo, NAME)
            assert hibernate.boot_id(silo, NAME) == boot
            assert silo.exec(NAME, "cat", "/hibernate-crash-marker").stdout == "before-wake"
            finish(trace, silo)
        finally:
            child.close()
