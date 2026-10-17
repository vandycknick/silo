from __future__ import annotations

import os
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from silo_smoke import images, procs
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


pytestmark = pytest.mark.slow
SOCKET_UNIT = "sshd-vsock.socket"
JOURNAL = "journalctl -b --no-pager -o short-monotonic -t sshd -t sshd-session -t silo-agent; journalctl -b --no-pager -o short-monotonic -u sshd-vsock.socket -u 'sshd-vsock@*'"
RESTORE = "systemd-run --unit=silo-test-restore-ssh --on-active=75s --timer-property=AccuracySec=1s -- /bin/sh -c 'systemctl start sshd-vsock.socket'; systemctl is-active --quiet silo-test-restore-ssh.timer"
STOP = 'systemctl stop sshd-vsock.socket; test "$(systemctl show sshd-vsock.socket -p ActiveState --value)" = inactive'


@pytest.fixture(scope="session")
def iproute_image(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    return registry.publish(images.build(images.IPROUTE, images.fetch_alpine(config.cache_dir)), "iproute")


@pytest.fixture
def systemd_image(config: SmokeConfig) -> str:
    if config.systemd_image is None:
        pytest.skip("SILO_SMOKE_SYSTEMD_IMAGE not set")
    return config.systemd_image


def _listener(silo: Silo, name: str, *, systemd: bool) -> str:
    sockets = silo.exec(name, "ss", "--vsock", "-H", "-lpn", user="root").stdout
    listeners = [line for line in sockets.splitlines() if any(field.rpartition(":")[2] == "22" for field in line.split())]
    assert len(listeners) == 1, sockets
    listener = listeners[0]
    if systemd:
        assert "systemd" in listener and "pid=1," in listener, sockets
    else:
        assert "silo-agent" in listener, sockets
    return sockets


def _certificate_login(silo: Silo, name: str) -> None:
    login = silo.shell(name, "printf 'Silo certificate login qualified\\n'; exit 0\n", user="root")
    assert "Silo certificate login qualified" in login.stdout
    assert login.stderr == ""


def _start_systemd(silo: Silo, workspace: Workspace, image: str, name: str) -> None:
    userdata = workspace.root / "systemd-ssh.sh"
    userdata.write_text(
        "#!/bin/sh\nset -eu\n"
        "for binary in systemctl journalctl systemd-run ss timeout cat tee; do command -v \"$binary\"; done\n"
        "test -x /usr/lib/systemd/system-generators/systemd-ssh-generator\n"
        "test -x /usr/sbin/sshd\n"
        "timeout 15 /bin/sh -c 'until timeout 1 systemctl show --property=Version >/dev/null 2>&1; do sleep 0.2; done'\n"
        "timeout 5 systemctl daemon-reload\n"
        "timeout 5 systemctl start sshd-vsock.socket\n"
        "timeout 5 systemctl is-active --quiet sshd-vsock.socket\n"
    )
    silo.create(name, image, "--pull", "missing", "--vsock", "--cpus", "1", "--memory", "1GiB",
                "--network", "none", "--userdata", str(userdata))
    silo.start(name)
    silo.wait_ready(name, timeout=75)
    assert silo.exec(name, "systemctl", "is-active", SOCKET_UNIT).stdout.strip() == "active"
    _listener(silo, name, systemd=True)
    _certificate_login(silo, name)


@dataclass(frozen=True)
class ProcessSample:
    start_ticks: int
    cpu_ticks: int
    fds: int

    @classmethod
    def read(cls, pid: int) -> ProcessSample:
        root = Path(f"/proc/{pid}")
        fields = (root / "stat").read_text().rsplit(") ", 1)[1].split()
        return cls(int(fields[19]), int(fields[11]) + int(fields[12]), len(list((root / "fd").iterdir())))


def _profile_start(workspace: Workspace, name: str) -> tuple[int, ProcessSample] | None:
    if platform.system() != "Linux":
        return None
    pid = procs.vmm_pid(workspace, name)
    assert pid is not None
    assert "silo-vmm" in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[0].decode()
    return pid, ProcessSample.read(pid)


def _profile_finish(workspace: Workspace, initial: tuple[int, ProcessSample] | None, elapsed: float) -> None:
    if initial is None:
        return
    pid, before = initial
    after = ProcessSample.read(pid)
    assert after.start_ticks == before.start_ticks
    cpu = 100 * (after.cpu_ticks - before.cpu_ticks) / os.sysconf("SC_CLK_TCK") / elapsed
    workspace.record("ssh-profile", f"pid={pid} seconds={elapsed:.3f} one_core_cpu_percent={cpu:.4f} fds_before={before.fds} fds_after={after.fds}")
    assert cpu <= 1.0, f"silo-vmm CPU {cpu:.4f}% exceeds one-core 1% ceiling"
    assert after.fds <= before.fds + 2


def _fresh(silo: Silo, name: str) -> dict[str, Any]:
    status = silo.show(name)
    assert status["observation"] == "observed", status
    assert status["state"] == "running", status
    assert status["guest"]["status"] == "running", status
    assert status["guest"]["ready"] is status["ready"], status
    return status


def _sample_healthy(silo: Silo, workspace: Workspace, name: str) -> None:
    profile = _profile_start(workspace, name)
    started = time.monotonic()
    receipts: set[int | str] = set()
    for sample in range(13):
        if sample:
            time.sleep(max(0, started + sample * 5 - time.monotonic()))
        status = _fresh(silo, name)
        assert status["ready"] is True, status
        receipts.add(status["updated_at"])
    assert len(receipts) >= 8, f"only {len(receipts)} distinct status receipts over 60s"
    _profile_finish(workspace, profile, time.monotonic() - started)


def test_ssh_agent_owned_listener(silo: Silo, workspace: Workspace, iproute_image: str) -> None:
    name = "ssh-agent-owned"
    silo.create(name, iproute_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none")
    silo.start(name)
    ready = silo.wait_ready(name)
    assert ready["guest"]["boot"]["agent_is_pid1"] is True
    sockets = _listener(silo, name, systemd=False)
    workspace.record("listener-ownership", sockets)
    print(sockets, end="")
    _certificate_login(silo, name)
    _sample_healthy(silo, workspace, name)
    _listener(silo, name, systemd=False)


def test_ssh_systemd_owned_listener_and_idle_readiness(
    silo: Silo, workspace: Workspace, systemd_image: str,
) -> None:
    name = "ssh-systemd-owned"
    _start_systemd(silo, workspace, systemd_image, name)
    # Rust tests start the losing sshd-vsock.socket with an agent-owned listener.
    # Here PID 1 already owns that unit, so a second socket unit tests the same bind conflict.
    clash = silo.exec(name, "sh", "-eu", "-c", """
cat > /run/systemd/system/silo-smoke-clash.socket <<'EOF'
[Socket]
ListenStream=vsock::22
Accept=yes
EOF
cat > /run/systemd/system/silo-smoke-clash@.service <<'EOF'
[Service]
ExecStart=/bin/true
StandardInput=socket
EOF
systemctl daemon-reload
if systemctl start silo-smoke-clash.socket; then echo 'losing socket unexpectedly bound' >&2; exit 1; fi
test "$(systemctl show silo-smoke-clash.socket -p ActiveState --value)" = failed
journalctl -b -u silo-smoke-clash.socket --no-pager
""", user="root")
    assert "address already in use" in clash.stdout.lower() or "eaddrinuse" in clash.stdout.lower(), clash.stdout
    silo.exec(name, "sh", "-c", JOURNAL)
    _sample_healthy(silo, workspace, name)
    _listener(silo, name, systemd=True)
    silo.exec(name, "sh", "-c", JOURNAL)


def test_ssh_systemd_failure_recovery(
    silo: Silo, workspace: Workspace, systemd_image: str,
) -> None:
    name = "ssh-systemd-recovery"
    _start_systemd(silo, workspace, systemd_image, name)
    # Schedule before stopping: exec remains available but the SSH socket will not.
    silo.exec(name, "sh", "-eu", "-c", RESTORE, user="root")
    started = time.monotonic()
    silo.exec(name, "sh", "-eu", "-c", STOP, user="root")
    failed_at: float | None = None
    receipts: set[int | str] = set()
    while True:
        status = _fresh(silo, name)
        elapsed = time.monotonic() - started
        receipts.add(status["updated_at"])
        if status["ready"] is False and failed_at is None:
            assert elapsed <= 65, status
            failed_at = elapsed
        if failed_at is not None and status["ready"] is True:
            assert elapsed <= 140, status
            retry_elapsed = elapsed - failed_at
            assert 59 <= retry_elapsed <= 66 or 119 <= retry_elapsed <= 131, retry_elapsed
            assert len(receipts) >= 11, f"guest status stalled: {receipts}"
            workspace.record("ssh-recovery", f"failure_at={failed_at:.3f} recovery_at={elapsed:.3f}")
            break
        assert elapsed < (65 if failed_at is None else 140), status
        time.sleep(0.5)
    _listener(silo, name, systemd=True)
    _certificate_login(silo, name)
    silo.exec(name, "sh", "-c", JOURNAL)
