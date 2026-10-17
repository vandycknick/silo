from __future__ import annotations

import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import time

import pytest

from silo_smoke import config as smoke_config
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.errors import SmokeEnvironmentError
from silo_smoke.procs import free_port
from silo_smoke.workspace import Workspace

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "distro_label" in metafunc.fixturenames:
        try:
            labels = list(smoke_config.resolve(metafunc.config).distro_images)
        except SmokeEnvironmentError:
            labels = []
        if not labels:
            metafunc.parametrize("distro_label", [pytest.param("none", marks=pytest.mark.skip(reason="SILO_SMOKE_DISTRO_IMAGES is empty"))])
            return
        metafunc.parametrize("distro_label", labels, ids=labels)


def _negative_auth(silo: Silo, workspace: Workspace, name: str, key: str) -> None:
    port = free_port()
    # SSH listens on vsock 22, not the guest TCP loopback used by P:22 shorthand.
    forward = silo.popen("forward", name, f"host:tcp:127.0.0.1:{port}", "vsock:22")
    output = bytearray()
    try:
        assert forward.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(forward.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 20
            while b"Forwarding " not in output:
                remaining = deadline - time.monotonic()
                assert remaining > 0, f"forward did not activate: {output!r}"
                if selector.select(remaining):
                    chunk = os.read(forward.stdout.fileno(), 4096)
                    assert chunk, f"forward exited before activation: {output!r}"
                    output.extend(chunk)
        result = subprocess.run(
            ["ssh", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             "-p", str(port), "root@127.0.0.1", "true"],
            env=workspace.env(), capture_output=True, text=True, timeout=20,
        )
        workspace.record("negative-auth", f"rc={result.returncode}\n{result.stdout}\n{result.stderr}")
        assert result.returncode == 255
        assert "Permission denied" in result.stderr
    finally:
        if forward.poll() is None:
            forward.send_signal(signal.SIGINT)
        try:
            stdout, stderr = forward.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            forward.kill()
            stdout, stderr = forward.communicate()
        workspace.record("forward-auth", (bytes(output) + stdout + stderr).decode(errors="replace"))
    assert forward.returncode == 0


@pytest.mark.slow
@pytest.mark.usefixtures("pulled_images")
def test_distro_certificate_two_boots(
    distro_label: str, config: SmokeConfig, silo: Silo, workspace: Workspace,
) -> None:
    for binary in ("ssh", "ssh-keygen"):
        if shutil.which(binary) is None:
            pytest.skip(f"{binary} not found on PATH")
    key = workspace.root / "stale"
    generated = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
        env=workspace.env(), capture_output=True, text=True, timeout=10,
    )
    workspace.record("ssh-keygen", generated.stdout + generated.stderr)
    assert generated.returncode == 0, generated.stderr
    public_key = key.with_suffix(".pub").read_text().strip()
    userdata = workspace.root / "certificate-userdata.sh"
    userdata.write_text(
        "#!/bin/sh\nset -eu\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\n"
        f"printf '%s\\n' {shlex.quote(public_key)} > /root/.ssh/authorized_keys\n"
        "chmod 600 /root/.ssh/authorized_keys\n"
        "printf '#!/bin/sh\\nprintf certificate-session\\nexit 7\\n' > /run/silo-test-login\n"
        "chmod 755 /run/silo-test-login\n"
    )
    name = "certificate-distro"
    created = silo.create(name, config.distro_images[distro_label], "--pull", "missing", "--vsock",
                          "--cpus", "1", "--memory", "1GiB", "--network", "none", "--userdata", str(userdata))
    pin: bytes | None = None
    for _ in range(2):
        silo.start(name)
        silo.wait_ready(name, timeout=75)
        current_pin = workspace.known_host(created["id"]).read_bytes()
        assert current_pin
        if pin is None:
            pin = current_pin
        else:
            assert current_pin == pin
        if distro_label == "systemd":
            # The CLI guest view does not expose the SSH backend descriptor.
            assert silo.exec(name, "systemctl", "is-active", "sshd-vsock.socket").stdout.strip() == "active"
        _negative_auth(silo, workspace, name, str(key))
        login = silo.shell(name, "printf 'certificate-session %s\\n' ok; exit 7\n", user="root", expect=7)
        assert "certificate-session ok" in login.stdout
        assert login.stderr == ""
        if silo.exec(name, "test", "-x", "/usr/sbin/sshd", expect=None).returncode == 0:
            # OpenSSH served the login (agent-owned `sshd -i` or systemd's socket); it logs
            # the accepted certificate through syslog, so the journal must carry it.
            journal = silo.exec(name, "sh", "-c", "journalctl --no-pager -b | grep 'silo:cli:' | grep 'CA ED25519'")
            assert "silo:cli:" in journal.stdout
        else:
            # No OpenSSH in the image: the agent's native backend served it and logs to serial.
            serial = ANSI.sub("", silo.run("logs", name, "--stream", "serial").stdout)
            assert "native SSH certificate authentication succeeded" in serial, serial[-2000:]
            assert 'key_id="silo:cli:' in serial
        silo.stop(name)
        assert silo.show(name)["state"] == "stopped"
