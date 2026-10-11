from __future__ import annotations

import json

from silo_smoke.cli import Silo, Vm
from silo_smoke.workspace import Workspace


def test_exec_streams_and_exit_codes(silo: Silo, vm: Vm) -> None:
    proof = silo.exec(vm.name, "cat", "/etc/proof")
    assert proof.stdout == "silo-smoke-proof\n"
    assert proof.stderr == ""
    streams = silo.exec(vm.name, "sh", "-c", "echo out; echo err >&2; exit 7", expect=7)
    assert streams.returncode == 7
    assert streams.stdout == "out\n"
    assert streams.stderr == "err\n"
    missing = silo.exec(vm.name, "/nonexistent", expect=127)
    assert missing.returncode == 127
    assert "command not found" in missing.stderr
    terminated = silo.exec(vm.name, "sh", "-c", "kill -TERM $$", expect=143)
    assert terminated.returncode == 143
    echoed = silo.exec(vm.name, "cat", stdin=b"ping")
    assert echoed.stdout == "ping"
    assert echoed.stderr == ""


def test_shell_certificate_login_and_user(silo: Silo, workspace: Workspace, vm: Vm) -> None:
    root = silo.shell(vm.name, "echo S1; id -u; cat /etc/proof; exit 0\n", user="root")
    assert root.returncode == 0
    assert "S1\n0\nsilo-smoke-proof\n" in root.stdout.replace("\r\n", "\n")
    user = silo.shell(vm.name, "id -u; echo $HOME; exit 3\n", user="silo", expect=3)
    assert user.returncode == 3
    assert "1000\n/home/silo\n" in user.stdout.replace("\r\n", "\n")
    secrets = json.loads(workspace.machine_secrets(vm.id).read_text())
    ca = silo.exec(vm.name, "cat", "/etc/ssh/silo_ca.pub")
    assert ca.stdout.strip() == secrets["silo.ssh_ca.public_key"]["value"].strip()
    assert ca.stderr == ""
