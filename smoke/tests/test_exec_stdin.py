from __future__ import annotations

import hashlib
import subprocess

from silo_smoke.cli import Silo, Vm


def test_exec_large_stdin_digest(silo: Silo, vm: Vm) -> None:
    data = bytes(range(256)) * (64 * 1024 * 1024 // 256)
    expected = hashlib.sha256(data).hexdigest()
    result = silo.exec(vm.name, "sh", "-c", "sha256sum", stdin=data, timeout=120)
    assert result.stdout.split() == [expected, "-"]
    assert result.stderr == ""


def test_exec_stdin_early_exit(silo: Silo, vm: Vm) -> None:
    data = b"first line\n" + b"unread input\n" * (4 * 1024 * 1024)
    first = silo.exec(vm.name, "sh", "-c", "head -n 1; exit 7", stdin=data, expect=7, timeout=15)
    assert first.stdout == "first line\n"
    assert first.stderr == ""
    no_reader = silo.exec(vm.name, "sh", "-c", "exit 9", stdin=data, expect=9, timeout=15)
    assert no_reader.stdout == ""
    assert no_reader.stderr == ""
    closed = silo.exec(vm.name, "sh", "-c", "exec 0<&-; sleep 0.1; exit 11", stdin=data, expect=11, timeout=15)
    assert closed.stdout == ""
    assert closed.stderr == ""


def test_exec_zero_byte_stdin(silo: Silo, vm: Vm) -> None:
    result = silo.exec(vm.name, "wc", "-c", stdin=b"", timeout=15)
    assert result.stdout.strip() == "0"
    assert result.stderr == ""
    with silo.popen("exec", vm.name, "--", "wc", "-c", stdin=subprocess.DEVNULL) as process:
        try:
            stdout, stderr = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        assert process.returncode == 0
        assert stdout.strip() == b"0"
        assert stderr == b""
