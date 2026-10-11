from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import signal
import subprocess

import pytest

from silo_smoke.cli import Silo, Vm
from silo_smoke.terminal import PtyCommand
from silo_smoke.workspace import Workspace


@contextmanager
def _terminal(workspace: Workspace, vm: Vm, *argv: str) -> Iterator[PtyCommand]:
    command = PtyCommand(workspace, [str(workspace.config.silo), "exec", vm.id, "--tty", "--", *argv])
    try:
        yield command
    finally:
        if command.proc.poll() is None:
            command.proc.kill()
            command.wait(timeout=15)


def test_tty_resize_input_and_exit(workspace: Workspace, vm: Vm) -> None:
    # The window change travels host -> CLI -> agent asynchronously, so the guest polls
    # for it instead of racing the input that follows; `wait()` bounds the poll.
    script = (
        "sleep .2; stty size; printf 'READY\\n'; IFS= read -r v; printf 'INPUT:%s\\n' \"$v\"; "
        "while [ \"$(stty size)\" = '37 119' ]; do sleep .05; done; stty size; exit 7"
    )
    with _terminal(workspace, vm, "/bin/sh", "-c", script) as command:
        command.wait_for(b"READY\r\n")
        command.resize(41, 127)
        command.write(b"literal:$HOME\n")
        assert command.wait() == 7
        assert command.raw_mode_seen is True
        assert b"37 119\r\n" in command.output
        assert b"41 127\r\n" in command.output
        assert b"INPUT:literal:$HOME\r\n" in command.output
        assert command.restored is True


def test_tty_launch_failure_never_enters_raw(workspace: Workspace, vm: Vm) -> None:
    with _terminal(workspace, vm, "/nonexistent-cli-regression") as command:
        assert command.wait() == 127
        assert command.raw_mode_seen is False
        assert command.restored is True


@pytest.mark.parametrize(("sig", "expected"), [(signal.SIGINT, 42), (signal.SIGTERM, 43), (signal.SIGUSR1, 44), (signal.SIGUSR2, 45)], ids=["SIGINT", "SIGTERM", "SIGUSR1", "SIGUSR2"])
def test_tty_forwards_signals(workspace: Workspace, vm: Vm, sig: signal.Signals, expected: int) -> None:
    script = "trap 'exit 42' INT; trap 'exit 43' TERM; trap 'exit 44' USR1; trap 'exit 45' USR2; printf 'READY\\n'; while :; do sleep .1; done"
    with _terminal(workspace, vm, "/bin/sh", "-c", script) as command:
        command.wait_for(b"READY\r\n")
        command.signal(sig)
        assert command.wait() == expected
        assert command.raw_mode_seen is True
        assert command.restored is True


def test_tty_with_null_stdin_drains_output(silo: Silo, workspace: Workspace, vm: Vm) -> None:
    with silo.popen("exec", vm.id, "--tty", "--", "sh", "-c", "sleep .2; printf trailing; exit 7", stdin=subprocess.DEVNULL) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=15)
        workspace.record("tty-null", f"stdout: {stdout!r}\nstderr: {stderr!r}\n")
        assert proc.returncode == 7
        assert stdout == b"trailing"
