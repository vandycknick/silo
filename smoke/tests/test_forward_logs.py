from __future__ import annotations

import json
import os
import select
import signal
import socket
import subprocess
import time
from typing import BinaryIO

import pytest

from silo_smoke.cli import Silo, Vm
from silo_smoke.procs import free_port
from silo_smoke.workspace import Workspace


def _read_status(stream: BinaryIO, timeout: float = 30) -> bytes:
    deadline = time.monotonic() + timeout
    output = bytearray()
    while b"\n" not in output:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"Forward status timed out: {output!r}"
        readable, _, _ = select.select([stream], [], [], remaining)
        assert readable, f"Forward status timed out: {output!r}"
        chunk = os.read(stream.fileno(), 8192)
        assert chunk != b"", f"Forward exited before status: {output!r}"
        output.extend(chunk)
    return bytes(output)


def _finish(proc: subprocess.Popen[bytes], workspace: Workspace, label: str) -> None:
    if proc.poll() is None:
        proc.kill()
    stdout, stderr = proc.communicate(timeout=15)
    workspace.record(label, f"stdout: {stdout!r}\nstderr: {stderr!r}\n")


def test_inbound_forward_host_to_guest(silo: Silo, workspace: Workspace, basic_image: str) -> None:
    name = "forward-vm"
    silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock")
    silo.start(name)
    silo.wait_ready(name)
    port = free_port()
    guest = silo.popen("exec", name, "--", "sh", "-c", "printf hello | nc -l -p 9000", stdin=subprocess.DEVNULL)
    forward: subprocess.Popen[bytes] | None = None
    try:
        deadline = time.monotonic() + 15
        while True:
            tcp = silo.exec(name, "cat", "/proc/net/tcp", "/proc/net/tcp6").stdout
            if any(len(fields := line.split()) > 3 and fields[1].endswith(":2328") and fields[3] == "0A" for line in tcp.splitlines()):
                break
            assert time.monotonic() < deadline, f"Guest listener not ready: {tcp}"
            time.sleep(0.05)
        forward = silo.popen("forward", name, f"{port}:9000", stdin=subprocess.DEVNULL)
        assert forward.stdout is not None
        status = _read_status(forward.stdout)
        workspace.record("forward-status", status.decode())
        assert status == f"Forwarding host:tcp:127.0.0.1:{port} -> guest:tcp:127.0.0.1:9000 (inbound)\n".encode()
        active = silo.run("forward", name, "--list").stdout
        assert "inbound" in active
        assert "active" in active
        assert f"host:tcp:127.0.0.1:{port}" in active
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            data = bytearray()
            while chunk := connection.recv(1024):
                data.extend(chunk)
        assert bytes(data) == b"hello"
        assert guest.wait(timeout=15) == 0
        forward.send_signal(signal.SIGINT)
        assert forward.wait(timeout=15) == 0
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=2)
        listed = silo.run("forward", name, "--list").stdout
        assert f"host:tcp:127.0.0.1:{port}" not in listed
        assert len(listed.strip().splitlines()) == 1
    finally:
        if forward is not None:
            _finish(forward, workspace, "forward")
        _finish(guest, workspace, "forward-guest")


def test_logs_streams(silo: Silo, vm: Vm) -> None:
    silo.exec(vm.name, "cat", "/etc/proof")
    executed = silo.run("logs", vm.name, "--stream", "exec").stdout
    records = [json.loads(line) for line in executed.splitlines()]
    assert any(record["s"] == "system" and record["d"].startswith("--- silo-vmm generation started") for record in records)
    assert any(record["s"] == "stdout" and record["d"] == "silo-smoke-proof\n" and isinstance(record.get("id"), str) and record["id"] != "" for record in records)
    monitor = silo.run("logs", vm.name, "--stream", "monitor").stdout
    assert monitor != ""
    serial = silo.run("logs", vm.name, "--stream", "serial").stdout
    assert "silo-vmm generation start" in serial
