"""Real CLI pause witnesses: retained guest output, generation sysfs and run identity."""
from __future__ import annotations

import json
import os
import select
import subprocess
import time
from uuid import uuid4

from .cli import Silo

from .config import REPO

class Counter:
    """One existing guest session must stop advancing without being replaced."""

    def __init__(self, silo: Silo, name: str) -> None:
        self.silo = silo
        self.process = silo.popen(
            "exec", name, "--", "/bin/sh", "-c",
            "i=0; while :; do printf 'PAUSE_COUNTER=%s\\n' \"$i\"; i=$((i+1)); sleep 0.05; done",
        )
        assert self.process.stdout is not None
        self.fd = self.process.stdout.fileno()
        self.pending = b""
        self.values: list[int] = []

    def receive(self, timeout: float) -> bool:
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        data = os.read(self.fd, 65536)
        assert data, f"retained guest counter stream ended, CLI exit={self.process.poll()}"
        self.pending += data
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            assert line.startswith(b"PAUSE_COUNTER="), line
            value = int(line.removeprefix(b"PAUSE_COUNTER="))
            assert value == (self.values[-1] + 1 if self.values else 0), (self.values[-5:], value)
            self.values.append(value)
        return True

    def advances(self) -> None:
        initial = len(self.values)
        deadline = time.monotonic() + 10
        while len(self.values) < initial + 3:
            assert time.monotonic() < deadline, "retained guest counter did not advance"
            self.receive(min(0.1, max(0, deadline - time.monotonic())))

    def stationary(self) -> None:
        # Deliver bytes already in the host transport, then require a quiet
        # interval. A still-running workload cannot pass the bounded drain.
        deadline = time.monotonic() + 3
        while self.receive(0.2):
            assert time.monotonic() < deadline, "guest counter still advancing after Paused"
        assert not self.receive(0.5), "guest counter advanced while Paused"

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            output, errors = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            output, errors = self.process.communicate(timeout=10)
        self.silo.ws.record("pause-counter", json.dumps({
            "values": self.values, "partialHex": self.pending.hex(),
            "remainingHex": output.hex(), "stderr": errors.decode(errors="replace"),
            "exit": self.process.returncode,
        }) + "\n")


def generation(silo: Silo, name: str) -> dict[str, str]:
    result = silo.exec(name, "/bin/sh", "-c", (
        "for d in /sys/bus/virtio/devices/*; do "
        "[ \"$(cat \"$d/device\")\" = 0x5347 ] && cat \"$d/generation_state\"; done; true"
    ))
    lines = result.stdout.splitlines()
    assert len(lines) == 1, f"expected one real generation device: {result.stdout!r}"
    fields: dict[str, str] = {}
    for word in lines[0].split():
        key, value = word.split("=", 1)
        assert key not in fields, f"duplicate generation evidence: {key}"
        fields[key] = value
    assert fields["version"] == "1" and fields["error"] == "0", fields
    return fields


def request(silo: Silo, name: str, command: dict, *, expect: int = 0) -> dict | None:
    binary = silo.ws.config.bin_dir / "examples" / "live_acceptance"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/live_acceptance"
    assert binary.is_file(), "build cargo build -p libvm --example live_acceptance"
    path = silo.ws.root / f"pause-request-{uuid4().hex}.json"
    path.write_text(json.dumps(command))
    result = subprocess.run(
        [str(binary), name, str(path)], env=silo.ws.env(),
        capture_output=True, text=True, timeout=70,
    )
    silo.ws.record("pause-request", json.dumps({
        "request": command, "exit": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr,
    }) + "\n")
    assert result.returncode == expect, result
    return json.loads(result.stdout) if expect == 0 else None
