"""Private daemon lifecycle and status polling."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from .cli import Result
from .errors import SmokeAssertion

if TYPE_CHECKING:
    from .workspace import Workspace


class Daemon:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.proc: subprocess.Popen[bytes] | None = None
        self._log: BinaryIO | None = None
        self._launch_count = 0
        ws.register_daemon(self)

    @property
    def pid(self) -> int:
        return self._process().pid

    def _process(self) -> subprocess.Popen[bytes]:
        if self.proc is None:
            raise SmokeAssertion("daemon has not been started")
        return self.proc

    def _close_log(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None

    def start(self, *args: str, label: str = "daemon") -> None:
        flags = list(args)
        if not any(arg == "--system-enabled" or arg.startswith("--system-enabled=") for arg in flags):
            flags.insert(0, "--system-enabled=false")
        if not any(arg == "--tailscale-enabled" or arg.startswith("--tailscale-enabled=") for arg in flags):
            flags.insert(0, "--tailscale-enabled=false")
        self.start_raw(*flags, label=label)

    def start_raw(self, *args: str, label: str) -> subprocess.Popen[bytes]:
        if self.proc is not None and self.proc.poll() is None:
            raise SmokeAssertion("this Daemon driver already owns a running process")
        self._close_log()
        self._launch_count += 1
        self._log = self.ws.evidence_path(f"{label}-{self._launch_count}").open("ab")
        command = [str(self.ws.config.silo), "daemon", "run", *args]
        self._log.write(f"$ {shlex.join(command)}\n".encode())
        self._log.flush()
        try:
            self.proc = subprocess.Popen(command, env=self.ws.env(), stdout=self._log, stderr=self._log)
        except BaseException:
            self._close_log()
            raise
        return self.proc

    def status(self) -> dict[str, Any] | None:
        try:
            return json.loads((self.ws.silo_home / "daemon" / "status.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def wait_core(self, phase: str = "ready", timeout: float = 60) -> dict[str, Any]:
        return self._wait(phase, timeout, system=False)

    def wait_system(self, phase: str, timeout: float) -> dict[str, Any]:
        return self._wait(phase, timeout, system=True)

    def _wait(self, phase: str, timeout: float, *, system: bool) -> dict[str, Any]:
        proc = self._process()
        deadline = time.monotonic() + timeout
        while True:
            last = self.status()
            if last is not None and last.get("pid") == proc.pid:
                section = last.get("system") if system else last
                actual = section.get("phase" if system else "core") if isinstance(section, dict) else None
                if actual == phase:
                    return last
            code = proc.poll()
            if code is not None and (system or phase != "stopped"):
                raise SmokeAssertion(f"daemon exited {code} before {'system' if system else 'core'} {phase}: {json.dumps(last)}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeAssertion(f"daemon did not reach {'system' if system else 'core'} {phase} after {timeout}s: {json.dumps(last)}")
            time.sleep(min(0.1, remaining))

    @property
    def control_sock(self) -> Path:
        return self.ws.run_root / "silod" / "control.sock"

    def terminate(self, timeout: float = 15) -> int:
        if self.proc is None:
            self._close_log()
            return 0
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
            return self.proc.wait(timeout=timeout)
        finally:
            self._close_log()

    def kill(self) -> None:
        try:
            if self.proc is not None:
                if self.proc.poll() is None:
                    self.proc.kill()
                self.proc.wait(timeout=15)
        finally:
            self._close_log()

    def stop_installation(self, timeout: float = 90) -> Result:
        if self.proc is not None and self.proc.poll() is None:
            raise SmokeAssertion("terminate the daemon before stopping the installation")
        command = [str(self.ws.config.silo), "daemon", "run", "--stop"]
        try:
            completed = subprocess.run(command, env=self.ws.env(), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"").decode(errors="replace")
            stderr = (exc.stderr or b"").decode(errors="replace")
            self.ws.record("daemon-stop", f"$ {shlex.join(command)}\n{stdout}\n[stderr]\n{stderr}\n")
            raise SmokeAssertion(f"silo daemon run --stop timed out after {timeout}s: {stderr[-4000:]}") from exc
        result = Result(command, completed.returncode, completed.stdout.decode(errors="replace"), completed.stderr.decode(errors="replace"))
        self.ws.record("daemon-stop", f"$ {shlex.join(command)}\n{result.stdout}\n[stderr]\n{result.stderr}\n")
        if result.returncode != 0:
            raise SmokeAssertion(f"silo daemon run --stop exited {result.returncode} (expected 0): {result.stderr[-4000:]}")
        return result
