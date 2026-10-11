"""Evidence-recording black-box CLI driver."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, IO

from .errors import SmokeAssertion

if TYPE_CHECKING:
    from .workspace import Workspace


@dataclass
class Result:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Vm:
    """A created, started and ready machine owned by a test."""

    name: str
    id: str


class Silo:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws

    def run(
        self,
        *args: str,
        stdin: bytes | str | None = None,
        timeout: float = 120,
        expect: int | None = 0,
        env: dict[str, str] | None = None,
        label: str | None = None,
    ) -> Result:
        command = [str(self.ws.config.silo), *args]
        data = stdin.encode() if isinstance(stdin, str) else stdin
        evidence_label = label or (args[0] if args else "silo")
        try:
            completed = subprocess.run(
                command, input=data, env=self.ws.env() if env is None else env,
                capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"").decode(errors="replace")
            stderr = (exc.stderr or b"").decode(errors="replace")
            self.ws.record(evidence_label, f"$ silo {shlex.join(args)}\n{stdout}\n[stderr]\n{stderr}\n")
            raise SmokeAssertion(f"silo {shlex.join(args)} timed out after {timeout}s: {stderr[-4000:]}") from exc
        result = Result(command, completed.returncode, completed.stdout.decode(errors="replace"), completed.stderr.decode(errors="replace"))
        self.ws.record(evidence_label, f"$ silo {shlex.join(args)}\n{result.stdout}\n[stderr]\n{result.stderr}\n")
        if expect is not None and result.returncode != expect:
            raise SmokeAssertion(f"silo {shlex.join(args)} exited {result.returncode} (expected {expect}): {result.stderr[-4000:]}")
        return result

    def json(
        self, *args: str, stdin: bytes | str | None = None,
        timeout: float = 120, expect: int | None = 0,
        env: dict[str, str] | None = None, label: str | None = None,
    ) -> Any:
        result = self.run(*args, "--format", "json", stdin=stdin, timeout=timeout, expect=expect, env=env, label=label)
        return json.loads(result.stdout)

    def show(self, name: str) -> dict[str, Any]:
        return self.json("show", name)

    def ls(self) -> list[dict[str, Any]]:
        return self.json("ls")

    def wait_ready(self, name: str, timeout: float = 90) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            last = self.show(name)
            if last.get("observation") == "observed" and last.get("state") == "running" and last.get("ready") is True:
                return last
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeAssertion(f"machine {name} not ready after {timeout}s: {json.dumps(last)}")
            time.sleep(min(0.25, remaining))

    def create(self, name: str, image: str, *flags: str) -> dict[str, Any]:
        self.run("create", image, "--name", name, *flags)
        self.ws.register_machine(name)
        return self.show(name)

    def start(self, name: str) -> None:
        self.run("start", name)

    def stop(self, name: str, timeout: str = "20s", force: bool = False) -> None:
        self.run("stop", name, "--timeout", timeout, *( ["--force"] if force else []))

    def rm(self, name: str, force: bool = False) -> None:
        self.run("rm", name, *(["--force"] if force else []))

    def exec(
        self, name: str, *argv: str, stdin: bytes | str | None = None,
        expect: int | None = 0, timeout: float = 60, user: str | None = None,
    ) -> Result:
        return self.run("exec", name, *(["--user", user] if user is not None else []), "--", *argv, stdin=stdin, expect=expect, timeout=timeout)

    def shell(self, name: str, script: str, user: str = "root", expect: int | None = 0) -> Result:
        return self.run("shell", name, "--user", user, stdin=script, expect=expect)

    def machine_id(self, name: str) -> str:
        return str(self.show(name)["id"])

    def popen(
        self, *args: str, env: dict[str, str] | None = None,
        stdin: int | IO[bytes] | None = None,
        stdout: int | IO[bytes] | None = subprocess.PIPE,
        stderr: int | IO[bytes] | None = subprocess.PIPE,
        cwd: str | Path | None = None,
    ) -> subprocess.Popen[bytes]:
        self.ws.record(args[0] if args else "silo", f"$ silo {shlex.join(args)}\n")
        return subprocess.Popen([str(self.ws.config.silo), *args], env=self.ws.env() if env is None else env, stdin=stdin, stdout=stdout, stderr=stderr, cwd=cwd, start_new_session=False)
