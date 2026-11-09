"""Evidence-recording black-box CLI driver."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, IO, Literal

from .errors import SmokeAssertion

if TYPE_CHECKING:
    from .workspace import Workspace

TIMING_EVIDENCE = "timing"
# Per-test JUnit property; session preparations append `-prepare-<catalog>`.
TIMINGS_PROPERTY = "silo-smoke-timings"
# Lifecycle matrices: an explicitly converted opaque raw disk, or the ordinary
# OCI default (layered `linux-erofs-overlay-v1` root on libkrun).
RootProfile = Literal["raw", "layered"]
ROOT_PROFILES: tuple[RootProfile, ...] = ("raw", "layered")


def record_timing(ws: Workspace, operation: str, started: float, outcome: str) -> None:
    """Append one monotonic duration line to the workspace's evidence log."""
    elapsed = time.monotonic() - started
    ws.record(TIMING_EVIDENCE, json.dumps({"operation": operation, "outcome": outcome, "seconds": round(elapsed, 6)}, sort_keys=True) + "\n")


@contextmanager
def timed(ws: Workspace, operation: str) -> Iterator[None]:
    """Time one harness operation, recording failures under their exception type."""
    started = time.monotonic()
    try:
        yield
    except BaseException as error:
        record_timing(ws, operation, started, type(error).__name__)
        raise
    record_timing(ws, operation, started, "ok")


def timing_summary(ws: Workspace) -> dict[str, dict[str, dict[str, float]]]:
    """Aggregate timing evidence per operation and outcome; size is independent of call count."""
    path = ws.evidence_path(TIMING_EVIDENCE)
    summary: dict[str, dict[str, dict[str, float]]] = {}
    if not path.is_file():
        return summary
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        aggregate = summary.setdefault(entry["operation"], {}).setdefault(entry["outcome"], {"count": 0, "seconds": 0.0, "maxSeconds": 0.0})
        aggregate["count"] += 1
        aggregate["seconds"] += entry["seconds"]
        aggregate["maxSeconds"] = max(aggregate["maxSeconds"], entry["seconds"])
    for outcomes in summary.values():
        for aggregate in outcomes.values():
            aggregate["seconds"] = round(aggregate["seconds"], 3)
            aggregate["maxSeconds"] = round(aggregate["maxSeconds"], 3)
    return summary


def release(ws: Workspace, *, failed: bool, publish: Callable[[str], None]) -> None:
    """Clean up a workspace and publish its timing summary outside the evidence tree.

    Successful cleanup deletes the workspace evidence, so the bounded aggregate,
    including cleanup itself, goes to the caller's pytest report instead.
    """
    try:
        summary = timing_summary(ws)
    except BaseException:
        # Never leak guests over unreadable timing evidence; retain it instead.
        ws.cleanup(failed=True)
        raise
    started = time.monotonic()
    outcome = "ok"
    try:
        ws.cleanup(failed=failed)
    except BaseException as error:
        outcome = type(error).__name__
        raise
    finally:
        elapsed = round(time.monotonic() - started, 3)
        summary["workspace cleanup"] = {outcome: {"count": 1, "seconds": elapsed, "maxSeconds": elapsed}}
        publish(json.dumps(summary, sort_keys=True))


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
        operation = "silo " + evidence_label
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, input=data, env=self.ws.env() if env is None else env,
                capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            record_timing(self.ws, operation, started, "timeout")
            stdout = (exc.stdout or b"").decode(errors="replace")
            stderr = (exc.stderr or b"").decode(errors="replace")
            self.ws.record(evidence_label, f"$ silo {shlex.join(args)}\n{stdout}\n[stderr]\n{stderr}\n")
            raise SmokeAssertion(f"silo {shlex.join(args)} timed out after {timeout}s: {stderr[-4000:]}") from exc
        except OSError:
            record_timing(self.ws, operation, started, "spawn-error")
            raise
        record_timing(self.ws, operation, started, f"exit-{completed.returncode}")
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

    def info(self, name: str) -> dict[str, Any]:
        return self.json("info", name)

    def ls(self) -> list[dict[str, Any]]:
        return self.json("ls")

    def wait_ready(self, name: str, timeout: float = 90, *, poll_interval: float = 0.25) -> dict[str, Any]:
        # Polls log under their own label, so identity/state `info` counts stay
        # comparable independently of how many readiness retries a boot needed.
        with timed(self.ws, "wait_ready"):
            deadline = time.monotonic() + timeout
            while True:
                last = self.json("info", name, label="wait-ready")
                if last.get("observation") == "observed" and last.get("state") == "running" and last.get("ready") is True:
                    return last
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SmokeAssertion(f"machine {name} not ready after {timeout}s: {json.dumps(last)}")
                time.sleep(min(poll_interval, remaining))

    def create(self, name: str, image: str, *flags: str) -> dict[str, Any]:
        self.run("create", image, "--name", name, *flags)
        self.ws.register_machine(name)
        return self.info(name)

    def raw_image(self, reference: str) -> str:
        """Explicitly convert an OCI reference into the opaque raw disk family.

        New OCI machines default to the layered EROFS root; tests that need
        opaque whole-disk bytes request them through the real conversion CLI.
        Returns the immutable managed `image:sha256:HEX` spelling.
        """
        converted = json.loads(self.run("image", "convert", reference, "--disk-format", "raw", timeout=600, label="image-convert-raw").stdout)
        return "image:" + str(converted["id"])

    def root_image(self, reference: str, profile: RootProfile) -> str:
        """The create source for one lifecycle matrix root profile."""
        return self.raw_image(reference) if profile == "raw" else reference

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
        return str(self.info(name)["id"])

    def popen(
        self, *args: str, env: dict[str, str] | None = None,
        stdin: int | IO[bytes] | None = None,
        stdout: int | IO[bytes] | None = subprocess.PIPE,
        stderr: int | IO[bytes] | None = subprocess.PIPE,
        cwd: str | Path | None = None,
        start_new_session: bool = False,
    ) -> subprocess.Popen[bytes]:
        self.ws.record(args[0] if args else "silo", f"$ silo {shlex.join(args)}\n")
        return subprocess.Popen([str(self.ws.config.silo), *args], env=self.ws.env() if env is None else env, stdin=stdin, stdout=stdout, stderr=stderr, cwd=cwd, start_new_session=start_new_session)
