from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Protocol

from silo_smoke.catalog_observer import observe
from silo_smoke.workspace import Workspace
from silo_perf.model import Cohort, Mode


class Action(StrEnum):
    RUN = "run_true"
    CREATE = "create"
    START = "start"
    EXEC = "start_exec"
    FORK_FIRST = "fork_first"
    FORK_FIRST_EXEC = "fork_first_exec"
    FORK_SECOND = "fork_second"
    FORK_SECOND_EXEC = "fork_second_exec"
    SNAPSHOT_FULL = "snapshot_full"
    SNAPSHOT_INCREMENTAL = "snapshot_incremental"
    RESTORE_FIRST = "restore_first"
    RESTORE_FIRST_EXEC = "restore_first_exec"
    RESTORE_SECOND = "restore_second"
    RESTORE_SECOND_EXEC = "restore_second_exec"


@dataclass(frozen=True)
class Names:
    source: str
    snapshot_source: str



@dataclass(frozen=True)
class Context:
    workspace: Workspace
    cache: Path
    cohort: Cohort
    mode: Mode
    disk: str
    names: Names


class Driver(Protocol):
    system: str
    modes: tuple[Mode, ...]
    def __init__(self, context: Context) -> None: ...

    @classmethod
    def available(cls) -> str | None: ...
    @classmethod
    def supports(cls, cohort: Cohort) -> bool: ...
    def version(self) -> str: ...
    def prepare(self) -> None: ...
    def populate_source(self) -> None: ...
    def measure(self, action: Action) -> dict[str, float]: ...
    def prepare_snapshots(self) -> None: ...
    def remove_fork_sources(self) -> None: ...
    def cleanup(self) -> None: ...


def snapshot_id(database: Path, alias: str) -> str | None:
    """Decode the existing read-only observer's image_alias row, never CLI output."""
    if not database.exists():
        return None
    rows = observe(database).get("image_alias", [])
    def text(value: str) -> str | None:
        kind, _, encoded = value.partition(":")
        return bytes.fromhex(encoded).decode() if kind == "text" else None
    matches = [text(row[1]) for row in rows if text(row[0]) == alias]
    if not matches:
        return None
    if len(matches) != 1 or matches[0] is None:
        raise ValueError(f"snapshot alias is ambiguous or not a snapshot: {alias}")
    return matches[0]


@dataclass
class CommandDriver:
    context: Context
    binary: Path
    environment: dict[str, str]
    machines: list[str] = field(default_factory=list)
    snapshots: list[str] = field(default_factory=list)

    def call(self, *args: str) -> float:
        started = time.perf_counter_ns()
        result = subprocess.run([str(self.binary), *args], env=self.environment,
                                capture_output=True, text=True, errors="replace", timeout=300)
        seconds = (time.perf_counter_ns() - started) / 1e9
        self.context.workspace.record("perf-commands", f"{self.binary} {args}\nexit={result.returncode}\n"
                                      f"seconds={seconds:.9f}\n{result.stdout}\n{result.stderr}\n")
        if result.returncode:
            raise RuntimeError(f"{self.binary.name} {args} exited {result.returncode}: {result.stderr[-4000:]}")
        return seconds

    def version(self) -> str:
        return subprocess.run([str(self.binary), "--version"], env=self.environment,
                              capture_output=True, text=True, check=True, timeout=15).stdout.strip()



class SiloDriver(CommandDriver):
    system = "silo"
    modes = (Mode.IMAGE, Mode.AGENT)

    def __init__(self, context: Context) -> None:
        super().__init__(context, context.workspace.config.silo, context.workspace.env())
        self.snapshot_ids: dict[str, str] = {}

    @classmethod
    def available(cls) -> str | None:
        return None

    @classmethod
    def supports(cls, cohort: Cohort) -> bool:
        return True

    def shape(self) -> list[str]:
        cohort = self.context.cohort
        args = ["--cpus", str(cohort.cpus), "--memory", f"{cohort.memory_gib}gib"]
        if self.context.disk:
            args += ["--disk-size", self.context.disk]
        if self.context.mode == Mode.AGENT:
            args += ["--kernel-arg", "init="]
        return args

    def prepare(self) -> None:
        name = self.context.names.source + "-prepare"
        self.machines.append(name)
        self.context.workspace.register_machine(name)
        self.call("create", "--name", name, *self.shape(), self.context.cohort.image)
        self.call("rm", "--force", name)
        self.machines.remove(name)
        self.context.workspace.unregister_machine(name)

    def create(self, name: str) -> float:
        self.machines.append(name)
        self.context.workspace.register_machine(name)
        return self.call("create", "--name", name, *self.shape(), self.context.cohort.image)

    def populate(self, name: str) -> None:
        if self.context.cohort.written_mib:
            self.call("exec", name, "--", "/bin/sh", "-ec",
                      f"yes SILO-PERF | head -c {self.context.cohort.written_mib * 1024 * 1024} "
                      "> /perf-payload; sync")

    def populate_source(self) -> None:
        self.populate(self.context.names.source)

    def measure(self, action: Action) -> dict[str, float]:
        a, b = self.context.names.source, self.context.names.snapshot_source
        if action == Action.RUN:
            try:
                seconds = self.call("run", *self.shape(), self.context.cohort.image, "--", "/bin/true")
            finally:
                if self.context.workspace.state_db().exists():
                    for row in observe(self.context.workspace.state_db()).get("machine_config", []):
                        name = bytes.fromhex(row[1].partition(":")[2]).decode()
                        if name not in self.machines:
                            self.machines.append(name)
                            self.context.workspace.register_machine(name)
        elif action == Action.CREATE:
            seconds = self.create(a)
        elif action == Action.START:
            seconds = self.call("start", a)
        elif action in EXEC_NAMES:
            seconds = self.call("exec", EXEC_NAMES[action](a, b), "--", "/bin/true")
        elif action in (Action.FORK_FIRST, Action.FORK_SECOND):
            name = a + ("-f1" if action == Action.FORK_FIRST else "-f2")
            self.machines.append(name)
            self.context.workspace.register_machine(name)
            seconds = self.call("fork", a, "--live", "--name", name)
        elif action in (Action.SNAPSHOT_FULL, Action.SNAPSHOT_INCREMENTAL):
            name = b + ("-s1" if action == Action.SNAPSHOT_FULL else "-s2")
            self.snapshots.append(name)
            seconds = self.call("snapshot", "create", b, "--live", "--name", name,
                                *(["--capture-policy", "full"] if action == Action.SNAPSHOT_FULL else []))
            identity = snapshot_id(self.context.workspace.state_db(), name)
            if identity is None:
                raise RuntimeError(f"published snapshot has no catalog alias: {name}")
            self.snapshot_ids[name] = identity
        else:
            name = b + ("-r1" if action == Action.RESTORE_FIRST else "-r2")
            self.machines.append(name)
            self.context.workspace.register_machine(name)
            seconds = self.call("restore", "image:" + b + "-s2", "--name", name)
        return {action.value: seconds}

    def remove_fork_sources(self) -> None:
        a = self.context.names.source
        for name in (a + "-f2", a + "-f1", a):
            self.call("rm", "--force", name)
            self.machines.remove(name)
            self.context.workspace.unregister_machine(name)

    def prepare_snapshots(self) -> None:
        name = self.context.names.snapshot_source
        self.create(name)
        self.call("start", name)
        self.populate(name)

    def cleanup(self) -> None:
        errors: list[Exception] = []
        for name in reversed(self.machines):
            try:
                # A failed command may have committed a machine before reporting failure.
                catalog = observe(self.context.workspace.state_db()) if self.context.workspace.state_db().exists() else {}
                encoded = "text:" + name.encode().hex().upper()
                if any(encoded == row[1] for row in catalog.get("machine_config", [])):
                    self.call("rm", "--force", name)
                self.context.workspace.unregister_machine(name)
            except Exception as error:
                errors.append(error)
        for name in reversed(self.snapshots):
            try:
                identity = self.snapshot_ids.get(name) or snapshot_id(self.context.workspace.state_db(), name)
                if identity is not None:
                    self.call("image", "remove", "image:" + name)
                    self.call("snapshot", "remove", "image:" + identity)
            except Exception as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup("Silo performance cleanup failed", errors)


EXEC_NAMES: dict[Action, Callable[[str, str], str]] = {
    Action.EXEC: lambda a, b: a,
    Action.FORK_FIRST_EXEC: lambda a, b: a + "-f1",
    Action.FORK_SECOND_EXEC: lambda a, b: a + "-f2",
    Action.RESTORE_FIRST_EXEC: lambda a, b: b + "-r1",
    Action.RESTORE_SECOND_EXEC: lambda a, b: b + "-r2",
}


class MsbDriver(CommandDriver):
    system = "msb"
    modes = (Mode.DEFAULT,)

    def __init__(self, context: Context) -> None:
        binary = self.find_binary()
        if binary is None:
            raise FileNotFoundError("enter the perf shell: nix develop .#perf")
        root = Path(tempfile.mkdtemp(prefix="msb-", dir=context.cache))
        prefix, home = root / "prefix", root / "home"
        prefix.mkdir()
        home.mkdir()
        environment = {**os.environ, "MSB_HOME": str(prefix), "HOME": str(home),
                       "MSB_CONFIG_PATH": str(home / "config.json"), "MSB_BACKEND": "local",
                       "NO_COLOR": "1", "TERM": "dumb"}
        super().__init__(context, binary, environment)
        self.root = root

    @classmethod
    def find_binary(cls) -> Path | None:
        value = os.environ.get("PERF_MSB_BIN") or shutil.which("msb")
        if value is None:
            return None
        path = Path(value).expanduser().resolve()
        return path if path.is_file() and os.access(path, os.X_OK) else None

    @classmethod
    def available(cls) -> str | None:
        return None if cls.find_binary() else "enter the perf shell: nix develop .#perf"

    @classmethod
    def supports(cls, cohort: Cohort) -> bool:
        return cohort.msb_image is not None

    def shape(self) -> list[str]:
        return ["-c", str(self.context.cohort.cpus), "-m", f"{self.context.cohort.memory_gib}G"]

    def prepare(self) -> None:
        image = self.context.cohort.msb_image
        if image is None:
            raise ValueError("msb cohort needs an msb_image")
        self.call("pull", image)

    def populate_source(self) -> None:
        if self.context.cohort.written_mib:
            raise ValueError("disk-invariance is a Silo-only cohort")

    def create(self, name: str) -> float:
        self.machines.append(name)
        return self.call("create", "-n", name, *self.shape(), str(self.context.cohort.msb_image))

    def measure(self, action: Action) -> dict[str, float]:
        a, b = self.context.names.source, self.context.names.snapshot_source
        if action == Action.RUN:
            seconds = self.call("run", *self.shape(), str(self.context.cohort.msb_image), "--", "/bin/true")
        elif action == Action.CREATE:
            seconds = self.create(a)
            return {"create": seconds, "start": seconds}
        elif action == Action.START:
            return {}
        elif action in EXEC_NAMES:
            seconds = self.call("exec", EXEC_NAMES[action](a, b), "--", "/bin/true")
        elif action in (Action.FORK_FIRST, Action.FORK_SECOND):
            name = a + ("-f1" if action == Action.FORK_FIRST else "-f2")
            self.machines.append(name)
            seconds = self.call("fork", a, "-n", name)
        elif action in (Action.SNAPSHOT_FULL, Action.SNAPSHOT_INCREMENTAL):
            name = "s1" if action == Action.SNAPSHOT_FULL else "s2"
            self.snapshots.append(b + ":" + name)
            seconds = self.call("snap", "create", name, "--sandbox", b, "--full")
        else:
            name = b + ("-r1" if action == Action.RESTORE_FIRST else "-r2")
            self.machines.append(name)
            seconds = self.call("restore", b + ":s2", "-n", name)
        return {action.value: seconds}

    def remove_fork_sources(self) -> None:
        a = self.context.names.source
        self.call("rm", "-f", a + "-f1", a + "-f2", a)
        for name in (a + "-f1", a + "-f2", a):
            self.machines.remove(name)

    def prepare_snapshots(self) -> None:
        self.create(self.context.names.snapshot_source)

    def cleanup(self) -> None:
        errors: list[Exception] = []
        machines = list(self.machines)
        try:
            inventory = subprocess.run([str(self.binary), "ls", "-q"], env=self.environment,
                                       capture_output=True, text=True, check=True, timeout=30)
            machines = inventory.stdout.splitlines()
        except Exception as error:
            errors.append(error)
        # msb refuses to remove the head snapshot while an older one exists,
        # so snapshots go oldest first.
        for args in [*(("rm", "-f", name) for name in reversed(machines)),
                     *(("snap", "rm", "-f", name) for name in self.snapshots)]:
            try:
                self.call(*args)
            except Exception as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup(f"msb cleanup failed; retained {self.root}", errors)
        shutil.rmtree(self.root)


REGISTRY: dict[str, type[Driver]] = {"silo": SiloDriver, "msb": MsbDriver}
