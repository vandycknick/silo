from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import json
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
from silo_perf.workload import INPUT, Write, marker_check, marker_write, writes


class Action(StrEnum):
    IMAGE_CONVERT_RAW = "image_convert_raw"
    CREATE_FIRST = "create_first"
    RUN = "run_true"
    CREATE = "create"
    START = "start"
    EXEC = "start_exec"
    FORK_FIRST = "fork_first"
    FORK_FIRST_EXEC = "fork_first_exec"
    FORK_SECOND = "fork_second"
    FORK_SECOND_EXEC = "fork_second_exec"
    FORK_OF_FORK = "fork_of_fork"
    SNAPSHOT_FULL = "snapshot_full"
    SNAPSHOT_INCREMENTAL = "snapshot_incremental"
    SNAPSHOT_VERIFY = "snapshot_verify"
    RESTORE_FIRST = "restore_first"
    RESTORE_FIRST_EXEC = "restore_first_exec"
    RESTORE_SECOND = "restore_second"
    RESTORE_SECOND_EXEC = "restore_second_exec"
    SNAPSHOT_OF_RESTORED = "snapshot_of_restored"
    SNAPSHOT_AFTER_RESTART = "snapshot_after_restart"
    SNAPSHOT_SOURCE_AFTER_FORKS = "snapshot_source_after_two_forks"
    SNAPSHOT_FORK_CHILD_FIRST = "snapshot_fork_child_first"
    SNAPSHOT_FORK_CHILD_SECOND = "snapshot_fork_child_second"


INFORMATIONAL_METRICS = frozenset({
    Action.IMAGE_CONVERT_RAW.value, Action.CREATE_FIRST.value, Action.FORK_OF_FORK.value,
    Action.SNAPSHOT_OF_RESTORED.value, Action.SNAPSHOT_AFTER_RESTART.value, Action.SNAPSHOT_VERIFY.value,
    Action.SNAPSHOT_SOURCE_AFTER_FORKS.value, Action.SNAPSHOT_FORK_CHILD_FIRST.value,
    Action.SNAPSHOT_FORK_CHILD_SECOND.value,
})


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
    def rewrite_source(self, *, snapshot: bool) -> None: ...
    def before_snapshot(self) -> None: ...
    def after_snapshot(self) -> None: ...
    def check_restore(self, action: Action) -> None: ...
    def check_fork(self) -> None: ...
    def measure(self, action: Action) -> dict[str, float]: ...
    def prepare_snapshots(self) -> None: ...
    def remove_fork_sources(self) -> None: ...
    def prepare_fork_snapshots(self) -> None: ...
    def cleanup(self) -> None: ...


def snapshot_id(database: Path, name: str) -> str | None:
    """Decode the existing read-only observer's snapshot_name row, never CLI output."""
    if not database.exists():
        return None
    def text(value: str) -> str:
        kind, _, encoded = value.partition(":")
        if kind != "text":
            raise ValueError(f"snapshot_name column is not text: {value}")
        return bytes.fromhex(encoded).decode()
    matches = [text(row[1]) for row in observe(database).get("snapshot_name", []) if text(row[0]) == name]
    return matches[0] if matches else None


def raw_conversion_command(cohort: Cohort) -> tuple[str, ...]:
    if cohort.raw_root:
        return ("image", "convert", cohort.image, "--disk-format", "raw", "--format", "json")
    # image pull acquires Silo VM artifacts, not ordinary OCI container images.
    return ()


def copy_command(system: str, source: Path, machine: str, destination: str) -> tuple[str, ...]:
    target = f"{machine}:{destination}"
    if system == "silo":
        return ("cp", "--owner", "0:0", "--mode", "600", str(source), target)
    if system == "msb":
        return ("copy", str(source), target)
    raise ValueError(f"unsupported workload copy system: {system}")


@dataclass
class CommandDriver:
    context: Context
    binary: Path
    environment: dict[str, str]
    machines: list[str] = field(default_factory=list)
    snapshots: list[str] = field(default_factory=list)
    workload_generations: dict[str, int] = field(default_factory=dict)

    def call(self, *args: str) -> float:
        command = [str(self.binary), *args]
        started = time.perf_counter_ns()
        timed_out = False
        with subprocess.Popen(command, env=self.environment, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, errors="replace") as process:
            try:
                stdout, stderr = process.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout, stderr = process.communicate()
            except BaseException:
                process.kill()
                process.communicate()
                raise
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        seconds = (time.perf_counter_ns() - started) / 1e9
        self.context.workspace.record("perf-commands", f"{self.binary} {args}\nexit={result.returncode}\n"
                                      f"seconds={seconds:.9f}\n{result.stdout}\n{result.stderr}\n")
        if result.returncode or timed_out:
            reason = " (timed out after 300 seconds)" if timed_out else ""
            raise RuntimeError(f"{self.binary.name} {args} exited {result.returncode}{reason}: "
                               f"{result.stderr[-4000:]}")
        self.last_stdout = result.stdout
        return seconds

    def version(self) -> str:
        return subprocess.run([str(self.binary), "--version"], env=self.environment,
                              capture_output=True, text=True, check=True, timeout=15).stdout.strip()

    def guest(self, name: str, script: str) -> None:
        self.call("exec", name, "--user", "root", "--", "/bin/sh", "-ec", script)

    def populate(self, name: str) -> None:
        if self.context.cohort.written_mib:
            self.guest(name, f"yes SILO-PERF | head -c {self.context.cohort.written_mib * 1024 * 1024} "
                            "> /perf-payload; sync")
        self.workload(name, initialize=True)

    def workload(self, name: str, *, initialize: bool) -> None:
        workload = self.context.cohort.workload
        if workload is None:
            return
        if initialize:
            # msb supplies this mount through create --tmpfs, like bench2.
            script = "test -d /fill"
            if self.system == "silo":
                script = f"mkdir -p /fill; mount -t tmpfs -o size={workload.tmpfs_mib}m tmpfs /fill"
            self.guest(name, script)
        generation = self.workload_generations.get(name, 0)
        for step in writes(workload, generation, initialize=initialize):
            self.write_payload(name, step)
        self.workload_generations[name] = generation + 1

    def write_payload(self, name: str, step: Write) -> None:
        with tempfile.TemporaryDirectory(prefix="perf-payload-", dir=self.context.workspace.root) as directory:
            source = Path(directory) / "payload"
            step.save(source)
            failure: BaseException | None = None
            try:
                self.call(*copy_command(self.system, source, name, step.destination))
                self.guest(name, step.script)
            except BaseException as error:
                failure = error
            try:
                if step.destination == INPUT:
                    self.guest(name, f"rm -f {INPUT}")
            except BaseException as error:
                if failure is not None:
                    raise BaseExceptionGroup("workload and staging cleanup failed", [failure, error])
                raise
            if failure is not None:
                raise failure

    def populate_source(self) -> None:
        self.populate(self.context.names.source)

    def rewrite_source(self, *, snapshot: bool) -> None:
        name = self.context.names.snapshot_source if snapshot else self.context.names.source
        self.workload(name, initialize=False)

    def before_snapshot(self) -> None:
        self.guest(self.context.names.snapshot_source, marker_write("before-snapshot"))

    def after_snapshot(self) -> None:
        name = self.context.names.snapshot_source
        self.guest(name, marker_write("after-snapshot"))

    def check_fork(self) -> None:
        name = self.context.names.snapshot_source
        child = name + "-check"
        self.fork(name, child)
        self.guest(child, marker_check("after-snapshot"))
        self.remove_machine(child)

    def check_restore(self, action: Action) -> None:
        name = EXEC_NAMES[action](self.context.names.source, self.context.names.snapshot_source)
        self.guest(name, marker_check("before-snapshot"))

    def prepare_fork_snapshots(self) -> None:
        # Run after all existing rows so this conditioning cannot warm their clocks.
        source = self.context.names.snapshot_source
        for suffix in ("-identity-f1", "-identity-f2"):
            self.workload(source, initialize=False)
            self.fork(source, source + suffix)
        self.workload(source, initialize=False)

    def fork(self, source: str, name: str) -> float:
        raise NotImplementedError

    def remove_machine(self, name: str) -> None:
        raise NotImplementedError



class SiloDriver(CommandDriver):
    system = "silo"
    modes = (Mode.IMAGE, Mode.AGENT)

    def __init__(self, context: Context) -> None:
        super().__init__(context, context.workspace.config.silo, context.workspace.env())
        self.snapshot_ids: dict[str, str] = {}
        self.image = context.cohort.image

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
        # Container acquisition and lower preparation belong to create_first.
        # Raw conversion is likewise a separately recorded scenario action.
        pass

    def create(self, name: str) -> float:
        self.machines.append(name)
        self.context.workspace.register_machine(name)
        return self.call("create", "--name", name, *self.shape(), self.image)

    def fork(self, source: str, name: str) -> float:
        self.machines.append(name)
        self.context.workspace.register_machine(name)
        return self.call("fork", source, "--live", "--name", name)

    def remove_machine(self, name: str) -> None:
        self.call("rm", "--force", name)
        self.machines.remove(name)
        self.context.workspace.unregister_machine(name)


    def measure(self, action: Action) -> dict[str, float]:
        a, b = self.context.names.source, self.context.names.snapshot_source
        if action == Action.IMAGE_CONVERT_RAW:
            command = raw_conversion_command(self.context.cohort)
            if not command:
                return {}
            seconds = self.call(*command)
            converted = json.loads(self.last_stdout)
            identity = converted["id"]
            if not isinstance(identity, str) or not identity:
                raise ValueError("raw image conversion returned no image id")
            self.image = identity
            return {action.value: seconds}
        if action == Action.CREATE_FIRST:
            name = a + "-first"
            seconds = self.create(name)
            self.remove_machine(name)
            return {action.value: seconds}
        if action == Action.RUN:
            try:
                seconds = self.call("run", *self.shape(), self.image, "--", "/bin/true")
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
        elif action == Action.SNAPSHOT_VERIFY:
            if not self.context.cohort.raw_root:
                return {}
            seconds = self.call("snapshot", "verify", b + "-s2")
        elif action in (Action.FORK_FIRST, Action.FORK_SECOND):
            name = a + ("-f1" if action == Action.FORK_FIRST else "-f2")
            seconds = self.fork(a, name)
        elif action == Action.FORK_OF_FORK:
            seconds = self.fork(a + "-f1", a + "-f1-f1")
        elif action in (Action.SNAPSHOT_FULL, Action.SNAPSHOT_INCREMENTAL,
                        Action.SNAPSHOT_OF_RESTORED, Action.SNAPSHOT_AFTER_RESTART,
                        Action.SNAPSHOT_SOURCE_AFTER_FORKS, Action.SNAPSHOT_FORK_CHILD_FIRST,
                        Action.SNAPSHOT_FORK_CHILD_SECOND):
            source = (b + "-r1" if action == Action.SNAPSHOT_OF_RESTORED else
                      b + "-identity-f1" if action in (Action.SNAPSHOT_FORK_CHILD_FIRST,
                                                      Action.SNAPSHOT_FORK_CHILD_SECOND) else b)
            if action == Action.SNAPSHOT_FORK_CHILD_SECOND:
                self.workload(source, initialize=False)
            if action == Action.SNAPSHOT_AFTER_RESTART:
                self.call("stop", source)
                self.call("start", source)
                self.call("exec", source, "--", "/bin/true")
                self.populate(source)
            suffix = {Action.SNAPSHOT_FULL: "-s1", Action.SNAPSHOT_INCREMENTAL: "-s2",
                      Action.SNAPSHOT_OF_RESTORED: "-restored", Action.SNAPSHOT_AFTER_RESTART: "-restarted",
                      Action.SNAPSHOT_SOURCE_AFTER_FORKS: "-after-forks",
                      Action.SNAPSHOT_FORK_CHILD_FIRST: "-fork-first",
                      Action.SNAPSHOT_FORK_CHILD_SECOND: "-fork-second"}[action]
            name = b + suffix
            self.snapshots.append(name)
            seconds = self.call("snapshot", "create", source, "--memory", "--name", name,
                                *(["--capture-policy", "full"] if action == Action.SNAPSHOT_FULL else []))
            identity = snapshot_id(self.context.workspace.state_db(), name)
            if identity is None:
                raise RuntimeError(f"published snapshot has no catalog name: {name}")
            self.snapshot_ids[name] = identity
        elif action in (Action.RESTORE_FIRST, Action.RESTORE_SECOND):
            name = b + ("-r1" if action == Action.RESTORE_FIRST else "-r2")
            self.machines.append(name)
            self.context.workspace.register_machine(name)
            seconds = self.call("restore", b + "-s2", "--name", name)
        else:
            raise ValueError(f"unsupported Silo action: {action}")
        return {action.value: seconds}

    def remove_fork_sources(self) -> None:
        a = self.context.names.source
        for name in (a + "-f1-f1", a + "-f2", a + "-f1", a):
            self.remove_machine(name)

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
                    self.call("snapshot", "rm", identity)
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
        args = ["-c", str(self.context.cohort.cpus), "-m", f"{self.context.cohort.memory_gib}G"]
        if self.context.cohort.workload is not None:
            args += ["--tmpfs", f"/fill:{self.context.cohort.workload.tmpfs_mib}M"]
        return args

    def prepare(self) -> None:
        image = self.context.cohort.msb_image
        if image is None:
            raise ValueError("msb cohort needs an msb_image")
        self.call("pull", image)


    def create(self, name: str) -> float:
        self.machines.append(name)
        return self.call("create", "-n", name, *self.shape(), str(self.context.cohort.msb_image))

    def fork(self, source: str, name: str) -> float:
        self.machines.append(name)
        return self.call("fork", source, "-n", name)

    def remove_machine(self, name: str) -> None:
        self.call("rm", "-f", name)
        self.machines.remove(name)

    def measure(self, action: Action) -> dict[str, float]:
        a, b = self.context.names.source, self.context.names.snapshot_source
        if action in (Action.IMAGE_CONVERT_RAW, Action.SNAPSHOT_VERIFY):
            return {}
        if action == Action.CREATE_FIRST:
            name = a + "-first"
            seconds = self.create(name)
            self.remove_machine(name)
            return {action.value: seconds}
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
            seconds = self.fork(a, name)
        elif action == Action.FORK_OF_FORK:
            seconds = self.fork(a + "-f1", a + "-f1-f1")
        elif action in (Action.SNAPSHOT_FULL, Action.SNAPSHOT_INCREMENTAL,
                        Action.SNAPSHOT_OF_RESTORED, Action.SNAPSHOT_AFTER_RESTART,
                        Action.SNAPSHOT_SOURCE_AFTER_FORKS, Action.SNAPSHOT_FORK_CHILD_FIRST,
                        Action.SNAPSHOT_FORK_CHILD_SECOND):
            source = (b + "-r1" if action == Action.SNAPSHOT_OF_RESTORED else
                      b + "-identity-f1" if action in (Action.SNAPSHOT_FORK_CHILD_FIRST,
                                                      Action.SNAPSHOT_FORK_CHILD_SECOND) else b)
            if action == Action.SNAPSHOT_FORK_CHILD_SECOND:
                self.workload(source, initialize=False)
            if action == Action.SNAPSHOT_AFTER_RESTART:
                self.call("stop", source)
                self.call("start", source)
                self.call("exec", source, "--", "/bin/true")
                self.populate(source)
            name = {Action.SNAPSHOT_FULL: "s1", Action.SNAPSHOT_INCREMENTAL: "s2",
                    Action.SNAPSHOT_OF_RESTORED: "restored", Action.SNAPSHOT_AFTER_RESTART: "restarted",
                    Action.SNAPSHOT_SOURCE_AFTER_FORKS: "after-forks",
                    Action.SNAPSHOT_FORK_CHILD_FIRST: "fork-first",
                    Action.SNAPSHOT_FORK_CHILD_SECOND: "fork-second"}[action]
            self.snapshots.append(source + ":" + name)
            seconds = self.call("snap", "create", name, "--sandbox", source, "--full")
        elif action in (Action.RESTORE_FIRST, Action.RESTORE_SECOND):
            name = b + ("-r1" if action == Action.RESTORE_FIRST else "-r2")
            self.machines.append(name)
            seconds = self.call("restore", b + ":s2", "-n", name)
        else:
            raise ValueError(f"unsupported msb action: {action}")
        return {action.value: seconds}

    def remove_fork_sources(self) -> None:
        a = self.context.names.source
        self.call("rm", "-f", a + "-f1-f1", a + "-f1", a + "-f2", a)
        for name in (a + "-f1-f1", a + "-f1", a + "-f2", a):
            self.machines.remove(name)

    def prepare_snapshots(self) -> None:
        self.create(self.context.names.snapshot_source)
        self.populate(self.context.names.snapshot_source)

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
