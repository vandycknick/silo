"""Real live-fork observables: CLI result, durable journal, local cut and /proc.

Every value here comes from the staged `silo fork` CLI, its durable journal
(`live_fork`, `live_fork_child`, `fork_event`), the authenticated local cut
under `images/tmp/<operation>/cut`, monitor trace logs, `/proc` and the guest's
own witnesses. Nothing grants a capability, edits a journal row or synthesizes
a result. The CLI prints exactly one `LiveForkResult` document on stdout for
every accepted operation; refusals before admission print nothing there.

Durable phase stamps are `CLOCK_MONOTONIC` nanoseconds, the same clock as
`time.monotonic_ns()` on Linux, so caller dispatch/exit brackets every stamp.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess
import sys
import threading
import time
from uuid import UUID, uuid4

from . import pause, procs, restore, shutdown, stopped
from .cli import Silo, record_timing
from .config import REPO

STAGES = ("admitted", "capturing", "restoring", "settling", "finished")
CAPTURE_KINDS = {"pending", "sealed", "failed", "abandoned"}
SOURCE_KINDS = {"pending", "unchanged", "resumed", "preserved", "resume-failed", "unknown"}
CHILD_KINDS = {"pending", "constructing", "activating", "running", "failed", "cancelled",
               "abandoned", "recovery-pending"}
FAILURE_PHASES = {"capture", "construction", "activation", "cleanup"}
# Lifecycle diagnostics use the shared bounded UTF-8 string wire representation.
_DIAGNOSED = {"failed", "abandoned", "recovery-pending", "resume-failed", "unknown"}
PARENT_PHASES = ("api_entered", "admission_committed", "capture_submitted", "seal_authenticated",
                 "source_settled", "finished")
CHILD_PHASES = ("constructing", "prepared", "activating", "running")
RESULT_KEYS = {"operationId", "sourceMachineId", "sourceRunId", "captureId", "stage",
               "cancellationRequested", "capture", "source", "resources", "children"}
CHILD_KEYS = {"index", "name", "machineId", "runId", "outcome"}
FORK_TIMEOUT = 600
MIB = 1024 * 1024


def _uuid(value: object, what: str) -> UUID:
    assert isinstance(value, str), (what, value)
    parsed = UUID(value)
    assert parsed.int != 0, f"nil {what}"
    return parsed


def _outcome(value: object, kinds: set[str], what: str) -> str:
    assert isinstance(value, dict) and isinstance(value.get("kind"), str), (what, value)
    kind = value["kind"]
    assert kind in kinds, (what, value)
    if kind in _DIAGNOSED:
        diagnostic = value.get("diagnostic")
        assert isinstance(diagnostic, str), f"{what} {kind} lacks its diagnostic: {value}"
        assert len(diagnostic.encode("utf-8")) <= 4096, f"{what} diagnostic exceeds its bound"
    return kind


def validate(result: object, *, operation: str, names: list[str]) -> dict:
    """Strict public result shape: every requested child, named and identified."""
    assert isinstance(result, dict) and set(result) == RESULT_KEYS, result
    assert result["operationId"] == operation, (result["operationId"], operation)
    for key in ("sourceMachineId", "sourceRunId", "captureId"):
        _uuid(result[key], key)
    assert result["stage"] in STAGES, result["stage"]
    assert isinstance(result["cancellationRequested"], bool)
    capture = _outcome(result["capture"], CAPTURE_KINDS, "capture")
    if capture == "sealed":
        cut = result["capture"].get("cutId")
        assert isinstance(cut, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", cut), result["capture"]
    _outcome(result["source"], SOURCE_KINDS, "source")
    assert isinstance(result["resources"], dict), result["resources"]
    children = result["children"]
    assert isinstance(children, list) and len(children) == len(names), (children, names)
    machines, runs = set(), set()
    for index, (child, name) in enumerate(zip(children, names)):
        assert isinstance(child, dict) and set(child) == CHILD_KEYS, child
        assert child["index"] == index and child["name"] == name, (index, name, child)
        machines.add(_uuid(child["machineId"], "child machineId"))
        runs.add(_uuid(child["runId"], "child runId"))
        kind = _outcome(child["outcome"], CHILD_KINDS, f"child {index}")
        if kind == "failed":
            assert child["outcome"].get("phase") in FAILURE_PHASES, child
    assert len(machines) == len(runs) == len(names), "reserved child identities must be unique"
    assert _uuid(result["sourceMachineId"], "source") not in machines
    assert _uuid(result["sourceRunId"], "source run") not in runs
    return result


def outcomes(result: dict) -> list[str]:
    return [child["outcome"]["kind"] for child in result["children"]]


@dataclass(frozen=True)
class Call:
    """One real CLI invocation with harness monotonic dispatch/exit brackets."""
    operation: str
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    result: dict | None
    dispatched_ns: int
    exited_ns: int

    @property
    def caller_seconds(self) -> float:
        return (self.exited_ns - self.dispatched_ns) / 1e9


def children_json(names: list[str], *, hooks: dict[int, dict] | None = None) -> str:
    """Explicit per-child requests with empty destinations (no host grants)."""
    hooks = hooks or {}
    return json.dumps([{"name": name, "activationHook": hooks.get(index), "destination": {}}
                       for index, name in enumerate(names)])


def create_argv(source: str, names: list[str], *flags: str, operation: str,
                hooks: dict[int, dict] | None = None) -> list[str]:
    selection = (["--children-json", children_json(names, hooks=hooks)] if hooks
                 else [argument for name in names for argument in ("--name", name)])
    return ["fork", source, "--live", *selection, "--operation-id", operation, *flags]


def _nofile(limit: int | None):
    if limit is None:
        return None

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    return apply


def spawn(silo: Silo, source: str, names: list[str], *flags: str, operation: str | None = None,
          hooks: dict[int, dict] | None = None, nofile: int | None = None,
          ) -> tuple[subprocess.Popen[bytes], list[str], str, int]:
    """Start a real `silo fork --live`; children are registered for cleanup first."""
    operation = operation or str(uuid4())
    for name in names:
        # Register even refusal paths: a failed refusal must not leak machines.
        silo.ws.register_machine(name)
    args = create_argv(source, names, *flags, operation=operation, hooks=hooks)
    silo.ws.record("fork", f"$ silo {shlex.join(args)}\n")
    dispatched = time.monotonic_ns()
    process = subprocess.Popen([str(silo.ws.config.silo), *args], env=silo.ws.env(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=_nofile(nofile))
    return process, args, operation, dispatched


def finish(silo: Silo, process: subprocess.Popen[bytes], args: list[str], operation: str,
           dispatched: int, *, names: list[str], timeout: float = FORK_TIMEOUT,
           expect: int | None = None) -> Call:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=30)
        silo.ws.record("fork", f"timeout\n{stdout.decode(errors='replace')}\n[stderr]\n"
                               f"{stderr.decode(errors='replace')}\n")
        raise AssertionError(f"silo {shlex.join(args[:3])} exceeded {timeout}s; see fork.log")
    exited = time.monotonic_ns()
    record_timing(silo.ws, "silo fork", dispatched / 1e9, f"exit-{process.returncode}")
    text, errors = stdout.decode(errors="replace"), stderr.decode(errors="replace")
    silo.ws.record("fork", json.dumps({"operation": operation, "exit": process.returncode,
                                       "dispatchedNs": dispatched, "exitedNs": exited,
                                       "stdout": text, "stderr": errors}) + "\n")
    result = validate(json.loads(text), operation=operation, names=names) if text.strip() else None
    if expect is not None:
        assert process.returncode == expect, (process.returncode, errors[-4000:])
    return Call(operation, args, process.returncode, text, errors, result, dispatched, exited)


def run(silo: Silo, source: str, names: list[str], *flags: str, operation: str | None = None,
        hooks: dict[int, dict] | None = None, nofile: int | None = None,
        expect: int | None = None, timeout: float = FORK_TIMEOUT) -> Call:
    process, args, operation, dispatched = spawn(silo, source, names, *flags, operation=operation,
                                                 hooks=hooks, nofile=nofile)
    return finish(silo, process, args, operation, dispatched, names=names, timeout=timeout,
                  expect=expect)


def observe(silo: Silo, operation: str, *, cancel: bool = False) -> dict:
    """`silo fork --operation` (exit 0 even for failed operations), plus `--cancel`."""
    result = silo.run("fork", "--operation", operation, *(["--cancel"] if cancel else []),
                      timeout=180, label="fork-observe")
    value = json.loads(result.stdout)
    return validate(value, operation=operation, names=[child["name"] for child in value["children"]])


def settle(silo: Silo, operation: str, *, timeout: float = 240) -> dict:
    """Observe (and thereby recover) until the operation is finished."""
    deadline = time.monotonic() + timeout
    while True:
        value = observe(silo, operation)
        if value["stage"] == "finished":
            return value
        assert time.monotonic() < deadline, f"fork {operation} never finished: {json.dumps(value)}"
        time.sleep(0.5)


class TracedSource:
    """A source started under `stopped_trace` through `fork_process`.

    The real `silo fork --live` manager and every child monitor/worker it
    launches are traced descendants, so one real source monitor syscall can be
    held at a capture boundary while the manager is cancelled or killed.
    The controller's EXITKILL fence reaps everything it owns.
    """

    def __init__(self, silo: Silo, source: str, names: list[str], boundary: str, *flags: str) -> None:
        self.silo = silo
        self.names = names
        self.operation = str(uuid4())
        evidence = silo.ws.evidence
        for name in names:
            silo.ws.register_machine(name)
        driver = evidence / "fork-process-request.json"
        driver.write_text(json.dumps({
            "silo": str(silo.ws.config.silo), "name": source, "evidence": str(evidence),
            "fork": create_argv(source, names, *flags, operation=self.operation),
        }) + "\n")
        request = evidence / "boundary-request.json"
        request.write_text(json.dumps({
            "command": [sys.executable, "-m", "silo_smoke.fork_process", str(driver)],
            "target": str(stopped.writable_paths(silo, source)["root"]), "boundary": boundary,
            "machines": str(silo.ws.silo_home / "machines"),
            "evidence": str(evidence), "release": str(evidence / "boundary-release"),
        }) + "\n")
        with (evidence / "boundary-controller.log").open("wb") as output:
            self.controller = subprocess.Popen(
                [sys.executable, "-m", "silo_smoke.stopped_trace", str(request)],
                env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")),
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT)
        self.manager: int | None = None
        assert self.wait("fork-traced-start.json")["code"] == 0

    def record(self, filename: str) -> dict | None:
        path = self.silo.ws.evidence / filename
        if path.exists():
            return json.loads(path.read_text())
        assert self.controller.poll() is None, f"fork tracer ended before {filename}"
        return None

    def wait(self, filename: str, timeout: float = 180) -> dict:
        return shutdown.until(lambda: self.record(filename), timeout=timeout,
                              description=f"fork trace did not produce {filename}")

    def command(self, line: str) -> None:
        assert self.controller.stdin is not None
        self.controller.stdin.write((line + "\n").encode())
        self.controller.stdin.flush()

    def fork(self) -> dict:
        """Dispatch the traced manager and wait for the held real boundary."""
        self.command("fork")
        self.manager = int(self.wait("fork-manager-process.json")["pid"])
        held = self.wait("boundary-held.json")
        assert held["injectedReturn"] is False, held
        self.silo.ws.record("fork-boundary-held", json.dumps(held, sort_keys=True) + "\n")
        return held

    def release(self) -> None:
        (self.silo.ws.evidence / "boundary-release").touch(exist_ok=True)

    def manager_exit(self, timeout: float = 180) -> tuple[int, dict | None]:
        code = int(self.wait("fork-manager-result.json", timeout=timeout)["code"])
        text = (self.silo.ws.evidence / "fork-manager.stdout").read_text(errors="replace")
        result = validate(json.loads(text), operation=self.operation, names=self.names) if text.strip() else None
        return code, result

    def finish(self) -> None:
        """Stop the traced source; every traced owner must exit and be reaped."""
        self.command("stop")
        assert self.controller.wait(timeout=180) == 0, "fork trace owners did not finish"
        assert self.wait("fork-traced-stop.json")["code"] == 0

    def close(self) -> None:
        self.release()
        if self.controller.poll() is None:
            self.controller.terminate()
            try:
                self.controller.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.controller.kill()
                self.controller.wait(timeout=5)
        assert self.controller.stdin is not None
        self.controller.stdin.close()



# -- durable journal ------------------------------------------------------------

def _hex(operation: str) -> str:
    return UUID(operation).hex


def events(silo: Silo, operation: str) -> dict[tuple[int | None, str], int]:
    """Durable fork phase stamps keyed by (child index or None, phase)."""
    rows = procs.query(silo.ws.state_db(),
                       "SELECT ifnull(child_index,''),phase,monotonic_ns FROM fork_event"
                       f" WHERE replace(operation_id,'-','')='{_hex(operation)}'")
    found: dict[tuple[int | None, str], int] = {}
    for index, phase, stamp in rows:
        key = (int(index) if index != "" else None, phase)
        assert key not in found, f"duplicate fork phase {key}"
        assert phase in (CHILD_PHASES if key[0] is not None else PARENT_PHASES), key
        found[key] = int(stamp)
    return found


def journal(silo: Silo, operation: str) -> tuple[dict, list[dict]]:
    parents = procs.query(silo.ws.state_db(),
                          "SELECT json(result_json) FROM live_fork"
                          f" WHERE replace(operation_id,'-','')='{_hex(operation)}'")
    assert len(parents) == 1, parents
    rows = procs.query(silo.ws.state_db(),
                       "SELECT child_index,name,machine_id,run_id,ifnull(launch_id,''),json(result_json)"
                       " FROM live_fork_child"
                       f" WHERE replace(operation_id,'-','')='{_hex(operation)}' ORDER BY child_index")
    children = [{"index": int(index), "name": name, "machineId": machine, "runId": run_id,
                 "launchId": launch or None, "result": json.loads(value)}
                for index, name, machine, run_id, launch, value in rows]
    return json.loads(parents[0][0]), children


def journal_matches(silo: Silo, call_result: dict) -> None:
    parent, children = journal(silo, call_result["operationId"])
    for key in ("stage", "cancellationRequested", "capture", "source"):
        assert parent[key] == call_result[key], (key, parent, call_result)
    assert [child["index"] for child in children] == list(range(len(call_result["children"])))
    for row, child in zip(children, call_result["children"]):
        assert row["name"] == child["name"]
        assert UUID(row["machineId"]) == UUID(child["machineId"])
        assert UUID(row["runId"]) == UUID(child["runId"])
    silo.ws.record("fork-journal", json.dumps({"parent": parent, "children": children}) + "\n")


def ordered_events(call: Call, stamps: dict[tuple[int | None, str], int], *,
                   running: list[int]) -> None:
    """Parent and Running-child phases exist, are ordered and fall in the call."""
    for phase in PARENT_PHASES:
        assert (None, phase) in stamps, (phase, stamps)
    parent = [stamps[(None, phase)] for phase in PARENT_PHASES[:4]]
    assert parent == sorted(parent), stamps
    assert all(stamps[(None, phase)] <= stamps[(None, "finished")] for phase in PARENT_PHASES)
    for index in running:
        child = [stamps[(index, phase)] for phase in CHILD_PHASES]
        assert child == sorted(child), (index, stamps)
        assert stamps[(None, "seal_authenticated")] <= child[0], "child construction preceded the seal"
        assert child[-1] <= stamps[(None, "finished")]
    # The same CLOCK_MONOTONIC brackets every durable stamp.
    assert call.dispatched_ns <= min(stamps.values()) <= max(stamps.values()) <= call.exited_ns, (
        call.dispatched_ns, stamps, call.exited_ns)


# -- local cut ------------------------------------------------------------------

def cut_directory(silo: Silo, operation: str) -> Path:
    return silo.ws.silo_home / "images/tmp" / str(UUID(operation)) / "cut"


def cut(silo: Silo, call: Call, source_info: dict, boot_id: str,
        generation: dict[str, str]) -> restore.Checkpoint:
    """The authenticated local cut as a matched-cut oracle input; never a snapshot."""
    directory = cut_directory(silo, call.operation)
    seal = json.loads((directory / "vm.capture.json").read_bytes())
    assert seal["captureOutcome"] == "coherent" and seal["error"] is None, seal
    assert UUID(seal["captureId"]) == UUID(call.result["captureId"])
    assert seal["runId"] == source_info["run_id"]
    assert seal["freezeOperationId"] and seal["freezeEpoch"] > 0
    return restore.Checkpoint("", f"fork:{call.operation}", directory, seal, source_info, boot_id,
                              generation)


# -- children -------------------------------------------------------------------

def child_identity(silo: Silo, name: str, child: dict, saved: restore.Checkpoint) -> dict:
    """Fresh machine/run/generation identity; inherited boot identity."""
    info = silo.info(name)
    assert info["state"] == "running" and info["ready"] is True, info
    assert UUID(info["id"]) == UUID(child["machineId"]) and UUID(info["run_id"]) == UUID(child["runId"])
    assert info["id"] != saved.source_info["id"] and info["run_id"] != saved.source_info["run_id"]
    assert silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout == saved.boot_id
    generation = pause.generation(silo, name)
    assert generation["request_id"] != saved.generation["request_id"]
    assert generation["completed_sequence"] == generation["ack_sequence"] == generation["request_sequence"]
    assert generation["request_flags"] == generation["completed_flags"] == "1"
    assert int(generation["reseed_count"]) == int(saved.generation["reseed_count"]) + 1
    silo.ws.record("fork-child-generation", json.dumps({
        "machine": name, "source": saved.generation, "child": generation,
        "sourceIdentity": saved.source_info, "childIdentity": info, "bootId": saved.boot_id,
    }, sort_keys=True) + "\n")
    return {"info": info, "generation": generation}


def absent(silo: Silo, child: dict) -> None:
    """A child that never ran (cancelled/abandoned): no machine, process or directory."""
    assert not any(entry["name"] == child["name"] for entry in silo.ls()), child
    assert not (silo.ws.silo_home / "machines" / UUID(child["machineId"]).hex).exists(), child
    assert not (silo.ws.silo_home / "machines" / str(UUID(child["machineId"]))).exists(), child


def stop_and_remove(silo: Silo, names: list[str]) -> None:
    """Normal exact-run stop (monitor/worker exit, lease released), then removal."""
    for name in names:
        stopped.stop(silo, name, require_clean=False)
    for name in names:
        silo.rm(name)


# -- processes ------------------------------------------------------------------

def _cmdline(pid: int) -> str:
    return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")


def _comm(pid: int) -> str:
    return Path(f"/proc/{pid}/comm").read_text().strip()


def vm_processes(silo: Silo) -> dict[int, str]:
    """Monitors whose arguments name this workspace, plus their krun workers."""
    roots = {str(silo.ws.root), str(silo.ws.run_root), str(silo.ws.silo_home)}
    found: dict[int, str] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        pid = int(entry.name)
        try:
            comm = _comm(pid)
            if comm in {"netd", "silo"} or comm.startswith("python"):
                continue
            state = (entry / "stat").read_text().rsplit(") ", 1)[1].split()[0]
            if state in {"Z", "X"} or not any(root in _cmdline(pid) for root in roots):
                continue
            found[pid] = comm
            for task in (entry / "task").iterdir():
                for child in (task / "children").read_text().split():
                    if _comm(int(child)) == "krun":
                        found[int(child)] = "krun"
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return found


def assert_no_orphans(silo: Silo, live: list[str]) -> dict:
    """Every workspace VM process belongs to exactly one live machine's holder record."""
    expected: dict[int, str] = {}
    for name in live:
        holders, _ = shutdown.holder(silo, name)
        for entry in holders["holders"]:
            expected[int(entry["pid"])] = name
    found = vm_processes(silo)
    evidence = {"live": live, "expected": {str(pid): name for pid, name in expected.items()},
                "found": {str(pid): comm for pid, comm in found.items()}}
    silo.ws.record("fork-process-ownership", json.dumps(evidence, sort_keys=True) + "\n")
    orphans = sorted(set(found) - set(expected))
    assert not orphans, f"unowned workspace VM processes: {[(pid, found[pid], _cmdline(pid)) for pid in orphans]}"
    assert set(expected) <= set(found), f"live machine holders are not running: {evidence}"
    return evidence


def worker(silo: Silo, name: str) -> int:
    holders, _ = shutdown.holder(silo, name)
    workers = [int(entry["pid"]) for entry in holders["holders"] if entry["role"] == "krun-worker"]
    assert len(workers) == 1, holders
    return workers[0]


# -- physical sharing -----------------------------------------------------------

SMAPS_BOUND = 64 * MIB
_SMAPS_HEADER = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) (\d+)\s*(.*)$")
_SMAPS_FIELD = re.compile(r"^(\w+):\s+(\d+) kB$")
SHARING_KEYS = ("Rss", "Pss", "Shared_Clean", "Shared_Dirty", "Private_Clean", "Private_Dirty",
                "Anonymous")


def smaps(pid: int) -> list[dict]:
    with open(f"/proc/{pid}/smaps", "rb") as stream:
        raw = stream.read(SMAPS_BOUND + 1)
    assert len(raw) <= SMAPS_BOUND, "unbounded smaps"
    mappings: list[dict] = []
    for line in raw.decode(errors="replace").splitlines():
        header = _SMAPS_HEADER.match(line)
        if header is not None:
            start, end, permissions, offset, major, minor, inode, name = header.groups()
            mappings.append({"start": int(start, 16), "end": int(end, 16), "permissions": permissions,
                             "offset": int(offset, 16), "device": f"{int(major, 16)}:{int(minor, 16)}",
                             "inode": int(inode), "name": name, "metrics": {}})
            continue
        field = _SMAPS_FIELD.match(line)
        if field is not None and mappings:
            mappings[-1]["metrics"][field.group(1)] = int(field.group(2)) * 1024
    return mappings


def ram_mapping(pid: int, ram: Path) -> dict:
    """Exact MAP_PRIVATE VMAs of the cut RAM inode in one native worker."""
    metadata = ram.stat()
    path = str(ram.resolve())
    selected = [mapping for mapping in smaps(pid) if mapping["inode"] == metadata.st_ino
                and mapping["name"].removesuffix(" (deleted)") == path]
    assert selected, f"worker {pid} does not map the cut RAM inode {path}"
    assert all(mapping["permissions"] == "rw-p" for mapping in selected), selected
    devices = {mapping["device"] for mapping in selected}
    assert len(devices) == 1, selected
    totals = {key: sum(mapping["metrics"].get(key, 0) for mapping in selected) for key in SHARING_KEYS}
    return {"pid": pid, "inode": metadata.st_ino, "statDevice": metadata.st_dev,
            "smapsDevice": next(iter(devices)), "mappedBytes": sum(m["end"] - m["start"] for m in selected),
            "vmas": len(selected), "totals": totals}


def sharing(silo: Silo, names: list[str], ram: Path, *, source: str | None = None) -> dict:
    """One shared RAM inode across every child; PSS, never RSS sums, as physical RAM.

    A running source may still map the same accepted baseline inode; its VMAs
    (if any) are recorded and included in the unique-RAM PSS sum, since PSS
    divides every shared page among all of its mappers.
    """
    measured = {name: ram_mapping(worker(silo, name), ram) for name in names}
    identities = {(value["smapsDevice"], value["inode"]) for value in measured.values()}
    assert len(identities) == 1, f"children map different RAM inodes: {measured}"
    rss = sum(value["totals"]["Rss"] for value in measured.values())
    pss = sum(value["totals"]["Pss"] for value in measured.values())
    baseline = None
    if source is not None:
        path, inode = str(ram.resolve()), ram.stat().st_ino
        held = [mapping for mapping in smaps(worker(silo, source)) if mapping["inode"] == inode
                and mapping["name"].removesuffix(" (deleted)") == path]
        baseline = {"vmas": len(held), "totals": {key: sum(m["metrics"].get(key, 0) for m in held)
                                                  for key in SHARING_KEYS}}
    return {"children": len(names), "ram": str(ram), "identity": sorted(identities)[0],
            "perChild": measured, "rssSumBytes": rss, "childPssBytes": pss,
            "sourceBaseline": baseline,
            "uniqueRamPssBytes": pss + (baseline["totals"]["Pss"] if baseline else 0)}


# -- source capture boundaries from the source monitor's own trace ----------------

_TRACE_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z\s+(\w+)\s+(.*)$")
STAGING_DURABLE = "capture staging and request.json are durable"
PAUSE_ESTABLISHED = "capture pause established"
SEALED = "capture sealed"
PAUSE_RELEASED = "capture pause released with ClockOnly"
CONTINUATION_FINISHED = "capture continuation finished"
DISK_SEALED = "sealed writable disk role"


def source_trace(silo: Silo, source_id: str) -> Path:
    return silo.ws.silo_home / "logs/machines" / UUID(source_id).hex / "vm.trace.log"


def _realtime_ns(seconds: str, fraction: str | None) -> int:
    whole = datetime.strptime(seconds, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(whole.timestamp()) * 1_000_000_000 + int((fraction or "0").ljust(9, "0"))


_CAPTURE_EVENTS = (STAGING_DURABLE, PAUSE_ESTABLISHED, SEALED, PAUSE_RELEASED, CONTINUATION_FINISHED)


def capture_events(silo: Silo, source_id: str, capture_id: str) -> dict[str, list[tuple[int, str]]]:
    """This capture's monitor lines, keyed by event, with realtime nanoseconds.

    The staging event names the capture directory; its `operation` field then
    selects the remaining lines of the same live operation. Disk-seal lines
    carry no operation and are selected by the staging-to-seal window.
    """
    lines = source_trace(silo, source_id).read_text(errors="replace").splitlines()
    spellings = (str(UUID(capture_id)), UUID(capture_id).hex)
    staged = [line for line in lines
              if STAGING_DURABLE in line and any(spelling in line for spelling in spellings)]
    assert len(staged) == 1, f"source monitor staged capture {capture_id} {len(staged)} times"
    match = re.search(r"\boperation=(\S+)", staged[0])
    assert match is not None, staged[0]
    operation = match.group(1)
    found: dict[str, list[tuple[int, str]]] = {}
    disks: list[tuple[int, str]] = []
    for line in lines:
        parsed = _TRACE_LINE.match(line)
        if parsed is None:
            continue
        body = parsed.group(4)
        stamp = _realtime_ns(parsed.group(1), parsed.group(2))
        for name in _CAPTURE_EVENTS:
            if name in body and re.search(rf"\boperation={re.escape(operation)}(\s|$)", body):
                found.setdefault(name, []).append((stamp, line))
        if DISK_SEALED in body:
            disks.append((stamp, line))
    for name in _CAPTURE_EVENTS:
        assert len(found.get(name, [])) == 1, (name, found.get(name))
    first, sealed = found[STAGING_DURABLE][0][0], found[SEALED][0][0]
    found[DISK_SEALED] = [entry for entry in disks if first <= entry[0] <= sealed]
    return found


def product_interruption(found: dict[str, list[tuple[int, str]]]) -> dict:
    """Conservative monitor-reported interruption: staging durable (before the
    guest freeze) through continuation finished (after thaw and readiness)."""
    stamp = {name: values[0][0] for name, values in found.items() if name != DISK_SEALED}
    order = [stamp[name] for name in (STAGING_DURABLE, PAUSE_ESTABLISHED, SEALED, PAUSE_RELEASED,
                                      CONTINUATION_FINISHED)]
    assert order == sorted(order), found
    return {
        "conservativeSeconds": (stamp[CONTINUATION_FINISHED] - stamp[STAGING_DURABLE]) / 1e9,
        "vcpuPausedSeconds": (stamp[PAUSE_RELEASED] - stamp[PAUSE_ESTABLISHED]) / 1e9,
        "pauseToSealSeconds": (stamp[SEALED] - stamp[PAUSE_ESTABLISHED]) / 1e9,
        "clock": "monitor trace CLOCK_REALTIME",
    }


# -- independent host observation of the guest's durable workload ------------------

class WorkloadObserver:
    """Host-side, product-independent view of the guest witness's durable log.

    The `restore-execution` daemon commits a 64-byte record with fdatasync every
    50 ms into pre-materialized blocks. The host locates those exact bytes in
    the source's writable backing once, then polls the next sequence with pread
    and timestamps its first appearance on the host's CLOCK_MONOTONIC. A gap in
    appearances bounds the workload interruption without trusting any product
    timestamp. Resolution is the 50 ms commit cadence plus flush latency.
    """

    LIMIT = 32768

    def __init__(self, backing: Path, records: list[list[int]]) -> None:
        assert len(records) >= 2, "observer needs two committed witness records"
        self.backing = backing
        self.fd = os.open(backing, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.offset = self._locate([tuple(record) for record in records])
        self.next = records[-1][0] + 1
        self.seen: list[tuple[int, int, int]] = []
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="fork-workload-observer", daemon=True)
        self._thread.start()

    def _locate(self, records: list[tuple[int, ...]]) -> int:
        needle = restore.RECORD.pack(*records[0])
        size = os.fstat(self.fd).st_size
        chunk = 8 * MIB
        matches: list[int] = []
        position = 0
        while position < size:
            try:
                start = os.lseek(self.fd, position, os.SEEK_DATA)
            except OSError:
                break
            end = os.lseek(self.fd, start, os.SEEK_HOLE)
            cursor = start - start % restore.RECORD.size
            while cursor < end:
                data = os.pread(self.fd, min(chunk, end - cursor) + restore.RECORD.size, cursor)
                found = data.find(needle)
                while found >= 0:
                    if found % restore.RECORD.size == 0 and cursor + found not in matches:
                        matches.append(cursor + found)
                    found = data.find(needle, found + 1)
                cursor += chunk
            position = end
        assert len(matches) == 1, f"witness record 1 located {len(matches)} times in {self.backing}"
        offset = matches[0]
        for record in records:
            raw = os.pread(self.fd, restore.RECORD.size, offset + (record[0] - 1) * restore.RECORD.size)
            assert restore.RECORD.unpack(raw) == record, "witness log is not contiguous in the backing"
        return offset

    def _run(self) -> None:
        try:
            while not self._stop.is_set() and self.next <= self.LIMIT:
                raw = os.pread(self.fd, restore.RECORD.size,
                               self.offset + (self.next - 1) * restore.RECORD.size)
                if len(raw) == restore.RECORD.size and restore.RECORD.unpack(raw)[0] == self.next:
                    self.seen.append((self.next, time.monotonic_ns(), restore.RECORD.unpack(raw)[6]))
                    self.next += 1
                    continue
                time.sleep(0.002)
        except BaseException as error:  # noqa: BLE001 - surfaced by gap()/close()
            self._failure = error

    def wait_beyond(self, stamp_ns: int, count: int = 3, timeout: float = 30) -> None:
        shutdown.until(lambda: sum(1 for entry in self.seen if entry[1] > stamp_ns) >= count,
                       timeout=timeout, description="source workload made no durable progress")

    def gap(self, start_ns: int, end_ns: int) -> dict:
        """Largest appearance gap overlapping the caller's window."""
        if self._failure is not None:
            raise AssertionError("workload observer failed") from self._failure
        pairs = [(left, right) for left, right in zip(self.seen, self.seen[1:])
                 if right[1] >= start_ns and left[1] <= end_ns]
        assert pairs, "no host observations bracket the operation"
        left, right = max(pairs, key=lambda pair: pair[1][1] - pair[0][1])
        assert any(entry[1] < start_ns for entry in self.seen) and any(entry[1] > end_ns for entry in self.seen), (
            "workload observations do not bracket the operation window")
        return {"hostGapSeconds": (right[1] - left[1]) / 1e9,
                "guestClockGapSeconds": (right[2] - left[2]) / 1e9,
                "beforeSequence": left[0], "afterSequence": right[0],
                "clock": "host CLOCK_MONOTONIC first appearance in the source backing"}

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        os.close(self.fd)
