"""Two real local runtimes and black-box stopped-handoff evidence.

Each `Runtime` is one private Workspace (Home, config root, short run root)
with its own foreground daemon. The coordinator is always the actual
`silo handoff` CLI in the source runtime's environment; the destination is
selected only by explicit flags. Oracles are independent read-only catalog
queries and host-side reads of each Home's own private files. Nothing here
speaks the daemon protocol, fakes a peer or reads another runtime on a
runtime's behalf.

    laptop Workspace                      cloud Workspace
    SILO_HOME/config/run root A           SILO_HOME/config/run root B
    silo daemon run (A)  <-- same-euid --> silo daemon run (B)
            ^          gRPC, coordinator          ^
            +------ silo handoff (env A, --destination-* B) ------+
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
from uuid import UUID, uuid4

from . import procs, stopped
from .cli import Result, Silo
from .daemon import Daemon
from .errors import SmokeAssertion

# silo-chunks-v1 logical chunk geometry (ADR 0014); never a frame size.
CHUNK = 8 * 1024**2
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass
class Runtime:
    """One real Silo runtime: private roots plus its own foreground daemon."""
    label: str
    silo: Silo
    daemon: Daemon

    @property
    def ws(self):
        return self.silo.ws

    @property
    def config_dir(self) -> Path:
        # HostPaths::from_env: $XDG_CONFIG_HOME/silo; Workspace sets XDG_CONFIG_HOME.
        return self.ws.config_home / "silo"

    def destination_flags(self) -> list[str]:
        return ["--destination-home", str(self.ws.silo_home), "--destination-config", str(self.config_dir),
                "--destination-run-root", str(self.ws.run_root)]

    def runtime_id(self) -> UUID:
        rows = procs.query(self.ws.state_db(), "SELECT runtime_id FROM db_config WHERE id=1")
        assert len(rows) == 1, rows
        value = UUID(rows[0][0])
        assert value.int != 0
        return value

    def start(self) -> dict[str, Any]:
        self.daemon.start()
        status = self.daemon.wait_core()
        assert self.daemon.control_sock.is_socket()
        # Opening the catalog through the daemon initializes this Home's identity.
        self.silo.ls()
        self.ws.record("handoff-runtime", json.dumps({"label": self.label, "pid": status["pid"], "generation": status.get("generation"), "runtime": str(self.runtime_id()), "runRoot": str(self.ws.run_root)}, sort_keys=True) + "\n")
        return status

    def restart(self) -> None:
        """Explicitly restart the daemon; persistent identity survives, session identity does not."""
        identity = self.runtime_id()
        before = self.daemon.status()
        if self.daemon.proc is not None and self.daemon.proc.poll() is None:
            assert self.daemon.terminate(timeout=30) == 0
            assert self.daemon.wait_core("stopped")["core"] == "stopped"
        after = self.start()
        assert self.runtime_id() == identity
        if before is not None:
            assert after["pid"] != before["pid"]
            assert after.get("generation") != before.get("generation"), "daemon generation is session identity and must change"

    def kill_daemon(self) -> None:
        """SIGKILL and reap the daemon: an abrupt participant crash, not a shutdown."""
        assert self.daemon.proc is not None and self.daemon.proc.poll() is None
        pid = self.daemon.pid
        self.daemon.kill()
        procs.wait_gone(pid, 15)
        self.ws.record("handoff-runtime", json.dumps({"label": self.label, "killed": pid}) + "\n")


def new_operation() -> str:
    # The CLI requires canonical lowercase hyphenated UUIDs.
    return str(uuid4())


def _report(result: Result) -> dict[str, Any]:
    value = json.loads(result.stdout)
    assert isinstance(value, dict), result.stdout
    return value


def handoff(source: Runtime, destination: Runtime, *args: str, expect: int | None = 0, timeout: float = 600) -> Result:
    """Run the real coordinator in the source environment against explicit destination roots."""
    return source.silo.run("handoff", *args, *destination.destination_flags(), expect=expect, timeout=timeout, label="handoff-" + args[0])


def plan(source: Runtime, destination: Runtime, name: str, mode: str, operation: str, *flags: str, running: bool = False,
         batch: NoEffects | None = None) -> dict[str, Any]:
    """Preflight is an observation: it never reserves, stops or writes on either runtime.

    A running source's own guest legitimately writes its files, so then only the
    destination is held to byte-for-byte no-effect evidence."""
    runtimes = (destination,) if running else (source, destination)
    result = without_effects(runtimes, "plan", lambda: handoff(source, destination, "plan", name, "--mode", mode, "--operation", operation, *flags, timeout=300), batch=batch)
    value = _report(result)
    assert _DIGEST.fullmatch(value["digest"]), value["digest"]
    assert UUID(value["operation"]) == UUID(operation)
    assert UUID(value["sourceRuntime"]) == source.runtime_id()
    assert UUID(value["destinationRuntime"]) == destination.runtime_id()
    assert isinstance(value["plan"], dict)
    return value


def transfer_args(name: str, mode: str, operation: str, digest: str, *flags: str) -> list[str]:
    return ["transfer", name, "--mode", mode, "--operation", operation, "--approve-plan", digest, *flags]


def transfer(source: Runtime, destination: Runtime, name: str, mode: str, operation: str, digest: str, *flags: str) -> dict[str, Any]:
    report = _report(handoff(source, destination, *transfer_args(name, mode, operation, digest, *flags)))
    assert_committed(report, source, destination, operation, mode)
    return report


def status(source: Runtime, destination: Runtime, operation: str, *, batch: NoEffects | None = None) -> dict[str, Any]:
    """Read-only two-sided observation; it never chooses an outcome."""
    value = _report(without_effects((source, destination), "status", lambda: handoff(source, destination, "status", operation), batch=batch))
    assert UUID(value["operation"]) == UUID(operation)
    return value


def stale(source: Runtime, destination: Runtime, label: str, *args: str, batch: NoEffects | None = None) -> dict[str, Any] | None:
    """Replay an old request: refusal or a historical answer, never a durable change."""
    result = without_effects((source, destination), label, lambda: handoff(source, destination, *args, expect=None), batch=batch)
    return _report(result) if result.returncode == 0 else None


def recover(source: Runtime, destination: Runtime, operation: str, mode: str) -> dict[str, Any]:
    report = _report(handoff(source, destination, "recover", operation))
    assert_committed(report, source, destination, operation, mode)
    return report


def abort(source: Runtime, destination: Runtime, operation: str) -> dict[str, Any]:
    value = _report(handoff(source, destination, "abort", operation))
    assert UUID(value["operation"]) == UUID(operation)
    for side in ("source", "destination"):
        record = value[side]
        assert record["phase"] == "aborted" and record["terminal"]["decision"] == "aborted", (side, record)
        assert record["terminal"].get("authorization") is None
    return value


def assert_committed(report: dict[str, Any], source: Runtime, destination: Runtime, operation: str, mode: str) -> None:
    assert UUID(report["operation"]) == UUID(operation)
    assert report["decision"] == "committed", report
    for side, role in (("source", "source"), ("destination", "destination")):
        record = report[side]
        assert record["role"] == role and record["phase"] == "committed", (side, record)
        assert record["terminal"]["decision"] == "committed"
        intent = record["intent"]
        assert UUID(intent["operation"]) == UUID(operation) and intent["mode"] == mode
        assert UUID(intent["sourceRuntime"]) == source.runtime_id()
        assert UUID(intent["destinationRuntime"]) == destination.runtime_id()
    assert report["source"]["intent"] == report["destination"]["intent"]
    assert report["source"]["binding"] is not None
    assert report["source"]["binding"] == report["destination"]["binding"]
    for bucket in ("immutable", "mutable", "metadata"):
        counts = report["payload"][bucket]
        assert isinstance(counts["payloads"], int) and isinstance(counts["payloadBytes"], int) and counts["payloads"] >= 0


def destination_machine(report: dict[str, Any]) -> UUID:
    return UUID(report["destination"]["intent"]["destinationMachine"])


def destination_epoch(report: dict[str, Any]) -> int:
    intent = report["destination"]["intent"]
    return intent["fromEpoch"] + 1 if intent["mode"] == "relocate" else 0


def ledger(runtime: Runtime, operation: str) -> dict[str, Any] | None:
    """Read-only durable journal row, independent of any daemon."""
    wanted = UUID(operation)
    for operation_id, role, mode, phase, terminal, record in procs.query(runtime.ws.state_db(), "SELECT operation_id,role,mode,phase,terminal,json(record_json) FROM handoff_operation"):
        if UUID(operation_id) == wanted:
            return {"role": role, "mode": mode, "phase": phase, "terminal": terminal == "1", "record": json.loads(record)}
    return None


def ownership(runtime: Runtime, name: str) -> tuple[int, dict[str, Any]]:
    record = stopped.record(runtime.silo, name)
    return record["ownershipEpoch"], record["ownership"]


def machine_ids(runtime: Runtime) -> set[UUID]:
    return {UUID(row[0]) for row in procs.query(runtime.ws.state_db(), "SELECT id FROM machine_config")}


def assert_stopped_unstarted(runtime: Runtime, name: str) -> None:
    info = runtime.silo.info(name)
    assert info["state"] == "stopped" and info["run_id"] is None and info["ready"] is False, info
    state = procs.machine_state_json(runtime.ws, name)
    assert state["status"] == "stopped" and state.get("runId") is None and state.get("vmmonPid") is None, state


def refuse_start(runtime: Runtime, name: str) -> str:
    """A non-owner start fails typed, names the blocking operation and changes nothing."""
    epoch, owner = ownership(runtime, name)
    assert owner["state"] in {"reserved", "fenced", "relocated"}, owner
    result = runtime.silo.run("start", name, expect=None, timeout=60, label="handoff-refused-start")
    assert result.returncode != 0, result.stdout
    operation = UUID(owner["operation"])
    assert str(operation) in result.stderr or operation.hex in result.stderr, result.stderr
    assert ownership(runtime, name) == (epoch, owner)
    state = procs.machine_state_json(runtime.ws, name)
    assert state["status"] == "stopped" and state.get("runId") is None and state.get("vmmonPid") is None, state
    runtime.ws.record("handoff-refused-start", json.dumps({"machine": name, "ownership": owner, "epoch": epoch, "exit": result.returncode}, sort_keys=True) + "\n")
    return owner["state"]


# --- Independent payload oracle --------------------------------------------

def _read_exact(fd: int, offset: int, length: int) -> bytes:
    parts = []
    while length:
        block = os.pread(fd, length, offset)
        assert block, (fd, offset, length)
        parts.append(block)
        offset += len(block)
        length -= len(block)
    return b"".join(parts)


def chunk_digests(path: Path) -> dict[str, int]:
    """Nonzero 8 MiB-aligned decoded chunk identities (hex -> length) of one private file."""
    result: dict[str, int] = {}
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        for offset in range(0, before.st_size, CHUNK):
            block = _read_exact(fd, offset, min(CHUNK, before.st_size - offset))
            if block.count(0) != len(block):
                result[hashlib.sha256(block).hexdigest()] = len(block)
        after = os.fstat(fd)
        assert (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns), path
    finally:
        os.close(fd)
    return result


def writable_chunks(runtime: Runtime, name: str) -> dict[str, int]:
    """Captured writable streams: raw root or overlay upper, plus managed-writable disks."""
    result: dict[str, int] = {}
    for path in stopped.writable_paths(runtime.silo, name).values():
        result.update(chunk_digests(path))
    return result


def _pool(runtime: Runtime, kind: str) -> Path:
    return runtime.ws.silo_home / "images" / kind / "sha256"


def _verified_object(path: Path, digest: str, length: int | None) -> bool:
    if not path.is_file():
        return False
    data = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024**2):
            data.update(block)
            size += len(block)
    return data.hexdigest() == digest and (length is None or size == length)


def _hex(digest: str) -> str:
    assert _DIGEST.fullmatch(digest), digest
    return digest.removeprefix("sha256:")


def _lower_closure(runtime: Runtime, machine: str) -> tuple[list[str], list[str], list[str]]:
    """A layered root's immutable composition graph: lower IDs, pack streams and objects."""
    database = runtime.ws.state_db()
    lowers = [row[0] for row in procs.query(database, f"SELECT lower_id FROM machine_lower_dependency WHERE machine_id='{machine}'")]
    streams: list[str] = []
    objects: list[str] = []
    for lower in lowers:
        rows = procs.query(database, f"SELECT r.record_digest,r.fsmeta_digest,p.record_digest FROM composition_result r JOIN composition_recipe p ON p.id=r.recipe_id WHERE r.id='{lower}'")
        assert len(rows) == 1, (lower, rows)
        objects.extend(rows[0])
        packs = [row[0] for row in procs.query(database, f"SELECT l.pack_stream FROM composition_layer c JOIN layer_result l ON l.id=c.layer_result_id WHERE c.result_id='{lower}' ORDER BY c.position")]
        assert packs, f"composition {lower} names no layer occurrence"
        streams.extend(packs)
        objects.extend(row[0] for row in procs.query(database, f"SELECT DISTINCT o.object_digest FROM composition_layer c JOIN layer_object_dependency o ON o.result_id=c.layer_result_id WHERE c.result_id='{lower}'"))
    return lowers, streams, objects


def assert_immutable_warm(source: Runtime, name: str, destination: Runtime) -> None:
    """Prove the precondition for zero immutable payload: D already holds S's exact closure,
    including every composition graph member of a layered root."""
    machine = procs.machine_id(source.ws, name)
    streams = [row[0] for row in procs.query(source.ws.state_db(), f"SELECT stream_id FROM machine_stream_dependency WHERE machine_id='{machine}'")]
    objects = [row[0] for row in procs.query(source.ws.state_db(), f"SELECT object_digest FROM machine_object_dependency WHERE machine_id='{machine}'")]
    lowers, lower_streams, lower_objects = _lower_closure(source, machine)
    streams = sorted({*streams, *lower_streams})
    objects = sorted({*objects, *lower_objects})
    missing_lowers = [lower for lower in lowers if procs.query(destination.ws.state_db(), f"SELECT id FROM composition_result WHERE id='{lower}'") != [(lower,)]]
    missing_streams = [stream for stream in streams if not (_pool(destination, "streams") / _hex(stream)).is_file()]
    missing_objects = [digest for digest in objects if not _verified_object(_pool(destination, "objects") / _hex(digest), _hex(digest), None)]
    destination.ws.record("handoff-oracle", json.dumps({"warm": name, "lowers": lowers, "streams": streams, "objects": objects, "missingLowers": missing_lowers, "missingStreams": missing_streams, "missingObjects": missing_objects}, sort_keys=True) + "\n")
    assert streams or objects, "source closure has no immutable dependency to prove reuse against"
    assert not missing_lowers and not missing_streams and not missing_objects, (missing_lowers, missing_streams, missing_objects)


def expected_mutable(source: Runtime, name: str, destination: Runtime) -> dict[str, int]:
    """Chunks D must request: S's nonzero captured chunks minus verified D pool objects and,
    only for direct return to a recorded prior owner, chunks of that owner's own files."""
    needed = writable_chunks(source, name)
    pool = _pool(destination, "objects")
    present = {digest for digest, length in needed.items() if _verified_object(pool / digest, digest, length)}
    prior_owner = False
    if UUID(procs.machine_id(source.ws, name)) in machine_ids(destination):
        epoch, owner = ownership(destination, name)
        prior_owner = owner["state"] == "relocated" and UUID(owner["successorRuntime"]) == source.runtime_id()
        if prior_owner:
            present |= needed.keys() & writable_chunks(destination, name).keys()
    missing = {digest: length for digest, length in needed.items() if digest not in present}
    destination.ws.record("handoff-oracle", json.dumps({"machine": name, "captured": len(needed), "capturedBytes": sum(needed.values()), "reused": len(present), "priorOwner": prior_owner, "missing": len(missing), "missingBytes": sum(missing.values())}, sort_keys=True) + "\n")
    return missing


def assert_payload(report: dict[str, Any], *, mutable: dict[str, int]) -> None:
    payload = report["payload"]
    assert payload["immutable"] == {"payloads": 0, "payloadBytes": 0}, payload
    assert payload["mutable"] == {"payloads": len(mutable), "payloadBytes": sum(mutable.values())}, (payload, len(mutable), sum(mutable.values()))


# --- No-side-effect oracle ----------------------------------------------------

def _files(root: Path) -> dict[str, tuple]:
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] == "daemon" or path.name in {"state.db", "state.db-wal", "state.db-shm"}:
            continue
        metadata = path.lstat()
        result[str(relative)] = (metadata.st_mode, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns if not stat.S_ISDIR(metadata.st_mode) else None)
    return result


def _state(runtimes: tuple[Runtime, ...]) -> list:
    return [(stopped.catalog(runtime.silo), _files(runtime.ws.silo_home)) for runtime in runtimes]


class NoEffects:
    """A no-writer interval of serial read-only/rejected requests on stopped VMs.

    Construct after all setup/writes and discard before any boot, transfer,
    recovery, abort or daemon restart. Only read-only assertions and evidence
    logs (outside the Home) may intervene. Each request still independently
    inventories both catalogs and every previously checked private-file fact;
    its verified after-state supplies the next request's before-state.
    """

    def __init__(self, runtimes: tuple[Runtime, ...]) -> None:
        self.runtimes = runtimes
        self.before = _state(runtimes)

    def run(self, label: str, action: Callable[[], Result]) -> Result:
        result = action()
        after = _state(self.runtimes)
        changes = {}
        for runtime, (old_catalog, old_files), (new_catalog, new_files) in zip(self.runtimes, self.before, after):
            for scope, old, new in (("catalog", old_catalog, new_catalog), ("files", old_files, new_files)):
                delta = {key: {"before": old.get(key), "after": new.get(key)} for key in sorted(old.keys() | new.keys()) if old.get(key) != new.get(key)}
                if delta:
                    changes[f"{runtime.label}:{scope}"] = delta
        self.runtimes[0].ws.record("handoff-no-effects", json.dumps({"label": label, "args": result.args[1:], "exit": result.returncode, "changes": changes}, sort_keys=True, default=str) + "\n")
        assert not changes, (label, changes)
        self.before = after
        return result


def without_effects(runtimes: tuple[Runtime, ...], label: str, action: Callable[[], Result], *, batch: NoEffects | None = None) -> Result:
    """Require unchanged logical catalogs and private Home files after one CLI action."""
    if batch is None:
        batch = NoEffects(runtimes)
    assert batch.runtimes == runtimes, "a no-effects batch is bound to its ordered runtime pair"
    return batch.run(label, action)


def refuse(source: Runtime, destination: Runtime, label: str, *args: str, batch: NoEffects | None = None) -> Result:
    result = without_effects((source, destination), label, lambda: handoff(source, destination, *args, expect=None), batch=batch)
    assert result.returncode != 0, (label, result.stdout)
    return result


# --- Coordinator death --------------------------------------------------------

def interrupt_transfer(source: Runtime, destination: Runtime, name: str, mode: str, operation: str, digest: str, *flags: str, timeout: float = 300) -> dict[str, Any]:
    """Run a real transfer and SIGKILL the destination daemon after S sealed its cut and D
    accepted the binding, i.e. while missing mutable payload is being written.

    The coordinator then loses its peer mid-protocol and must exit with an error.
    Returns both read-only journal rows observed after the crash."""
    args = ["handoff", *transfer_args(name, mode, operation, digest, *flags), *destination.destination_flags()]
    process = source.silo.popen(*args)
    observed: dict[str, Any] = {}
    try:
        deadline = time.monotonic() + timeout
        while True:
            source_row = ledger(source, operation)
            destination_row = ledger(destination, operation)
            if source_row is not None and source_row["phase"] != "reserved" and destination_row is not None and destination_row["record"].get("binding") is not None:
                break
            if process.poll() is not None:
                raise SmokeAssertion(f"transfer finished before the interruption point: {source_row} {destination_row}")
            if time.monotonic() >= deadline:
                raise SmokeAssertion(f"transfer did not reach a sealed, offered cut within {timeout}s")
            time.sleep(0.01)
        destination.kill_daemon()
        stdout, stderr = process.communicate(timeout=120)
        source.ws.record("handoff-transfer", f"[interrupted coordinator exit {process.returncode}]\n{stdout.decode(errors='replace')}\n[stderr]\n{stderr.decode(errors='replace')}\n")
        assert process.returncode != 0, "a coordinator that lost its destination cannot report success"
        observed = {"source": ledger(source, operation), "destination": ledger(destination, operation)}
        source.ws.record("handoff-interrupted", json.dumps(observed, sort_keys=True) + "\n")
        return observed
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=30)


def published(destination: Runtime, missing: dict[str, int]) -> dict[str, int]:
    """Expected payloads already durably verified in D's pool (e.g. before a crash)."""
    pool = _pool(destination, "objects")
    return {digest: length for digest, length in missing.items() if _verified_object(pool / digest, digest, length)}


# --- Guest content ------------------------------------------------------------

def write_marker(silo: Silo, name: str, path: str, text: str) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$1" >"$2"; sync', "handoff-marker", text, path, user="root")


def read_file(silo: Silo, name: str, path: str) -> str:
    return silo.exec(name, "cat", path, user="root").stdout


def write_bulk(silo: Silo, name: str, path: str, mib: int) -> str:
    """Incompressible durable guest data, widening the mutable-payload window."""
    output = silo.exec(name, "sh", "-eu", "-c", 'dd if=/dev/urandom of="$1" bs=1048576 count="$2" conv=fsync 2>/dev/null; sync; sha256sum "$1"', "handoff-bulk", path, str(mib), user="root", timeout=180).stdout
    return output.split()[0]


def guest_sha256(silo: Silo, name: str, path: str) -> str:
    return silo.exec(name, "sha256sum", path, user="root", timeout=120).stdout.split()[0]


def boot(runtime: Runtime, name: str) -> dict[str, Any]:
    runtime.silo.start(name)
    return runtime.silo.wait_ready(name)


def stop(runtime: Runtime, name: str) -> None:
    stopped.stop(runtime.silo, name, require_clean=False)
    assert_stopped_unstarted(runtime, name)
