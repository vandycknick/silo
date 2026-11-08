"""Independent stopped-storage byte, SQL and process evidence for real CLI smoke.

No storage identities are calculated by libvm's stream implementation here. The
host reader pins each inode, hashes its complete logical bytes, and checks its
metadata again. SQLite observations always run in an independent read-only
process, preserving the catalog owner's process-associated locks.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from uuid import UUID, uuid4

from . import overlay, procs, shutdown
from .cli import Silo, timed
from .config import REPO


@dataclass(frozen=True)
class Bytes:
    path: str
    device: int
    inode: int
    length: int
    allocated: int
    mode: int
    sha256: str

    def content(self) -> tuple[int, str]:
        return self.length, self.sha256


def read_bytes(path: Path) -> Bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            block = os.pread(fd, min(1024**2, before.st_size - offset), offset)
            assert block, (path, offset, before.st_size)
            digest.update(block)
            offset += len(block)
        after = os.fstat(fd)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), path
        return Bytes(str(path), before.st_dev, before.st_ino, before.st_size, before.st_blocks * 512, stat.S_IMODE(before.st_mode), digest.hexdigest())
    finally:
        os.close(fd)


def record(silo: Silo, name: str) -> dict:
    machine_id = procs.machine_id(silo.ws, name)
    rows = procs.query(silo.ws.state_db(), f"SELECT json(record_json) FROM machine_storage WHERE machine_id='{machine_id}'")
    assert len(rows) == 1
    return json.loads(rows[0][0])


def configuration(silo: Silo, name: str) -> dict:
    machine_id = procs.machine_id(silo.ws, name)
    rows = procs.query(silo.ws.state_db(), f"SELECT json(config_json) FROM machine_config WHERE id='{machine_id}'")
    assert len(rows) == 1
    result = json.loads(rows[0][0])
    assert "machineDir" not in result
    return result


def private_path(silo: Silo, name: str, relative: str) -> Path:
    component = Path(relative)
    assert not component.is_absolute() and component.parts and ".." not in component.parts
    return silo.ws.silo_home / "machines" / procs.machine_id(silo.ws, name) / component


def writable_paths(silo: Silo, name: str) -> dict[str, Path]:
    value = record(silo, name)
    root = value["root"]
    assert root["kind"] in {"opaque-raw", "linux-overlay"}
    result = {"root": private_path(silo, name, root["path"] if root["kind"] == "opaque-raw" else root["upper"])}
    for disk in value["disks"]:
        storage = disk["storage"]
        if storage["kind"] == "managed-writable":
            result[f"{disk['role']}:{disk['order']}"] = private_path(silo, name, storage["path"])
    return result


def backing(silo: Silo, name: str, stage: str) -> dict[str, Bytes]:
    with timed(silo.ws, "stopped.backing"):
        result = {role: read_bytes(path) for role, path in writable_paths(silo, name).items()}
    silo.ws.record("stopped-bytes", json.dumps({"stage": stage, "machine": name, "files": {role: asdict(value) for role, value in result.items()}}, sort_keys=True) + "\n")
    return result


def same_content(left: dict[str, Bytes], right: dict[str, Bytes]) -> None:
    assert {role: value.content() for role, value in left.items()} == {role: value.content() for role, value in right.items()}


def independent(*copies: dict[str, Bytes]) -> None:
    identities = [(value.device, value.inode) for files in copies for value in files.values()]
    assert len(identities) == len(set(identities)), "writable role/source/sibling inode alias"
    assert all(value.mode == 0o600 for files in copies for value in files.values())


def fork(silo: Silo, source: str, child: str) -> None:
    silo.run("fork", source, "--name", child, timeout=240)
    silo.ws.register_machine(child)
    info = silo.info(child)
    assert info["state"] == "stopped" and info["run_id"] is None and info["ready"] is False
    # Identity only: a fresh independent catalog read, compared canonically.
    assert UUID(procs.machine_id(silo.ws, source)) != UUID(info["id"])


def restore(silo: Silo, reference: str, child: str) -> None:
    silo.run("restore", reference, "--name", child, timeout=240)
    silo.ws.register_machine(child)
    info = silo.info(child)
    assert info["state"] == "stopped" and info["run_id"] is None and info["ready"] is False


def stop(silo: Silo, name: str, *, require_clean: bool = True) -> None:
    bound, lease = shutdown.holder(silo, name)
    processes = [shutdown.Process(entry["pid"]) for entry in bound["holders"]]
    try:
        silo.stop(name, timeout="45s")
        terminal = shutdown.exit_record(silo, name, bound["runId"])
        for process in processes:
            process.wait()
        assert not shutdown.lease_busy(lease)
        actual = shutdown.outcome(silo, name)
        if require_clean or actual == "clean":
            shutdown.assert_clean(silo, name, terminal)
        else:
            assert actual in {"forced", "unknown"}, "capture may not invent stronger shutdown evidence"
    finally:
        for process in processes:
            process.close()


def mount_evidence(silo: Silo, expected: str | None = None) -> dict:
    result = subprocess.run(["findmnt", "--json", "--target", str(silo.ws.silo_home), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"], capture_output=True, text=True, timeout=15)
    silo.ws.record("stopped-host-mount", result.stdout + result.stderr)
    result.check_returncode()
    mounts = json.loads(result.stdout)["filesystems"]
    assert len(mounts) == 1
    actual = mounts[0]
    if expected is not None:
        assert actual["fstype"] == expected, actual
    silo.ws.record("stopped-host-mount", json.dumps({"kernel": os.uname().release, "stateDevice": silo.ws.silo_home.stat().st_dev, "requestedFilesystem": expected, "mount": actual}) + "\n")
    return actual


def catalog(silo: Silo) -> dict[str, list[tuple[str, ...]]]:
    """Full logical schema/rows, excluding only SQLite's physical sidecars."""
    schema = procs.query(silo.ws.state_db(), "SELECT quote(type),quote(name),quote(tbl_name),quote(sql) FROM sqlite_schema ORDER BY type,name")
    result = {"schema": schema}
    for (table,) in procs.query(silo.ws.state_db(), "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
        identifier = '"' + table.replace('"', '""') + '"'
        columns = procs.query(silo.ws.state_db(), f"PRAGMA table_info({identifier})")
        names = ['"' + column[1].replace('"', '""') + '"' for column in columns]
        expressions = [f"typeof({name}) || ':' || hex({name})" for name in names]
        result[table] = sorted(procs.query(silo.ws.state_db(), f"SELECT {','.join(expressions)} FROM {identifier}"))
    return result


def inventory(root: Path) -> dict[str, tuple]:
    result = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        if path.name in {"state.db", "state.db-wal", "state.db-shm"}:
            continue
        metadata = path.lstat()
        key = str(path.relative_to(root))
        if stat.S_ISREG(metadata.st_mode):
            result[key] = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_size, overlay.digest(path))
        elif stat.S_ISLNK(metadata.st_mode):
            result[key] = (metadata.st_mode, os.readlink(path))
        else:
            result[key] = (metadata.st_mode, metadata.st_uid, metadata.st_gid)
    return result


def refuse_without_effects(silo: Silo, *args: str) -> None:
    before = (catalog(silo), inventory(silo.ws.silo_home), inventory(silo.ws.run_root))
    result = silo.run(*args, expect=None, timeout=30)
    after = (catalog(silo), inventory(silo.ws.silo_home), inventory(silo.ws.run_root))
    changes = {
        scope: {
            key: {"before": old.get(key), "after": new.get(key)}
            for key in sorted(old.keys() | new.keys())
            if old.get(key) != new.get(key)
        }
        for scope, old, new in zip(("catalog", "stateFiles", "runFiles"), before, after)
    }
    # Retain exact logical row/file deltas before assertions and teardown.
    # SQLite sidecar churn stays excluded; lifecycle rows do not.
    silo.ws.record("stopped-refusal-delta", json.dumps({"args": args, "exit": result.returncode, "changes": changes}, sort_keys=True) + "\n")
    assert result.returncode != 0, (args, result.stdout, result.stderr)
    assert after == before, (args, changes)
    silo.ws.record("stopped-refusal", json.dumps({"args": args, "exit": result.returncode, "logicalCatalogUnchanged": True, "ownedInventoryUnchanged": True}) + "\n")


def install_managed_fixture(silo: Silo, name: str, *, custom_boot: bool) -> dict[str, str]:
    """Install real bytes/current-schema rows before the fixture's first launch.

    This is deliberately fixture construction, not an import/ownership API.
    Ordinary --disk remains external. Hold the real lifecycle inode and require
    affirmative never-run state before changing the fresh catalog.
    """
    config = configuration(silo, name)
    lock = silo.ws.run_root / "locks" / str(config["lockId"])
    fd = os.open(lock, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = procs.machine_state_json(silo.ws, name)
        assert state["status"] == "stopped" and state.get("runId") is None and state["vmmonPid"] is None
        machine_id = config["id"]
        assert procs.query(silo.ws.state_db(), f"SELECT operation_id FROM storage_operation WHERE machine_id='{machine_id}'") == []
        storage = record(silo, name)
        assert storage["disks"] == []
        directory = overlay.machine_dir(silo, name) / "disks"
        directory.mkdir(mode=0o700)
        path = directory / "data.raw"
        data_fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            os.ftruncate(data_fd, 8 * 1024**2)
            os.pwrite(data_fd, b"managed-before-capture\n", 4096)
            os.fsync(data_fd)
        finally:
            os.close(data_fd)
        geometry = {"length": 8 * 1024**2, "logicalSectorSize": 512}
        storage["disks"].append({"id": str(uuid4()), "role": "data", "order": len(config["spec"]["storage"]["disks"]), "storage": {"kind": "managed-writable", "path": "disks/data.raw", "geometry": geometry}})
        config["spec"]["storage"]["disks"].append({"path": str(path), "role": "data", "format": "raw", "geometry": geometry, "blockId": "silo-data-0", "readOnly": False})
        config["process"] = {"entrypoint": None, "command": [], "environment": {"CAPTURE_EMPTY": "", "CAPTURE_UNICODE": "雪/é", "CAPTURE_SECRET_WARNING": "exact-not-sanitized"}, "workingDirectory": "/", "user": "root"}
        config["labels"] = {"capture": "nondefault", "é": "雪"}
        config["metadata"] = {"opaque": "preserve"}
        assets = {}
        if custom_boot:
            boot_dir = overlay.machine_dir(silo, name) / "custom-boot"
            boot_dir.mkdir(mode=0o700)
            for role, source in {"kernel": "kernel-default", "baseInitramfs": "initramfs", "agent": "agent"}.items():
                destination = boot_dir / source
                shutil.copyfile(silo.ws.config.runtime_dir / "assets" / source, destination)
                destination.chmod(0o700 if role == "agent" else 0o600)
                assets[role] = overlay.digest(destination)
            config["spec"]["boot"]["kernel"]["path"] = str(boot_dir / "kernel-default")
            config["spec"]["boot"]["kernel"]["initramfs"] = str(boot_dir / "initramfs")
            config["guest"] = {"agent": {"mode": "custom", "path": str(boot_dir / "agent")}}
        def literal(value: dict) -> str:
            return "'" + json.dumps(value, ensure_ascii=False).replace("'", "''") + "'"
        statement = f"BEGIN IMMEDIATE; UPDATE machine_config SET config_json=jsonb({literal(config)}) WHERE id='{machine_id}'; UPDATE machine_storage SET record_json=jsonb({literal(storage)}) WHERE machine_id='{machine_id}'; COMMIT;"
        result = subprocess.run(["sqlite3", str(silo.ws.state_db()), statement], capture_output=True, text=True, timeout=15)
        silo.ws.record("stopped-fixture-sql", result.stdout + result.stderr)
        result.check_returncode()
        assert configuration(silo, name) == config and record(silo, name) == storage
        return assets
    finally:
        os.close(fd)


def configured_semantics(value: dict) -> dict:
    """Independent configured projection, excluding only regenerated authority."""
    result = {key: copy.deepcopy(value[key]) for key in ("spec", "retention", "process", "templateName", "agentMode", "labels", "metadata", "network")}
    result["guest"] = copy.deepcopy(value.get("guest", {}))
    # Paths to captured bytes are necessarily rebound. Boot identity is checked
    # separately against exact independently hashed pinned object bytes.
    kernel = result["spec"]["boot"]["kernel"]
    kernel.pop("path", None)
    kernel.pop("initramfs", None)
    agent = result["guest"].get("agent", {"mode": "default"})
    if agent["mode"] in {"custom", "default"}:
        result["guest"]["agent"] = {"mode": "captured"}
    for disk in result["spec"]["storage"]["disks"]:
        disk.pop("path")
        disk.pop("blockId")
    return result


@contextmanager
def syscall_boundary(silo: Silo, command: list[str], target: Path, boundary: str, *, stdin: Path | None = None, injected_errno: int | None = None):
    request = {"command": command, "target": str(target), "boundary": boundary, "machines": str(silo.ws.silo_home / "machines"), "evidence": str(silo.ws.evidence), "release": str(silo.ws.evidence / "boundary-release")}
    source = target.stat()
    source_identity = {"path": str(target), "device": source.st_dev, "inode": source.st_ino}
    if stdin is not None:
        request["stdin"] = str(stdin)
    if injected_errno is not None:
        request["errno"] = injected_errno
    path = silo.ws.evidence / "boundary-request.json"
    path.write_text(json.dumps(request) + "\n")
    with (silo.ws.evidence / "boundary-controller.log").open("wb") as output:
        controller = subprocess.Popen([sys.executable, "-m", "silo_smoke.stopped_trace", str(path)], env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")), stdout=output, stderr=subprocess.STDOUT)
        try:
            def held():
                marker = silo.ws.evidence / "boundary-held.json"
                if marker.exists():
                    return json.loads(marker.read_text())
                assert controller.poll() is None, "actual syscall gate exited before target; inspect boundary-controller.log"
                return None
            receipt = shutdown.until(held, timeout=60, description=f"real {boundary} syscall did not reach the boundary; inspect boundary-trace.json and boundary-controller.log")
            assert receipt["injectedReturn"] == (injected_errno is not None)
            assert receipt["source"] == source_identity, "boundary controller observed a different source inode"
            yield receipt
            Path(request["release"]).touch()
            assert controller.wait(timeout=180) == 0, "actual syscall gate failed; inspect boundary-controller.log"
            result = json.loads((silo.ws.evidence / "boundary-result.json").read_text())
            assert (result["returncode"] == 0) == (injected_errno is None), "unexpected real command result; inspect boundary-command.log"
            if injected_errno is not None:
                injected = json.loads((silo.ws.evidence / "boundary-injected.json").read_text())
                assert all(injected[key] == value for key, value in receipt.items())
                assert injected["errno"] == injected_errno
        finally:
            Path(request["release"]).touch(exist_ok=True)
            if controller.poll() is None:
                controller.terminate()
                try:
                    controller.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=5)
