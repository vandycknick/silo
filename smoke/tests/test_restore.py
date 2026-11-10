from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import time

import pytest

from silo_smoke import capture, incremental, overlay, pause, procs, restore, shutdown, stopped
from silo_smoke.cli import ROOT_PROFILES, Result, RootProfile, Silo
from silo_smoke.restore import restore_image, restore_irq_fixture  # noqa: F401, pytest fixtures

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]


@pytest.fixture
def restore_processes(silo: Silo) -> Iterator[list[shutdown.Process]]:
    """Adopt only this test's tracked monitor/worker generations and reap them."""
    with shutdown.subreaper():
        processes: list[shutdown.Process] = []
        try:
            yield processes
        finally:
            with shutdown.owned_processes(*processes):
                pass


def own(silo: Silo, name: str, processes: list[shutdown.Process]) -> None:
    holders, _ = shutdown.holder(silo, name)
    processes.extend(shutdown.Process(entry["pid"]) for entry in holders["holders"])


def reap_terminal(processes: list[shutdown.Process]) -> None:
    for process in processes[:]:
        if process.terminal():
            try:
                process.reap()
            except ChildProcessError:
                # Workers normally belong to, and are reaped by, their monitor.
                pass
            finally:
                process.close()
                processes.remove(process)


def stop_owned(silo: Silo, name: str, processes: list[shutdown.Process]) -> None:
    stopped.stop(silo, name, require_clean=False)
    reap_terminal(processes)


def private_inodes(silo: Silo, names: list[str]) -> None:
    identities = []
    for name in names:
        for role, path in stopped.writable_paths(silo, name).items():
            metadata = path.stat()
            assert metadata.st_nlink == 1
            identities.append((metadata.st_dev, metadata.st_ino))
            silo.ws.record("restore-private-inode", json.dumps({
                "machine": name, "role": role, "path": str(path),
                "device": metadata.st_dev, "inode": metadata.st_ino,
            }) + "\n")
    assert len(identities) == len(set(identities)), "source/sibling writable disk inode alias"


def mark(silo: Silo, name: str, value: str) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$1" >/restore-private; sync',
              "restore-private", value, user="root")


def marker(silo: Silo, name: str) -> str:
    return silo.exec(name, "cat", "/restore-private").stdout.strip()


def test_restore_inspection_rejects_writable_state_descriptors(
    silo: Silo, restore_image: str, restore_processes: list[shutdown.Process],
) -> None:
    restore.create_source(silo, restore_image, profile="layered")
    own(silo, "restore-source", restore_processes)
    saved = restore.checkpoint(silo, "restore-source")
    child = restore.restore_child(silo, saved, "inspection-source")
    own(silo, "inspection-source", restore_processes)
    records = procs.query(
        silo.ws.state_db(),
        "SELECT json(record_json) FROM storage_operation WHERE kind='launch'",
    )
    retained = next(json.loads(row[0]) for row in records
                    if json.loads(row[0])["machineId"] == child["id"])
    request = retained["restore"]["request"]
    paths = {(path.stat().st_dev, path.stat().st_ino): path
             for path in restore.closure_paths(silo, saved)}
    ram = request["objects"][0]
    copied = silo.ws.root / "inspection-ram"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always",
                    str(paths[(ram["fileDevice"], ram["fileInode"])]), str(copied)],
                   check=True, timeout=30)
    copied.chmod(0o600)

    def inspect(writable: bool) -> subprocess.CompletedProcess[str]:
        with ExitStack() as stack:
            descriptors = []
            for index, entry in enumerate(request["objects"]):
                path = copied if index == 0 else paths[(entry["fileDevice"], entry["fileInode"])]
                file = stack.enter_context(path.open("r+b" if writable and index == 0 else "rb"))
                stat = os.fstat(file.fileno())
                entry.update(fd=file.fileno(), fileDevice=stat.st_dev, fileInode=stat.st_ino)
                descriptors.append(file.fileno())
            encoded = json.dumps({"version": 1, "restore": request, "network": False}) + "\n"
            result = subprocess.run(
                [str(silo.ws.config.runtime_dir / "bin/silo-vmm"), "inspect-restore"],
                input=encoded, text=True, capture_output=True,
                pass_fds=descriptors, timeout=30,
            )
            silo.ws.record("inspection-descriptor-access", json.dumps({
                "writable": writable, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
            }) + "\n")
            return result

    rejected = inspect(True)
    assert rejected.returncode != 0 and rejected.stdout == "", rejected
    accepted = inspect(False)
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["checkpoint"] == request["checkpoint"]
    stop_owned(silo, "inspection-source", restore_processes)
    stop_owned(silo, "restore-source", restore_processes)


@pytest.mark.parametrize("profile", ROOT_PROFILES)
@pytest.mark.parametrize("borrowed", [False, True], ids=["acquired-freeze", "borrowed-freeze"])
def test_restore_execution_continues_exact_cut_and_isolates_siblings(
    silo: Silo, restore_image: str, profile: RootProfile, borrowed: bool,
    restore_processes: list[shutdown.Process],
) -> None:
    # The private runtime lets the test replace the current boot assets later.
    # Restoring must use captured objects, never today's similarly named files.
    runtime = silo.ws.root / "restore-runtime"
    overlay.copy_runtime(silo.ws.config.runtime_dir, runtime)
    silo.ws.config = replace(silo.ws.config, runtime_dir=runtime)
    expected_boot = {role: overlay.digest(runtime / "assets" / filename)
                     for role, filename in {"kernel": "kernel-default", "baseInitramfs": "initramfs",
                                            "agent": "agent"}.items()}
    restore.create_source(silo, restore_image, profile=profile)
    own(silo, "restore-source", restore_processes)
    mark(silo, "restore-source", "captured")
    initial = restore.start_witness(silo, "restore-source")
    armed = restore.witness(silo, "restore-source", "arm")
    assert armed["timerPending"] == armed["signalPending"] == 1
    saved = restore.checkpoint(silo, "restore-source", borrowed=borrowed)
    cut = restore.matched_cut(silo, saved, initial, profile=profile)
    sealed = capture.inventory(saved.staging)
    source_pause = silo.info("restore-source")["lifecycle"]["lifecycle"]["currentPause"]
    source_paths = stopped.writable_paths(silo, "restore-source")
    children = []
    for name in ("restore-first", "restore-second"):
        child = restore.restore_child(silo, saved, name)
        own(silo, name, restore_processes)
        assert child["id"] not in {entry["id"] for entry in children}
        assert child["run_id"] not in {entry["run_id"] for entry in children}
        children.append(child)
        restore.exact_boot(silo, name, expected_boot)
        assert marker(silo, name) == "captured"
        restore.resumed(silo, name, initial, cut)
        assert silo.info("restore-source")["lifecycle"]["lifecycle"]["currentPause"] == source_pause
    private_inodes(silo, ["restore-source", "restore-first", "restore-second"])
    assert stopped.writable_paths(silo, "restore-source") == source_paths
    # Thawing each child cannot consume the source's borrowed/acquired authority.
    assert silo.info("restore-source")["state"] == "paused"
    silo.run("resume", "restore-source")
    restore.resumed(silo, "restore-source", initial, cut)
    assert silo.exec("restore-source", "cat", "/proc/sys/kernel/random/boot_id").stdout == saved.boot_id
    assert pause.generation(silo, "restore-source")["reseed_count"] == saved.generation["reseed_count"]
    for name, value in (("restore-source", "source-only"), ("restore-first", "first-only"),
                        ("restore-second", "second-only")):
        mark(silo, name, value)
    assert [marker(silo, name) for name in ("restore-source", "restore-first", "restore-second")] == [
        "source-only", "first-only", "second-only"]
    capture.unchanged(silo, saved.staging, sealed)
    for name in ("restore-source", "restore-first", "restore-second"):
        stop_owned(silo, name, restore_processes)
    for name in ("restore-source", "restore-first", "restore-second"):
        silo.rm(name)
    assert not (silo.ws.silo_home / "machines" / saved.source_info["id"]).exists()
    silo.run("image", "remove", "image:restore-checkpoint")
    # No original source, sibling, alias or runtime boot bytes remain authoritative.
    closure_before = {str(path.relative_to(silo.ws.silo_home)): stopped.read_bytes(path).content()
                      for path in restore.closure_paths(silo, saved)}
    old_home = silo.ws.silo_home
    relocated = silo.ws.root / "relocated-restore-home"
    old_home.rename(relocated)
    silo.ws.silo_home = relocated
    shutdown.storage_tool(silo, "remove-image", restore_image)
    shutdown.storage_tool(silo, "prune")
    assert not old_home.exists()
    for filename in ("kernel-default", "initramfs", "agent"):
        asset = runtime / "assets" / filename
        asset.unlink()
        asset.write_bytes(b"not the checkpoint boot bytes\n")
        asset.chmod(0o755 if filename == "agent" else 0o644)
    assert {relative: stopped.read_bytes(relocated / relative).content()
            for relative in closure_before} == closure_before
    assert json.loads(silo.run("snapshot", "inspect", saved.reference).stdout)["retained"] is True
    relocated_saved = replace(saved, staging=relocated / saved.staging.relative_to(old_home))
    restore.restore_child(silo, relocated_saved, "restore-relocated")
    own(silo, "restore-relocated", restore_processes)
    restore.exact_boot(silo, "restore-relocated", expected_boot)
    assert marker(silo, "restore-relocated") == "captured"
    restore.resumed(silo, "restore-relocated", initial, cut)
    # Recapture after relocation, then continue that exact second execution cut.
    # This exercises repeated generation, pending-event and timer transitions.
    next_identity = restore.witness(silo, "restore-relocated", "arm")
    recaptured = restore.checkpoint(silo, "restore-relocated", alias="restore-recaptured")
    next_cut = restore.matched_cut(silo, recaptured, next_identity, profile=profile)
    stop_owned(silo, "restore-relocated", restore_processes)
    silo.rm("restore-relocated")
    restore.restore_child(silo, recaptured, "restore-recursion")
    own(silo, "restore-recursion", restore_processes)
    restore.resumed(silo, "restore-recursion", next_identity, next_cut)
    restore.exact_boot(silo, "restore-recursion", expected_boot)
    # Delete every checkpoint root while its immutable RAM is privately mapped.
    # Registered leases, not aliases or source machine paths, must protect it.
    mapped = restore.closure_paths(silo, recaptured)
    expected = {str(path): stopped.read_bytes(path).content() for path in mapped}
    holders, lease = shutdown.holder(silo, "restore-recursion")
    processes = [shutdown.Process(entry["pid"]) for entry in holders["holders"]]
    try:
        assert shutdown.lease_busy(lease)
        silo.run("image", "remove", "image:restore-recaptured")
        silo.run("snapshot", "remove", saved.reference)
        silo.run("snapshot", "remove", recaptured.reference)
        shutdown.storage_tool(silo, "prune")
        assert shutdown.lease_busy(lease)
        assert {str(path): stopped.read_bytes(path).content() for path in mapped} == expected
        previous = restore.witness(silo, "restore-recursion")
        restore.advances(silo, "restore-recursion", previous)
        silo.stop("restore-recursion")
        for process in processes:
            process.wait()
        reap_terminal(restore_processes)
        assert not shutdown.lease_busy(lease)
        silo.rm("restore-recursion")
        shutdown.storage_tool(silo, "prune")
        assert not any(path.exists() for path in mapped if path.parent.parent.name == "streams"), (
            "reaped child left execution streams permanently retained", mapped)
    finally:
        for process in processes:
            process.close()
    silo.ws.record("restore-retention", json.dumps({
        "checkpoint": saved.snapshot, "recaptured": recaptured.snapshot,
        "originalHomeGone": not old_home.exists(), "relocatedHome": str(relocated),
        "sourceDeleted": True, "aliasesDeleted": True, "closureBefore": closure_before,
        "mappedClosure": expected, "leaseReleasedAfterReap": True,
    }, sort_keys=True) + "\n")


def allocation_state(silo: Silo) -> dict:
    """Observe logical catalog and owned topology without hashing mutable WALs."""
    roots = [silo.ws.silo_home / "machines", silo.ws.run_root]
    return {"catalog": stopped.catalog(silo), "directories": {
        str(root): sorted(str(path.relative_to(root)) for path in root.rglob("*"))
        for root in roots
    }}


def refused_before_allocation(silo: Silo, reference: str, name: str, *,
                             env: dict[str, str] | None = None,
                             verification_lease: bool = True) -> Result:
    before = allocation_state(silo)
    leases = silo.ws.silo_home / "images/locks/leases"
    original_leases = set(leases.iterdir())
    silo.ws.register_machine(name)
    result = silo.run(*restore.restore_argv(reference, name), expect=None, timeout=60, env=env)
    after = allocation_state(silo)
    new_leases = set(leases.iterdir()) - original_leases
    silo.ws.record("restore-preallocation-refusal", json.dumps({
        "reference": reference, "name": name, "exit": result.returncode,
        "before": before, "after": after, "newVerificationLeases": sorted(map(str, new_leases)),
    }, sort_keys=True) + "\n")
    assert result.returncode != 0, "incompatible/corrupt execution checkpoint restored"
    assert before == after, "restore rejection allocated child state or leaked catalog resources"
    # A verification consumer protects bytes from GC before descriptor inspection.
    # Its stable inode remains by pool design, but its operation and OFD must not.
    assert all(not shutdown.lease_busy(path) for path in new_leases)
    if not verification_lease:
        assert not new_leases, "unsupported backend refusal acquired an operational lease"
    return result


def checkpoint_for_policy(silo: Silo, policy: str) -> restore.Checkpoint:
    if policy == "full":
        return restore.checkpoint(silo, "restore-source")
    baseline = restore.checkpoint(silo, "restore-source", alias="restore-baseline")
    silo.run("resume", "restore-source")
    silo.exec("restore-source", "sh", "-eu", "-c", "printf incremental >/dev/shm/incremental-negative", user="root")
    saved = restore.checkpoint(silo, "restore-source", policy="incremental")
    incremental.authenticated_map(silo, saved, mode="incremental", baseline=baseline)
    return saved


# Execution members are root-independent; the root stream is exercised for
# both families, and the layered closure adds every composition graph member.
EXECUTION_MEMBERS = ("ram", "root", "layout", "execution", "devices", "kernel",
                     "baseInitramfs", "agent", "map", "map-page", "provenance")
COMPOSITION_MEMBERS = ("lower-record", "lower-recipe", "lower-fsmeta", "layer-recipe",
                       "layer-result", "layer-index", "layer-pack", "layer-pack-map")
CLOSURE_CASES = ([("layered", member) for member in (*EXECUTION_MEMBERS, *COMPOSITION_MEMBERS)]
                 + [("raw", "root")])


@pytest.mark.parametrize("policy", ["full", "incremental"])
@pytest.mark.parametrize(("profile", "member"), CLOSURE_CASES,
                         ids=[f"{profile}-{member}" for profile, member in CLOSURE_CASES])
def test_restore_corrupt_real_closure_refuses_before_child_allocation(
    silo: Silo, restore_image: str, profile: RootProfile, member: str, policy: str,
    restore_processes: list[shutdown.Process],
) -> None:
    restore.create_source(silo, restore_image, profile=profile)
    own(silo, "restore-source", restore_processes)
    saved = checkpoint_for_policy(silo, policy)
    record = restore.snapshot_record(silo, saved)
    stop_owned(silo, "restore-source", restore_processes)
    shutdown.storage_tool(silo, "prune")
    execution = record["execution"]
    stream_members = {"ram": execution["memory"]["stream"], "root": record["root"]["stream"]["stream"]}
    objects = {key: execution[key] for key in ("layout", "execution", "devices")}
    objects.update({key: record["boot"]["binding"][key] for key in ("kernel", "baseInitramfs", "agent")})
    objects["map"] = execution["memory"]["map"]
    objects["map-page"] = execution["memory"]["mapPages"][0]
    root_profile = record["root"]["profile"]
    if profile == "layered":
        assert root_profile["kind"] == "linux-overlay", root_profile
        lower = root_profile["lower"]
        layer = lower["layers"][0]
        objects.update({"lower-record": lower["record"], "lower-recipe": lower["recipe"],
                        "lower-fsmeta": lower["fsmeta"], "layer-recipe": layer["recipe"],
                        "layer-result": layer["result"], "layer-index": layer["indexRoot"],
                        "layer-pack-map": layer["pack"]["map"]})
        stream_members["layer-pack"] = layer["pack"]["stream"]
    else:
        assert root_profile == {"kind": "opaque-raw"}, root_profile
    evidence = procs.query(silo.ws.state_db(),
                           f"SELECT evidence_digest FROM snapshot_capture_provenance WHERE snapshot_id='{saved.snapshot}'")
    assert len(evidence) == 1
    objects["provenance"] = evidence[0][0]
    digest = stream_members[member] if member in stream_members else objects[member]
    pool = "streams" if member in stream_members else "objects"
    if member in COMPOSITION_MEMBERS:
        table, column = (("snapshot_stream_dependency", "stream_id") if pool == "streams"
                         else ("snapshot_object_dependency", "object_digest"))
        assert procs.query(silo.ws.state_db(),
                           f"SELECT 1 FROM {table} WHERE snapshot_id='{saved.snapshot}' AND {column}='{digest}'") == [("1",)], (
            "closed snapshot graph does not retain composition member", member, digest)
    path = silo.ws.silo_home / "images" / pool / "sha256" / digest.removeprefix("sha256:")
    # Real captured bytes only. Restore the one changed byte even on failure so
    # normal workspace teardown is not debugging a deliberately corrupt catalog.
    mode = path.stat().st_mode & 0o7777
    path.chmod(0o600)
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        offset = min(4096, path.stat().st_size - 1)
        original = os.pread(fd, 1, offset)
        assert len(original) == 1
        assert os.pwrite(fd, bytes([original[0] ^ 0x80]), offset) == 1
        os.fsync(fd)
        # Restore the immutable pool mode before admission, so the negative is
        # the altered bytes, not a writable-file metadata rejection.
        os.fchmod(fd, mode)
        try:
            refused_before_allocation(silo, saved.reference, "restore-corrupt-" + member.lower())
        finally:
            assert os.pwrite(fd, original, offset) == 1
            os.fsync(fd)
    finally:
        os.close(fd)
        path.chmod(mode)


@pytest.mark.parametrize("policy", ["full", "incremental"])
@pytest.mark.parametrize("mutation", ["cpu", "profile", "schema", "architecture", "xsave", "tsc-rate", "msr"])
def test_restore_real_native_incompatibility_refuses_before_child_allocation(
    silo: Silo, restore_image: str, mutation: str, policy: str, restore_processes: list[shutdown.Process],
) -> None:
    restore.create_source(silo, restore_image, profile="layered")
    own(silo, "restore-source", restore_processes)
    saved = checkpoint_for_policy(silo, policy)
    stop_owned(silo, "restore-source", restore_processes)
    shutdown.storage_tool(silo, "prune")
    with restore.incompatible_checkpoint(silo, saved, mutation) as (reference, subject):
        result = refused_before_allocation(silo, reference, "restore-incompatible-" + mutation)
        pin = {"cpu": "cpu.cpuid", "profile": "host-build", "schema": "live-state-schema", "architecture": "architecture",
               "xsave": "cpu.xsave", "tsc-rate": "clock.tsc-rate", "msr": "cpu.msr-inventory"}[mutation]
        for required in ("restore-preflight", "pin " + pin, "expected ", "destination ",
                         "no execution child was started"):
            assert required in result.stderr, result.stderr
        assert subject in result.stderr, "refusal did not reach the actual native compatibility subject"
    shutdown.storage_tool(silo, "prune")


def test_restore_selected_vz_backend_rejects_before_any_operational_allocation(
    silo: Silo, restore_image: str, restore_processes: list[shutdown.Process],
) -> None:
    restore.create_source(silo, restore_image, profile="layered")
    own(silo, "restore-source", restore_processes)
    saved = restore.checkpoint(silo, "restore-source")
    stop_owned(silo, "restore-source", restore_processes)
    shutdown.storage_tool(silo, "prune")
    result = refused_before_allocation(
        silo, saved.reference, "restore-wrong-backend",
        env=silo.ws.env(SILO_VIRT_BACKEND="vz"), verification_lease=False)
    assert "backend-excluded" in result.stderr and "vz" in result.stderr.lower(), result.stderr


@pytest.mark.skip(reason=(
    "IRQ restore requires an explicitly staged diagnostic monitor; "
    "the staged runtime has no IRQ probe transport"
))
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_restore_pending_hardware_irq_continues_exactly_once(
    silo: Silo, restore_image: str, restore_irq_fixture: Path,
    profile: RootProfile, restore_processes: list[shutdown.Process],
) -> None:
    # Linux keeps CPUs 0/1; only the one-time native source bootstrap starts
    # reserved AP2. AP3 stays unstarted in captured and restored execution.
    restore.create_source(
        silo, restore_image, "--kernel-arg", "maxcpus=2",
        "--kernel-arg", "memmap=16M$448M", "--kernel-arg", "memmap=64K$448K",
        profile=profile, cpus=4)
    own(silo, "restore-source", restore_processes)
    initial = restore.start_witness(silo, "restore-source")
    restore.witness(silo, "restore-source", "arm")
    silo.run("pause", "restore-source")
    restore.initialize_irq_probe(silo, "restore-source", restore_irq_fixture)
    silo.run("resume", "restore-source")
    restore.irq_wait(
        silo, "restore-source",
        lambda observation: observation["words"][0] == 0x53494C4F
        and observation["words"][1] == 1 and observation["words"][2] > 0,
        description="privileged AP2 source witness did not begin its only initialization")
    restore.irq_probe(silo, "restore-source", {"request": "command", "command": "reset"})
    baseline = restore.irq_wait(
        silo, "restore-source", lambda observation: observation["words"][4] == 12,
        description="AP2 did not process the actual reset guest command")
    restore.irq_probe(silo, "restore-source", {"request": "command", "command": "pending"})
    restore.irq_wait(
        silo, "restore-source",
        lambda observation: observation["words"][4] == 2 and observation["words"][8] == 1,
        description="real AP2 comparator never expired into its pending LAPIC IRR")
    saved = restore.checkpoint(silo, "restore-source", borrowed=True, alias="restore-hardware-irq")
    cut = restore.matched_cut(silo, saved, initial, profile=profile)
    original = restore.irq_cut(silo, saved, pending=True)
    assert original["words"][5] == baseline["words"][5]
    assert original["words"][20] == baseline["words"][20]
    source_paused = restore.irq_probe(silo, "restore-source", {"request": "observe"})
    assert source_paused["pending"] is True and source_paused["in_service"] is False
    assert source_paused["deadline"] == 0
    assert tuple(source_paused["words"]) == original["words"][:23]
    sealed = capture.inventory(saved.staging)

    restore.restore_child(silo, saved, "restore-hardware-child")
    own(silo, "restore-hardware-child", restore_processes)
    child = restore.irq_wait(
        silo, "restore-hardware-child",
        lambda observation: observation["words"][2] > original["words"][2],
        description="restored AP2 did not execute past its captured instruction")
    assert child["words"][1] == 1, "child reinitialized the source-only privileged fixture"
    assert child["words"][5] == baseline["words"][5]
    assert child["words"][20] == baseline["words"][20]
    # A feature-gated probe still may not turn restored state into source state.
    restore.initialize_irq_probe(silo, "restore-hardware-child", restore_irq_fixture, refused="restored")
    restore.irq_probe(silo, "restore-hardware-child", {"request": "command", "command": "accept"})
    delivered = restore.irq_wait(
        silo, "restore-hardware-child",
        lambda observation: observation["words"][5] == baseline["words"][5] + 1
        and observation["words"][20] == baseline["words"][20] + 1,
        description="restored original vector 224 interrupt/EOI was lost or duplicated")
    # No host setter, comparator rewrite or synthetic IRQ follows activation.
    # The only release was the captured AP2 guest's own STI command.
    time.sleep(0.65)
    final = restore.irq_wait(
        silo, "restore-hardware-child",
        lambda observation: observation["words"][2] > delivered["words"][2],
        description="restored AP2 ceased making sustained execution progress")
    assert final["words"][1] == 1
    assert final["words"][5] == baseline["words"][5] + 1
    assert final["words"][20] == baseline["words"][20] + 1
    restore.resumed(silo, "restore-hardware-child", initial, cut)
    # A second real capture proves the architectural IRR/ISR are now empty,
    # live GPR/x87/SSE/YMM sentinels persist, and AP3 stayed never-started.
    restore.witness(silo, "restore-hardware-child", "arm")
    recaptured = restore.checkpoint(silo, "restore-hardware-child", alias="restore-hardware-recaptured")
    completed = restore.irq_cut(silo, recaptured, pending=False)
    assert completed["words"][5] == baseline["words"][5] + 1
    assert completed["words"][20] == baseline["words"][20] + 1
    assert completed["words"][7] == original["words"][7], "original guest comparator was rewritten"
    # Child acceptance cannot consume the independent source's pending IRQ.
    unchanged = restore.irq_probe(silo, "restore-source", {"request": "observe"})
    assert tuple(unchanged["words"]) == original["words"][:23]
    silo.run("resume", "restore-source")
    restore.irq_probe(silo, "restore-source", {"request": "command", "command": "accept"})
    source_delivered = restore.irq_wait(
        silo, "restore-source",
        lambda observation: observation["words"][5] == baseline["words"][5] + 1
        and observation["words"][20] == baseline["words"][20] + 1,
        description="source could not independently consume its original pending IRQ")
    restore.resumed(silo, "restore-source", initial, cut)
    capture.unchanged(silo, saved.staging, sealed)
    stop_owned(silo, "restore-hardware-child", restore_processes)
    stop_owned(silo, "restore-source", restore_processes)
    silo.ws.record("restore-pending-hardware-irq", json.dumps({
        "sourceCheckpoint": saved.snapshot, "childCheckpoint": recaptured.snapshot,
        "original": original, "restoredDelivery": delivered, "sustained": final,
        "recapturedCompletion": completed, "sourceDelivery": source_delivered,
        "scope": "diagnostic feature only",
    }, sort_keys=True) + "\n")
