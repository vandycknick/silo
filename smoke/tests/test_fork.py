"""Live fork acceptance, crash and physical-sharing gates (ADR 0021 `## Fork`).

Every case drives the real `silo fork --live` against a real guest running the
detached `restore_execution.c` witness. Results come from the CLI's single
`LiveForkResult` document, the durable fork journal, the authenticated local
cut, monitor traces, `/proc` and the guest. Admission is compiled only into the
isolated `capture_candidate --restore --fork` build, never production policy.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import signal
from uuid import UUID

import pytest

from silo_smoke import capture, fork, pause, procs, restore, shutdown, stopped
from silo_smoke import restore_lifecycle as lifecycle
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo, TIMINGS_PROPERTY, release
from silo_smoke.config import SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.restore import restore_image  # noqa: F401, pytest fixture
from silo_smoke.workspace import Workspace

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]

SOURCE = "fork-source"
NAMES = ["fork-a", "fork-b", "fork-c", "fork-d"]
FORWARD = f"host:unix:fork.sock=guest:tcp:127.0.0.1:{lifecycle.LISTEN_PORT}"
BLOB = 128 * fork.MIB
DIRTY_MIB = 32
MIB = fork.MIB
# ADR 0021 restore reservation: per-child private allowance rounded to the
# granule, plus ceil(RAM/512) and the 64 MiB state reserve; baseline once.
STATE_RESERVE = 64 * MIB
FAILING_HOOK = {"argv": ["/bin/sh", "-c", "exit 7"], "environment": [], "workingDirectory": "/",
                "timeoutMs": 5000}
BUDGET_REFUSAL = re.compile(r"RAM budget requires (\d+) bytes, available (\d+) bytes")


@dataclass(frozen=True)
class Prepared:
    info: dict
    initial: dict
    boot_id: str
    generation: dict[str, str]
    blob: str


def require_fork(info: dict) -> None:
    restore.require_restore_candidate(info)
    live = info["lifecycle"]["report"]["live"]
    assert live["fork"]["availability"] == {"status": "supported"}, (
        "select the explicit isolated capture_candidate --restore --fork build", live["fork"])


def create(silo: Silo, image: str, *flags: str, profile: RootProfile, name: str = SOURCE,
           memory: str = "512mib", network: str = "none") -> None:
    silo.create(name, silo.root_image(image, profile), "--cpus", "2", "--memory", memory,
                "--disk-size", "512mib", "--vsock", "--network", network, *flags)


def witness_source(silo: Silo, name: str = SOURCE) -> Prepared:
    """Persistent witness with armed pending timer/signal, plus a RAM-only blob."""
    info = silo.wait_ready(name)
    require_fork(info)
    mark(silo, name, "captured")
    initial = restore.start_witness(silo, name)
    armed = restore.witness(silo, name, "arm")
    assert armed["timerPending"] == armed["signalPending"] == 1
    # tmpfs pages stay guest-RAM resident: every child reads identical clean
    # baseline pages, so shared residency is deterministic, not page-cache luck.
    blob = silo.exec(name, "sh", "-eu", "-c",
                     "mkdir -p /fork-share; mount -t tmpfs -o size=224m,mode=0700 fork-share /fork-share;"
                     f" dd if=/dev/urandom of=/fork-share/blob bs=1M count={BLOB // MIB} 2>/dev/null;"
                     " sha256sum /fork-share/blob", user="root", timeout=120).stdout.split()[0]
    boot_id = silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout
    return Prepared(info, initial, boot_id, pause.generation(silo, name), blob)


def prepare(silo: Silo, image: str, *flags: str, profile: RootProfile, memory: str = "512mib",
            network: str = "none") -> Prepared:
    create(silo, image, *flags, memory=memory, profile=profile, network=network)
    silo.start(SOURCE)
    return witness_source(silo)


def mark(silo: Silo, name: str, value: str) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$1" >/fork-private; sync',
              "fork-private", value, user="root")


def marker(silo: Silo, name: str) -> str:
    return silo.exec(name, "cat", "/fork-private").stdout.strip()


def touch_blob(silo: Silo, name: str) -> str:
    return silo.exec(name, "sha256sum", "/fork-share/blob", user="root", timeout=120).stdout.split()[0]


def dirty(silo: Silo, name: str) -> None:
    silo.exec(name, "sh", "-eu", "-c",
              f"dd if=/dev/urandom of=/fork-share/private bs=1M count={DIRTY_MIB} 2>/dev/null; sync",
              user="root", timeout=120)


def private_inodes(silo: Silo, names: list[str], cut: Path) -> None:
    identities = {(path.stat().st_dev, path.stat().st_ino) for path in (cut / "disks").glob("*.raw")}
    assert identities, "local cut lacks its sealed disk"
    count = len(identities)
    for name in names:
        for role, path in stopped.writable_paths(silo, name).items():
            metadata = path.stat()
            assert metadata.st_nlink == 1, (name, role)
            identities.add((metadata.st_dev, metadata.st_ino))
            count += 1
            silo.ws.record("fork-private-inode", json.dumps({
                "machine": name, "role": role, "path": str(path),
                "device": metadata.st_dev, "inode": metadata.st_ino}) + "\n")
    assert len(identities) == count, "writable source/sibling/cut inode alias"


def continued(silo: Silo, call: fork.Call, prepared: Prepared, *, profile: RootProfile
              ) -> tuple[restore.Checkpoint, restore.Cut]:
    saved = fork.cut(silo, call, prepared.info, prepared.boot_id, prepared.generation)
    return saved, restore.matched_cut(silo, saved, prepared.initial, profile=profile)


def running_children(silo: Silo, result: dict, saved: restore.Checkpoint, prepared: Prepared,
                     cut: restore.Cut) -> list[str]:
    names = []
    for child in result["children"]:
        if child["outcome"]["kind"] != "running":
            continue
        fork.child_identity(silo, child["name"], child, saved)
        assert marker(silo, child["name"]) == "captured"
        restore.resumed(silo, child["name"], prepared.initial, cut)
        names.append(child["name"])
    return names


def gone_after_prune(silo: Silo, *operations: str) -> None:
    """After the source run and every child generation ended, prune retires each cut.

    A running source may still map an accepted capture baseline, and capture
    GC waits for its exact launch lease, so callers stop the source first.
    """
    shutdown.storage_tool(silo, "prune")
    for operation in operations:
        directory = fork.cut_directory(silo, operation)
        assert not directory.exists(), f"local cut outlived every mapping generation: {directory}"
        assert not directory.parent.exists(), "fork operation-owned transient root leaked"


def source_running(silo: Silo, prepared: Prepared) -> None:
    current = silo.info(SOURCE)
    assert current["state"] == "running" and current["run_id"] == prepared.info["run_id"], current
    restore.advances(silo, SOURCE, restore.witness(silo, SOURCE))


# -- acceptance -------------------------------------------------------------------

@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_fork_four_children_run_from_one_matched_cut_with_unique_identities(
    silo: Silo, restore_image: str, profile: RootProfile,  # noqa: F811
) -> None:
    prepared = prepare(silo, restore_image, "--forward", FORWARD, profile=profile, network="private")
    source_identity = lifecycle.guest_identity(silo, SOURCE)
    source_paths = stopped.writable_paths(silo, SOURCE)
    call = fork.run(silo, SOURCE, NAMES, expect=0)
    result = call.result
    assert result is not None and result["stage"] == "finished" and not result["cancellationRequested"]
    assert result["capture"]["kind"] == "sealed" and result["source"] == {"kind": "resumed"}, result
    assert fork.outcomes(result) == ["running"] * len(NAMES), result
    assert all(child["durability"] == "durable" for child in result["children"]), result
    assert UUID(result["sourceMachineId"]) == UUID(prepared.info["id"])
    assert UUID(result["sourceRunId"]) == UUID(prepared.info["run_id"])
    fork.journal_matches(silo, result)
    stamps = fork.events(silo, call.operation)
    fork.ordered_events(call, stamps, running=list(range(len(NAMES))))
    saved, cut = continued(silo, call, prepared, profile=profile)
    sealed = capture.inventory(saved.staging)

    identities = {SOURCE: source_identity}
    for child in result["children"]:
        name = child["name"]
        identity = lifecycle.guest_identity(silo, name)
        assert identity == lifecycle.requested_network(silo, UUID(child["machineId"]).hex), name
        identities[name] = identity
        # Destination authority: inherited host grants are stripped, never copied.
        assert stopped.configuration(silo, name)["spec"].get("forwards", []) == [], name
        assert not lifecycle.runtime_socket(silo, UUID(child["machineId"]).hex, "fork.sock").exists()
    assert running_children(silo, result, saved, prepared, cut) == NAMES
    assert len({value.mac for value in identities.values()}) == len(identities), identities
    networks = {}
    runs = {SOURCE: prepared.info["run_id"], **{child["name"]: child["runId"] for child in result["children"]}}
    unix_sockets = [line.split(maxsplit=7) for line in Path("/proc/net/unix").read_text().splitlines()[1:]]
    for name, identity in identities.items():
        rows = procs.query(silo.ws.state_db(),
                           "SELECT c.id,a.network_instance_id,a.guest_mac,json(n.attachment_json),"
                           "json(n.driver_state_json),n.state FROM machine_config c "
                           "JOIN network_attachments a ON a.machine_id=c.id "
                           "JOIN network_instances n ON n.id=a.network_instance_id "
                           f"WHERE c.id='{procs.machine_id(silo.ws, name)}'")
        assert len(rows) == 1, (name, rows)
        machine, network, mac, attachment_json, driver_json, state = rows[0]
        attachment, driver = json.loads(attachment_json), json.loads(driver_json)
        assert state == "running" and mac.lower() == identity.mac, rows
        assert attachment["ipv4"] == {
            "address": identity.ipv4, "prefix_length": identity.prefix_length, "gateway": identity.gateway,
        }, attachment
        assert UUID(driver["machine_id"]) == UUID(machine), driver
        assert UUID(driver["run_id"]) == UUID(runs[name]), driver
        pid = int(driver["helper_pid"])
        args = (Path("/proc") / str(pid) / "cmdline").read_text().split("\0")
        socket = silo.ws.run_root / "networks" / network / "netd.sock"
        assert socket.is_socket(), socket
        assert args[args.index("--network-id") + 1] == network, args
        assert UUID(args[args.index("--vm-id") + 1]) == UUID(machine), args
        assert args[args.index("--run-id") + 1] == driver["run_id"], args
        assert args[args.index("--static-lease") + 1] == f"{identity.ipv4}={identity.mac}", args
        assert args[args.index("--listen-vfkit") + 1] == f"unixgram://{socket}", args
        owned = [row for row in unix_sockets if len(row) == 8 and row[7] == str(socket)]
        assert len(owned) == 1, (socket, owned)
        inode = int(owned[0][6])
        descriptors = set()
        for fd in (Path("/proc") / str(pid) / "fd").iterdir():
            try:
                descriptors.add(os.readlink(fd))
            except FileNotFoundError:
                continue
        assert f"socket:[{inode}]" in descriptors, (pid, socket, inode)
        networks[name] = {"instance": network, "pid": pid, "socket": str(socket),
                          "socketInode": inode, "mac": identity.mac, "ipv4": identity.ipv4}
    for key in ("instance", "pid", "socket", "socketInode"):
        assert len({value[key] for value in networks.values()}) == len(identities), networks
    assert stopped.configuration(silo, SOURCE)["spec"]["forwards"], "source lost its own grant"

    # The source resumed under its own run and continues the same cut once.
    source_running(silo, prepared)
    restore.resumed(silo, SOURCE, prepared.initial, cut)
    assert silo.exec(SOURCE, "cat", "/proc/sys/kernel/random/boot_id").stdout == prepared.boot_id
    assert pause.generation(silo, SOURCE)["reseed_count"] == prepared.generation["reseed_count"]
    assert stopped.writable_paths(silo, SOURCE) == source_paths
    private_inodes(silo, [SOURCE, *NAMES], saved.staging)
    shared = fork.sharing(silo, NAMES, saved.staging / "memory.ram")
    ownership = fork.assert_no_orphans(silo, [SOURCE, *NAMES])
    for name in (SOURCE, *NAMES):
        mark(silo, name, name + "-only")
    assert [marker(silo, name) for name in (SOURCE, *NAMES)] == [name + "-only" for name in (SOURCE, *NAMES)]
    capture.unchanged(silo, saved.staging, sealed)
    silo.ws.record("fork-four-children", json.dumps({
        "operation": call.operation, "result": result, "phases": {f"{key[0]}:{key[1]}": value
                                                                    for key, value in stamps.items()},
        "identities": {name: value.__dict__ for name, value in identities.items()},
        "networks": networks, "sharing": shared, "ownership": ownership, "callerSeconds": call.caller_seconds,
    }, sort_keys=True) + "\n")
    fork.stop_and_remove(silo, NAMES)
    stopped.stop(silo, SOURCE, require_clean=False)
    gone_after_prune(silo, call.operation)


def test_fork_child_failure_after_seal_names_that_child_and_keeps_siblings(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    prepared = prepare(silo, restore_image, profile="layered")
    failing = 2
    call = fork.run(silo, SOURCE, NAMES, hooks={failing: FAILING_HOOK}, expect=1)
    result = call.result
    assert result is not None and result["stage"] == "finished", call.stderr
    assert result["capture"]["kind"] == "sealed" and result["source"] == {"kind": "resumed"}, result
    failed = result["children"][failing]
    assert failed["name"] == NAMES[failing]
    assert failed["outcome"]["kind"] == "failed" and failed["outcome"]["phase"] == "activation", failed
    assert [kind for index, kind in enumerate(fork.outcomes(result)) if index != failing] == ["running"] * 3
    fork.journal_matches(silo, result)
    running = [index for index in range(len(NAMES)) if index != failing]
    fork.ordered_events(call, fork.events(silo, call.operation), running=running)
    saved, cut = continued(silo, call, prepared, profile="layered")
    survivors = running_children(silo, result, saved, prepared, cut)
    assert survivors == [NAMES[index] for index in running]
    live = [SOURCE, *survivors]
    state = failed_child(silo, failed)
    if state is not None:
        # Stop-only fenced child: still owned by its exact run until stopped.
        live.append(NAMES[failing])
    fork.assert_no_orphans(silo, live)
    source_running(silo, prepared)
    silo.ws.record("fork-child-failure", json.dumps({"result": result, "failedState": state},
                                                    sort_keys=True) + "\n")
    if state is not None:
        stopped.stop(silo, NAMES[failing], require_clean=False)
        silo.rm(NAMES[failing])
    fork.stop_and_remove(silo, survivors)
    stopped.stop(silo, SOURCE, require_clean=False)
    gone_after_prune(silo, call.operation)


def failed_child(silo: Silo, child: dict) -> dict | None:
    """A failed activation is destroyed or left stop-only fenced, never Running."""
    if child["name"] not in {entry["name"] for entry in silo.ls()}:
        lifecycle.assert_destroyed(silo, child["name"], UUID(child["machineId"]).hex)
        return None
    state = silo.info(child["name"])
    assert state["ready"] is False and state["state"] == "activation-failed", state
    assert UUID(state["run_id"]) == UUID(child["runId"]), state
    return state


def test_fork_children_share_one_clean_ram_inode_by_pss_not_rss(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    prepared = prepare(silo, restore_image, profile="layered")
    report, operations = [], []
    for count in (1, 2, 4):
        names = [f"share-{count}-{index}" for index in range(count)]
        call = fork.run(silo, SOURCE, names, expect=0)
        assert fork.outcomes(call.result) == ["running"] * count, call.result
        operations.append(call.operation)
        ram = fork.cut_directory(silo, call.operation) / "memory.ram"
        for name in names:
            assert touch_blob(silo, name) == prepared.blob, name
        before = fork.sharing(silo, names, ram, source=SOURCE)
        for name in names:
            totals = before["perChild"][name]["totals"]
            assert totals["Rss"] >= 0.9 * BLOB, (name, totals)
            if count > 1:
                assert totals["Shared_Clean"] >= 0.9 * BLOB, (name, totals)
        # RSS double-counts shared clean pages; PSS divides them.
        assert before["rssSumBytes"] - before["childPssBytes"] >= (count - 1) * 0.9 * BLOB, before
        dirty(silo, names[0])
        after = fork.sharing(silo, names, ram, source=SOURCE)
        grown = {name: after["perChild"][name]["totals"]["Private_Dirty"]
                 - before["perChild"][name]["totals"]["Private_Dirty"] for name in names}
        assert grown[names[0]] >= 0.9 * DIRTY_MIB * MIB, grown
        assert all(value < 16 * MIB for name, value in grown.items() if name != names[0]), grown
        report.append({"children": count, "operation": call.operation, "before": before, "after": after,
                       "privateDirtyGrowth": grown})
        fork.stop_and_remove(silo, names)
    silo.ws.record("fork-physical-sharing", json.dumps(report, sort_keys=True) + "\n")
    stopped.stop(silo, SOURCE, require_clean=False)
    gone_after_prune(silo, *operations)


def test_fork_children_outlive_source_deletion_and_gc_then_recapture(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    prepared = prepare(silo, restore_image, profile="layered")
    names = NAMES[:2]
    call = fork.run(silo, SOURCE, names, expect=0)
    saved, cut = continued(silo, call, prepared, profile="layered")
    assert running_children(silo, call.result, saved, prepared, cut) == names
    ram = saved.staging / "memory.ram"
    identity = (ram.stat().st_dev, ram.stat().st_ino)
    sealed = capture.inventory(saved.staging)
    stopped.stop(silo, SOURCE, require_clean=False)
    silo.rm(SOURCE)
    assert not (silo.ws.silo_home / "machines" / UUID(prepared.info["id"]).hex).exists()
    shutdown.storage_tool(silo, "prune")
    # Generation dependencies, not the source or the parent result, root the cut.
    assert (ram.stat().st_dev, ram.stat().st_ino) == identity
    capture.unchanged(silo, saved.staging, sealed)
    assert fork.sharing(silo, names, ram)["children"] == 2
    for name in names:
        restore.advances(silo, name, restore.witness(silo, name))
    assert fork.observe(silo, call.operation)["stage"] == "finished"
    next_identity = restore.witness(silo, names[0], "arm")
    recaptured = restore.checkpoint(silo, names[0], alias="fork-recaptured")
    next_cut = restore.matched_cut(silo, recaptured, next_identity, profile="layered")
    silo.run("resume", names[0])
    restore.restore_child(silo, recaptured, "fork-recaptured-child")
    restore.resumed(silo, "fork-recaptured-child", next_identity, next_cut)
    fork.assert_no_orphans(silo, [*names, "fork-recaptured-child"])
    fork.stop_and_remove(silo, names)
    gone_after_prune(silo, call.operation)
    restore.advances(silo, "fork-recaptured-child", restore.witness(silo, "fork-recaptured-child"))
    fork.assert_no_orphans(silo, ["fork-recaptured-child"])
    silo.ws.record("fork-source-deletion", json.dumps({
        "operation": call.operation, "ram": list(identity), "recaptured": recaptured.snapshot,
    }) + "\n")
    stopped.stop(silo, "fork-recaptured-child", require_clean=False)


# -- pre-freeze refusal -----------------------------------------------------------

def capture_dirs(silo: Silo, machine_id: str) -> set[str]:
    root = silo.ws.silo_home / "machines" / UUID(machine_id).hex / "captures"
    return {path.name for path in root.iterdir()} if root.is_dir() else set()


def staged_lines(silo: Silo, machine_id: str) -> int:
    path = fork.source_trace(silo, machine_id)
    return sum(1 for line in path.read_text(errors="replace").splitlines() if fork.STAGING_WRITTEN in line)


def ledger(silo: Silo) -> dict[str, bytes]:
    """This home's records in the same-euid cross-home restore ledger.

    libvm names each record `<state.db device>-<state.db inode>-<id>.json`.
    """
    directory = Path(f"/tmp/silo-restore-budget-{os.geteuid()}")
    metadata = silo.ws.state_db().stat()
    prefix = f"{metadata.st_dev}-{metadata.st_ino}-"
    if not directory.is_dir():
        return {}
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())
            if path.name.startswith(prefix) and path.name.endswith(".json") and path.is_file()}


def refused_before_freeze(silo: Silo, prepared: Prepared, names: list[str], *flags: str,
                          nofile: int | None = None) -> fork.Call:
    """Whole-batch refusal: no freeze, capture, child, cut or ledger charge."""
    captures, staged = capture_dirs(silo, prepared.info["id"]), staged_lines(silo, prepared.info["id"])
    charges = ledger(silo)
    call = fork.run(silo, SOURCE, names, *flags, nofile=nofile, timeout=120)
    assert call.returncode != 0, "batch over budget was admitted"
    if call.result is not None:
        assert call.result["capture"]["kind"] in {"pending", "abandoned", "failed"}, call.result
        assert call.result["source"] == {"kind": "unchanged"}, call.result
        assert "running" not in fork.outcomes(call.result), call.result
        for child in call.result["children"]:
            if child["outcome"]["kind"] == "failed":
                assert child["outcome"]["phase"] == "capture", child
    assert capture_dirs(silo, prepared.info["id"]) == captures, "refusal staged a capture"
    assert staged_lines(silo, prepared.info["id"]) == staged, "refused batch froze the source"
    assert not fork.cut_directory(silo, call.operation).parent.exists()
    assert ledger(silo) == charges, "refused batch published a cross-home charge"
    listed = {entry["name"] for entry in silo.ls()}
    assert not listed & set(names), listed
    source_running(silo, prepared)
    silo.ws.record("fork-refusal", json.dumps({
        "flags": list(flags), "children": len(names), "nofile": nofile, "exit": call.returncode,
        "stderr": call.stderr, "result": call.result}, sort_keys=True) + "\n")
    return call


def refusal_diagnostic(call: fork.Call) -> str:
    if call.result is not None:
        diagnostic = call.result["capture"].get("diagnostic")
        if diagnostic is not None:
            assert isinstance(diagnostic, str)
            return diagnostic
    return call.stderr


def mem_available() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            value, unit = line.split()[1:]
            assert unit == "kB"
            return int(value) * 1024
    raise AssertionError("kernel omitted MemAvailable")


def batch_bytes(ram: int, children: int, percent: int = 100) -> int:
    granule = os.sysconf("SC_PAGE_SIZE")
    private = math.ceil(ram * percent / 100 / granule) * granule
    return ram + children * (private + math.ceil(ram / 512) + STATE_RESERVE)


def children_for(ram: int, target: int) -> int:
    return max(1, math.ceil((target - ram) / (batch_bytes(ram, 1) - ram)))


def test_fork_refuses_count_memory_and_descriptor_budgets_before_freeze(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    ram = 1024 * MIB
    prepared = prepare(silo, restore_image, profile="layered", memory="1gib")
    # Count: 17 children exceed the default maximum of 16 without an explicit flag.
    refused_before_freeze(silo, prepared, [f"count-{index}" for index in range(17)])
    # Memory: the whole batch at 100% private allowance is twice MemAvailable.
    count = children_for(ram, 2 * mem_available())
    call = refused_before_freeze(silo, prepared, [f"m{index}" for index in range(count)],
                                 "--max-children", str(count), "--private-write-percent", "100")
    diagnostic = refusal_diagnostic(call)
    match = BUDGET_REFUSAL.search(diagnostic)
    assert match is not None, diagnostic
    assert int(match.group(1)) >= batch_bytes(ram, count) > int(match.group(2)), diagnostic
    # Descriptors: the manager's own RLIMIT_NOFILE cannot hold sixteen handoffs.
    call = refused_before_freeze(silo, prepared, [f"fd-{index}" for index in range(16)], nofile=48)
    diagnostic = refusal_diagnostic(call)
    assert "file descriptor budget requires" in diagnostic, diagnostic
    stopped.stop(silo, SOURCE, require_clean=False)


@pytest.fixture
def other_silo(config: SmokeConfig, registry: LoopbackRegistry,
               request: pytest.FixtureRequest) -> Iterator[Silo]:
    """A second same-user home sharing only the per-euid restore ledger."""
    instance = Workspace(config, registry.ca_path)
    try:
        yield Silo(instance)
    finally:
        release(instance, failed=request.session.testsfailed > 0,
                publish=lambda summary: request.node.user_properties.append(
                    (TIMINGS_PROPERTY + "-other-home", summary)))


def test_fork_whole_batch_refusal_counts_another_homes_admitted_batch_then_pre_seal_cancel(
    silo: Silo, other_silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    ram = 1024 * MIB
    prepared = prepare(silo, restore_image, profile="layered", memory="1gib")
    available = mem_available()
    other_count = children_for(ram, int(0.6 * available))
    count = children_for(ram, int(0.6 * available))
    alone = batch_bytes(ram, count)
    assert alone < available and alone + batch_bytes(ram, other_count) > available
    other_names = [f"b{index}" for index in range(other_count)]
    create(other_silo, restore_image, profile="layered", memory="1gib")
    traced = fork.TracedSource(other_silo, SOURCE, other_names, "capture-execution-write",
                               "--max-children", str(other_count), "--private-write-percent", "100")
    try:
        other = witness_source(other_silo)
        other_run = other.info["run_id"]
        traced.fork()
        # Home B's whole batch is admitted and its capture is held before the seal.
        stamps = fork.events(other_silo, traced.operation)
        assert (None, "admission_committed") in stamps and (None, "seal_authenticated") not in stamps, stamps
        assert ledger(other_silo), "admitted batch is not visible in the cross-home ledger"
        call = refused_before_freeze(silo, prepared, [f"a{index}" for index in range(count)],
                                     "--max-children", str(count), "--private-write-percent", "100")
        diagnostic = refusal_diagnostic(call)
        match = BUDGET_REFUSAL.search(diagnostic)
        assert match is not None, diagnostic
        required, reported = int(match.group(1)), int(match.group(2))
        assert required >= alone + batch_bytes(ram, other_count) and required > reported, diagnostic
        assert alone < reported, "home A alone would not have fit; refusal proves nothing about B"

        cancelled = fork.observe(other_silo, traced.operation, cancel=True)
        assert cancelled["cancellationRequested"] is True and cancelled["stage"] != "finished", cancelled
        shutdown.until(lambda: "live cancellation admitted" in fork.source_trace(
            other_silo, other.info["id"]).read_text(errors="replace"), timeout=60,
            description="source monitor never admitted the pre-seal capture cancellation")
        traced.release()
        code, result = traced.manager_exit()
        assert code == 1 and result is not None and result["stage"] == "finished", (code, result)
        assert result["capture"]["kind"] in {"failed", "abandoned"}, result
        assert result["source"] == {"kind": "unchanged"}, result
        for child in result["children"]:
            outcome = child["outcome"]
            assert outcome["kind"] == "cancelled" or (
                outcome["kind"] == "failed" and outcome["phase"] == "capture"), child
            fork.absent(other_silo, child)
        assert not fork.cut_directory(other_silo, traced.operation).exists()
        assert not ledger(other_silo), "cancelled batch kept its cross-home charge"
        current = other_silo.info(SOURCE)
        assert current["state"] == "running" and current["run_id"] == other_run, current
        restore.advances(other_silo, SOURCE, restore.witness(other_silo, SOURCE))
        other_silo.ws.record("fork-pre-seal-cancel", json.dumps({
            "operation": traced.operation, "result": result, "refusal": diagnostic,
            "available": available, "homeA": alone, "homeB": batch_bytes(ram, other_count),
        }, sort_keys=True) + "\n")
        traced.finish()
    finally:
        traced.close()
    stopped.stop(silo, SOURCE, require_clean=False)


# -- cancellation and manager death ------------------------------------------------

def test_fork_post_seal_cancel_preserves_submitted_children_and_cancels_the_rest(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    names = NAMES[:2]
    create(silo, restore_image, profile="layered")
    traced = fork.TracedSource(silo, SOURCE, names, "capture-source-write")
    try:
        prepared = witness_source(silo)
        traced.fork()
        seal = json.loads((Path(traced.wait("boundary-held.json")["target"]).parent / "vm.capture.json")
                          .read_bytes())
        assert seal["captureOutcome"] == "coherent", seal
        cancelled = fork.observe(silo, traced.operation, cancel=True)
        assert cancelled["cancellationRequested"] is True, cancelled
        traced.release()
        code, result = traced.manager_exit()
        assert code == 1 and result is not None and result["stage"] == "finished", (code, result)
        assert result["cancellationRequested"] is True
        assert result["capture"]["kind"] == "sealed" and result["source"] == {"kind": "resumed"}, result
        assert set(fork.outcomes(result)) <= {"running", "cancelled"}, result
        running = []
        if "running" in fork.outcomes(result):
            saved, cut = continued(silo, fork.Call(traced.operation, [], code, "", "", result, 0, 0),
                                   prepared, profile="layered")
            running = running_children(silo, result, saved, prepared, cut)
        for child in result["children"]:
            if child["outcome"]["kind"] == "cancelled":
                fork.absent(silo, child)
        if running:
            assert fork.cut_directory(silo, traced.operation).is_dir(), "running children lost their cut"
        fork.assert_no_orphans(silo, [SOURCE, *running])
        source_running(silo, prepared)
        silo.ws.record("fork-post-seal-cancel", json.dumps({"result": result, "running": running},
                                                           sort_keys=True) + "\n")
        for name in running:
            stopped.stop(silo, name, require_clean=False)
        traced.finish()
        for name in running:
            silo.rm(name)
        gone_after_prune(silo, traced.operation)
    finally:
        traced.close()


def test_fork_manager_killed_before_seal_recovers_one_cut_and_abandons_children(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    names = NAMES[:2]
    create(silo, restore_image, profile="layered")
    traced = fork.TracedSource(silo, SOURCE, names, "capture-execution-write")
    try:
        prepared = witness_source(silo)
        traced.fork()
        assert traced.manager is not None
        os.kill(traced.manager, signal.SIGKILL)
        code, printed = traced.manager_exit()
        assert code == -signal.SIGKILL and printed is None, (code, printed)
        traced.release()
        shutdown.until(lambda: fork.CONTINUATION_FINISHED in fork.source_trace(
            silo, prepared.info["id"]).read_text(errors="replace"), timeout=120,
            description="the source monitor did not finish the manager-less capture")
        result = fork.settle(silo, traced.operation)
        assert result["capture"]["kind"] in {"sealed", "abandoned"}, result
        assert result["source"] == {"kind": "resumed"}, result
        assert fork.outcomes(result) == ["abandoned"] * len(names), result
        for child in result["children"]:
            fork.absent(silo, child)
        # Recovery authenticated or abandoned the one cut; it never recaptured.
        fork.capture_events(silo, prepared.info["id"], result["captureId"])
        assert staged_lines(silo, prepared.info["id"]) == 1
        fork.assert_no_orphans(silo, [SOURCE])
        source_running(silo, prepared)
        silo.ws.record("fork-manager-killed-pre-seal", json.dumps(result, sort_keys=True) + "\n")
        traced.finish()
        gone_after_prune(silo, traced.operation)
    finally:
        traced.close()


def test_fork_manager_killed_during_child_construction_recovers_without_orphans(
    silo: Silo, restore_image: str,  # noqa: F811
) -> None:
    prepared = prepare(silo, restore_image, profile="layered")
    process, args, operation, dispatched = fork.spawn(silo, SOURCE, NAMES)
    try:
        def constructing() -> bool:
            assert process.poll() is None, "fork finished before any child construction was observed"
            return any(key[0] is not None for key in fork.events(silo, operation))
        shutdown.until(constructing, timeout=240, description="no child construction began")
    finally:
        # Kill immediately after the first durable child stamp (or on any failure).
        if process.poll() is None:
            process.send_signal(signal.SIGKILL)
        call = fork.finish(silo, process, args, operation, dispatched, names=NAMES, timeout=60)
    assert call.returncode == -signal.SIGKILL, call
    at_kill = fork.events(silo, operation)
    assert (None, "finished") not in at_kill and (None, "seal_authenticated") in at_kill, at_kill
    result = fork.settle(silo, operation)
    assert result["capture"]["kind"] == "sealed" and result["source"] == {"kind": "resumed"}, result
    assert set(fork.outcomes(result)) <= {"running", "abandoned", "failed"}, result
    saved, cut = continued(silo, fork.Call(operation, args, call.returncode, "", "", result,
                                           call.dispatched_ns, call.exited_ns), prepared, profile="layered")
    running = running_children(silo, result, saved, prepared, cut)
    for child in result["children"]:
        if child["outcome"]["kind"] == "running":
            continue
        if child["name"] in {entry["name"] for entry in silo.ls()}:
            # Positive exact-run retirement; recovery never leaves it live.
            state = silo.info(child["name"])
            assert state["state"] == "stopped" and state["run_id"] is None, (child, state)
        else:
            lifecycle.assert_destroyed(silo, child["name"], UUID(child["machineId"]).hex)
    ownership = fork.assert_no_orphans(silo, [SOURCE, *running])
    source_running(silo, prepared)
    silo.ws.record("fork-manager-killed-constructing", json.dumps({
        "atKill": {f"{key[0]}:{key[1]}": value for key, value in at_kill.items()},
        "result": result, "ownership": ownership}, sort_keys=True) + "\n")
    fork.stop_and_remove(silo, running)
    for child in result["children"]:
        if child["outcome"]["kind"] != "running" and child["name"] in {entry["name"] for entry in silo.ls()}:
            silo.rm(child["name"])
    stopped.stop(silo, SOURCE, require_clean=False)
    gone_after_prune(silo, operation)
    assert procs.vmm_pid(silo.ws, SOURCE) is None
