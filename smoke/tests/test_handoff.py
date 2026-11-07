"""Phase 19 stopped handoff and relocation between two real local runtimes.

Every test runs two foreground daemons with separate Homes, config roots and
short run roots, and drives only the actual `silo handoff` CLI. Guests boot on
whichever runtime owns them; the old owner is refused through real `silo
start`. Daemon crashes are real SIGKILLs. Oracles are independent read-only
catalog reads and host-side hashes of each runtime's own private files. The
exhaustive lost-message matrix is the host-only ledger tests' job; this file
proves the transport, ownership and guest-observed state end to end.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest

from silo_smoke import handoff, image_cache, overlay, procs, stopped
from silo_smoke.cli import TIMINGS_PROPERTY, Silo, release
from silo_smoke.config import SmokeConfig
from silo_smoke.daemon import Daemon
from silo_smoke.handoff import Runtime
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace
# The overlay-probe image fixture stays owned by its existing module.
from .test_stopped import stopped_image

pytestmark = [pytest.mark.linux_only, pytest.mark.daemon]

RESOURCES = ("--cpus", "1", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock")
PROFILES = {"raw": (), "flat": ("--root-profile", overlay.PROFILE)}
OWNED = {"state": "owned"}
NO_PAYLOAD = {"payloads": 0, "payloadBytes": 0}
MIB = 1024**2


@pytest.fixture
def runtimes(config: SmokeConfig, registry: LoopbackRegistry, overlay_image_caches: dict[str, Path],
             request: pytest.FixtureRequest) -> Iterator[tuple[Runtime, Runtime]]:
    """Laptop and cloud runtimes: independent catalogs, identities, sockets and owner locks."""
    workspaces: list[Workspace] = []
    failures = request.session.testsfailed
    try:
        pair = []
        for label in ("laptop", "cloud"):
            workspace = Workspace(config, registry.ca_path)
            workspaces.append(workspace)
            seeded = image_cache.seed(overlay_image_caches["stopped"], workspace.silo_home)
            assert len(seeded) == 1, seeded
            workspace.record("image-cache", f"seeded session-prepared stopped image: {sorted(seeded)}\n")
            runtime = Runtime(label, Silo(workspace), Daemon(workspace))
            runtime.start()
            pair.append(runtime)
        laptop, cloud = pair
        assert laptop.runtime_id() != cloud.runtime_id(), "seeded Homes must not share persistent runtime identity"
        assert laptop.ws.run_root != cloud.ws.run_root and laptop.daemon.control_sock != cloud.daemon.control_sock
        assert laptop.daemon.pid != cloud.daemon.pid
        yield laptop, cloud
    finally:
        failed = request.session.testsfailed > failures
        for workspace in reversed(workspaces):
            release(workspace, failed=failed, publish=lambda value: request.node.user_properties.append((TIMINGS_PROPERTY, value)))


def _create(runtime: Runtime, image: str, name: str, profile: str) -> UUID:
    runtime.silo.create(name, image, *RESOURCES, *PROFILES[profile])
    return UUID(procs.machine_id(runtime.ws, name))


def _warm(runtime: Runtime, image: str, profile: str) -> None:
    """Prepare a destination the ordinary way: an unrelated never-booted machine
    from the same image retains the exact lower stream and pinned boot objects."""
    _create(runtime, image, f"warm-{profile}", profile)
    handoff.assert_stopped_unstarted(runtime, f"warm-{profile}")


def _relocated(runtime: Runtime, name: str, *, operation: str, successor: Runtime, successor_epoch: int, epoch: int) -> None:
    current, owner = handoff.ownership(runtime, name)
    assert current == epoch, (current, owner)
    assert owner["state"] == "relocated" and UUID(owner["operation"]) == UUID(operation), owner
    assert UUID(owner["successorRuntime"]) == successor.runtime_id() and owner["successorEpoch"] == successor_epoch, owner


def _records(report: dict) -> tuple[dict, dict]:
    return report["source"], report["destination"]


def test_relocate_raw_keeps_identity_fences_source_and_boots_only_destination(runtimes: tuple[Runtime, Runtime], stopped_image: str) -> None:
    laptop, cloud = runtimes
    name = "mover"
    machine = _create(laptop, stopped_image, name, "raw")
    _warm(cloud, stopped_image, "raw")
    handoff.boot(laptop, name)
    handoff.write_marker(laptop.silo, name, "/handoff-proof", "laptop-before-relocation")
    handoff.stop(laptop, name)
    cut = stopped.backing(laptop.silo, name, "relocate-source-cut")
    record = stopped.record(laptop.silo, name)
    configured = stopped.configured_semantics(stopped.configuration(laptop.silo, name))
    assert (record["ownershipEpoch"], record["ownership"]) == (0, OWNED)

    operation = handoff.new_operation()
    # Runtime selection is explicit and verified: neither the source itself nor
    # another runtime's run root can stand in for the selected destination Home.
    handoff.refuse(laptop, laptop, "same-runtime", "plan", name, "--mode", "relocate", "--operation", operation)
    mixed = ["--destination-home", str(cloud.ws.silo_home), "--destination-config", str(cloud.config_dir), "--destination-run-root", str(laptop.ws.run_root)]
    wrong_root = handoff.without_effects((laptop, cloud), "mismatched-run-root", lambda: laptop.silo.run(
        "handoff", "plan", name, "--mode", "relocate", "--operation", operation, *mixed, expect=None, label="handoff-plan"))
    assert wrong_root.returncode != 0

    proposal = handoff.plan(laptop, cloud, name, "relocate", operation)
    assert handoff.plan(laptop, cloud, name, "relocate", operation)["digest"] == proposal["digest"], "preflight must be deterministic"
    handoff.assert_immutable_warm(laptop, name, cloud)
    missing = handoff.expected_mutable(laptop, name, cloud)
    assert missing, "a booted raw root has private chunks the destination lacks"
    report = handoff.transfer(laptop, cloud, name, "relocate", operation, proposal["digest"])
    cloud.ws.register_machine(name)
    handoff.assert_payload(report, mutable=missing)
    assert handoff.destination_machine(report) == machine and report["destination"]["intent"]["fromEpoch"] == 0
    assert handoff.destination_epoch(report) == 1

    # Destination: same machine identity at the next epoch, stopped, never started.
    assert UUID(procs.machine_id(cloud.ws, name)) == machine
    handoff.assert_stopped_unstarted(cloud, name)
    assert handoff.ownership(cloud, name) == (1, OWNED)
    received = stopped.backing(cloud.silo, name, "relocate-destination-before-boot")
    stopped.same_content(cut, received)
    stopped.independent(cut, received)
    moved = stopped.record(cloud.silo, name)
    assert moved["boot"] == record["boot"] and moved["stopOutcome"] == record["stopOutcome"]
    assert stopped.configured_semantics(stopped.configuration(cloud.silo, name)) == configured

    # Source: a fenced prior-owner record that real start refuses.
    _relocated(laptop, name, operation=operation, successor=cloud, successor_epoch=1, epoch=0)
    handoff.refuse_start(laptop, name)
    handoff.assert_stopped_unstarted(laptop, name)
    # Ordinary growth and launch must use the catalog-selected generation,
    # not a historical assumption that every raw root is named root.raw.
    cloud.silo.run("set", name, "disk=576mib")

    handoff.boot(cloud, name)
    assert handoff.read_file(cloud.silo, name, "/handoff-proof") == "laptop-before-relocation\n"
    handoff.write_marker(cloud.silo, name, "/handoff-proof", "cloud-after-relocation")
    handoff.stop(cloud, name)
    assert stopped.writable_paths(cloud.silo, name)["root"].stat().st_size == 576 * MIB

    # Restarted daemons keep persistent identity, decisions and the fence.
    for runtime in (laptop, cloud):
        runtime.restart()
    handoff.refuse_start(laptop, name)
    assert _records(handoff.status(laptop, cloud, operation)) == _records(report)
    handoff.boot(cloud, name)
    assert handoff.read_file(cloud.silo, name, "/handoff-proof") == "cloud-after-relocation\n"
    handoff.stop(cloud, name)


def test_fork_handoff_from_running_source_gets_distinct_identity_and_independent_writes(runtimes: tuple[Runtime, Runtime], stopped_image: str) -> None:
    laptop, cloud = runtimes
    name, child = "parent", "forked"
    parent = _create(laptop, stopped_image, name, "raw")
    _warm(cloud, stopped_image, "raw")
    handoff.boot(laptop, name)
    handoff.write_marker(laptop.silo, name, "/handoff-proof", "parent-before-fork")

    operation = handoff.new_operation()
    proposal = handoff.plan(laptop, cloud, name, "fork", operation, "--name", child, running=True)
    assert laptop.silo.info(name)["state"] == "running", "preflight of a running source must not stop it"
    assert handoff.ledger(laptop, operation) is None and handoff.ledger(cloud, operation) is None
    handoff.assert_immutable_warm(laptop, name, cloud)
    report = handoff.transfer(laptop, cloud, name, "fork", operation, proposal["digest"], "--name", child, "--stop-running")
    cloud.ws.register_machine(child)

    fork = handoff.destination_machine(report)
    assert fork != parent and UUID(procs.machine_id(cloud.ws, child)) == fork
    assert parent not in handoff.machine_ids(cloud)
    assert handoff.destination_epoch(report) == 0
    # Fork never transfers ownership: the deliberately stopped source is not restarted.
    handoff.assert_stopped_unstarted(laptop, name)
    assert handoff.ownership(laptop, name) == (0, OWNED)
    handoff.assert_stopped_unstarted(cloud, child)
    assert handoff.ownership(cloud, child) == (0, OWNED)
    captured = handoff.writable_chunks(laptop, name)
    assert report["payload"]["immutable"] == NO_PAYLOAD
    mutable = report["payload"]["mutable"]
    assert 0 < mutable["payloads"] <= len(captured) and mutable["payloadBytes"] <= sum(captured.values()), (mutable, len(captured))
    source_bytes = stopped.backing(laptop.silo, name, "fork-source-after")
    child_bytes = stopped.backing(cloud.silo, child, "fork-child-before-boot")
    stopped.same_content(source_bytes, child_bytes)
    stopped.independent(source_bytes, child_bytes)

    # Both distinct machines may run at once; private writes stay private.
    handoff.boot(laptop, name)
    handoff.boot(cloud, child)
    assert handoff.read_file(laptop.silo, name, "/handoff-proof") == "parent-before-fork\n"
    assert handoff.read_file(cloud.silo, child, "/handoff-proof") == "parent-before-fork\n"
    handoff.write_marker(laptop.silo, name, "/parent-only", "parent")
    handoff.write_marker(cloud.silo, child, "/child-only", "child")
    laptop.silo.exec(name, "sh", "-eu", "-c", "test ! -e /child-only", user="root")
    cloud.silo.exec(child, "sh", "-eu", "-c", "test ! -e /parent-only", user="root")
    handoff.stop(laptop, name)
    handoff.stop(cloud, child)
    assert stopped.backing(laptop.silo, name, "fork-source-after-write")["root"].content() != stopped.backing(cloud.silo, child, "fork-child-after-write")["root"].content()
    assert _records(handoff.status(laptop, cloud, operation)) == _records(report)


def test_wrong_or_stale_approved_plan_refuses_before_any_side_effect(runtimes: tuple[Runtime, Runtime], stopped_image: str) -> None:
    laptop, cloud = runtimes
    name = "planned"
    _create(laptop, stopped_image, name, "raw")
    _warm(cloud, stopped_image, "raw")
    operation = handoff.new_operation()
    relocate = handoff.plan(laptop, cloud, name, "relocate", operation)["digest"]
    fork = handoff.plan(laptop, cloud, name, "fork", operation)["digest"]
    renamed = handoff.plan(laptop, cloud, name, "relocate", operation, "--name", "renamed")["digest"]
    assert len({relocate, fork, renamed}) == 3
    for label, digest, flags in (
        ("fork-plan-approves-relocation", fork, ()),
        ("unrelated-digest", "sha256:" + "0" * 64, ()),
        ("renamed-plan-approves-default-name", renamed, ()),
        ("default-plan-approves-renamed", relocate, ("--name", "renamed")),
    ):
        handoff.refuse(laptop, cloud, label, *handoff.transfer_args(name, "relocate", operation, digest, *flags))
    assert handoff.ledger(laptop, operation) is None and handoff.ledger(cloud, operation) is None
    assert handoff.ownership(laptop, name) == (0, OWNED)

    # The source changes after approval: the old approval is stale, not reinterpreted.
    handoff.boot(laptop, name)
    handoff.write_marker(laptop.silo, name, "/handoff-proof", "changed-after-approval")
    handoff.stop(laptop, name)
    handoff.refuse(laptop, cloud, "stale-after-source-change", *handoff.transfer_args(name, "relocate", operation, relocate))
    assert handoff.ledger(laptop, operation) is None and handoff.ledger(cloud, operation) is None

    fresh = handoff.plan(laptop, cloud, name, "relocate", operation)["digest"]
    assert fresh != relocate
    cut = stopped.backing(laptop.silo, name, "replanned-cut")
    handoff.assert_immutable_warm(laptop, name, cloud)
    missing = handoff.expected_mutable(laptop, name, cloud)
    report = handoff.transfer(laptop, cloud, name, "relocate", operation, fresh)
    cloud.ws.register_machine(name)
    handoff.assert_payload(report, mutable=missing)
    assert handoff.ownership(cloud, name) == (1, OWNED)
    _relocated(laptop, name, operation=operation, successor=cloud, successor_epoch=1, epoch=0)
    stopped.same_content(cut, stopped.backing(cloud.silo, name, "replanned-destination"))
    handoff.assert_stopped_unstarted(cloud, name)


def test_destination_crash_then_explicit_abort_unfences_only_the_source(runtimes: tuple[Runtime, Runtime], stopped_image: str) -> None:
    laptop, cloud = runtimes
    name = "unmoved"
    machine = _create(laptop, stopped_image, name, "raw")
    _warm(cloud, stopped_image, "raw")
    handoff.boot(laptop, name)
    bulk = handoff.write_bulk(laptop.silo, name, "/handoff-bulk", 160)
    handoff.write_marker(laptop.silo, name, "/handoff-proof", "never-moved")
    handoff.stop(laptop, name)

    operation = handoff.new_operation()
    approved = handoff.plan(laptop, cloud, name, "relocate", operation)["digest"]
    handoff.assert_immutable_warm(laptop, name, cloud)
    assert sum(handoff.expected_mutable(laptop, name, cloud).values()) >= 160 * MIB
    observed = handoff.interrupt_transfer(laptop, cloud, name, "relocate", operation, approved)
    assert observed["source"]["phase"] in {"captured", "fenced"}, observed
    assert observed["destination"]["phase"] in {"receiving", "prepared"}, "the destination committed before the crash point"

    # Outcome unknown: neither runtime may start the machine.
    handoff.refuse_start(laptop, name)
    assert machine not in handoff.machine_ids(cloud), "prepared bytes never publish a runnable destination"
    cloud.restart()
    unresolved = handoff.status(laptop, cloud, operation)
    assert (unresolved["source"]["phase"], unresolved["destination"]["phase"]) == (observed["source"]["phase"], observed["destination"]["phase"]), "a restart decides nothing"
    handoff.refuse_start(laptop, name)

    aborted = handoff.abort(laptop, cloud, operation)
    assert handoff.ownership(laptop, name) == (0, OWNED)
    handoff.assert_stopped_unstarted(laptop, name)
    assert machine not in handoff.machine_ids(cloud)
    assert handoff.ledger(cloud, operation)["phase"] == "aborted" and handoff.ledger(cloud, operation)["terminal"]

    # The abort is final: replays repeat it, and nothing can resurrect a commit.
    replay = handoff.stale(laptop, cloud, "abort-replay", "abort", str(operation))
    assert replay is not None and _records(replay) == _records(aborted)
    for label, args in (("recover-after-abort", ("recover", operation)),
                        ("transfer-after-abort", tuple(handoff.transfer_args(name, "relocate", operation, approved)))):
        answer = handoff.stale(laptop, cloud, label, *args)
        assert answer is None or answer.get("decision") == "aborted", answer
    assert machine not in handoff.machine_ids(cloud)

    # The unfenced source is an ordinary stopped owner again, contents intact.
    handoff.boot(laptop, name)
    assert handoff.guest_sha256(laptop.silo, name, "/handoff-bulk") == bulk
    assert handoff.read_file(laptop.silo, name, "/handoff-proof") == "never-moved\n"
    handoff.stop(laptop, name)

    # A new operation still relocates; a crash-orphaned payload is never trusted
    # beyond the destination's verified pool.
    retry = handoff.new_operation()
    digest = handoff.plan(laptop, cloud, name, "relocate", retry)["digest"]
    handoff.assert_immutable_warm(laptop, name, cloud)
    missing = handoff.expected_mutable(laptop, name, cloud)
    report = handoff.transfer(laptop, cloud, name, "relocate", retry, digest)
    cloud.ws.register_machine(name)
    handoff.assert_payload(report, mutable=missing)
    assert handoff.destination_epoch(report) == 1 and handoff.ownership(cloud, name) == (1, OWNED)
    _relocated(laptop, name, operation=retry, successor=cloud, successor_epoch=1, epoch=0)
    handoff.boot(cloud, name)
    assert handoff.guest_sha256(cloud.silo, name, "/handoff-bulk") == bulk
    handoff.stop(cloud, name)


def test_direct_return_cycles_recover_after_crash_and_ignore_stale_requests(runtimes: tuple[Runtime, Runtime], stopped_image: str) -> None:
    laptop, cloud = runtimes
    name = "roamer"
    machine = _create(laptop, stopped_image, name, "flat")
    for runtime in (laptop, cloud):
        _warm(runtime, stopped_image, "flat")
    handoff.boot(laptop, name)
    handoff.write_marker(laptop.silo, name, "/handoff-cycle", "laptop-0")
    handoff.stop(laptop, name)

    # op1 laptop -> cloud: warm lower, only private upper chunks travel.
    op1 = handoff.new_operation()
    plan1 = handoff.plan(laptop, cloud, name, "relocate", op1)
    handoff.assert_immutable_warm(laptop, name, cloud)
    missing1 = handoff.expected_mutable(laptop, name, cloud)
    report1 = handoff.transfer(laptop, cloud, name, "relocate", op1, plan1["digest"])
    cloud.ws.register_machine(name)
    handoff.assert_payload(report1, mutable=missing1)
    assert handoff.destination_machine(report1) == machine
    assert handoff.ownership(cloud, name) == (1, OWNED)
    _relocated(laptop, name, operation=op1, successor=cloud, successor_epoch=1, epoch=0)
    handoff.refuse_start(laptop, name)

    handoff.boot(cloud, name)
    assert handoff.read_file(cloud.silo, name, "/handoff-cycle") == "laptop-0\n"
    handoff.write_marker(cloud.silo, name, "/handoff-cycle", "cloud-1")
    bulk = handoff.write_bulk(cloud.silo, name, "/handoff-bulk", 96)
    handoff.stop(cloud, name)

    # op2 cloud -> laptop, direct return; the returning destination crashes mid-payload.
    op2 = handoff.new_operation()
    plan2 = handoff.plan(cloud, laptop, name, "relocate", op2)
    handoff.assert_immutable_warm(cloud, name, laptop)
    missing2 = handoff.expected_mutable(cloud, name, laptop)
    assert sum(missing2.values()) >= 96 * MIB
    observed = handoff.interrupt_transfer(cloud, laptop, name, "relocate", op2, plan2["digest"])
    assert observed["source"]["phase"] in {"captured", "fenced"}, observed
    assert observed["destination"]["phase"] in {"receiving", "prepared"}, "the destination committed before the crash point"
    handoff.refuse_start(cloud, name)
    # Laptop's daemon is down: the local libvm path still refuses its prior-owner record.
    _relocated(laptop, name, operation=op1, successor=cloud, successor_epoch=1, epoch=0)
    handoff.refuse_start(laptop, name)
    already = handoff.published(laptop, missing2)
    laptop.restart()
    unresolved = handoff.status(cloud, laptop, op2)
    assert (unresolved["source"]["phase"], unresolved["destination"]["phase"]) == (observed["source"]["phase"], observed["destination"]["phase"])
    report2 = handoff.recover(cloud, laptop, op2, "relocate")
    # Recovery requests exactly what the crash left unpublished, never verified bytes again.
    handoff.assert_payload(report2, mutable={digest: length for digest, length in missing2.items() if digest not in already})
    assert report2["destination"]["intent"]["fromEpoch"] == 1 and handoff.destination_epoch(report2) == 2
    assert handoff.ownership(laptop, name) == (2, OWNED)
    _relocated(cloud, name, operation=op2, successor=laptop, successor_epoch=2, epoch=1)
    handoff.refuse_start(cloud, name)

    handoff.boot(laptop, name)
    assert handoff.read_file(laptop.silo, name, "/handoff-cycle") == "cloud-1\n"
    assert handoff.guest_sha256(laptop.silo, name, "/handoff-bulk") == bulk
    handoff.write_marker(laptop.silo, name, "/handoff-cycle", "laptop-2")
    handoff.stop(laptop, name)

    # op3 laptop -> cloud, direct return again: unchanged bulk chunks are reused.
    op3 = handoff.new_operation()
    plan3 = handoff.plan(laptop, cloud, name, "relocate", op3)
    handoff.assert_immutable_warm(laptop, name, cloud)
    missing3 = handoff.expected_mutable(laptop, name, cloud)
    assert 0 < sum(missing3.values()) < 96 * MIB, "a direct return must not resend the prior owner's unchanged chunks"
    report3 = handoff.transfer(laptop, cloud, name, "relocate", op3, plan3["digest"])
    handoff.assert_payload(report3, mutable=missing3)
    assert handoff.ownership(cloud, name) == (3, OWNED)
    _relocated(laptop, name, operation=op3, successor=cloud, successor_epoch=3, epoch=2)
    assert [report["destination"]["intent"]["fromEpoch"] for report in (report1, report2, report3)] == [0, 1, 2]

    # Every earlier request replayed after later commits: history only, no effect.
    history = ((op1, plan1, report1, laptop, cloud), (op2, plan2, report2, cloud, laptop))
    for operation, approved, original, source, destination in history:
        for label, args in (("stale-transfer", tuple(handoff.transfer_args(name, "relocate", operation, approved["digest"]))),
                            ("stale-recover", ("recover", operation)), ("stale-abort", ("abort", operation))):
            answer = handoff.stale(source, destination, label, *args)
            assert answer is None or _records(answer) == _records(original), (label, answer)
        assert _records(handoff.status(source, destination, operation)) == _records(original)
    assert handoff.ownership(cloud, name) == (3, OWNED)
    _relocated(laptop, name, operation=op3, successor=cloud, successor_epoch=3, epoch=2)

    # Both participants restart: identities, decisions and fences persist.
    for runtime in (laptop, cloud):
        runtime.restart()
    handoff.refuse_start(laptop, name)
    for operation, original, source, destination in ((op1, report1, laptop, cloud), (op2, report2, cloud, laptop), (op3, report3, laptop, cloud)):
        assert _records(handoff.status(source, destination, operation)) == _records(original)
    handoff.boot(cloud, name)
    assert handoff.read_file(cloud.silo, name, "/handoff-cycle") == "laptop-2\n"
    assert handoff.guest_sha256(cloud.silo, name, "/handoff-bulk") == bulk
    handoff.stop(cloud, name)
