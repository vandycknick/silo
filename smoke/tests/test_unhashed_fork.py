"""Real release-VM fork ownership, retained identity and first-snapshot gates."""
from __future__ import annotations

import json

import pytest

from silo_smoke import capture_multidisk as multidisk
from silo_smoke import fork, incremental, reclaim, restore, shutdown, stopped
from silo_smoke.catalog_observer import observe
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo
from silo_smoke.filesystem import disk_clone_probe

pytestmark = [pytest.mark.krun_live, pytest.mark.slow, pytest.mark.serial]
SOURCE = "unhashed-source"


def pool_state(silo: Silo) -> dict:
    """Existing read-only catalog oracle plus actual immutable pool membership."""
    catalog = observe(silo.ws.state_db())
    return {
        "catalog": {table: catalog[table] for table in (
            "stream_map_object", "stream_map_root", "stream_map_edge", "storage_stream")},
        "files": {kind: sorted(path.name for path in
                  (silo.ws.silo_home / "images" / kind / "sha256").iterdir())
                  for kind in ("objects", "streams")},
    }


def create(silo: Silo, image: str, profile: RootProfile, data: bool, *, external: bool = False) -> dict:
    silo.create(SOURCE, silo.root_image(image, profile), "--cpus", "2", "--memory", "512mib",
                "--disk-size", "512mib", "--vsock", "--network", "none")
    if data:
        multidisk.install_disks(silo, SOURCE, external=external)
    silo.start(SOURCE)
    silo.wait_ready(SOURCE)
    if data:
        multidisk.mount_sources(silo, SOURCE)
    return incremental.witness(silo, SOURCE, "start")


def mark(silo: Silo, name: str, text: str, data: bool) -> None:
    paths = ["/unhashed-marker"]
    if data:
        paths += [mount + "/unhashed-marker" for mount in multidisk.MOUNTS]
    for path in paths:
        silo.exec(name, "sh", "-eu", "-c", 'printf "%s\\n" "$1" >"$2"; sync',
                  "unhashed-marker", text, path, user="root")


def assert_mark(silo: Silo, name: str, text: str, data: bool) -> None:
    paths = ["/unhashed-marker"]
    if data:
        paths += [mount + "/unhashed-marker" for mount in multidisk.MOUNTS]
    assert silo.exec(name, "cat", *paths).stdout == (text + "\n") * len(paths)


def owned_fork(silo: Silo, parent: str, child: str, baseline: restore.Checkpoint,
               *, preserve: bool = False) -> restore.Checkpoint:
    before = pool_state(silo)
    source = silo.info(parent)
    call = fork.run(silo, parent, [child], *(["--preserve"] if preserve else []), expect=0)
    assert fork.outcomes(call.result) == ["running"]
    cut = fork.cut(silo, call, source, baseline.boot_id, baseline.generation)
    assert pool_state(silo) == before, "live fork published content maps or pool objects"
    info = silo.info(child)
    assert info["ram_identity"] == {"kind": "unknown-after-fork"}, info
    assert info["disk_identities"] and all(
        disk["identity"] == {"kind": "unknown-after-fork"} for disk in info["disk_identities"]), info
    plain = silo.run("info", child).stdout.lower()
    assert "forked" in plain and "first snapshot will compute it in full" in plain
    return cut


@pytest.mark.parametrize("profile", ROOT_PROFILES)
@pytest.mark.parametrize(("data", "external"), [(False, False), (True, False), (True, True)],
                         ids=["root-only", "managed-data", "managed-and-external-data"])
def test_source_snapshot_retains_dirty_union_after_three_unhashed_forks(
    silo: Silo, incremental_image: str, profile: RootProfile, data: bool, external: bool,
) -> None:
    pages = create(silo, incremental_image, profile, data, external=external)
    mark(silo, SOURCE, "baseline", data)
    reclaim.settle_before_capture(silo, SOURCE)
    baseline = restore.checkpoint(silo, SOURCE, alias="unhashed-baseline")
    incremental.authenticated_map(silo, baseline, mode="full", reason="no-baseline")
    children = []
    for index, operation in enumerate(("first", "second", "zero")):
        silo.run("resume", SOURCE)
        pages = incremental.witness(silo, SOURCE, operation, previous=pages)
        mark(silo, SOURCE, f"cut-{index}", data)
        child = f"unhashed-child-{index}"
        # Also exercises the user-borrowed pause lane on the second fork.
        if index == 1:
            silo.run("pause", SOURCE)
        cut = owned_fork(silo, SOURCE, child, baseline, preserve=True)
        incremental.pages_at_cut(silo, cut, pages)
        assert_mark(silo, child, f"cut-{index}", data)
        private_disks = stopped.record(silo, child)["disks"]
        assert len(private_disks) == (2 if data else 0)
        assert all(disk["storage"]["kind"] == "managed-writable" for disk in private_disks)
        children.append(child)
    silo.run("resume", SOURCE)
    saved = restore.checkpoint(silo, SOURCE, alias="unhashed-source-after-forks")
    facts = incremental.authenticated_map(silo, saved, mode="incremental", baseline=baseline)
    incremental.pages_at_cut(silo, saved, pages)
    incremental.full_file_oracle(silo, saved)
    assert facts["stats"]["identityBytesHashed"] < facts["stats"]["logicalBytes"] // 4, facts
    disk_stats = saved.seal["diskStats"]
    if disk_clone_probe(saved.staging)["reflink"]:
        managed = disk_stats[:-1] if external else disk_stats
        assert all(disk["baselineReused"] and incremental.disk_full_scan_reason(disk) is None
                   for disk in managed), disk_stats
        if external:
            assert (not disk_stats[-1]["baselineReused"]
                    and incremental.disk_full_scan_reason(disk_stats[-1]) == "external"), disk_stats
    else:
        assert all(not disk["baselineReused"]
                   and incremental.disk_full_scan_reason(disk) in ("copy-lane", "external")
                   for disk in disk_stats), disk_stats
    silo.ws.record("source-after-unhashed-forks", json.dumps(saved.seal, sort_keys=True) + "\n")
    silo.run("resume", SOURCE)
    if external:
        child_snapshot = restore.checkpoint(silo, children[0], alias="external-child-first",
                                             full_identity_reason="unknown-after-fork")
        incremental.full_file_oracle(silo, child_snapshot, full_identity=True)
        restore.restore_child(silo, child_snapshot, "external-child-restored")
        assert_mark(silo, "external-child-restored", "cut-0", True)
        silo.run("resume", children[0])
    fork.stop_and_remove(silo, children[1:])
    shutdown.storage_tool(silo, "prune")
    for name, expected in ((SOURCE, "cut-2"), (children[0], "cut-0")):
        stopped.stop(silo, name, require_clean=False)
        silo.start(name)
        silo.wait_ready(name)
        # Data mounts are execution state and do not survive cold boot.
        assert_mark(silo, name, expected, False)


@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_fork_child_full_first_identity_then_incremental_and_orphan_grandchild_restore(
    silo: Silo, incremental_image: str, profile: RootProfile,
) -> None:
    pages = create(silo, incremental_image, profile, False)
    mark(silo, SOURCE, "inherited", False)
    baseline = restore.checkpoint(silo, SOURCE, alias="lineage-baseline")
    silo.run("resume", SOURCE)
    child, grandchild = "unhashed-child", "unhashed-grandchild"
    owned_fork(silo, SOURCE, child, baseline)
    inherited = incremental.witness(silo, child, previous=pages)
    assert inherited == pages
    owned_fork(silo, child, grandchild, baseline)
    assert incremental.witness(silo, grandchild, previous=pages) == pages
    first = restore.checkpoint(silo, child, alias="child-first-identity",
                               full_identity_reason="unknown-after-fork")
    incremental.full_file_oracle(silo, first, full_identity=True)
    assert all(not disk["baselineReused"] and incremental.disk_full_scan_reason(disk) is not None
               for disk in first.seal["diskStats"]), first.seal["diskStats"]
    assert silo.info(child)["ram_identity"]["kind"] == "identified"
    silo.run("resume", child)
    changed = incremental.witness(silo, child, "first", previous=pages)
    second = restore.checkpoint(silo, child, alias="child-second-identity")
    incremental.authenticated_map(silo, second, mode="incremental", baseline=first)
    incremental.full_file_oracle(silo, second)
    silo.run("resume", child)
    fork.stop_and_remove(silo, [SOURCE, child])
    shutdown.storage_tool(silo, "prune")
    orphan = restore.checkpoint(silo, grandchild, alias="orphan-grandchild-identity",
                                full_identity_reason="unknown-after-fork")
    incremental.pages_at_cut(silo, orphan, pages)
    incremental.full_file_oracle(silo, orphan, full_identity=True)
    restore.restore_child(silo, orphan, "unhashed-grandchild-restored")
    assert incremental.witness(silo, "unhashed-grandchild-restored", previous=pages) == pages
    assert_mark(silo, "unhashed-grandchild-restored", "inherited", False)
    silo.run("resume", grandchild)
    stopped.stop(silo, grandchild, require_clean=False)
    silo.start(grandchild)
    silo.wait_ready(grandchild)
    assert_mark(silo, grandchild, "inherited", False)


def test_owned_fork_cut_refuses_verification_export_push_and_handoff(
    silo: Silo, incremental_image: str,
) -> None:
    create(silo, incremental_image, "layered", False)
    baseline = restore.checkpoint(silo, SOURCE, alias="refusal-baseline")
    silo.run("resume", SOURCE)
    cut = owned_fork(silo, SOURCE, "refusal-child", baseline)
    reference = "fork:" + cut.seal["captureId"]
    output = silo.ws.evidence / "refused-fork.tar"
    cut_refusal = "snapshot the child first"
    for args, refusal in (
        (("snapshot", "verify", reference), cut_refusal),
        (("storage", "export", reference, str(output), "--disk-format", "raw"), cut_refusal),
        # Images and snapshots are separate namespaces: a cut is never an image.
        (("image", "push", reference, "127.0.0.1:1/refused:latest"), f"image {reference} not found"),
        (("handoff", "plan", reference, "--mode", "fork",
          "--operation", "00000000-0000-4000-8000-000000000001",
          "--destination-home", str(silo.ws.evidence / "destination"),
          "--destination-config", str(silo.ws.evidence / "destination.toml"),
          "--destination-run-root", str(silo.ws.evidence / "destination-run")), cut_refusal),
    ):
        result = silo.run(*args, expect=None, timeout=30)
        assert result.returncode != 0
        assert refusal in result.stderr.lower(), result
    assert not output.exists(), "refused cut export created an artifact"
