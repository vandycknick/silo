"""Host memory reclaim on real tracked boot and restored-private RAM."""
from __future__ import annotations

import pytest

from silo_smoke import fork, incremental, reclaim, restore
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo
from silo_smoke.reclaim import reclaim_image, reclaim_silo  # noqa: F401, pytest fixtures

pytestmark = [pytest.mark.linux_only, pytest.mark.slow]
SOURCE = "reclaim-a"
RESTORED = "reclaim-b"


def create(silo: Silo, image: str, profile: RootProfile) -> reclaim.Sample:
    # BASIC, as in the restore suites, removes /sbin/init. The explicit empty
    # init also prevents an image-init handoff from making live capture ineligible.
    silo.create(SOURCE, silo.root_image(image, profile), "--cpus", "2", "--memory", "4gib",
                "--disk-size", "512mib", "--vsock", "--network", "none", "--kernel-arg", "init=")
    silo.start(SOURCE)
    ready = silo.wait_ready(SOURCE)
    live = ready["lifecycle"]["report"]["live"]
    assert live["fork"]["availability"] == {"status": "supported"}, live
    reclaim.mount(silo, SOURCE)
    return reclaim.observed(silo, SOURCE, "boot")


def seeded(silo: Silo, baseline: reclaim.Sample) -> reclaim.Sample:
    reclaim.workload(silo, SOURCE, "seed")
    return reclaim.wait(silo, SOURCE, baseline.pid, "boot",
        lambda current: current.rss.anonymous - baseline.rss.anonymous >= reclaim.MIN_PAYLOAD_RESIDENCY,
        description="touching 2 GiB did not grow boot worker RssAnon by at least 1.5 GiB")


@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_boot_restore_reclaim_zero_and_incremental_frozen_full(
    reclaim_silo: Silo, reclaim_image: str, profile: RootProfile,  # noqa: F811
) -> None:
    silo = reclaim_silo
    idle = create(silo, reclaim_image, profile)
    allocated = seeded(silo, idle)
    reclaim.free(silo, SOURCE)
    reclaimed = reclaim.freed(silo, SOURCE, allocated, idle.rss, "boot")
    assert allocated.rss.anonymous - reclaimed.rss.anonymous >= reclaim.MIN_PAYLOAD_RESIDENCY

    # Snapshot x holds the exact nonzero 2 GiB in guest tmpfs, not on a disk.
    source_loaded = seeded(silo, idle)
    expected = reclaim.pattern_hash()
    assert reclaim.guest_hash(silo, SOURCE) == expected
    checkpoint = restore.checkpoint(silo, SOURCE, alias="reclaim-seeded-x", policy="full")
    # Read the real saved queue, including negotiated VIRTIO_BALLOON_F_REPORTING.
    # Config flags alone cannot prove that the guest and device negotiated it.
    incremental.balloon_report_queue(silo, checkpoint)
    immutable = reclaim.ram_hashes(silo, checkpoint)
    silo.run("resume", SOURCE)

    restore.restore_child(silo, checkpoint, RESTORED)
    lazy = reclaim.observed(silo, RESTORED, "restored-private")
    assert lazy.rss.total <= source_loaded.rss.total // reclaim.RESTORE_RSS_DIVISOR, (
        "restore eagerly populated RAM instead of retaining lazy private file backing",
        source_loaded, lazy)
    assert reclaim.guest_hash(silo, RESTORED) == expected
    read = reclaim.wait(silo, RESTORED, lazy.pid, "restored-private",
        lambda current: current.rss.file - lazy.rss.file >= reclaim.MIN_PAYLOAD_RESIDENCY,
        description="reading seeded 2 GiB did not grow restored worker RssFile by at least 1.5 GiB")

    # Establish a child-local full baseline after activation/reporting and the
    # read. Otherwise early reporting of already-free inherited pages can make
    # the 60% dirty-crossover choose full, hiding the incremental discard test.
    baseline = restore.checkpoint(silo, RESTORED, alias="reclaim-b-baseline", policy="full")
    incremental.authenticated_map(silo, baseline, mode="full", reason="requested")
    incremental.balloon_report_queue(silo, baseline)
    silo.run("resume", RESTORED)
    before_write = reclaim.observed(silo, RESTORED, "restored-private")
    assert before_write.pid == read.pid
    reclaim.workload(silo, RESTORED, "rewrite")
    written = reclaim.wait(silo, RESTORED, lazy.pid, "restored-private",
        lambda current: (
            reclaim.MIN_COW_RESIDENCY <= current.rss.anonymous - before_write.rss.anonymous
            <= reclaim.REWRITE_BYTES + reclaim.COW_MARGIN),
        description="rewriting 1 GiB did not grow RssAnon by 1 GiB +/- 256 MiB")
    reclaim.free(silo, RESTORED)
    # The full baseline capture above read all of b's RAM, mapping every clean
    # checkpoint page (shared page cache, not private memory). Freeing x must
    # drop x's file pages and the rewritten private half, not that remainder.
    after_capture = reclaim.Rss(lazy.rss.anonymous,
                                before_write.rss.file - reclaim.PAYLOAD_BYTES, lazy.rss.total)
    reclaim.freed(silo, RESTORED, written, after_capture, "restored-private", file_drop=True)

    # No guest allocations between reclaim and this capture. The incremental
    # dirty union must include discarded bytes, not silently reuse x's pattern.
    saved = restore.checkpoint(silo, RESTORED, alias="reclaim-b-freed", policy="incremental")
    facts = incremental.authenticated_map(silo, saved, mode="incremental", baseline=baseline)
    assert facts["affected"], "free-page reporting did not dirty any incremental RAM chunks"
    incremental.frozen_full_oracle(silo, RESTORED, saved)
    silo.run("resume", RESTORED)
    reclaim.workload(silo, RESTORED, "zero")
    increment_child = "reclaim-incremental-restored"
    restore.restore_child(silo, saved, increment_child)
    reclaim.observed(silo, increment_child, "restored-private")
    silo.exec(increment_child, "test", "!", "-e", reclaim.BLOB, user="root")
    reclaim.workload(silo, increment_child, "zero")
    silo.stop(increment_child, force=True)
    silo.stop(RESTORED, force=True)

    # Source a's tracked anonymous RAM must still reclaim after taking x.
    source_before_free = reclaim.observed(silo, SOURCE, "boot")
    assert source_before_free.pid == idle.pid
    assert reclaim.guest_hash(silo, SOURCE) == expected
    reclaim.free(silo, SOURCE)
    source_reclaimed = reclaim.freed(silo, SOURCE, source_before_free, idle.rss, "boot")
    assert source_before_free.rss.anonymous - source_reclaimed.rss.anonymous >= reclaim.MIN_PAYLOAD_RESIDENCY
    assert reclaim.ram_hashes(silo, checkpoint) == immutable

    again = "reclaim-x-again"
    restore.restore_child(silo, checkpoint, again)
    reclaim.observed(silo, again, "restored-private")
    assert reclaim.guest_hash(silo, again) == expected, "child activity changed the seeded checkpoint"
    silo.stop(again, force=True)
    assert reclaim.ram_hashes(silo, checkpoint) == immutable


@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_live_fork_two_children_reclaim_independently(
    reclaim_silo: Silo, reclaim_image: str, profile: RootProfile,  # noqa: F811
) -> None:
    silo = reclaim_silo
    idle = create(silo, reclaim_image, profile)
    seeded(silo, idle)
    expected = reclaim.pattern_hash()
    assert reclaim.guest_hash(silo, SOURCE) == expected
    names = ["reclaim-fork-first", "reclaim-fork-second"]
    call = fork.run(silo, SOURCE, names, expect=0, timeout=240)
    assert call.result is not None and call.result["stage"] == "finished", call.stderr
    assert call.result["source"] == {"kind": "resumed"}, call.result
    assert fork.outcomes(call.result) == ["running", "running"], call.result

    lazy = {}
    written = {}
    for name in names:
        silo.wait_ready(name)
        lazy[name] = reclaim.observed(silo, name, "restored-private")
        assert reclaim.guest_hash(silo, name) == expected
        before = reclaim.observed(silo, name, "restored-private")
        assert before.rss.file - lazy[name].rss.file >= reclaim.MIN_PAYLOAD_RESIDENCY
        reclaim.workload(silo, name, "rewrite")
        written[name] = reclaim.wait(silo, name, before.pid, "restored-private",
            lambda current, prior=before: (
                reclaim.MIN_COW_RESIDENCY <= current.rss.anonymous - prior.rss.anonymous
                <= reclaim.REWRITE_BYTES + reclaim.COW_MARGIN),
            description="fork child did not acquire about 1 GiB of private COW pages")
    assert len({idle.pid, *(value.pid for value in written.values())}) == 3

    first, second = names
    rewritten = reclaim.pattern_hash(rewritten=True)
    assert reclaim.guest_hash(silo, first) == rewritten
    assert reclaim.guest_hash(silo, second) == rewritten
    # Free only first. The second child retains both its 1 GiB private COW and
    # byte-identical file content while the first returns memory to the host.
    reclaim.free(silo, first)
    reclaim.freed(silo, first, written[first], lazy[first].rss, "restored-private", file_drop=True)
    sibling = reclaim.observed(silo, second, "restored-private")
    assert sibling.rss.anonymous >= written[second].rss.anonymous - reclaim.COW_MARGIN, sibling
    assert reclaim.guest_hash(silo, second) == rewritten
    assert reclaim.guest_hash(silo, SOURCE) == expected
    reclaim.workload(silo, first, "zero")
    silo.stop(first, force=True)

    reclaim.free(silo, second)
    reclaim.freed(silo, second, written[second], lazy[second].rss, "restored-private", file_drop=True)
    reclaim.workload(silo, second, "zero")
    assert reclaim.guest_hash(silo, SOURCE) == expected
    # A final source sample checks that child reporting did not change its
    # backing policy or introduce mapping-limit skips in the boot worker.
    assert reclaim.observed(silo, SOURCE, "boot").pid == idle.pid
