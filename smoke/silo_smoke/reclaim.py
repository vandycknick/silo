"""Real guest workload, worker RSS and public reclaim-status smoke evidence."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

import pytest

from . import fork, images, overlay, restore, stopped
from .cli import TIMINGS_PROPERTY, Silo, release
from .config import REPO, SmokeConfig
from .registry import LoopbackRegistry
from .workspace import Workspace

MIB = 1024 ** 2
GIB = 1024 ** 3
PAYLOAD_BYTES = 2 * GIB
REWRITE_BYTES = GIB
# These bounds distinguish a missing 1-2 GiB discard from kernel/agent churn.
BASELINE_MARGIN = 512 * MIB
COW_MARGIN = 256 * MIB
MIN_PAYLOAD_RESIDENCY = PAYLOAD_BYTES - BASELINE_MARGIN
MIN_COW_RESIDENCY = REWRITE_BYTES - COW_MARGIN
RESTORE_RSS_DIVISOR = 4
RECLAIM_TIMEOUT = 60.0
POLL_INTERVAL = 0.5
PROBE = "/usr/local/bin/reclaim-memory"
DIRECTORY = "/dev/shm/reclaim"
BLOB = DIRECTORY + "/blob"
STATUS_COUNTERS = ("released_bytes", "released_extents", "skipped_reports",
                   "failed_operations", "mapping_limit_skips", "replaced_islands")


@pytest.fixture(scope="session")
def reclaim_image(config: SmokeConfig, registry: LoopbackRegistry,
                  tmp_path_factory: pytest.TempPathFactory) -> str:
    """Follow the live suites' static probe plus BASIC Alpine image convention."""
    configured = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
    assert configured, (
        "reclaim smoke requires SILO_SMOKE_KERNEL_CONFIG pointing to the staged "
        "workload kernel's actual emitted .config")
    path = Path(configured).resolve(strict=True)
    lines = set(path.read_text().splitlines())
    required = {"CONFIG_PAGE_REPORTING=y", "CONFIG_VIRTIO_BALLOON=y"}
    assert required <= lines, (
        f"{path}: reclaim smoke requires built-in free page reporting and the "
        f"virtio-balloon driver; missing {sorted(required - lines)}")
    output = tmp_path_factory.mktemp("reclaim-probe") / "reclaim-memory"
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2",
               "-Wall", "-Wextra", "-Werror", "-std=c11",
               str(REPO / "smoke/fixtures/reclaim_memory.c"), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    spec = replace(images.BASIC, name="reclaim-memory", files={
        **images.BASIC.files, PROBE.lstrip("/"): images.GuestFile(output.read_bytes(), mode=0o755),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "reclaim-memory")


@pytest.fixture
def reclaim_silo(config: SmokeConfig, registry: LoopbackRegistry,
                 request: pytest.FixtureRequest) -> Iterator[Silo]:
    """Put all durable bytes on the stopped lane's real mount, not /tmp."""
    supplied = os.environ.get("SILO_SMOKE_STOPPED_DIR")
    parent = Path(supplied) if supplied else None
    if parent is not None:
        assert parent.is_absolute() and parent.is_dir(), (
            "SILO_SMOKE_STOPPED_DIR must name an existing mounted writable directory")
    expected = os.environ.get("SILO_SMOKE_STOPPED_FS")
    assert expected is None or parent is not None, (
        "SILO_SMOKE_STOPPED_FS requires SILO_SMOKE_STOPPED_DIR")
    workspace = Workspace(config, registry.ca_path, parent=parent,
                          runtime_parent=Path("/tmp") if parent is not None else None)
    try:
        silo = Silo(workspace)
        stopped.mount_evidence(silo, expected)
        configured = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
        if configured:
            kernel_config = Path(configured).resolve(strict=True)
            workspace.record("reclaim-kernel-config", json.dumps({
                "path": str(kernel_config), "sha256": overlay.digest(kernel_config),
                "config": kernel_config.read_text()}, sort_keys=True) + "\n")
        yield silo
    finally:
        # Registered VMs always stop, including on an assertion or command error.
        # Successful non-kept workspaces remove checkpoints along with the Home.
        release(workspace, failed=request.session.testsfailed > 0,
                publish=lambda summary: request.node.user_properties.append((TIMINGS_PROPERTY, summary)))


@dataclass(frozen=True)
class Rss:
    anonymous: int
    file: int
    total: int


@dataclass(frozen=True)
class Sample:
    pid: int
    rss: Rss
    status: dict | None
    # Bytes of anonymous replacement islands inside restored file-private RAM.
    islands: int = 0


def island_bytes(pid: int) -> int:
    """Anonymous VMAs that host reclaim mapped over freed restored RAM.

    Restored RAM is the largest writable private file mapping; reclaim replaces
    freed ranges inside its span with anonymous memory. RssFile is not used:
    it also counts clean checkpoint pages faulted by captures and readahead.
    """
    mappings = fork.smaps(pid)
    files: dict[int, list[dict]] = {}
    for mapping in mappings:
        if mapping["inode"] != 0 and mapping["permissions"] == "rw-p":
            files.setdefault(mapping["inode"], []).append(mapping)
    assert files, f"worker {pid} has no private file-backed RAM mapping"
    ram = max(files.values(), key=lambda vmas: sum(m["end"] - m["start"] for m in vmas))
    start, end = min(m["start"] for m in ram), max(m["end"] for m in ram)
    return sum(m["end"] - m["start"] for m in mappings
               if m["inode"] == 0 and not m["name"] and m["permissions"] == "rw-p"
               and start <= m["start"] and m["end"] <= end)


def rss(pid: int) -> Rss:
    with Path(f"/proc/{pid}/status").open() as stream:
        text = stream.read(64 * 1024 + 1)
    assert len(text) <= 64 * 1024, "unbounded worker status"
    values = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in {"RssAnon", "RssFile", "VmRSS"}:
            fields = value.split()
            assert len(fields) == 2 and fields[1] == "kB", line
            values[key] = int(fields[0]) * 1024
    assert set(values) == {"RssAnon", "RssFile", "VmRSS"}, (pid, values)
    return Rss(values["RssAnon"], values["RssFile"], values["VmRSS"])


def sample(silo: Silo, name: str, pid: int, backing: str, *, timeout: float = 10) -> Sample:
    info = silo.json("info", name, timeout=timeout, label="reclaim-info")
    assert info["state"] == "running", info
    status = info.get("host_memory_reclaim")
    assert status is not None, info
    assert status["backing"] == backing and status["effective"] is True, status
    assert status["requested"] is True and status["reason"] == "none", status
    assert isinstance(status["qualification"], str), status
    for key in STATUS_COUNTERS:
        assert type(status[key]) is int and status[key] >= 0, (key, status)
    assert status["mapping_limit_skips"] == 0, status
    assert status["failed_operations"] == 0, status
    islands = island_bytes(pid) if backing == "restored-private" else 0
    measured = Sample(pid, rss(pid), status, islands)
    silo.ws.record("reclaim-samples", json.dumps({"machine": name, "monotonic": time.monotonic(),
                                                **asdict(measured)}, sort_keys=True) + "\n")
    return measured


def wait(silo: Silo, name: str, pid: int, backing: str, predicate: Callable[[Sample], bool],
         *, description: str) -> Sample:
    deadline = time.monotonic() + RECLAIM_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"{name}: {description}; see reclaim-samples.log"
        last = sample(silo, name, pid, backing, timeout=min(10, remaining))
        if last.status is not None and predicate(last):
            return last
        assert time.monotonic() < deadline, (
            f"{name}: {description}; last observation: {last}")
        time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))


def observed(silo: Silo, name: str, backing: str) -> Sample:
    pid = overlay.worker_pid(silo, name)
    return wait(silo, name, pid, backing, lambda value: True,
                description="monitor did not publish effective host reclaim status")


SETTLE_QUIET = 5.0


def settled(silo: Silo, name: str, backing: str = "boot") -> Sample:
    """Waits until the guest's initial free-page reports stop discarding RAM.

    Reclaim dirties every discarded range, so a capture baseline taken while the
    guest still reports its boot-time free memory makes the next incremental
    capture cross the full-capture threshold.
    """
    pid = overlay.worker_pid(silo, name)
    deadline = time.monotonic() + RECLAIM_TIMEOUT
    last = observed(silo, name, backing)
    quiet_since = time.monotonic()
    while time.monotonic() - quiet_since < SETTLE_QUIET:
        assert time.monotonic() < deadline, f"{name}: free-page reporting never settled: {last}"
        time.sleep(POLL_INTERVAL)
        current = sample(silo, name, pid, backing)
        if current.status["released_bytes"] != last.status["released_bytes"]:
            quiet_since = time.monotonic()
        last = current
    return last


def mount(silo: Silo, name: str) -> None:
    silo.exec(name, "sh", "-eu", "-c",
              f"test -d /sys/bus/virtio/drivers/virtio_balloon; "
              f"mkdir -p {DIRECTORY}; mount -t tmpfs -o size=3g,mode=0700 reclaim {DIRECTORY}",
              user="root")


def workload(silo: Silo, name: str, operation: str) -> None:
    result = silo.exec(name, PROBE, operation, user="root", timeout=120)
    if operation == "zero":
        assert result.stdout == f"zero bytes={PAYLOAD_BYTES}\n", result


def guest_hash(silo: Silo, name: str) -> str:
    output = silo.exec(name, "sha256sum", BLOB, user="root", timeout=120).stdout.split()
    assert len(output) == 2 and output[1] == BLOB, output
    return output[0]


def pattern_hash(*, rewritten: bool = False) -> str:
    digest = hashlib.sha256()
    seed, changed = bytes([0x5a]) * MIB, bytes([0xa5]) * MIB
    for index in range(PAYLOAD_BYTES // MIB):
        digest.update(changed if rewritten and index < REWRITE_BYTES // MIB else seed)
    return digest.hexdigest()


def free(silo: Silo, name: str) -> None:
    # Only this guest's cache is dropped. Never change the host's page cache.
    silo.exec(name, "sh", "-eu", "-c",
              f"rm {BLOB}; sync; echo 3 >/proc/sys/vm/drop_caches", user="root")


def freed(silo: Silo, name: str, before: Sample, baseline: Rss, backing: str,
          *, file_drop: bool = False) -> Sample:
    return wait(silo, name, before.pid, backing,
        lambda current: (
            current.rss.anonymous <= baseline.anonymous + BASELINE_MARGIN
            and before.rss.anonymous - current.rss.anonymous >= (
                MIN_COW_RESIDENCY if file_drop else MIN_PAYLOAD_RESIDENCY)
            and current.status["released_bytes"] - before.status["released_bytes"] >= MIN_PAYLOAD_RESIDENCY
            and (not file_drop or (
                current.islands - before.islands >= MIN_PAYLOAD_RESIDENCY
                and current.rss.file <= before.rss.file))),
        description="2 GiB free did not release RSS and advance released_bytes within 60s")


def ram_hashes(silo: Silo, saved: restore.Checkpoint) -> dict[str, str]:
    stream = restore.snapshot_record(silo, saved)["execution"]["memory"]["stream"]
    assert stream.startswith("sha256:")
    paths = (saved.staging / "memory.ram", silo.ws.silo_home / "images/streams/sha256" / stream[7:])
    result = {str(path): overlay.digest(path) for path in paths}
    silo.ws.record("reclaim-checkpoint-hashes", json.dumps({"snapshot": saved.snapshot,
                                                          "ram": result}, sort_keys=True) + "\n")
    return result
