from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess

import pytest

from silo_smoke import images, overlay, procs, shutdown, stopped
from silo_smoke.cli import Silo
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace

pytestmark = pytest.mark.linux_only


@pytest.fixture
def stopped_silo(config: SmokeConfig, registry: LoopbackRegistry, request: pytest.FixtureRequest) -> Generator[Silo, None, None]:
    supplied = os.environ.get("SILO_SMOKE_STOPPED_DIR")
    parent = Path(supplied) if supplied else None
    if parent is not None:
        assert parent.is_absolute() and parent.is_dir(), "SILO_SMOKE_STOPPED_DIR must name an existing mounted writable directory"
    workspace = Workspace(config, registry.ca_path, parent=parent, runtime_parent=Path("/tmp") if parent is not None else None)
    try:
        yield Silo(workspace)
    finally:
        # Pytest records call failure before fixture teardown. Keep all evidence
        # for a failed native gate, while always terminating registered guests.
        failed = request.session.testsfailed > 0
        workspace.cleanup(failed=failed)


@pytest.fixture(scope="session")
def stopped_image(registry: LoopbackRegistry, overlay_image_bytes: images.OciImage) -> str:
    return registry.publish(overlay_image_bytes, "stopped")


def create(silo: Silo, image: str, name: str, profile: str, *flags: str) -> None:
    silo.create(name, image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock", *(["--root-profile", overlay.PROFILE] if profile == "flat" else []), *flags)
    stopped.mount_evidence(silo, os.environ.get("SILO_SMOKE_STOPPED_FS"))


def boot(silo: Silo, name: str) -> dict:
    silo.start(name)
    value = silo.wait_ready(name)
    silo.exec(name, "test", "-f", "/etc/proof", user="root")
    endpoint = silo.ws.run_root / "machines" / value["id"] / "vsock.sock"
    assert endpoint.is_socket(), "ready child did not receive its own transport namespace"
    endpoint_stat = endpoint.stat()
    silo.ws.record("stopped-endpoint-identity", json.dumps({"machine": value["id"], "run": value["run_id"], "path": str(endpoint), "device": endpoint_stat.st_dev, "inode": endpoint_stat.st_ino, "networkIntent": "none"}) + "\n")
    return value


def durable(silo: Silo, name: str, path: str) -> None:
    silo.exec(name, overlay.PROBE, "durable", path, user="root")


def assert_guest_copy(silo: Silo, name: str, *, absent: str) -> None:
    # Keep the same reads and absence check, but pay for one CLI/agent session.
    # The marker preserves the exact cat bytes, including its final newline.
    observed = silo.exec(name, "sh", "-eu", "-c", """
cat /stopped-common
printf '%s\\n' SILO_STOPPED_COMMON_END
test ! -e "$1"
stat -c '%i %h' /stopped-hard-a /stopped-hard-b
stat -c '%i %h' /stopped-hard-b
""", "stopped-copy", absent, user="root").stdout
    common, links = observed.split("SILO_STOPPED_COMMON_END\n", 1)
    assert common == "committed\n"
    identities = links.splitlines()
    assert len(identities) == 3, identities
    assert identities[0] == identities[2].strip()


@pytest.mark.parametrize("profile", ["raw", "flat"])
@pytest.mark.parametrize("dirty", [False, True], ids=["clean", "dirty-replay"])
def test_stopped_two_child_fork_independent_replay(stopped_silo: Silo, stopped_image: str, profile: str, dirty: bool) -> None:
    silo = stopped_silo
    source, first, second = "fork-source", "fork-first", "fork-second"
    create(silo, stopped_image, source, profile)
    original_run = boot(silo, source)["run_id"]
    silo.exec(source, "sh", "-eu", "-c", """
"$1" durable /stopped-common
printf hardlink >/stopped-hard-a
ln /stopped-hard-a /stopped-hard-b
printf 'stopped-guest-identity\\n' >/etc/machine-id
sync
""", "stopped-source", overlay.PROBE, user="root")
    lower = overlay.records(overlay.machine_dir(silo, source) / "lower.vmdk")[0].path if profile == "flat" else None
    lower_before = overlay.digest(lower) if lower is not None else None
    if dirty:
        bound, lease = shutdown.holder(silo, source)
        processes = {entry["role"]: shutdown.Process(entry["pid"]) for entry in bound["holders"]}
        writer = silo.popen("exec", source, "--user", "root", "--", overlay.PROBE, "write-loop", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            assert writer.stdout is not None
            with selectors.DefaultSelector() as ready:
                ready.register(writer.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), "actual dirty writer made no fsync progress"
                assert writer.stdout.readline().strip() == b"SILO_DIRTY_WRITER_STARTED"
            processes["krun-worker"].send(signal.SIGKILL)
            for process in processes.values():
                process.wait()
            shutdown.exit_record(silo, source, bound["runId"])
            assert not shutdown.lease_busy(lease)
            # Reconcile only, never replay/mount/fsck the captured source.
            silo.stop(source, timeout="45s")
            assert shutdown.outcome(silo, source) in {"forced", "unknown"}
        finally:
            if writer.poll() is None:
                writer.kill()
            writer.wait(timeout=10)
            if writer.stdout is not None:
                writer.stdout.close()
            for process in processes.values():
                process.close()
    else:
        stopped.stop(silo, source)
    baseline = stopped.backing(silo, source, "before-fork")
    root = stopped.writable_paths(silo, source)["root"]
    filesystem = overlay.ext4(root)
    assert bool(filesystem["incompat"] & 4) == dirty
    stopped.fork(silo, source, first)
    stopped.fork(silo, source, second)
    a = stopped.backing(silo, first, "first-before-boot")
    b = stopped.backing(silo, second, "second-before-boot")
    stopped.same_content(baseline, a)
    stopped.same_content(baseline, b)
    stopped.independent(baseline, a, b)
    for child in (first, second):
        assert overlay.ext4(stopped.writable_paths(silo, child)["root"])["uuid"] == filesystem["uuid"]
    run_a = boot(silo, first)["run_id"]
    assert_guest_copy(silo, first, absent="/second-only")
    assert silo.exec(first, "cat", "/etc/machine-id", user="root").stdout == "stopped-guest-identity\n"
    durable(silo, first, "/first-only")
    stopped.stop(silo, first)
    a_after = stopped.backing(silo, first, "first-after-write-replay")
    stopped.same_content(baseline, stopped.backing(silo, source, "source-after-first"))
    stopped.same_content(b, stopped.backing(silo, second, "second-still-unreplayed"))
    run_b = boot(silo, second)["run_id"]
    assert_guest_copy(silo, second, absent="/first-only")
    durable(silo, second, "/second-only")
    stopped.stop(silo, second)
    stopped.same_content(a_after, stopped.backing(silo, first, "first-after-second"))
    stopped.same_content(baseline, stopped.backing(silo, source, "source-after-both"))
    assert len({original_run, run_a, run_b}) == 3
    assert len({silo.machine_id(name) for name in (source, first, second)}) == 3
    if lower is not None:
        assert overlay.digest(lower) == lower_before
        assert stopped.record(silo, first)["root"]["lower"] == stopped.record(silo, source)["root"]["lower"]
    boot(silo, source)
    assert_guest_copy(silo, source, absent="/first-only")
    silo.exec(source, "test", "!", "-e", "/second-only", user="root")
    stopped.stop(silo, source)


def test_stopped_flat_snapshot_and_explicit_live_refuse_before_effects(stopped_silo: Silo, stopped_image: str) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "refuse-flat", "flat")
    stopped.refuse_without_effects(silo, "snapshot", "create", "refuse-flat", "--name", "never-published")
    for args in [("fork", "refuse-flat", "--live", "--name", "never-live-child"), ("snapshot", "create", "refuse-flat", "--live"), ("restore", str(silo.ws.root / "absent-execution-artifact"), "--execution", "--name", "never-execution-child")]:
        stopped.refuse_without_effects(silo, *args)
    assert [item["name"] for item in silo.ls()] == ["refuse-flat"]


@pytest.mark.parametrize("profile", ["raw", "flat"])
@pytest.mark.slow
def test_stopped_orphan_worker_fences_fork_and_snapshot(stopped_silo: Silo, stopped_image: str, profile: str) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "orphan-source", profile)
    with shutdown.subreaper():
        boot(silo, "orphan-source")
        durable(silo, "orphan-source", "/stopped-common")
        bound, lease = shutdown.holder(silo, "orphan-source")
        pids = {entry["role"]: entry["pid"] for entry in bound["holders"]}
        monitor, worker = shutdown.Process(pids["monitor"]), shutdown.Process(pids["krun-worker"])
        with shutdown.owned_processes(monitor, worker):
            held = stopped.writable_paths(silo, "orphan-source")["root"]
            worker.send(signal.SIGSTOP)
            shutdown.until(worker.stopped, description="whole actual orphan worker not stopped")
            monitor.send(signal.SIGKILL)
            monitor.reap()
            baseline = stopped.read_bytes(held)
            assert shutdown.lease_busy(lease)
            shutdown.handles(silo, worker.pid, [lease, held])
            # A refusal is not permission to persist the observation that the
            # monitor died: the still-live worker owns this exact generation.
            source_state = procs.machine_state_json(silo.ws, "orphan-source")
            assert source_state["status"] == "running"
            assert source_state["runId"] == bound["runId"]
            assert source_state["vmmonPid"] == monitor.pid
            assert source_state["lastError"] is None
            for args in [("set", "orphan-source", "disk=1gib"), ("rm", "orphan-source", "--force"), ("fork", "orphan-source", "--name", "fenced-child"), ("snapshot", "create", "orphan-source", "--name", "fenced-snapshot"), ("start", "orphan-source")]:
                stopped.refuse_without_effects(silo, *args)
                assert procs.machine_state_json(silo.ws, "orphan-source") == source_state
                assert worker.stopped()
                assert shutdown.lease_busy(lease)
                current = stopped.read_bytes(held)
                assert (current.device, current.inode, current.mode, current.content()) == (baseline.device, baseline.inode, baseline.mode, baseline.content())
            shutdown.storage_tool(silo, "remove-image", stopped_image)
            shutdown.storage_tool(silo, "prune")
            current = stopped.read_bytes(held)
            assert (current.device, current.inode, current.mode, current.content()) == (baseline.device, baseline.inode, baseline.mode, baseline.content())
            assert shutdown.lease_busy(lease)
            worker.send(signal.SIGCONT)
            worker.reap(code=125)
            assert not shutdown.lease_busy(lease)
            silo.stop("orphan-source", timeout="45s")
            stopped.fork(silo, "orphan-source", "after-orphan")
            stopped.same_content({"root": baseline}, stopped.backing(silo, "after-orphan", "orphan-terminal-fork"))


@pytest.mark.slow
def test_stopped_host_ext4_fork_requires_actual_mount(stopped_silo: Silo, stopped_image: str) -> None:
    """An ext4 image on Btrfs/tmpfs is not this host-mounted fallback lane."""
    assert os.environ.get("SILO_SMOKE_STOPPED_DIR"), "pending ext4 gate: provide the owner-mounted SILO_SMOKE_STOPPED_DIR, never /boot"
    assert os.environ.get("SILO_SMOKE_STOPPED_FS") == "ext4"
    create(stopped_silo, stopped_image, "ext4-source", "raw")
    stopped.mount_evidence(stopped_silo, "ext4")
    before = stopped.backing(stopped_silo, "ext4-source", "ext4-source")
    stopped.fork(stopped_silo, "ext4-source", "ext4-child")
    child = stopped.backing(stopped_silo, "ext4-child", "ext4-child")
    stopped.same_content(before, child)
    stopped.independent(before, child)


@pytest.mark.parametrize("custom_boot", [False, True], ids=["runtime-boot", "source-private-boot"])
def test_stopped_snapshot_full_config_managed_data_exact_boot(stopped_silo: Silo, stopped_image: str, custom_boot: bool) -> None:
    silo = stopped_silo
    private_runtime = silo.ws.root / "private-runtime"
    shutil.copytree(silo.ws.config.runtime_dir, private_runtime)
    silo.ws.config = replace(silo.ws.config, runtime_dir=private_runtime)
    userdata = silo.ws.root / "userdata"
    userdata.write_text("#!/bin/sh\nprintf 'captured-host\\n' >/etc/hostname\n")
    create(silo, stopped_image, "snapshot-source", "raw", "--kernel-arg", "silo.capture_config=exact", "--userdata", str(userdata), "--label", "owner=stopped-gate")
    expected_boot = stopped.install_managed_fixture(silo, "snapshot-source", custom_boot=custom_boot)
    if not custom_boot:
        expected_boot = {role: overlay.digest(private_runtime / "assets" / component) for role, component in {"kernel": "kernel-default", "baseInitramfs": "initramfs", "agent": "agent"}.items()}
    expected_config = stopped.configured_semantics(stopped.configuration(silo, "snapshot-source"))
    boot(silo, "snapshot-source")
    durable(silo, "snapshot-source", "/stopped-common")
    shutdown.write_raw_data(silo, "snapshot-source")
    # Managed Data is included semantic storage, unlike Phase 5's external
    # negative fixture. Preserve the actual existing shutdown classification;
    # exact capture does not upgrade a previously unsupported shape to Clean.
    stopped.stop(silo, "snapshot-source", require_clean=False)
    source = stopped.backing(silo, "snapshot-source", "before-snapshot")
    assert set(source) == {"root", "data:1"}
    captured = json.loads(silo.run("snapshot", "create", "snapshot-source", "--name", "stopped-checkpoint", timeout=240).stdout)
    assert captured["retained"] is True and "stopped-checkpoint" in captured["aliases"]
    captured_rows = procs.query(silo.ws.state_db(), f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{captured['id']}'")
    assert len(captured_rows) == 1
    captured_record = json.loads(captured_rows[0][0])
    assert captured_record["captureKind"] == "stopped-storage"
    assert captured_record["stopOutcome"] == shutdown.outcome(silo, "snapshot-source")
    assert captured_record["purpose"] == "checkpoint"
    immutable = "image:" + captured["id"]
    inspected = json.loads(silo.run("snapshot", "inspect", immutable).stdout)
    assert inspected == captured
    stopped.same_content(source, stopped.backing(silo, "snapshot-source", "source-after-snapshot"))
    stopped.fork(silo, "snapshot-source", "boot-pinned-fork")
    stopped.restore(silo, "image:stopped-checkpoint", "snapshot-first")
    a = stopped.backing(silo, "snapshot-first", "first-restored")
    stopped.same_content(source, a)
    stopped.independent(source, a)
    for child in ("snapshot-first", "boot-pinned-fork"):
        assert stopped.configured_semantics(stopped.configuration(silo, child)) == expected_config
        pinned = stopped.record(silo, child)["boot"]["binding"]
        assert pinned["kind"] == "pinned" and pinned["abi"] == "silo-direct-v1"
        for role, expected in expected_boot.items():
            object_path = silo.ws.silo_home / "images/objects/sha256" / pinned[role].removeprefix("sha256:")
            assert overlay.digest(object_path) == expected
    source_dir = overlay.machine_dir(silo, "snapshot-source")
    silo.rm("snapshot-source")
    assert not source_dir.exists()
    # Remove unrelated OCI retention and collect before restoring the sibling.
    # The artifact and committed child must keep precisely their own closure.
    shutdown.storage_tool(silo, "remove-image", stopped_image)
    shutdown.storage_tool(silo, "prune")
    for component in ("kernel-default", "initramfs", "agent"):
        target = private_runtime / "assets" / component
        target.unlink()
        target.write_bytes(b"not-the-captured-boot-bytes\n")
        target.chmod(0o755 if component == "agent" else 0o644)
    stopped.restore(silo, immutable, "snapshot-second")
    b = stopped.backing(silo, "snapshot-second", "second-restored-after-source-deletion")
    stopped.same_content(a, b)
    stopped.independent(a, b)
    assert stopped.configured_semantics(stopped.configuration(silo, "snapshot-second")) == expected_config
    # Alias deletion and explicit retention release are different root changes.
    silo.run("image", "remove", "image:stopped-checkpoint")
    assert json.loads(silo.run("snapshot", "inspect", immutable).stdout)["retained"] is True
    silo.run("snapshot", "remove", immutable)
    shutdown.storage_tool(silo, "prune")
    first_after = None
    for child in ("snapshot-first", "snapshot-second", "boot-pinned-fork"):
        boot(silo, child)
        observed = silo.exec(child, "sh", "-eu", "-c", """
cat /stopped-common
printf '%s\\n' SILO_STOPPED_COMMON_END
cat /proc/cmdline
""", user="root").stdout
        common, cmdline = observed.split("SILO_STOPPED_COMMON_END\n", 1)
        assert common == "committed\n"
        assert "silo.capture_config=exact" in cmdline
        # The real worker must own the destination Data inode, never a path
        # retained from the deleted source's VmSpec.
        disk = stopped.writable_paths(silo, child)["data:1"]
        shutdown.handles(silo, overlay.worker_pid(silo, child), [disk])
        silo.exec(child, "sh", "-eu", "-c", 'device=""; for p in /sys/block/*; do if test "$(cat "$p/serial" 2>/dev/null)" = silo-data-0; then device=/dev/${p##*/}; fi; done; test -n "$device"; test "$(dd if="$device" bs=1 count=20 2>/dev/null)" = raw-data-before-stop; printf child-data | dd of="$device" bs=512 count=1 conv=sync,notrunc; sync', user="root")
        stopped.stop(silo, child, require_clean=False)
        if child == "snapshot-first":
            first_after = stopped.backing(silo, child, "first-data-mutated")
            stopped.same_content(b, stopped.backing(silo, "snapshot-second", "second-data-not-mutated"))
        elif first_after is not None:
            stopped.same_content(first_after, stopped.backing(silo, "snapshot-first", "first-unchanged-after-sibling"))


@pytest.mark.slow
def test_stopped_restore_retains_closure_during_concurrent_snapshot_removal(stopped_silo: Silo, stopped_image: str) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "retention-source", "raw")
    stopped.install_managed_fixture(silo, "retention-source", custom_boot=False)
    baseline = stopped.backing(silo, "retention-source", "retention-before")
    info = json.loads(silo.run("snapshot", "create", "retention-source", "--name", "retention-race", timeout=240).stdout)
    reference = "image:" + info["id"]
    rows = procs.query(silo.ws.state_db(), f"SELECT CAST(record_bytes AS TEXT) FROM storage_snapshot WHERE id='{info['id']}'")
    assert len(rows) == 1
    artifact = json.loads(rows[0][0])
    root_stream = artifact["root"]["stream"]["stream"]
    target = silo.ws.silo_home / "images/streams/sha256" / root_stream.removeprefix("sha256:")
    closure = [silo.ws.silo_home / "images/streams/sha256" / row[0].removeprefix("sha256:") for row in procs.query(silo.ws.state_db(), f"SELECT stream_id FROM snapshot_stream_dependency WHERE snapshot_id='{info['id']}'")]
    closure += [silo.ws.silo_home / "images/objects/sha256" / row[0].removeprefix("sha256:") for row in procs.query(silo.ws.state_db(), f"SELECT object_digest FROM snapshot_object_dependency WHERE snapshot_id='{info['id']}'")]
    expected = {path: (path.stat().st_size, overlay.digest(path)) for path in closure}
    silo.rm("retention-source")
    command = [str(silo.ws.config.silo), "restore", reference, "--name", "retention-child"]
    with stopped.syscall_boundary(silo, command, target, "source-read"):
        operations = procs.query(silo.ws.state_db(), "SELECT operation_id FROM storage_operation WHERE kind='import' AND state IN ('prepared','staging')")
        assert len(operations) == 1, "restore opened artifact bytes before registering its consumer"
        lease = silo.ws.silo_home / "images/locks/leases" / (operations[0][0] + ".lease")
        assert shutdown.lease_busy(lease)
        silo.run("image", "remove", "image:retention-race")
        silo.run("snapshot", "remove", reference)
        shutdown.storage_tool(silo, "remove-image", stopped_image)
        shutdown.storage_tool(silo, "prune")
        assert procs.query(silo.ws.state_db(), f"SELECT id FROM storage_snapshot WHERE id='{info['id']}'") == []
        assert {path: (path.stat().st_size, overlay.digest(path)) for path in closure} == expected
        assert shutdown.lease_busy(lease)
        assert not any(item["name"] == "retention-child" for item in silo.ls())
    silo.ws.register_machine("retention-child")
    stopped.same_content(baseline, stopped.backing(silo, "retention-child", "retention-after-publication"))
    shutdown.storage_tool(silo, "prune")
    boot(silo, "retention-child")
    disk = stopped.writable_paths(silo, "retention-child")["data:1"]
    shutdown.handles(silo, overlay.worker_pid(silo, "retention-child"), [disk])
    stopped.stop(silo, "retention-child", require_clean=False)


@pytest.mark.slow
def test_stopped_fork_cancelled_waiter_keeps_actual_worker_locks(stopped_silo: Silo, stopped_image: str) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "cancel-source", "raw")
    baseline = stopped.backing(silo, "cancel-source", "cancel-before")
    config = stopped.configuration(silo, "cancel-source")
    lock = silo.ws.run_root / "locks" / str(config["lockId"])
    binary = silo.ws.config.bin_dir / "examples/storage_acceptance"
    if not binary.is_file():
        binary = REPO / "target/debug/examples/storage_acceptance"
    assert binary.is_file(), "Main must build cargo build -p libvm --example storage_acceptance"
    fifo = silo.ws.root / "cancel-input"
    os.mkfifo(fifo, 0o600)
    input_fd = os.open(fifo, os.O_RDWR | os.O_CLOEXEC)
    try:
        command = [str(binary), "fork-cancellable", "cancel-source", "cancel-child"]
        with stopped.syscall_boundary(silo, command, stopped.writable_paths(silo, "cancel-source")["root"], "source-sync", stdin=fifo):
            os.write(input_fd, b"cancel\n")
            log = silo.ws.evidence / "boundary-command.log"
            shutdown.until(lambda: "SILO_STOPPED_WAITER_CANCELLED" in log.read_text(), description="async waiter did not cancel while actual worker was stopped")
            operation = procs.query(silo.ws.state_db(), "SELECT operation_id FROM storage_operation WHERE kind='fork'")
            assert len(operation) == 1
            lease = silo.ws.silo_home / "images/locks/leases" / (operation[0][0] + ".lease")
            assert shutdown.lease_busy(lease)
            lifecycle = os.open(lock, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(lifecycle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(lifecycle)
            shutdown.storage_tool(silo, "prune")
            assert shutdown.lease_busy(lease)
            stopped.same_content(baseline, stopped.backing(silo, "cancel-source", "cancel-while-worker-held"))
            assert not any(item["name"] == "cancel-child" for item in silo.ls())
            # Release the syscall first, keeping the async runtime alive until
            # its real worker has atomically published/committed the operation.
            (silo.ws.evidence / "boundary-release").touch()
            shutdown.until(lambda: procs.query(silo.ws.state_db(), "SELECT state FROM storage_operation WHERE kind='fork'") == [("committed",)], timeout=120, description="actual cancelled-worker ownership never committed")
            os.write(input_fd, b"finish\n")
        shutdown.storage_tool(silo, "prune")
        assert procs.query(silo.ws.state_db(), "SELECT operation_id FROM storage_operation WHERE kind='fork'") == []
        children = [item for item in silo.ls() if item["name"] == "cancel-child"]
        assert len(children) == 1, "the admitted worker must finish its complete publication, not orphan a half child"
        silo.ws.register_machine("cancel-child")
        copied = stopped.backing(silo, "cancel-child", "cancel-worker-completed")
        stopped.same_content(baseline, copied)
        stopped.independent(baseline, copied)
        stopped.same_content(baseline, stopped.backing(silo, "cancel-source", "cancel-source-after"))
    finally:
        os.close(input_fd)


@pytest.mark.parametrize("profile", ["raw", "flat"])
def test_stopped_fork_snapshot_running_generation_refuses_without_implicit_stop(stopped_silo: Silo, stopped_image: str, profile: str) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "running-source", profile)
    with shutdown.subreaper():
        boot(silo, "running-source")
        bound, lease = shutdown.holder(silo, "running-source")
        processes = [shutdown.Process(entry["pid"]) for entry in bound["holders"]]
        with shutdown.owned_processes(*processes):
            for process in processes:
                process.send(signal.SIGSTOP)
                shutdown.until(process.stopped, description="actual generation did not stop for stable no-effects oracle")
            try:
                baseline = stopped.backing(silo, "running-source", "running-refusal-before")
                for args in [("fork", "running-source", "--name", "never-running-child"), ("snapshot", "create", "running-source", "--name", "never-running-snapshot")]:
                    stopped.refuse_without_effects(silo, *args)
                assert procs.run_id(silo.ws, "running-source") == bound["runId"]
                assert shutdown.lease_busy(lease)
                assert all(not process.terminal() and process.stopped() for process in processes)
                stopped.same_content(baseline, stopped.backing(silo, "running-source", "running-refusal-after"))
            finally:
                for process in processes:
                    if not process.terminal():
                        process.send(signal.SIGCONT)
            stopped.stop(silo, "running-source")


@pytest.mark.slow
@pytest.mark.parametrize("profile", ["raw", "flat"])
@pytest.mark.parametrize(("boundary", "injected_errno"), [
    ("source-sync", errno.EIO),
    ("destination-copy", errno.EIO),
    ("destination-copy", errno.ENOSPC),
    ("destination-sync", errno.EIO),
    ("publication-rename", errno.EACCES),
    ("destination-directory-sync", errno.EIO),
])
def test_stopped_fork_real_syscall_failure_never_publishes_partial_child(stopped_silo: Silo, stopped_image: str, profile: str, boundary: str, injected_errno: int) -> None:
    silo = stopped_silo
    create(silo, stopped_image, "failure-source", profile)
    baseline = stopped.backing(silo, "failure-source", "failure-before")
    before_config = stopped.configuration(silo, "failure-source")
    before_storage = stopped.record(silo, "failure-source")
    command = [str(silo.ws.config.silo), "fork", "failure-source", "--name", "failed-child"]
    with stopped.syscall_boundary(silo, command, stopped.writable_paths(silo, "failure-source")["root"], boundary, injected_errno=injected_errno):
        assert not any(item["name"] == "failed-child" for item in silo.ls())
    receipt = json.loads((silo.ws.evidence / "boundary-injected.json").read_text())
    assert receipt["errno"] == injected_errno and receipt["injectedReturn"] is True
    assert receipt["kind"] == "injected syscall failure, not physical media/power-loss failure"
    stopped.same_content(baseline, stopped.backing(silo, "failure-source", "failure-after"))
    assert stopped.configuration(silo, "failure-source") == before_config
    assert stopped.record(silo, "failure-source") == before_storage
    assert [item["name"] for item in silo.ls()] == ["failure-source"]
    # Reconcile through the real collector. A retained operation may outlive
    # an uncertain boundary, but no partial child can become discoverable.
    shutdown.storage_tool(silo, "prune")
    assert [item["name"] for item in silo.ls()] == ["failure-source"]
    stopped.fork(silo, "failure-source", "retry-complete")
    retried = stopped.backing(silo, "retry-complete", "retry-complete")
    stopped.same_content(baseline, retried)
    stopped.independent(baseline, retried)
