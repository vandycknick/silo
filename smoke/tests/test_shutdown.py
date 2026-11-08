from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
import shutil
import signal
import subprocess
from uuid import UUID

import pytest

from silo_smoke import images, overlay, procs, shutdown, stopped
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.registry import LoopbackRegistry

pytestmark = pytest.mark.linux_only


@pytest.fixture(scope="session")
def image_pid1(config: SmokeConfig, registry: LoopbackRegistry) -> str:
    spec = replace(images.BASIC, name="shutdown-image-pid1", remove=frozenset(),
                   files={**images.BASIC.files, "sbin/init": images.GuestFile(
                       b"#!/bin/sh\ntrap 'exit 77' USR1\nwhile :; do sleep 1; done\n", mode=0o755)})
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "shutdown-image-pid1")


def boot(silo: Silo, image: str, name: str, *flags: str) -> tuple[str, shutdown.Process, shutdown.Process, Path]:
    silo.create(name, image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock", *flags)
    silo.start(name)
    silo.wait_ready(name)
    record, lease = shutdown.holder(silo, name)
    identities = {entry["role"]: entry["pid"] for entry in record["holders"]}
    assert identities["monitor"] == procs.vmm_pid(silo.ws, name)
    assert identities["krun-worker"] == overlay.worker_pid_of_monitor(identities["monitor"])
    monitor, worker = shutdown.Process(identities["monitor"]), shutdown.Process(identities["krun-worker"])
    assert shutdown.lease_busy(lease)
    shutdown.handles(silo, monitor.pid, [lease])
    shutdown.handles(silo, worker.pid, [lease])
    return record["runId"], monitor, worker, lease


def writable_root(silo: Silo, name: str) -> Path:
    """The catalog-selected writable root: raw disk or layered upper."""
    return stopped.writable_paths(silo, name)["root"]


@pytest.mark.slow
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_shutdown_cli_clean_independent_facts(silo: Silo, basic_image: str, profile: RootProfile) -> None:
    """Concurrent-writer positive gate through CLI/libvm, never a guest shortcut."""
    name = "shutdown-clean"
    with shutdown.subreaper():
        run, monitor, worker, lease = boot(silo, silo.root_image(basic_image, profile), name)
        with shutdown.owned_processes(monitor, worker):
            root = writable_root(silo, name)
            shutdown.handles(silo, monitor.pid, [root])
            shutdown.handles(silo, worker.pid, [root])
            silo.exec(name, "sh", "-c", "printf durable-before-stop >/shutdown-persist; sync", user="root")
            writers = [silo.popen("exec", name, "--user", "root", "--", "sh", "-c", f"while :; do echo running >>/shutdown-writer-{index}; sleep 0.05; done", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for index in range(2)]
            try:
                shutdown.until(lambda: all(silo.exec(name, "test", "-s", f"/shutdown-writer-{index}", user="root", expect=None).returncode == 0 for index in range(2)), description="guest writers did not independently publish data")
                shutdown.until(lambda: all(writer.poll() is None for writer in writers), description="writer exited before shutdown")
                silo.stop(name, timeout="45s")
                terminal = shutdown.exit_record(silo, name, run)
                worker.wait()
                monitor.wait()
                assert not shutdown.lease_busy(lease)
                shutdown.assert_clean(silo, name, terminal)
                assert overlay.ext4(root)["incompat"] & 4 == 0, "ext4 still requires recovery after certified shutdown"
            finally:
                for writer in writers:
                    if writer.poll() is None:
                        writer.terminate()
                    try:
                        writer.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        writer.kill()
                        writer.wait(timeout=5)
    silo.start(name)
    silo.wait_ready(name)
    assert silo.exec(name, "cat", "/shutdown-persist", user="root").stdout == "durable-before-stop"
    for index in range(2):
        silo.exec(name, "test", "-s", f"/shutdown-writer-{index}", user="root")
    silo.stop(name, timeout="45s")


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["clean-layered", "forced", "worker-crash", "guest-panic", "external-data", "writable-share", "image-pid1"])
def test_shutdown_real_outcome_and_unsupported_matrix(silo: Silo, basic_image: str, image_pid1: str, mode: str) -> None:
    name = "shutdown-" + mode
    flags = []
    external = silo.ws.root / "external-data.raw"
    share = silo.ws.root / "external-share"
    if mode == "external-data":
        with external.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        external_before = overlay.digest(external)
        flags += ["--disk", str(external)]
    if mode == "writable-share":
        share.mkdir()
        (share / "host-owned").write_text("external owner")
        flags += ["--mount", f"{share}:/external:rw"]
    with shutdown.subreaper():
        run, monitor, worker, lease = boot(silo, image_pid1 if mode in {"image-pid1", "guest-panic"} else basic_image, name, *flags)
        with shutdown.owned_processes(monitor, worker):
            if mode in {"image-pid1", "guest-panic"}:
                boot_report = silo.info(name)["guest"]["boot"]
                assert boot_report["agent_is_pid1"] is False and boot_report["agent_pid"] > 1
            silo.exec(name, "sh", "-c", "echo durable >/shutdown-matrix; sync", user="root")
            if mode == "guest-panic":
                # This is a real image-owned PID1 panic, not an agent-PID1
                # crash or a worker-kill substitute. Linux panics on init exit.
                def installed_panic_trap() -> dict | None:
                    status = silo.exec(name, "cat", "/proc/1/status", user="root", timeout=5).stdout
                    command = silo.exec(name, "cat", "/proc/1/cmdline", user="root", timeout=5).stdout
                    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                    captured = {"runId": run, "boot": boot_report, "pid1Status": status, "pid1Command": command}
                    silo.ws.record("shutdown-panic-prerequisites", json.dumps(captured) + "\n")
                    assert fields["Pid"].strip() == "1" and fields["Tgid"].strip() == "1"
                    caught = int(fields["SigCgt"].strip(), 16)
                    return captured if "/sbin/init" in command.split("\0") and caught & (1 << (int(signal.SIGUSR1) - 1)) else None
                shutdown.until(installed_panic_trap, timeout=15, description="controlled image PID1 did not install its required USR1 trap; see shutdown-panic-prerequisites.log")
                serial = silo.ws.silo_home / "logs/machines" / silo.machine_id(name) / "serial.log"
                offset = serial.stat().st_size
                # USR1 is explicitly handled by the controlled init script;
                # its exit77 must drive the kernel's real init-death panic.
                with (silo.ws.evidence / "guest-panic-trigger.stdout").open("wb") as stdout, (silo.ws.evidence / "guest-panic-trigger.stderr").open("wb") as stderr:
                    crash = silo.popen("exec", name, "--user", "root", "--", "sh", "-eu", "-c", "kill -USR1 1", stdout=stdout, stderr=stderr)
                    try:
                        def actual_panic() -> str | None:
                            tail = serial.read_bytes()[offset:].decode(errors="replace")
                            return tail if "Kernel panic - not syncing:" in tail and "Attempted to kill init! exitcode=0x00004d00" in tail else None
                        panic = shutdown.until(actual_panic, description="no actual image-PID1 exit77 kernel panic observed; see guest-panic-trigger.stderr")
                        silo.ws.record("shutdown-guest-panic", json.dumps({"runId": run, "serialOffset": offset, "bootRole": "image-owned-pid1", "triggerSignal": "SIGUSR1", "expectedInitExitCode": 77}) + "\n" + panic)
                    finally:
                        if crash.poll() is None:
                            crash.terminate()
                        try:
                            crash.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            crash.kill()
                            crash.wait(timeout=5)
                        silo.ws.record("shutdown-panic-trigger-result", json.dumps({"returncode": crash.returncode}) + "\n")
            if mode == "worker-crash":
                worker.send(signal.SIGKILL)
                worker.wait()
                monitor.wait()
                persisted = shutdown.outcome(silo, name)
                machine_id = silo.machine_id(name)
                operation_query = f"SELECT operation_id FROM storage_operation WHERE replace(machine_id,'-','')='{UUID(machine_id).hex}' AND replace(run_id,'-','')='{UUID(run).hex}'"
                retained_operations = procs.query(silo.ws.state_db(), operation_query)
                assert len(retained_operations) == 1, "terminal launch lost its pins before lifecycle reconciliation"
                observed = silo.info(name)
                assert observed["storage_stop_outcome"] == "forced"
                assert shutdown.outcome(silo, name) == persisted, "read-only info changed durable storage state"
                assert procs.query(silo.ws.state_db(), operation_query) == retained_operations
                # A public lifecycle command, not observation, commits the
                # exact-run terminal result and retires the launch operation.
                silo.stop(name, timeout="45s")
                assert procs.query(silo.ws.state_db(), operation_query) == [], "CLI stop did not retire the terminal launch operation"
            elif mode == "guest-panic":
                # Panic may already have terminated native execution; otherwise
                # bounded stop escalates the real unresponsive guest.
                silo.run("stop", name, "--timeout", "75s", expect=None, timeout=120)
            else:
                silo.stop(name, timeout="45s", force=mode == "forced")
            terminal = shutdown.exit_record(silo, name, run)
            worker.wait()
            monitor.wait()
            assert not shutdown.lease_busy(lease)
            if mode == "clean-layered":
                shutdown.assert_clean(silo, name, terminal)
                assert stopped.record(silo, name)["root"]["kind"] == "linux-overlay"
                assert overlay.ext4(overlay.upper(silo, name))["incompat"] & 4 == 0
            else:
                facts = terminal.get("storageShutdown")
                assert shutdown.outcome(silo, name) != "clean"
                if mode in {"forced", "worker-crash", "guest-panic"}:
                    assert shutdown.outcome(silo, name) == "forced"
                if mode == "forced":
                    assert terminal["outcome"] == "forced"
                    # The manager can publish a forced run fence after killing
                    # the monitor. It cannot invent the monitor's finalizer
                    # facts, even after the controller observes terminality.
                    if facts is not None:
                        assert facts["version"] == 1
                        assert facts["guestProtocolCompleted"] is False
                        assert facts["hostFlushCompleted"] is False
                else:
                    assert facts is not None, "surviving monitor omitted its completed storage finalization evidence"
                    assert facts["attachmentsClosed"] is True
                if mode in {"external-data", "writable-share", "image-pid1"}:
                    assert facts["guestProtocolCompleted"] is False
                    assert facts["hostFlushCompleted"] is False
    silo.rm(name)
    if mode == "external-data":
        assert external.is_file() and overlay.digest(external) == external_before
    if mode == "writable-share":
        assert (share / "host-owned").read_text() == "external owner"


@pytest.mark.slow
def test_shutdown_actual_stopped_worker_pins_gc_and_reuse(silo: Silo, basic_image: str) -> None:
    name = "shutdown-orphan"
    with shutdown.subreaper():
        run, monitor, worker, lease = boot(silo, basic_image, name)
        with shutdown.owned_processes(monitor, worker):
            machine_id = silo.machine_id(name)
            held = overlay.upper(silo, name)
            inode = held.stat().st_ino
            descriptor = overlay.machine_dir(silo, name) / "lower.vmdk"
            lower_digests = overlay.lower_digests(descriptor)
            lower = sorted(lower_digests)
            shutdown.handles(silo, worker.pid, [lease, held, *lower])
            worker.send(signal.SIGSTOP)  # entire actual process, including watchdog
            shutdown.until(worker.stopped, description="not every actual worker thread/watchdog is stopped")
            monitor.send(signal.SIGKILL)  # ONLY monitor, no group/name/CLI force stop
            monitor.reap()
            assert not worker.terminal() and worker.stopped()
            assert shutdown.lease_busy(lease), "surviving worker dropped its inherited OFD"
            shutdown.storage_tool(silo, "remove-image", basic_image)
            shutdown.storage_tool(silo, "prune")
            assert overlay.lower_digests(descriptor) == lower_digests
            operations = procs.query(silo.ws.state_db(), f"SELECT operation_id FROM storage_operation WHERE machine_id='{machine_id}' AND replace(run_id,'-','')='{UUID(run).hex}'")
            assert operations, "collector retired live worker operation"
            for args in [("start", name), ("rm", name, "--force"), ("set", name, "disk=256mib")]:
                result = silo.run(*args, expect=None, timeout=30)
                assert result.returncode != 0, (args, result.stdout, result.stderr)
                assert held.stat().st_ino == inode and shutdown.lease_busy(lease)
            silo.ws.record("shutdown-orphan-retention", json.dumps({"runId": run, "workerPid": worker.pid, "startTicks": worker.start_ticks, "taskStates": worker.task_states(), "leaseBusy": True, "operations": operations, "upperInode": inode, "lowerSha256": {str(path): digest for path, digest in lower_digests.items()}}) + "\n")
            worker.send(signal.SIGCONT)
            worker.reap(code=125)  # unchanged production watchdog, actual wait status
            assert not shutdown.lease_busy(lease)
            silo.rm(name, force=True)
            shutdown.storage_tool(silo, "prune")
            assert not held.exists() and not any(path.exists() for path in lower), "otherwise-unreachable closure not collected"


@pytest.mark.slow
@pytest.mark.parametrize("profile", ["raw", "layered", "external-data"])
def test_shutdown_retained_inode_survives_original_path_replacement(silo: Silo, basic_image: str, profile: str) -> None:
    name = "shutdown-path-race"
    flags = []
    data = silo.ws.root / "external-data.raw"
    if profile == "external-data":
        with data.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        flags += ["--disk", str(data)]
    with shutdown.subreaper():
        run, monitor, worker, lease = boot(silo, silo.raw_image(basic_image) if profile == "raw" else basic_image, name, *flags)
        with shutdown.owned_processes(monitor, worker):
            original = data if profile == "external-data" else writable_root(silo, name)
            pinned = original.with_name("pinned-original.raw")
            original.rename(pinned)
            try:
                shutil.copyfile(pinned, original)
                replacement = overlay.digest(original)
                metadata = pinned.stat()
                shutdown.handles(silo, monitor.pid, [pinned])
                shutdown.handles(silo, worker.pid, [pinned])
                if profile == "external-data":
                    shutdown.write_raw_data(silo, name)
                else:
                    silo.exec(name, "sh", "-c", "echo only-pinned-inode >/shutdown-path-proof; sync", user="root")
                silo.stop(name, timeout="45s")
                terminal = shutdown.exit_record(silo, name, run)
                worker.wait()
                monitor.wait()
                if profile == "external-data":
                    assert shutdown.outcome(silo, name) != "clean"
                    with pinned.open("rb") as stream:
                        assert stream.read(21) == b"raw-data-before-stop\n"
                else:
                    shutdown.assert_clean(silo, name, terminal)
                assert overlay.digest(original) == replacement, "native reopened replacement pathname"
                assert pinned.stat().st_ino == metadata.st_ino
                if profile != "external-data":
                    assert overlay.ext4(pinned)["incompat"] & 4 == 0
            finally:
                if not worker.terminal():
                    worker.send(signal.SIGKILL)
                    worker.wait()
                if not monitor.terminal():
                    monitor.send(signal.SIGTERM)
                    monitor.wait()
                # Do not leave a misleading replacement as the managed generation.
                os.replace(pinned, original)
    if profile != "external-data":
        silo.start(name)
        silo.wait_ready(name)
        assert silo.exec(name, "cat", "/shutdown-path-proof", user="root").stdout == "only-pinned-inode\n"
        silo.stop(name, timeout="45s")

@pytest.mark.slow
@pytest.mark.parametrize("inject_eio", [False, True], ids=["unmodified-success", "injected-syscall-eio"])
@pytest.mark.parametrize("profile", ["raw", "layered", "external-data"])
def test_shutdown_real_retained_host_fsync(silo: Silo, basic_image: str, inject_eio: bool, profile: str) -> None:
    """Observe the actual successful sync, or inject EIO at that exact syscall."""
    import platform
    import sys

    from silo_smoke.config import REPO

    assert platform.machine() == "x86_64", "native injected-EIO lane is qualified only on Linux x86_64"
    name = "shutdown-host-fsync"
    flags = []
    data = silo.ws.root / "unmounted-external-data.raw"
    if profile == "external-data":
        with data.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        flags += ["--disk", str(data)]
    silo.create(name, silo.raw_image(basic_image) if profile == "raw" else basic_image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock", *flags)
    machine_id = silo.machine_id(name)
    root = writable_root(silo, name)
    # The external-Data fault must exercise a non-root backing, not repeat root EIO.
    backings = [data, root] if profile == "external-data" else [root]
    expected = [{"path": str(path), "device": path.stat().st_dev, "inode": path.stat().st_ino} for path in backings]
    request = silo.ws.evidence / "retained-fsync-request.json"
    request.write_text(json.dumps({
        "silo": str(silo.ws.config.silo), "name": name,
        "backings": expected,
        "holder": str(silo.ws.run_root / "machines" / machine_id / "vm.storage-holder.json"),
        "closeTargets": str(silo.ws.evidence / "retained-close-targets.json"),
        "evidence": str(silo.ws.evidence),
        "injectEio": inject_eio,
    }))
    with (silo.ws.evidence / "retained-fsync-tracer.log").open("wb") as output:
        tracer = subprocess.Popen([sys.executable, "-m", "silo_smoke.shutdown_trace", str(request)], env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")), stdout=output, stderr=subprocess.STDOUT)
        try:
            silo.wait_ready(name)
            holder, lease = shutdown.holder(silo, name)
            # The descriptor is generated during launch. Bind the actual
            # ready monitor's retained FDs, never a predicted pathname inode.
            disks = silo.info(name)["spec"]["storage"]["disks"]
            paths = []
            for disk in disks:
                path = Path(disk["path"])
                paths.append(path if path.is_absolute() else overlay.machine_dir(silo, name) / path)
            retained = shutdown.handles(silo, next(entry["pid"] for entry in holder["holders"] if entry["role"] == "monitor"), paths)
            targets = []
            for disk, path in zip(disks, paths, strict=True):
                descriptors = retained[str(path)]
                assert len(descriptors) == 1, f"ambiguous retained monitor attachment FD: {path}: {descriptors}"
                metadata = path.stat()
                targets.append({"path": str(path), "fd": descriptors[0], "device": metadata.st_dev,
                                "inode": metadata.st_ino, "readOnly": disk["readOnly"], "format": disk["format"]})
            publication = silo.ws.evidence / "retained-close-targets.new"
            publication.write_text(json.dumps({"machineId": holder["machineId"], "runId": holder["runId"],
                                              "monitorPid": next(entry["pid"] for entry in holder["holders"] if entry["role"] == "monitor"),
                                              "workerPid": next(entry["pid"] for entry in holder["holders"] if entry["role"] == "krun-worker"),
                                              "attachments": targets}))
            os.replace(publication, silo.ws.evidence / "retained-close-targets.json")
            shutdown.until(lambda: (silo.ws.evidence / "retained-close-targets-accepted.json").is_file(),
                           description="tracer did not bind every ready retained attachment")
            silo.exec(name, "sh", "-c", "echo real-dirty-data >/shutdown-eio; sync", user="root")
            if profile == "external-data":
                shutdown.write_raw_data(silo, name)
            stopped = silo.run("stop", name, "--timeout", "45s", expect=None, timeout=90)
            silo.ws.record("shutdown-fsync-stop-result", f"exit={stopped.returncode}\n{stopped.stdout}{stopped.stderr}")
            assert tracer.wait(timeout=120) == 0, "see retained-fsync-tracer.log"
            receipt = json.loads((silo.ws.evidence / "retained-fsync-receipt.json").read_text())["attachments"]
            observed = {item["fd"]: item for item in receipt}
            assert set(observed) == {item["fd"] for item in targets}
            fault_identity = (expected[0]["device"], expected[0]["inode"])
            for item in targets:
                actual = observed[item["fd"]]
                identity = (item["device"], item["inode"])
                assert (actual["device"], actual["inode"]) == identity
                if not item["readOnly"]:
                    assert item["format"] == "raw"
                    assert actual["return"] == (-5 if inject_eio and identity == fault_identity else 0)
                else:
                    assert "return" not in actual, "read-only closure is not a fabricated fsync observation"
                assert actual["closeReturn"] == 0 and actual["workerState"] == "reaped"
                assert UUID(actual["runId"]) == UUID(holder["runId"])
            terminal = shutdown.exit_record(silo, name, holder["runId"])
            facts = terminal["storageShutdown"]
            assert facts["guestProtocolCompleted"] is (profile != "external-data")
            assert facts["hostFlushCompleted"] is (not inject_eio and profile != "external-data")
            assert facts["attachmentsClosed"] is True
            assert not shutdown.lease_busy(lease)
            if inject_eio:
                assert shutdown.outcome(silo, name) != "clean"
                assert terminal["error"], "actual fsync error must propagate into terminal diagnostic"
            elif profile == "external-data":
                assert shutdown.outcome(silo, name) != "clean"
            else:
                shutdown.assert_clean(silo, name, terminal)
            if profile == "external-data":
                with data.open("rb") as stream:
                    assert stream.read(21) == b"raw-data-before-stop\n"
        finally:
            if tracer.poll() is None:
                tracer.terminate()
                try:
                    tracer.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    tracer.kill()
                    tracer.wait(timeout=5)
