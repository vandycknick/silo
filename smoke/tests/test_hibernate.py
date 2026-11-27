"""ADR 0023 real-VM qualification. No synthetic saves or fault acknowledgements."""
from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import UUID

import pytest

from silo_smoke import (
    capture_multidisk,
    hibernate,
    images,
    procs,
    restore,
    shutdown,
    stopped,
    toolchain,
)
from silo_smoke import restore_lifecycle as network
from silo_smoke.cli import ROOT_PROFILES, Result, RootProfile, Silo
from silo_smoke.config import REPO, SmokeConfig
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.terminal import PtyCommand

pytestmark = [pytest.mark.krun_live, pytest.mark.slow]
NAME = "hibernate-vm"


@pytest.fixture(scope="session")
def hibernate_image(config: SmokeConfig, registry: LoopbackRegistry,
                    tmp_path_factory: pytest.TempPathFactory) -> str:
    """Existing execution witness with an image-owned, non-Silo machine id."""
    probe = {}
    if sys.platform != "darwin":
        output = tmp_path_factory.mktemp("hibernate-probe") / "restore-execution"
        subprocess.run([*toolchain.static_cc(), "-static", "-O2", "-pthread", "-Wall", "-Wextra", "-Werror",
                        "-std=c11", str(REPO / "virt/vmm/tests/guest/restore_execution.c"), "-o", str(output)],
                       capture_output=True, check=True, timeout=120)
        probe[restore.PROBE.lstrip("/")] = images.GuestFile(output.read_bytes(), mode=0o755)
    spec = replace(images.BASIC, name="hibernate", files={
        **images.BASIC.files,
        "etc/machine-id": (hibernate.IMAGE_MACHINE_ID + "\n").encode(),
        **probe,
    })
    image = images.build(spec, images.fetch_alpine(config.cache_dir))
    return registry.publish(image, "hibernate")


@pytest.mark.linux_only(reason="requires the x86_64 live-register witness")
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_process_memory_pid_boot_and_startup_survive_two_cycles(
    silo: Silo, hibernate_image: str, profile: RootProfile,
) -> None:
    """Conformance 1, repeated incremental saves, and snapshot after wake."""
    # Both native CPU/register witness threads pin themselves to guest CPU 1.
    hibernate.create(silo, hibernate_image, NAME, profile=profile, cpus=2)
    before = restore.start_witness(silo, NAME)
    boot = hibernate.boot_id(silo, NAME)
    run_id = silo.info(NAME)["run_id"]
    init = hibernate.boot_process(silo, NAME)
    for _ in range(2):
        hibernate.save(silo, NAME)
        current = hibernate.wake(silo, NAME)
        assert current != run_id
        run_id = current
        before = restore.advances(silo, NAME, before)
        assert hibernate.boot_id(silo, NAME) == boot
        assert hibernate.boot_process(silo, NAME) == init
    saved = restore.checkpoint(silo, NAME, alias="after-wake")
    assert saved.boot_id.strip() == boot
    silo.run("resume", NAME)
    restore.restore_child(silo, saved, "after-wake-child")
    restore.advances(silo, "after-wake-child", before)


def test_identity_is_preserved_including_image_machine_id(silo: Silo, hibernate_image: str) -> None:
    """Conformance 2, including an image-owned machine-id distinct from Silo's."""
    hibernate.create(silo, hibernate_image, NAME, network="private")
    before = hibernate.identity(silo, NAME)
    assert before.guest_machine_id == hibernate.IMAGE_MACHINE_ID
    assert before.guest_machine_id != UUID(before.machine_id).hex
    hibernate.save(silo, NAME)
    hibernate.wake(silo, NAME)
    assert hibernate.identity(silo, NAME) == before


def test_wall_clock_is_corrected_after_configurable_sleep(silo: Silo, basic_image: str) -> None:
    """Conformance 3 short lane. Set SILO_SMOKE_HIBERNATE_SLEEP=180 for minutes."""
    delay = float(os.environ.get("SILO_SMOKE_HIBERNATE_SLEEP", "3"))
    tolerance = float(os.environ.get("SILO_SMOKE_HIBERNATE_CLOCK_TOLERANCE", "1.5"))
    assert math.isfinite(delay) and delay > 0
    assert math.isfinite(tolerance) and tolerance > 0
    hibernate.create(silo, basic_image, NAME)
    hibernate.save(silo, NAME)
    time.sleep(delay)
    hibernate.wake(silo, NAME)
    before = time.time()
    guest = float(silo.exec(NAME, "date", "+%s").stdout)
    after = time.time()
    assert before - tolerance <= guest <= after + tolerance, (before, guest, after, delay)
    silo.ws.record("hibernate-clock", json.dumps({"sleep": delay, "tolerance": tolerance,
                                                "hostBefore": before, "guest": guest, "hostAfter": after}) + "\n")


def test_paused_hibernate_wakes_running(silo: Silo, basic_image: str) -> None:
    """Conformance 4: a borrowed user pause does not survive wake."""
    hibernate.create(silo, basic_image, NAME)
    boot = hibernate.boot_id(silo, NAME)
    silo.run("pause", NAME)
    hibernate.save(silo, NAME)
    hibernate.wake(silo, NAME)
    info = silo.info(NAME)
    assert info["state"] == "running" and info["ready"] is True
    assert info["lifecycle"]["lifecycle"]["currentPause"] is None
    assert hibernate.boot_id(silo, NAME) == boot


@pytest.mark.parametrize("force", [False, True], ids=["clean-stop", "discard"])
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_stop_hibernated_then_cold_start(silo: Silo, basic_image: str, force: bool, profile: RootProfile) -> None:
    """Conformance 5: unsynced file survives clean stop; force never wakes."""
    hibernate.create(silo, basic_image, NAME, profile=profile)
    boot = hibernate.boot_id(silo, NAME)
    silo.exec(NAME, "sh", "-ec", "printf unsynced-before-hibernate >/hibernate-unsynced", user="root")
    hibernate.save(silo, NAME)
    directory = hibernate.saved_directory(silo, NAME)
    result = silo.run("stop", NAME, *(["--force"] if force else []), "--timeout", "45s")
    assert silo.info(NAME)["state"] == "stopped"
    assert not directory.exists(), "discard/stop retained the unused save"
    if force:
        assert "Waking" not in result.stderr + result.stdout
    else:
        assert shutdown.outcome(silo, NAME) == "clean"
    silo.start(NAME)
    silo.wait_ready(NAME)
    assert hibernate.boot_id(silo, NAME) != boot
    if not force:
        assert silo.exec(NAME, "cat", "/hibernate-unsynced").stdout == "unsynced-before-hibernate"


REFUSED = (
    "snapshot", "snapshot-memory", "fork", "fork-live", "cpus", "memory", "disk", "network",
    "kernel", "boot-assets", "rename", "export", "pause", "resume",
)


@pytest.mark.parametrize("operation", REFUSED)
def test_protected_operations_leave_save_disks_and_config_unchanged(
    silo: Silo, basic_image: str, operation: str,
) -> None:
    """Conformance 6: each refusal is independently followed by a usable wake."""
    hibernate.create(silo, basic_image, NAME)
    silo.ws.register_machine("refused")
    boot = hibernate.boot_id(silo, NAME)
    hibernate.save(silo, NAME)
    before = stopped.backing(silo, NAME, "before-refusal")
    config = stopped.configuration(silo, NAME)
    machine_id = procs.machine_id(silo.ws, NAME)
    sql = f"SELECT hex(config_json) FROM machine_config WHERE id='{machine_id}'"
    config_bytes = procs.query(silo.ws.state_db(), sql)
    storage = stopped.record(silo, NAME)
    saved = {str(path): stopped.read_bytes(path) for path in hibernate.saved_files(silo, NAME)}
    output = silo.ws.evidence / "refused.raw"
    commands: dict[str, tuple[str, ...]] = {
        "snapshot": ("snapshot", "create", NAME, "--name", "refused"),
        "snapshot-memory": ("snapshot", "create", NAME, "--memory", "--name", "refused"),
        "fork": ("fork", NAME, "--name", "refused"),
        "fork-live": ("fork", NAME, "--live", "--name", "refused"),
        "cpus": ("set", NAME, "cpus=2"), "memory": ("set", NAME, "memory=1gib"),
        "disk": ("set", NAME, "disk=1gib"), "network": ("set", NAME, "network=private"),
        "kernel": ("set", NAME, "kernel-arg=hibernate.refused=1"),
        "boot-assets": ("set", NAME, "boot-assets=packaged"),
        "rename": ("set", NAME, "name=refused"),
        "export": ("storage", "export", NAME, str(output), "--disk-format", "raw", "--flatten-filesystem"),
        "pause": ("pause", NAME), "resume": ("resume", NAME),
    }
    result = silo.run(*commands[operation], expect=None)
    hint = (f"start it with `silo start {NAME}` first" if operation in {
        "snapshot", "snapshot-memory", "fork", "fork-live", "pause", "resume",
    } else f"run `silo stop {NAME}` first")
    hibernate.refused(result, f"machine `{NAME}` is hibernated; {hint}")
    assert silo.info(NAME)["state"] == "hibernated"
    assert stopped.configuration(silo, NAME) == config
    assert procs.query(silo.ws.state_db(), sql) == config_bytes
    assert stopped.record(silo, NAME) == storage
    assert stopped.backing(silo, NAME, "after-refusal") == before
    assert {str(path): stopped.read_bytes(path) for path in hibernate.saved_files(silo, NAME)} == saved
    assert not output.exists()
    hibernate.wake(silo, NAME)
    assert hibernate.boot_id(silo, NAME) == boot


@pytest.mark.parametrize("mutation", ["delete", "truncate", "replace"])
def test_every_saved_file_tamper_refuses_without_boot_then_plain_stop_discards(
    silo: Silo, basic_image: str, mutation: str,
) -> None:
    """Conformance 7: enumerate actual saved files, not a subset of file names."""
    hibernate.create(silo, basic_image, NAME)
    hibernate.save(silo, NAME)
    directory = hibernate.saved_directory(silo, NAME)
    relatives = [path.relative_to(directory) for path in hibernate.saved_files(silo, NAME)]
    hibernate.wake(silo, NAME)
    for relative in relatives:
        old_boot = hibernate.boot_id(silo, NAME)
        hibernate.save(silo, NAME)
        directory = hibernate.saved_directory(silo, NAME)
        path = directory / relative
        if mutation == "delete":
            path.unlink()
        elif mutation == "truncate":
            path.chmod(0o600)
            with path.open("r+b") as output:
                output.truncate(0)
        else:
            replacement = path.with_suffix(path.suffix + ".replacement")
            # Preserve mode and timestamps without materializing sparse guest RAM.
            copy = (["/bin/cp", "-c", "-p"] if sys.platform == "darwin" else
                    ["cp", "--sparse=always", "--preserve=mode,timestamps"])
            subprocess.run([*copy, str(path), str(replacement)], check=True, capture_output=True, timeout=120)
            replacement.replace(path)
        assert_unusable_then_discard(silo, "files are missing" if mutation == "delete" else "files were changed",
                                    old_boot, directory)


def assert_unusable_then_discard(silo: Silo, reason: str, old_boot: str, directory: Path) -> None:
    result = silo.run("start", NAME, expect=None)
    hibernate.refused(result, hibernate.unusable(NAME, reason))
    assert silo.info(NAME)["state"] == "hibernated"
    assert procs.vmm_pid(silo.ws, NAME) is None, "failed wake booted a monitor"
    result = silo.run("stop", NAME)
    assert "could not be shut down cleanly" in result.stderr + result.stdout, result
    assert silo.info(NAME)["state"] == "stopped"
    assert not directory.exists()
    hibernate.wake(silo, NAME)
    assert hibernate.boot_id(silo, NAME) != old_boot


@pytest.mark.parametrize("external", [False, True], ids=["managed", "external"])
def test_each_writable_disk_tamper_refuses_without_boot(
    silo: Silo, basic_image: str, external: bool,
) -> None:
    """Conformance 7: root upper and managed/external writable data disks."""
    hibernate.create(silo, basic_image, NAME, start=False)
    capture_multidisk.install_disks(silo, NAME, external=external)
    silo.start(NAME)
    silo.wait_ready(NAME)
    paths = stopped.writable_paths(silo, NAME)
    if external:
        paths["external"] = silo.ws.root / "external-data.raw"
    assert len(paths) == 3
    for path in paths.values():
        boot = hibernate.boot_id(silo, NAME)
        hibernate.save(silo, NAME)
        directory = hibernate.saved_directory(silo, NAME)
        # Write the same byte back: content is still bootable, but ctime proves
        # an out-of-band write and must invalidate the memory/disk pairing.
        with path.open("r+b") as disk:
            byte = disk.read(1)
            assert byte
            disk.seek(0)
            disk.write(byte)
            disk.flush()
            os.fsync(disk.fileno())
        assert_unusable_then_discard(silo, "disks were changed", boot, directory)


@pytest.mark.skip(reason="ADR 0023 item 9: no existing rootless bounded-filesystem Home fixture; "
                         "filling the shared host filesystem would endanger unrelated work")
def test_disk_full_during_memory_write_rolls_back() -> None:
    """Requires a rootless small-filesystem Home, not injected ENOSPC."""


@dataclass(frozen=True)
class Access:
    result: Result
    run_id: str


def test_twenty_concurrent_accesses_share_one_wake(silo: Silo, basic_image: str) -> None:
    """Conformance 10: exec, cp and shell all see one new run with clean stdout."""
    hibernate.create(silo, basic_image, NAME)
    silo.exec(NAME, "sh", "-ec", "printf copy-payload >/hibernate-copy", user="root")
    old_run = silo.info(NAME)["run_id"]
    boot = hibernate.boot_id(silo, NAME)
    hibernate.save(silo, NAME)
    barrier = threading.Barrier(20)

    def access(index: int) -> Access:
        barrier.wait(timeout=30)
        if index % 3 == 0:
            target = silo.ws.root / f"copy-{index}"
            result = silo.run("cp", f"{NAME}:/hibernate-copy", str(target))
            assert result.stdout == ""
            assert target.read_bytes() == b"copy-payload"
        elif index % 3 == 1:
            result = silo.exec(NAME, "printf", f"exec-{index}")
            assert result.stdout == f"exec-{index}"
        else:
            result = silo.shell(NAME, f"printf 'shell-{index}\\n'; exit 0\n")
            assert f"shell-{index}" in result.stdout.replace("\r\n", "\n").splitlines()
        return Access(result, str(silo.info(NAME)["run_id"]))

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(access, range(20)))
    runs = {access.run_id for access in results}
    assert len(runs) == 1 and old_run not in runs
    for access in results:
        hibernate.no_wake_line(access.result, NAME)
    assert hibernate.boot_id(silo, NAME) == boot


@pytest.mark.linux_only(reason="requires pidfd signaling of independently discovered workspace processes")
def test_hibernated_fresh_cli_without_silo_processes(silo: Silo, basic_image: str) -> None:
    """Conformance 11 surrogate only, not a reboot or Btrfs device-number test."""
    hibernate.create(silo, basic_image, NAME)
    boot = hibernate.boot_id(silo, NAME)
    hibernate.save(silo, NAME)
    # Only this private Home and run root, never the user's Silo processes.
    with hibernate.workspace_processes(silo) as processes:
        for process in processes:
            process.send(signal.SIGKILL)
        for process in processes:
            process.wait()
    with hibernate.workspace_processes(silo) as remaining:
        assert not remaining, "a workspace process survived the reboot surrogate"
    # Silo.run always spawns a fresh CLI. Nothing may automatically wake.
    fresh = Silo(silo.ws)
    assert fresh.info(NAME)["state"] == "hibernated"
    hibernate.wake(fresh, NAME)
    assert hibernate.boot_id(fresh, NAME) == boot


def test_exec_session_ends_and_configured_forward_reconnects(
    silo: Silo, hibernate_image: str,
) -> None:
    """Conformance 12: an old exec ends, a persistent listener returns on wake."""
    forward = "host:unix:hibernate.sock=guest:tcp:127.0.0.1:9000"
    hibernate.create(silo, hibernate_image, NAME, "--forward", forward, network="private")
    # A detached server is guest process state, not a session that should end.
    silo.exec(NAME, "sh", "-ec", "nohup sh -c 'while :; do printf hello | nc -l -p 9000; done' "
              ">/hibernate-server.log 2>&1 </dev/null &", user="root")
    path = network.runtime_socket(silo, procs.machine_id(silo.ws, NAME), "hibernate.sock")
    def listening() -> bool:
        tcp = silo.exec(NAME, "cat", "/proc/net/tcp", "/proc/net/tcp6").stdout
        return any(len(fields := line.split()) > 3 and fields[1].endswith(":2328") and fields[3] == "0A"
                   for line in tcp.splitlines())

    shutdown.until(listening, description="guest server not listening")
    assert network.forward_reply(path) == b"hello"
    session = silo.popen("exec", NAME, "--", "sh", "-ec", "echo SESSION-OPEN; exec sleep 2147483647")
    shell = PtyCommand(silo.ws, [str(silo.ws.config.silo), "shell", NAME, "--user", "root"],
                       label="hibernate-shell", term="dumb")
    forward_session: subprocess.Popen[bytes] | None = None
    try:
        assert hibernate.read_line(session) == b"SESSION-OPEN\n"
        # Input typed before the first prompt is discarded when the guest
        # shell switches the terminal into line-editing mode.
        shell.wait_for(b":~# ")
        shell.write(b"printf '\\nSHELL-OPEN\\n'; exec sleep 2147483647\n")
        shell.wait_for(b"\r\nSHELL-OPEN\r\n")
        forward_session = silo.popen("forward", NAME, "0:9000", stdin=subprocess.DEVNULL)
        assert procs.bound_port(hibernate.read_line(forward_session)) > 0
        hibernate.save(silo, NAME)
        for old in (session, forward_session):
            output, errors = old.communicate(timeout=15)
            assert old.returncode is not None
            assert b"Waking" not in output + errors
        shell.wait(timeout=15)
        assert b"Waking" not in shell.output
        assert network.unix_refused(path)
        hibernate.wake(silo, NAME)
        assert network.forward_reply(path) == b"hello"
        assert all(old.poll() is not None for old in (session, shell.proc, forward_session)), (
            "an old access command was replayed")
    finally:
        if forward_session is not None:
            hibernate.terminate(forward_session, silo, "hibernate-old-forward")
        if shell.proc.poll() is None:
            shell.proc.kill()
        shell.wait(timeout=15)
        hibernate.terminate(session, silo, "hibernate-old-exec")


def test_admission_and_observation_never_wake(silo: Silo, basic_image: str) -> None:
    hibernate.create(silo, basic_image, NAME, start=False)
    hibernate.refused(silo.run("hibernate", NAME, expect=None),
                     f"machine `{NAME}` is not running; start it with `silo start {NAME}`")
    silo.start(NAME)
    silo.wait_ready(NAME)
    boot = hibernate.boot_id(silo, NAME)
    hibernate.save(silo, NAME)
    before = hibernate.report(silo, NAME)
    hibernate.refused(silo.run("hibernate", NAME, expect=None),
                     f"machine `{NAME}` is already hibernated; wake it with `silo start {NAME}`")
    listed = silo.json("list")
    assert next(machine for machine in listed if machine["name"] == NAME)["state"] == "hibernated"
    silo.run("logs", NAME, "--stream", "monitor")
    silo.run("forward", NAME, "--list")
    assert hibernate.report(silo, NAME) == before
    assert procs.vmm_pid(silo.ws, NAME) is None
    hibernate.wake(silo, NAME)
    assert hibernate.boot_id(silo, NAME) == boot


def test_temporary_run_cannot_hibernate(silo: Silo, basic_image: str) -> None:
    # Only unnamed `run` machines are ephemeral. Hold stdin open and wait for
    # guest output before looking up its generated name, avoiding creation races.
    process = silo.popen("run", basic_image, "--cpus", "1", "--memory", "512mib",
                         "--vsock", "--network", "none", "--", "sh", "-ec",
                         "printf 'RUN-OPEN\\n'; cat >/dev/null", stdin=subprocess.PIPE)
    name: str | None = None
    try:
        assert hibernate.read_line(process) == b"RUN-OPEN\n"
        machines = silo.ls()
        assert len(machines) == 1, machines
        name = str(machines[0]["name"])
        silo.ws.register_machine(name)
        silo.wait_ready(name)
        hibernate.refused(silo.run("hibernate", name, expect=None),
                         f"machine `{name}` is a temporary `silo run` machine and cannot be hibernated")
        assert silo.info(name)["state"] == "running"
        assert silo.exec(name, "printf", "still-running").stdout == "still-running"
    finally:
        try:
            if name is not None:
                result = silo.run("stop", name, "--force", expect=None)
                assert result.returncode == 0 or "not found" in result.stderr, result
        finally:
            hibernate.terminate(process, silo, "hibernate-temporary")


@pytest.mark.parametrize("access", ["exec", "cp", "shell", "forward"])
def test_guest_access_wakes_without_a_wake_line(silo: Silo, basic_image: str, access: str) -> None:
    hibernate.create(silo, basic_image, NAME)
    boot = hibernate.boot_id(silo, NAME)
    silo.exec(NAME, "sh", "-ec", "printf content >/hibernate-access", user="root")
    hibernate.save(silo, NAME)
    if access == "exec":
        result = silo.exec(NAME, "printf", "content")
        assert result.stdout == "content"
    elif access == "cp":
        target = silo.ws.root / "download"
        result = silo.run("cp", f"{NAME}:/hibernate-access", str(target))
        assert result.stdout == "" and target.read_bytes() == b"content"
    elif access == "shell":
        result = silo.shell(NAME, "printf 'content\\n'; exit 0\n")
        assert "content" in result.stdout.replace("\r\n", "\n").splitlines()
    else:
        process = silo.popen("forward", NAME, "0:9000", stdin=subprocess.DEVNULL)
        try:
            status = hibernate.read_line(process)
            assert procs.bound_port(status) > 0
            process.send_signal(signal.SIGINT)
            output, errors = process.communicate(timeout=15)
            result = Result([], process.returncode, (status + output).decode(), errors.decode())
            assert result.returncode == 0
        finally:
            hibernate.terminate(process, silo, "hibernate-access-forward")
    hibernate.no_wake_line(result, NAME)
    assert hibernate.boot_id(silo, NAME) == boot
