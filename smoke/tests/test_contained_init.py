"""Stock image init handoff: real freezer, capture, activation and stop gates."""
from __future__ import annotations

import json
import re
import time

import pytest

from silo_smoke import contained_init as contained
from silo_smoke import pause
from silo_smoke.cli import ROOT_PROFILES, RootProfile, Silo

pytestmark = [pytest.mark.krun_live, pytest.mark.slow, pytest.mark.usefixtures("pulled_images")]


@pytest.mark.parametrize("kind", contained.INIT_KINDS)
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_stock_init_pause_snapshot_restore_and_fork(
    silo: Silo, kind: str, profile: RootProfile,
) -> None:
    source = "contained-source"
    original = contained.create(silo, source, kind, profile=profile)
    contained.shell(silo, source, "test ! -e /run/silo/generation; "
                    "printf 'captured image init\\n' >/contained-marker; sync")
    boot_id = contained.shell(silo, source, "cat /proc/sys/kernel/random/boot_id")
    machine_id = (contained.shell(silo, source, "cat /etc/machine-id")
                  if kind == "systemd" else None)
    if kind == "busybox":
        contained.shell(silo, source, "test ! -e /etc/machine-id")
    crond = contained.openrc_service(silo, source) if kind == "openrc" else None
    counter = pause.Counter(silo, source)
    try:
        counter.advances()
        silo.run("pause", source)
        paused = silo.info(source)
        assert paused["state"] == "paused" and paused["ready"] is False, paused
        assert paused["run_id"] == original["run_id"], paused
        counter.stationary()
        silo.run("resume", source)
        silo.wait_ready(source)
        counter.advances()
    finally:
        counter.close()

    restored = contained.snapshot_child(silo, source, "contained-restored")
    forked = contained.fork_child(silo, source, "contained-forked")
    for name, child in (("contained-restored", restored), ("contained-forked", forked)):
        contained.contained(silo, name)
        assert child["id"] != original["id"] and child["run_id"] != original["run_id"], child
        assert contained.shell(silo, name, "cat /proc/sys/kernel/random/boot_id") == boot_id
        assert contained.shell(silo, name, "cat /contained-marker") == "captured image init\n"
        if kind != "openrc":
            contained.identity(silo, name, child, machine_id=kind == "systemd")
        else:
            assert contained.openrc_service(silo, name) == crond
            assert contained.shell(silo, name, "cat /run/silo/generation").strip() == child["run_id"]
        if kind == "systemd":
            contained.wait_shell(silo, name, 'test "$(systemctl is-system-running)" = running')
    current = silo.wait_ready(source)
    assert current["run_id"] == original["run_id"], current
    contained.shell(silo, source, "test ! -e /run/silo/generation")
    if machine_id is not None:
        assert contained.shell(silo, source, "cat /etc/machine-id") == machine_id
    assert restored["id"] != forked["id"] and restored["run_id"] != forked["run_id"]
    # Workspace owns all three machines, including failed activation attempts.


@pytest.mark.parametrize("operation", ("restore", "fork"))
@pytest.mark.parametrize("profile", ROOT_PROFILES)
def test_systemd_activation_precedes_first_child_tick_and_path_reaction(
    silo: Silo, operation: str, profile: RootProfile,
) -> None:
    source, child = "contained-ordering", "contained-ordering-child"
    original = contained.create(silo, source, "systemd", profile=profile)
    machine_id = contained.shell(silo, source, "cat /etc/machine-id")
    contained.install_ticker(silo, source)
    if operation == "restore":
        info = contained.snapshot_child(silo, source, child)
    else:
        info = contained.fork_child(silo, source, child)
    contained.identity(silo, child, info, machine_id=True)
    contained.ordering(silo, child, info)
    assert contained.shell(silo, source, "cat /etc/machine-id") == machine_id
    contained.shell(silo, source, "test ! -e /run/silo/generation")
    assert silo.wait_ready(source)["run_id"] == original["run_id"]


def test_systemd_delegated_memory_limit_and_exec_namespace(silo: Silo) -> None:
    name = "contained-memory"
    info = contained.create(silo, name, "systemd")
    result = silo.exec(name, "systemd-run", "--unit=silo-contained-oom", "--wait",
                       "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0", "tail", "/dev/zero",
                       user="root", expect=None, timeout=45)
    assert result.returncode != 0, result
    assert contained.shell(silo, name, "systemctl show silo-contained-oom.service -p Result --value").strip() == "oom-kill"
    contained.wait_shell(silo, name, 'test "$(systemctl is-system-running)" = degraded')
    contained.shell(silo, name, "systemctl reset-failed silo-contained-oom.service")
    contained.wait_shell(silo, name, 'test "$(systemctl is-system-running)" = running')
    contained.shell(silo, name, "systemd-run --unit=silo-contained-cpu -p CPUQuota=25% sleep 60")
    quota, period = contained.shell(silo, name,
        "cat /sys/fs/cgroup/system.slice/silo-contained-cpu.service/cpu.max").split()
    assert int(quota) * 4 == int(period), (quota, period)
    contained.shell(silo, name, "systemctl stop silo-contained-cpu.service")
    # A fresh mount made by an ordinary exec exposes only the exec subtree.
    contained.shell(silo, name, "unshare -m --propagation private sh -eu -c '"
                    "mkdir -p /tmp/contained-exec-cgroup; "
                    "mount -t cgroup2 -o nsdelegate,memory_recursiveprot none /tmp/contained-exec-cgroup; "
                    "trap \"umount /tmp/contained-exec-cgroup\" EXIT; "
                    "test ! -e /tmp/contained-exec-cgroup/silo; "
                    "if echo max >/tmp/contained-exec-cgroup/memory.max; then exit 1; fi'")
    agent = info["guest"]["boot"]["agent_pid"]
    protections = contained.shell(silo, name, f"nsenter -C -t {agent} "
        "unshare -m --propagation private sh -eu -c '"
        "mkdir -p /tmp/contained-control-cgroup; "
        "mount -t cgroup2 -o nsdelegate,memory_recursiveprot none /tmp/contained-control-cgroup; "
        "trap \"umount /tmp/contained-control-cgroup\" EXIT; "
        "cat /tmp/contained-control-cgroup/silo/memory.min "
        "/tmp/contained-control-cgroup/silo/control/memory.min "
        "/tmp/contained-control-cgroup/silo/control/cpu.weight "
        "/tmp/contained-control-cgroup/silo/workloads/pids.max'")
    values = protections.splitlines()
    assert len(values) == 4, protections
    assert int(values[0]) >= 16 * 1024 * 1024 and int(values[1]) >= 16 * 1024 * 1024, protections
    assert values[2] == "1000" and values[3] != "max" and int(values[3]) > 0, protections
    silo.run("pause", name)
    silo.run("resume", name)
    contained.contained(silo, name)


def test_networkd_dhcp_survives_child_activation(silo: Silo) -> None:
    source, child = "contained-networkd", "contained-networkd-child"
    contained.create(silo, source, "systemd", network="private")
    contained.put(silo, source, "/etc/systemd/network/50-eth0.network", """[Match]
Name=eth0
[Network]
DHCP=yes
""")
    contained.shell(silo, source, "systemctl enable --now systemd-networkd")
    probe = ("systemctl is-active --quiet systemd-networkd; "
             "networkctl --no-pager status eth0; "
             "getent ahostsv4 archlinux.org")
    contained.wait_shell(silo, source, probe)
    # Wait for actual DHCP ownership, rather than capturing the original static route.
    lease = "networkctl --no-pager status eth0 | grep -E 'Address:.*DHCPv4 via'"
    contained.wait_shell(silo, source, lease)
    info = contained.fork_child(silo, source, child)
    contained.identity(silo, child, info, machine_id=True)
    contained.wait_shell(silo, child, probe)
    time.sleep(2)
    contained.wait_shell(silo, child, probe)
    contained.wait_shell(silo, child, lease)
    contained.wait_shell(silo, source, probe)


def test_escaped_task_refuses_freeze_and_source_recovers(silo: Silo) -> None:
    name = "contained-escape"
    original = contained.create(silo, name, "systemd")
    agent = original["guest"]["boot"]["agent_pid"]
    # setns is a deliberate privileged escape. Never mount from the initial
    # namespace without both options: that clears delegation guest-wide.
    script = """mkdir -p /tmp/contained-escape-cgroup
mount -t cgroup2 -o nsdelegate,memory_recursiveprot none /tmp/contained-escape-cgroup
trap 'umount /tmp/contained-escape-cgroup' EXIT
sleep 240 </dev/null >/dev/null 2>&1 &
pid=$!
echo "$pid" >/run/silo-contained-escape.pid
echo "$pid" >/tmp/contained-escape-cgroup/silo/control/cgroup.procs
cat /proc/$pid/cgroup
"""
    try:
        silo.exec(name, "nsenter", "-C", "-t", str(agent), "unshare", "-m", "--propagation", "private",
                  "sh", "-eu", "-c", script, user="root")
        escaped = contained.shell(silo, name, "cat /run/silo-contained-escape.pid").strip()
        assert escaped.isdecimal(), escaped
        refused = silo.run("pause", name, expect=None)
        diagnostic = refused.stdout + refused.stderr
        assert refused.returncode != 0 and "guest-containment-escaped" in diagnostic, refused
        for field in (rf"\bpid[ =]+{escaped}\b", rf"\btid[ =]+{escaped}\b", r"\bcomm[ =]+", r"\bcgroup[ =]+"):
            assert re.search(field, diagnostic), diagnostic
        assert "sleep" in diagnostic and "/silo/control" in diagnostic, diagnostic
        current = silo.wait_ready(name)
        assert current["run_id"] == original["run_id"], current
        assert current["lifecycle"]["lifecycle"]["currentPause"] is None, current
        assert contained.shell(silo, name, "printf 'still running'") == "still running"
        silo.ws.record("contained-escape", json.dumps({"pid": escaped, "diagnostic": diagnostic,
                                                       "source": current}) + "\n")
    finally:
        contained.shell(silo, name, "if test -f /run/silo-contained-escape.pid; then "
                        "kill -9 \"$(cat /run/silo-contained-escape.pid)\" 2>/dev/null || :; "
                        "rm /run/silo-contained-escape.pid; fi")
    silo.run("pause", name)
    assert silo.info(name)["state"] == "paused"
    silo.run("resume", name)
    contained.contained(silo, name)


@pytest.mark.linux_only
@pytest.mark.parametrize("kind", contained.INIT_KINDS)
def test_stop_syncs_image_init_writes_before_force_stop(silo: Silo, kind: str) -> None:
    name = "contained-stop"
    original = contained.create(silo, name, kind)
    # Deliberately no sync, sleep, guest shutdown or intervening info command.
    payload = "contained stop sync " + original["run_id"] + "\n"
    silo.exec(name, "sh", "-eu", "-c", "cat >/contained-stop-payload", stdin=payload, user="root")
    silo.stop(name)
    silo.start(name)
    current = contained.contained(silo, name)
    assert current["run_id"] != original["run_id"], current
    assert silo.exec(name, "cat", "/contained-stop-payload", user="root").stdout == payload
    contained.shell(silo, name, "test ! -e /run/silo/generation")
    if kind == "openrc":
        contained.openrc_service(silo, name)


def test_activation_preserves_an_empty_machine_id(silo: Silo) -> None:
    source, child = "contained-empty-id", "contained-empty-id-child"
    contained.create(silo, source, "busybox")
    contained.shell(silo, source, ": >/etc/machine-id; sync")
    info = contained.fork_child(silo, source, child)
    for name in (source, child):
        contained.shell(silo, name, "test -f /etc/machine-id; test ! -s /etc/machine-id")
    assert contained.shell(silo, child, "cat /run/silo/generation").strip() == info["run_id"]
    contained.shell(silo, source, "test ! -e /run/silo/generation")
