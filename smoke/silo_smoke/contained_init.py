"""Real image-init probes and guest-local activation ordering evidence."""
from __future__ import annotations

import json
import posixpath
import re
import time
from uuid import UUID

from . import fork, restore
from .cli import RootProfile, Silo

ARCH = "ghcr.io/vandycknick/archlinux:latest"
ALPINE = "docker.io/library/alpine:latest"
INIT_KINDS = ("systemd", "busybox", "openrc")
TICKS = "/run/silo-contained-ticks"
REACTIONS = "/var/log/silo-contained-generation"
GENERATION = "/run/silo/generation"


def shell(silo: Silo, name: str, script: str, *, timeout: float = 60) -> str:
    return silo.exec(name, "sh", "-eu", "-c", script, user="root", timeout=timeout).stdout


def wait_shell(silo: Silo, name: str, script: str, *, timeout: float = 45) -> str:
    deadline = time.monotonic() + timeout
    while True:
        result = silo.exec(name, "sh", "-eu", "-c", script, user="root", expect=None, timeout=10)
        if result.returncode == 0:
            return result.stdout
        assert time.monotonic() < deadline, (name, script, result)
        time.sleep(0.2)


def put(silo: Silo, name: str, path: str, content: str, *, executable: bool = False) -> None:
    silo.exec(name, "sh", "-eu", "-c", 'cat >"$1"', "contained-file", path,
              stdin=content, user="root")
    if executable:
        silo.exec(name, "chmod", "755", path, user="root")


def create(silo: Silo, name: str, kind: str, *, profile: RootProfile = "layered",
           network: str = "none") -> dict:
    assert kind in INIT_KINDS, kind
    image = ARCH if kind == "systemd" else ALPINE
    silo.create(name, silo.root_image(image, profile), "--cpus", "2",
                "--memory", "1gib", "--disk-size", "1gib", "--vsock",
                "--network", "private" if kind == "openrc" else network)
    # Deliberately no init= override: exercise the stock image's handoff.
    silo.start(name)
    silo.wait_ready(name)
    if kind == "openrc":
        shell(silo, name, "apk add --no-cache openrc busybox-openrc; "
              "rc-update add cgroups sysinit; rc-update add crond default; "
              "printf '\\nrc_cgroup_mode=\"unified\"\\n' >>/etc/rc.conf; sync", timeout=180)
        silo.stop(name)
        silo.start(name)
        silo.wait_ready(name)
        openrc_service(silo, name)
    if kind == "systemd":
        wait_shell(silo, name, 'test "$(systemctl is-system-running)" = running')
    return contained(silo, name)


def contained(silo: Silo, name: str) -> dict:
    info = silo.wait_ready(name)
    boot = info["guest"]["boot"]
    assert boot["mode"] == "contained-init" and boot["agent_is_pid1"] is False, boot
    agent = boot["agent_pid"]
    assert agent > 1, boot
    for operation in ("pause", "capture", "restore", "fork"):
        capability = info["lifecycle"]["report"]["live"][operation]
        assert capability["availability"] == {"status": "supported"}, capability
    observed = shell(silo, name, f"cat /proc/1/cgroup; cat /proc/self/cgroup; "
                     f"readlink /proc/1/ns/cgroup; readlink /proc/self/ns/cgroup; "
                     f"readlink /proc/{agent}/ns/cgroup; "
                     f"cat /proc/{agent}/oom_score_adj; cat /proc/self/oom_score_adj")
    lines = observed.splitlines()
    assert len(lines) == 7, observed
    # /proc renders paths relative to this exec session's namespace root.
    assert lines[0].startswith("0::/"), observed
    pid1_path = posixpath.normpath("/silo/workloads/exec/" + lines[0][4:].lstrip("/"))
    assert pid1_path == "/silo/workloads/image" or pid1_path.startswith("/silo/workloads/image/"), observed
    assert lines[1] == "0::/", observed
    assert len(set(lines[2:5])) == 3, observed
    assert lines[5:] == ["-1000", "0"], observed
    mount = shell(silo, name, "cat /proc/1/mountinfo")
    cgroups = [line.split() for line in mount.splitlines() if " - cgroup2 " in line]
    assert any(fields[4] == "/sys/fs/cgroup" and
               {"nsdelegate", "memory_recursiveprot"}.issubset(fields[-1].split(","))
               for fields in cgroups), mount
    silo.ws.record("contained-init", json.dumps({"name": name, "info": info,
                                                "membership": observed}) + "\n")
    return info


def openrc_service(silo: Silo, name: str) -> str:
    output = wait_shell(silo, name, "rc-service crond status; "
                        "pids=$(pidof crond); test -n \"$pids\"; "
                        "for pid in $pids; do cat /proc/$pid/cgroup; done")
    memberships = [line for line in output.splitlines() if line.startswith("0::")]
    assert memberships and all(line.startswith("0::/../image/openrc.crond") for line in memberships), output
    return shell(silo, name, "pidof crond").strip()


def identity(silo: Silo, name: str, info: dict, *, machine_id: bool) -> None:
    assert shell(silo, name, "cat /run/silo/generation").strip() == info["run_id"], info
    if machine_id:
        value = shell(silo, name, "cat /etc/machine-id").strip()
        assert re.fullmatch(r"[0-9a-f]{32}", value), value
        assert value == UUID(info["id"]).hex, (value, info)
    else:
        shell(silo, name, "test ! -e /etc/machine-id")


def fork_child(silo: Silo, source: str, child: str) -> dict:
    call = fork.run(silo, source, [child], expect=0, timeout=240)
    assert call.result is not None, call
    assert call.result["capture"]["kind"] == "sealed", call.result
    assert call.result["source"]["kind"] == "resumed", call.result
    result = call.result["children"][0]
    assert result["outcome"]["kind"] == "running", result
    info = silo.wait_ready(child)
    assert UUID(info["id"]) == UUID(result["machineId"]), (info, result)
    assert UUID(info["run_id"]) == UUID(result["runId"]), (info, result)
    return info


def install_ticker(silo: Silo, name: str) -> None:
    shell(silo, name, "test ! -e /run/silo/generation; "
          f": >{TICKS}; rm -f {REACTIONS}")
    put(silo, name, "/usr/local/bin/silo-contained-ticker", f"""#!/bin/sh
set -eu
while :; do
    date +%s%N >>{TICKS}
    sleep 0.05
done
""", executable=True)
    put(silo, name, "/usr/local/bin/silo-contained-reaction", f"""#!/bin/sh
set -eu
printf '%s %s\\n' "$(cat {GENERATION})" "$(date +%s%N)" >>{REACTIONS}
""", executable=True)
    put(silo, name, "/etc/systemd/system/silo-contained-ticker.service", """[Unit]
Description=Contained-init ordering witness
[Service]
ExecStart=/usr/local/bin/silo-contained-ticker
""")
    put(silo, name, "/etc/systemd/system/silo-contained-generation.service", """[Unit]
Description=Record the post-thaw generation reaction
[Service]
Type=oneshot
ExecStart=/usr/local/bin/silo-contained-reaction
""")
    put(silo, name, "/etc/systemd/system/silo-contained-generation.path", """[Unit]
Description=Watch Silo activation
[Path]
PathChanged=/run/silo/generation
Unit=silo-contained-generation.service
""")
    shell(silo, name, "systemctl daemon-reload; "
          "systemctl start silo-contained-generation.path silo-contained-ticker.service")
    wait_shell(silo, name, f'test "$(wc -l <{TICKS})" -ge 5')


def ticks(text: str) -> list[int]:
    lines = text.splitlines()
    if text and not text.endswith("\n"):
        partial = lines.pop()
        assert re.fullmatch(r"[0-9]{1,19}", partial), f"invalid final tick: {text!r}"
    assert lines and all(re.fullmatch(r"[0-9]{19}", line) for line in lines), f"invalid ticks: {text!r}"
    values = [int(line) for line in lines]
    assert all(left < right for left, right in zip(values, values[1:])), f"nonmonotonic ticks: {text!r}"
    return values


def ordering(silo: Silo, child: str, info: dict) -> None:
    """Find the capture gap in the child's inherited tmpfs log."""
    activated = int(shell(silo, child, f"date -r {GENERATION} +%s%N").strip())
    wait_shell(silo, child, f'last=$(tail -n 1 {TICKS}); test "$last" -ge {activated}')
    time.sleep(0.2)
    observed = ticks(shell(silo, child, f"cat {TICKS}"))
    assert len(observed) >= 8, observed
    boundary = max(range(1, len(observed)), key=lambda index: observed[index] - observed[index - 1])
    gap = observed[boundary] - observed[boundary - 1]
    assert gap >= 500_000_000, ("capture gap below 500 ms", gap, observed)
    assert observed[boundary - 1] < activated, (boundary, activated, observed)
    assert all(value >= activated for value in observed[boundary:]), (boundary, activated, observed)
    reaction = wait_shell(silo, child, f"grep '^{info['run_id']} ' {REACTIONS}").splitlines()
    assert reaction and all(int(line.split()[1]) >= activated for line in reaction), reaction
    assert shell(silo, child, "systemctl is-active silo-contained-ticker.service").strip() == "active"
    silo.ws.record("contained-ordering", json.dumps({"child": child, "ticks": observed,
                   "captureGapNs": gap, "captureBoundary": boundary,
                   "generationMtimeNs": activated, "reaction": reaction}) + "\n")


def snapshot_child(silo: Silo, source: str, child: str) -> dict:
    saved = restore.checkpoint(silo, source, alias="contained-checkpoint")
    info = restore.restore_child(silo, saved, child)
    silo.run("resume", source)
    silo.wait_ready(source)
    return info
