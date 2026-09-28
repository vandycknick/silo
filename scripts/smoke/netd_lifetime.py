#!/usr/bin/env python3
"""Real CLI/VMM/netd smoke test. Requires a built runtime and an immutable root disk.

SILO_SMOKE_DISK=/path/to/cached/rootfs.img python3 scripts/smoke/netd_lifetime.py
Optionally set SILO_SMOKE_BIN to the built silo binary. Never uses the user's DB.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


def main() -> None:
    disk = Path(os.environ["SILO_SMOKE_DISK"]).resolve(strict=True)
    binary = Path(os.environ.get("SILO_SMOKE_BIN", "target/debug/silo")).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="silo-lifetime-", dir="/tmp"))
    home = root / "home"
    user_home = root / "user"
    user_home.mkdir()
    environment = {**os.environ, "HOME": str(user_home), "SILO_HOME": str(home), "XDG_CONFIG_HOME": str(root / "config")}
    names = ["lifetime-broken", "lifetime-healthy"]
    complete = False
    original_config: str | None = None
    suspended_pid: int | None = None

    def cli(*args: str) -> str:
        result = subprocess.run([str(binary), *args], env=environment, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"silo {args}: {result.stderr}")
        return result.stdout

    def sql(query: str) -> str:
        return subprocess.check_output(["sqlite3", str(home / "state.db"), query], text=True).strip()

    def state(name: str) -> str:
        return sql("SELECT json(state_json) FROM machine_state s JOIN machine_config c ON c.id=s.machine_id WHERE c.name='" + name + "'")

    def monitor(name: str) -> int:
        return int(sql("SELECT json_extract(state_json,'$.vmmonPid') FROM machine_state s JOIN machine_config c ON c.id=s.machine_id WHERE c.name='" + name + "'"))

    def helper(name: str) -> int:
        return int(sql("SELECT json_extract(n.driver_state_json,'$.helper_pid') FROM network_instances n JOIN network_attachments a ON a.network_instance_id=n.id JOIN machine_config c ON c.id=a.machine_id WHERE c.name='" + name + "'"))

    def gone(pid: int) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        raise AssertionError(f"process {pid} did not exit and get reaped")

    try:
        for name in names:
            cli("create", f"disk:{disk}", "--name", name, "--cpus", "1", "--memory", "512mb", "--network", "private", "--no-agent")
            cli("start", name)
        # A hung monitor must not hang inventory or hide the other VM.
        suspended_pid = monitor(names[1])
        os.kill(suspended_pid, signal.SIGSTOP)
        started = time.monotonic()
        stalled = json.loads(cli("show", names[1], "--format", "json"))
        assert time.monotonic() - started < 5, "inspection deadline exceeded"
        assert stalled["state"] == "running" and not stalled["ready"], stalled
        assert any(issue["component"] == "telemetry" for issue in stalled["issues"]), stalled
        os.kill(suspended_pid, signal.SIGCONT)
        suspended_pid = None
        before = state(names[0])
        broken_pid = helper(names[0])
        os.kill(broken_pid, signal.SIGKILL)
        gone(broken_pid)
        snapshot = json.loads(cli("show", names[0], "--format", "json"))
        assert snapshot["state"] == "running", snapshot
        assert any(issue["component"] == "network" for issue in snapshot["issues"]), snapshot
        assert state(names[0]) == before, "inspection changed durable lifecycle state"
        listing = json.loads(cli("ls", "--format", "json"))
        assert len(listing) == 2
        assert all(vm["state"] == "running" for vm in listing), listing
        assert "Details: silo show" not in cli("ls", "--format", "json")
        cli("ls")
        assert "Issue (Network)" in cli("show", names[0])
        assert "generation started" in cli("logs", names[0], "--stream", "network")

        # Normal shutdown must close the lease in the final VMM, not in the CLI.
        healthy_pid = helper(names[1])
        cli("stop", names[1])
        gone(healthy_pid)
        cli("start", names[1])
        healthy_pid = helper(names[1])
        vmm_pid = monitor(names[1])
        os.kill(vmm_pid, signal.SIGKILL)
        gone(healthy_pid)
        gone(vmm_pid)
        cli("show", names[1])

        # Corrupt just one config record, retaining identity and historical logs.
        original_config = sql("SELECT json(config_json) FROM machine_config WHERE name='lifetime-healthy'")
        sql("UPDATE machine_config SET config_json=x'00' WHERE name='lifetime-healthy'")
        unknown = json.loads(cli("show", names[1], "--format", "json"))
        assert unknown["name"] == names[1] and unknown["state"] == "unknown", unknown
        assert len(json.loads(cli("ls", "--format", "json"))) == 2
        cli("logs", names[1], "--stream", "network")
        missing = subprocess.run([str(binary), "ls", "-v"], env={**environment, "NETD_BIN": str(root / "missing-netd")}, capture_output=True, text=True, timeout=10)
        assert missing.returncode != 0 and "NETD_BIN" in missing.stderr, missing.stderr
        complete = True
    finally:
        if suspended_pid is not None:
            os.kill(suspended_pid, signal.SIGCONT)
        if original_config is not None:
            sql("UPDATE machine_config SET config_json=jsonb('" + original_config.replace("'", "''") + "') WHERE name='lifetime-healthy'")
        cleanup_errors = []
        for name in names:
            result = subprocess.run([str(binary), "rm", "--force", name], env=environment, capture_output=True, text=True, timeout=90)
            if complete and result.returncode:
                cleanup_errors.append(result.stderr)
        if complete and not cleanup_errors:
            shutil.rmtree(root)
            print("PASS: real netd adoption/reaping, owner EOF, VMM crash, netd crash survival, bounded telemetry, partial inventory, JSON, logs and strict installation validation")
        else:
            print(f"Failure evidence retained at {root}")
        if cleanup_errors:
            raise RuntimeError(f"test VM cleanup failed: {cleanup_errors}")


if __name__ == "__main__":
    main()
