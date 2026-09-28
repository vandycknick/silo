#!/usr/bin/env python3
"""Verify real system-appliance adoption across a graceful silod restart.

Requires SILO_SMOKE_SYSTEM_IMAGE (a compatible OCI image). Optional
SILO_SMOKE_CACHE points at an immutable image cache to clone into the disposable
home. Uses built target/debug binaries unless SILO_SMOKE_SILOD is supplied.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def main() -> None:
    binary = Path(os.environ.get("SILO_SMOKE_SILOD", "target/debug/silod")).resolve(strict=True)
    image = os.environ["SILO_SMOKE_SYSTEM_IMAGE"]
    root = Path(tempfile.mkdtemp(prefix="silo-restart-", dir="/tmp"))
    # silod deliberately ignores SILO_HOME and uses HOME/.silo.
    user_home = root / "user"
    home = user_home / ".silo"
    home.mkdir(parents=True, mode=0o700)
    (home / "run").mkdir(mode=0o700)
    environment = {**os.environ, "HOME": str(user_home), "SILO_HOME": str(home), "XDG_CONFIG_HOME": str(root / "config")}
    cache = os.environ.get("SILO_SMOKE_CACHE")
    if cache:
        copy = ["/bin/cp", "-cR"] if sys.platform == "darwin" else ["cp", "-a", "--reflink=auto"]
        subprocess.run([*copy, str(Path(cache).resolve(strict=True)), str(home / "images")], check=True, timeout=30)
    command = [str(binary), "--system-image", image, "--system-backend", "krun",
               "--system-cpus", "1", "--system-memory", "1GiB", "--system-root-size", "2GiB",
               "--system-data-size", "512MiB", "--system-home-share", "false", "--system-rosetta", "false"]
    daemon: subprocess.Popen[bytes] | None = None
    complete = False

    def ready(timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert daemon is not None and daemon.poll() is None, "silod exited before ready"
            path = home / "daemon/status.json"
            if path.exists():
                status = json.loads(path.read_text())
                if status["pid"] == daemon.pid and status["phase"] == "ready":
                    return
            time.sleep(0.1)
        raise AssertionError("silod never became ready")

    def identity() -> str:
        query = "SELECT c.id, json_extract(s.state_json,'$.vmmonPid'), json_extract(s.state_json,'$.runId'), json_extract(n.driver_state_json,'$.helper_pid') FROM machine_config c JOIN machine_state s ON s.machine_id=c.id JOIN network_attachments a ON a.machine_id=c.id JOIN network_instances n ON n.id=a.network_instance_id WHERE s.status='running' ORDER BY c.id"
        result = subprocess.check_output(["sqlite3", "-readonly", str(home / "state.db"), query], text=True).strip()
        assert result and len(result.splitlines()) == 1, result
        return result

    with (root / "silod.log").open("wb") as log:
        try:
            daemon = subprocess.Popen(command, env=environment, stdout=log, stderr=log)
            ready(150)
            before = identity()
            vm_id, vmm_pid, run_id, netd_pid = before.split("|")
            assert vm_id and run_id
            daemon.terminate()
            daemon.wait(timeout=15)
            os.kill(int(vmm_pid), 0)
            os.kill(int(netd_pid), 0)
            assert identity() == before
            daemon = subprocess.Popen(command, env=environment, stdout=log, stderr=log)
            ready(60)
            assert identity() == before, "manager restart replaced a VM or netd generation"
            complete = True
        finally:
            if daemon is not None and daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)
            stopped = subprocess.run([str(binary), "--stop"], env=environment, stdout=log, stderr=log, timeout=90)
            if not complete or stopped.returncode:
                print(f"Failure evidence retained at {root}")
            if stopped.returncode:
                raise RuntimeError("explicit installation stop failed; inspect retained evidence")
    if complete:
        shutil.rmtree(root)
        print("PASS: graceful silod restart adopted the same real VMM/netd generation")


if __name__ == "__main__":
    main()
