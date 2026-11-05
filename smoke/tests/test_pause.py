from __future__ import annotations

import json
from uuid import uuid4

import pytest

from silo_smoke import pause, shutdown
from silo_smoke.cli import Silo

pytestmark = pytest.mark.linux_only


def test_pause_resume_retains_guest_session_and_user_authority(silo: Silo, basic_image: str) -> None:
    name = "pause-roundtrip"
    silo.create(name, basic_image, "--cpus", "2", "--memory", "512mib", "--vsock", "--network", "none")
    silo.start(name)
    running = silo.wait_ready(name)
    boot_id = silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout
    before = pause.generation(silo, name)
    counter = pause.Counter(silo, name)
    try:
        counter.advances()
        silo.run("pause", name)
        paused = silo.info(name)
        assert paused["state"] == "paused" and paused["ready"] is False, paused
        assert paused["run_id"] == running["run_id"]
        current = paused["lifecycle"]["lifecycle"]["currentPause"]
        assert current["token"]["owner"] == {"kind": "user"}, current
        assert current["token"]["generation"] > 0
        counter.stationary()
        envelope = {"machineId": current["token"]["machineId"], "runId": running["run_id"], "requestId": str(uuid4())}
        operation = pause.request(silo, name, {
            "command": "getOperation", "envelope": envelope, "operationId": current["operationId"],
        })
        assert operation["outcome"] == "observation", operation
        established = operation["observation"]["operation"]["outcome"]
        assert established["status"] == "succeeded"
        assert established["pause"]["token"] == current["token"]
        guest = established["pause"]["guest"]
        assert guest["workloadRoots"] and guest["workloadRoots"] == guest["observedFrozenRoots"]
        replay = pause.request(silo, name, {
            "command": "pause", "envelope": {**envelope, "requestId": current["operationId"]},
        })
        assert replay["outcome"] == "accepted", replay
        cancelled = pause.request(silo, name, {
            "command": "cancelOperation", "envelope": {**envelope, "requestId": str(uuid4())},
            "operationId": current["operationId"],
        })
        assert cancelled["outcome"] == "rejected", cancelled
        assert cancelled["rejection"]["reason"]["code"] == "invalidState", cancelled
        assert cancelled["rejection"]["state"] == "paused", cancelled
        stale = pause.request(silo, name, {
            "command": "resume", "envelope": {**envelope, "requestId": str(uuid4())},
            "operationId": current["operationId"],
            "token": {**current["token"], "generation": current["token"]["generation"] + 1},
        })
        assert stale["outcome"] == "rejected", stale
        # A fresh CLI process opens a fresh Runtime and reconciles the same
        # monitor. Neither manager lifetime nor status reconnect resumes it.
        reconnected = silo.info(name)
        assert reconnected["state"] == "paused"
        assert reconnected["lifecycle"]["lifecycle"]["currentPause"] == current
        counter.stationary()
        rejected = silo.exec(name, "/bin/sh", "-c", "echo bad >/pause-forbidden", expect=None, timeout=10)
        assert rejected.returncode != 0, rejected
        counter.stationary()
        silo.run("resume", name)
        resumed = silo.wait_ready(name)
        assert resumed["run_id"] == running["run_id"]
        assert resumed["lifecycle"]["lifecycle"]["currentPause"] is None
        counter.advances()
        historical = pause.request(silo, name, {
            "command": "getOperation", "envelope": {**envelope, "requestId": str(uuid4())},
            "operationId": current["operationId"],
        })
        assert historical["observation"]["operation"]["outcome"] == established
        assert historical["observation"]["currentPause"] is None
        assert silo.exec(name, "cat", "/proc/sys/kernel/random/boot_id").stdout == boot_id
        silo.exec(name, "/bin/sh", "-c", "test ! -e /pause-forbidden")
        after = pause.generation(silo, name)
        assert int(after["request_sequence"]) == int(before["request_sequence"]) + 1
        assert after["request_id"] == before["request_id"]
        assert after["request_flags"] == after["completed_flags"] == "3"
        assert after["reseed_count"] == before["reseed_count"]
        assert after["completed_sequence"] == after["ack_sequence"] == after["request_sequence"]
        assert after["ack_accessor_returned"] == "1"
        silo.ws.record("pause-roundtrip", json.dumps({"before": before, "after": after, "paused": paused, "resumed": resumed}) + "\n")
        silo.run("pause", name)
        second = silo.info(name)
        assert second["state"] == "paused"
        assert second["lifecycle"]["lifecycle"]["currentPause"]["token"]["generation"] > current["token"]["generation"]
        counter.stationary()
        holders, lease = shutdown.holder(silo, name)
        processes = [shutdown.Process(entry["pid"]) for entry in holders["holders"]]
        try:
            silo.stop(name)
            for process in processes:
                process.wait()
            assert not shutdown.lease_busy(lease)
            assert silo.info(name)["state"] == "stopped"
            output, errors = counter.process.communicate(timeout=10)
            silo.ws.record("pause-stop-counter", (output + b"\n[stderr]\n" + errors).decode(errors="replace"))
            assert output == b"", "stop resumed the paused workload before terminating it"
        finally:
            for process in processes:
                process.close()
    finally:
        counter.close()
