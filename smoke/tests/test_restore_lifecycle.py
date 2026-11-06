"""Real execution-restore activation: wire fence, fresh identity, fail-closed
generation/Activate/listener/hook/Thaw paths and manager/monitor/worker crashes.

Each case captures one networked source through the real CLI and restores it
with `silo restore`. Wire evidence is netd's own capture plus every native NIC
send toward netd recorded at the worker's real syscalls; order evidence is the
child monitor's own trace events. Holds pause one real native thread after the
monitor logged the event preceding the action. Nothing is injected, granted or
shortened: a missing production observable fails these cases.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import ipaddress
import json
import signal
import socket
import sqlite3
import struct
import subprocess
import time
from pathlib import Path
from uuid import UUID

import pytest

from silo_smoke import procs, restore, shutdown, stopped
from silo_smoke import restore_lifecycle as lifecycle
from silo_smoke.cli import Silo
from silo_smoke.restore_lifecycle import restore_network_image  # noqa: F401  session fixture

# VM cases need Main's explicit isolated capture+restore candidate
# (SILO_SMOKE_BIN_DIR and SILO_SMOKE_RUNTIME_DIR, like the capture gates) and
# are slow; production restore stays lane-not-qualified until Phase 16. The
# host-only oracle tests below use real bytes, sockets and files, no VM.
pytestmark = [pytest.mark.linux_only]
SOURCE = "restore-net-source"
UNIX_FORWARD = f"host:unix:svc.sock=guest:tcp:127.0.0.1:{lifecycle.LISTEN_PORT}"
UNIX_LISTENER = f"host:unix:svc.sock -> guest:tcp:127.0.0.1:{lifecycle.LISTEN_PORT}"
# One event per machine forward plus the public vsock surface (`--vsock`).
BOUND_LISTENERS = [UNIX_LISTENER, "vsock"]
AFTER_FAILURE = (lifecycle.EXPOSURE_COMMITTING, lifecycle.EXPOSURE_COMMITTED, lifecycle.STARTED)
WIRE_FREE = 2.0  # seconds of fenced observation while the restored kernel runs


def ordered(found: list[lifecycle.Event], *names: str) -> None:
    positions = [found.index(lifecycle.first(found, name)) for name in names]
    assert positions == sorted(positions), [event.line for event in found]


def assert_completed(found: list[lifecycle.Event], listeners: list[str]) -> None:
    lifecycle.single_activation(found)
    for name in lifecycle.SUCCESS_ORDER:
        assert len(lifecycle.named(found, name)) == 1, (name, [event.line for event in found])
    ordered(found, *lifecycle.SUCCESS_ORDER)
    lifecycle.assert_not_logged(found, lifecycle.FAILED, lifecycle.REAPING, lifecycle.GENERATION_EXPIRED,
                                lifecycle.THAW_RECOVERY_FREEZING, lifecycle.THAW_RECOVERY_FROZEN)
    sequence = lifecycle.first(found, lifecycle.GENERATION_ACKNOWLEDGED).fields.get("sequence", "")
    assert sequence.isdigit() and int(sequence) > 0, "exact acknowledged generation sequence missing"
    bound = lifecycle.named(found, lifecycle.LISTENER_BOUND)
    assert sorted(event.fields.get("listener") for event in bound) == sorted(listeners), bound
    acknowledged = found.index(lifecycle.first(found, lifecycle.ACTIVATE_ACKNOWLEDGED))
    thaw = found.index(lifecycle.first(found, lifecycle.THAW_SENDING))
    assert all(acknowledged < found.index(event) < thaw for event in bound), (
        "host listeners must be bound after Activate and before Thaw")


def assert_fenced_wire(evidence: lifecycle.ChildEvidence, traced: lifecycle.Traced | None,
                       record: Path) -> None:
    """Nothing crossed the fence: no native NIC send and nothing at netd."""
    frames = evidence.frames()
    sends = traced.net_egress() if traced is not None else []
    record.write_text(json.dumps({"netdFrames": [frame.json() for frame in frames],
                                  "nativeSends": sends}, indent=2) + "\n")
    assert not sends, f"native NIC sent toward netd before final release: {record}"
    assert not frames, f"netd saw child frames before final release: {record}"


def assert_failed_closed(silo: Silo, child: str, evidence: lifecycle.ChildEvidence,
                         sampler: lifecycle.StateSampler, result: tuple[int, str, str],
                         machine: str | None, *, monitor_alive: bool = True) -> list[lifecycle.Event]:
    """The manager reports failure, the child never published Running and its
    cleanup destroyed it. A live monitor names the failure or its reaping."""
    code, stdout, stderr = result
    assert code != 0 and stdout.strip() == "", ("failed activation reported success", stdout, stderr)
    found = evidence.events()
    lifecycle.single_activation(found)
    lifecycle.assert_not_logged(found, *AFTER_FAILURE)
    if monitor_alive:
        assert lifecycle.named(found, lifecycle.FAILED) or lifecycle.named(found, lifecycle.REAPING), (
            "activation failure was neither reported nor reaped", [event.line for event in found])
    sampler.close()
    assert "running" not in sampler.statuses(), sampler.samples
    lifecycle.assert_destroyed(silo, child, machine)
    return found


def test_activation_events_parse_exact_names_fields_and_wall_time() -> None:
    text = "\n".join([
        '2026-11-06T10:00:00.000001Z  INFO restore prepared activation=a1',
        '2026-11-06T10:00:00.5Z  INFO restore generation acknowledged activation=a1 sequence=2',
        '2026-11-06T10:00:01.123456789Z  INFO restore activation failed activation=a1 stage=exposure'
        ' code=bind-failed detail="port 80 busy"',
        '2026-11-06T10:00:02.000000Z  INFO restore prepared without fields',
        '2026-11-06T10:00:02.000000Z  INFO restore thaw recovery frozen activation=a1',
        'not a trace line restore prepared activation=a1',
    ])
    found = lifecycle.events(text)
    assert [event.name for event in found] == [lifecycle.PREPARED, lifecycle.GENERATION_ACKNOWLEDGED,
                                               lifecycle.FAILED, lifecycle.THAW_RECOVERY_FROZEN]
    assert lifecycle.single_activation(found) == "a1"
    assert found[1].fields["sequence"] == "2"
    assert found[2].fields == {"activation": "a1", "stage": "exposure", "code": "bind-failed",
                               "detail": "port 80 busy"}
    assert found[1].realtime_ns - found[0].realtime_ns == 499_999_000
    assert found[2].realtime_ns % 1_000_000_000 == 123_456_789
    with pytest.raises(AssertionError):
        lifecycle.assert_not_logged(found, lifecycle.FAILED)
    with pytest.raises(AssertionError):
        lifecycle.single_activation(found + lifecycle.events(
            '2026-11-06T10:00:03Z  INFO restore prepared activation=a2'))


def _pcap(frames: list[tuple[int, int, bytes]], *, nanoseconds: bool) -> bytes:
    data = struct.pack("<IHHiIII", 0xA1B23C4D if nanoseconds else 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for seconds, fraction, frame in frames:
        data += struct.pack("<IIII", seconds, fraction, len(frame), len(frame)) + frame
    return data


def test_netd_capture_rejects_raw_ip_without_mac_evidence() -> None:
    frame = _udp_frame("02:00:00:00:00:22", "192.168.64.2", b"payload")
    raw = bytearray(_pcap([(5, 0, frame[14:])], nanoseconds=True))
    struct.pack_into("<I", raw, 20, 101)  # gVisor's stack-level LINKTYPE_RAW
    with pytest.raises(AssertionError, match="not Ethernet"):
        lifecycle.pcap_frames(bytes(raw))


def _udp_frame(source_mac: str, source_ip: str, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", 40000, 9, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                         ipaddress.IPv4Address(source_ip).packed,
                         ipaddress.IPv4Address("192.168.64.254").packed)
    return (bytes.fromhex(lifecycle.GATEWAY_MAC.replace(":", "")) + bytes.fromhex(source_mac.replace(":", ""))
            + b"\x08\x00" + header + udp)


def test_netd_capture_parser_and_identity_oracle_use_real_frame_bytes(tmp_path: Path) -> None:
    child = lifecycle.Identity("02:00:00:00:00:22", "192.168.64.2", 24, "192.168.64.1")
    source = lifecycle.Identity("02:00:00:00:00:11", "192.168.63.2", 24, "192.168.63.1")
    datagram = b"SILO-RN-UDP pid=7 seq=12 uuid=0f8fad5b-d9cb-469f-a165-70867728950e\n"
    good = _udp_frame(child.mac, child.ipv4, datagram)
    for nanoseconds, fraction, expected in ((False, 250, 250_000), (True, 250, 250)):
        data = _pcap([(5, fraction, good), (6, 0, good)], nanoseconds=nanoseconds)
        frames = lifecycle.pcap_frames(data + b"\x01\x02\x03")  # torn live tail
        assert [frame.realtime_ns for frame in frames] == [5_000_000_000 + expected, 6_000_000_000]
    parsed = lifecycle.datagrams(frames, source_ip=child.ipv4)
    assert [(entry.pid, entry.sequence, entry.uuid) for entry in parsed] == [
        (7, 12, "0f8fad5b-d9cb-469f-a165-70867728950e")] * 2
    assert lifecycle.datagrams(frames, source_ip=source.ipv4) == []
    assert lifecycle.assert_identity_only(frames, allowed=child, forbidden=source,
                                          record=tmp_path / "clean.json")["violations"] == []
    eui = bytes([0x00, 0, 0, 0xFF, 0xFE, 0, 0, 0x11])
    ipv6 = (bytes.fromhex("333300000001") + bytes.fromhex(child.mac.replace(":", "")) + b"\x86\xdd"
            + bytes([0x60, 0, 0, 0]) + struct.pack("!HBB", 0, 58, 255)
            + bytes.fromhex("fe80000000000000") + eui + bytes(16))
    for bad in (_udp_frame(source.mac, child.ipv4, datagram), _udp_frame(child.mac, source.ipv4, datagram),
                _udp_frame("02:00:00:00:00:33", child.ipv4, datagram), ipv6):
        frames = lifecycle.pcap_frames(_pcap([(1, 0, bad)], nanoseconds=False))
        with pytest.raises(AssertionError):
            lifecycle.assert_identity_only(frames, allowed=child, forbidden=source, record=tmp_path / "bad.json")


def test_follower_keeps_new_files_after_unlink_and_ignores_existing(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    (root / "source").mkdir(parents=True)
    (root / "source/vm.trace.log").write_text("source\n")
    follower = lifecycle.Follower(root, "*/vm.trace.log", tmp_path / "copies")
    try:
        assert follower.ignored_paths() == [str(root / "source/vm.trace.log")]
        (root / "child").mkdir()
        log = root / "child/vm.trace.log"
        with log.open("w") as output:
            output.write("first\n")
            output.flush()
            shutdown.until(lambda: follower.files() == {"child/vm.trace.log": b"first\n"}, timeout=5,
                           description="follower missed the new file")
            log.unlink()
            output.write("second\n")
        shutdown.until(lambda: follower.files() == {"child/vm.trace.log": b"first\nsecond\n"}, timeout=5,
                       description="follower lost bytes written after unlink")
    finally:
        follower.close()
    assert (tmp_path / "copies/child__vm.trace.log").read_bytes() == b"first\nsecond\n"


@pytest.mark.slow
def test_restore_exposes_only_the_fresh_destination_after_final_release(
    silo: Silo, restore_network_image: str,  # noqa: F811
) -> None:
    """Activation, Fence and Network-and-sessions gates on the positive path."""
    captured: dict[str, object] = {}
    child = "restore-net-child"

    def stop_forward(forward: subprocess.Popen[bytes]) -> None:
        if forward.poll() is None:
            forward.send_signal(signal.SIGINT)
        output, errors = forward.communicate(timeout=15)
        silo.ws.record("restore-session-forward", f"stdout: {output!r}\nstderr: {errors!r}\n")

    with ExitStack() as cleanup:
        def sessions(machine: str, workload: dict) -> None:
            reply = lifecycle.forward_reply(lifecycle.runtime_socket(silo, machine, "svc.sock"))
            assert reply.startswith(f"SILO-RN-SVC pid={workload['pid']} ".encode()), reply
            stream = lifecycle.SessionStream(silo, SOURCE, f"{lifecycle.STATE}/session")
            cleanup.callback(stream.close)
            stream.advances()
            port = procs.free_port()
            forward = silo.popen("forward", SOURCE, f"{port}:{lifecycle.LISTEN_PORT}",
                                 stdin=subprocess.DEVNULL)
            cleanup.callback(stop_forward, forward)
            assert forward.stdout is not None
            status = forward.stdout.readline()
            assert status.startswith(b"Forwarding host:tcp:127.0.0.1:"), status
            captured.update(stream=stream, port=port)

        source = cleanup.enter_context(lifecycle.networked_source(
            silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD, before_capture=sessions))
        stream, session_port = captured["stream"], captured["port"]
        assert isinstance(stream, lifecycle.SessionStream)
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / "restore-positive-states.json")
        children = None
        try:
            stream.stationary()
            restored = restore.restore(silo, source.saved.reference, child, expect=0)
            machine = UUID(restored.stdout.strip()).hex
            assert machine == evidence.machine_hex()
            children = lifecycle.ChildProcesses.observe(silo, machine)
            found = evidence.events()
            assert_completed(found, BOUND_LISTENERS)
            committing = lifecycle.first(found, lifecycle.EXPOSURE_COMMITTING).realtime_ns
            committed = lifecycle.first(found, lifecycle.EXPOSURE_COMMITTED).realtime_ns
            identity = lifecycle.guest_identity(silo, child)
            # The guest's own interface is exactly the reservation bound into
            # the restore request; only the MAC is required to differ, since
            # isolated private networks may hand out the same address.
            assert identity == lifecycle.requested_network(silo, machine), identity
            assert identity.mac != source.identity.mac, "child kept the source MAC"

            # Exposure: every child frame at netd follows the final release and
            # carries only the reserved destination identity.
            shutdown.until(
                lambda: len(lifecycle.datagrams(evidence.frames(), source_ip=identity.ipv4)) >= 10,
                timeout=20, description="restored sender produced no destination traffic after release")
            frames = evidence.frames()
            early = [frame.json() for frame in frames if frame.realtime_ns < committing]
            assert not early, f"netd saw child frames before final release: {early[:4]}"
            lifecycle.assert_identity_only(frames, allowed=identity, forbidden=source.identity,
                                           record=silo.ws.evidence / "restore-positive-identity.json")
            sent = lifecycle.datagrams(frames)
            assert {datagram.pid for datagram in sent} == {source.workload["pid"]}
            sequences = [datagram.sequence for datagram in sent]
            assert sequences == sorted(set(sequences)) and sequences[0] > source.cut_floor, (
                "restored sender restarted, repeated or replayed pre-cut traffic", source.cut_floor, sequences[:4])
            delivered = {datagram.uuid for datagram in source.peers.datagrams(since_ns=committing)}
            assert delivered & {datagram.uuid for datagram in sent}, "netd did not route child traffic to the host"

            # Running is published only after the native exposure commit.
            running = shutdown.until(lambda: sampler.first("running"), timeout=10,
                                     description="catalog never published Running")
            assert running > committed, (running, committed, sampler.samples)
            before = sampler.statuses()[:sampler.statuses().index("running")]
            assert set(before) <= {None, "restoring", "activating"}, before

            # The captured workload continues; its listener serves the rebound forward.
            status = lifecycle.progress(silo, child)
            assert status["pid"] == source.workload["pid"] and status["udpSeq"] > source.cut_floor
            reply = lifecycle.forward_reply(lifecycle.runtime_socket(silo, machine, "svc.sock"))
            assert reply.startswith(f"SILO-RN-SVC pid={source.workload['pid']} ".encode()), reply

            # Old TCP, exec sessions and session forwards are not resurrected.
            assert not [record for record in source.peers.tcp_records()
                        if record["acceptedNs"] > source.paused_ns], "child reopened the captured TCP stream"
            shutdown.until(lambda: lifecycle.progress(silo, child)["tcpEstablished"] is False,
                           timeout=30, description="captured TCP stream survived activation")
            listed = silo.run("forward", child, "--list").stdout
            assert f":{session_port}" not in listed, f"session forward resurrected in child: {listed}"
            record = f"{lifecycle.STATE}/session/stream"
            first_read = silo.exec(child, "cat", record, user="root").stdout
            time.sleep(1)
            assert silo.exec(child, "cat", record, user="root").stdout == first_read, (
                "captured exec session kept streaming in the child")
            stream.stationary(0.5)

            # Fresh generation: identical RAM, divergent randomness per sequence.
            silo.run("resume", SOURCE)
            stream.advances()
            source_pcap = lifecycle.network_capture(silo, SOURCE)
            latest = max(sequences)

            def overlap() -> dict[int, tuple[str, str]] | None:
                source_sent = {datagram.sequence: datagram.uuid
                               for datagram in lifecycle.datagrams(lifecycle.pcap_frames(source_pcap.read_bytes()),
                                                                   source_ip=source.identity.ipv4)}
                if max(source_sent, default=0) < latest:
                    return None
                child_sent = {datagram.sequence: datagram.uuid
                              for datagram in lifecycle.datagrams(evidence.frames(), source_ip=identity.ipv4)}
                return {sequence: (source_sent[sequence], child_sent[sequence])
                        for sequence in set(source_sent) & set(child_sent)}

            pairs = shutdown.until(overlap, timeout=30, description="resumed source sent no overlap")
            silo.ws.record("restore-randomness-overlap", json.dumps(pairs, sort_keys=True) + "\n")
            assert pairs and all(left != right for left, right in pairs.values()), (
                "child repeated the source's post-cut randomness")
            # The whole child wire, including keepalives of the captured stream
            # and everything after the session checks, never used the source identity.
            lifecycle.assert_identity_only(evidence.frames(), allowed=identity, forbidden=source.identity,
                                           record=silo.ws.evidence / "restore-positive-identity-final.json")
            silo.stop(child)
            children.reaped()
        finally:
            sampler.close()
            evidence.close()
            if children is not None:
                children.close()


@pytest.mark.slow
@pytest.mark.parametrize("ack", ["late", "missing"])
def test_restore_generation_acknowledgement_missing_or_late_fails_closed(
    silo: Silo, restore_network_image: str, ack: str,  # noqa: F811
) -> None:
    """The only vCPU is held at its first KVM_RUN after the fresh generation is
    installed, so the guest cannot acknowledge within 5s. A late ACK after the
    deadline must not complete activation; nothing crosses the fence."""
    child = f"restore-ack-{ack}"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        machine = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-vcpu-run", lifecycle.GENERATION_INSTALLED,
                                          evidence.trace.ignored_paths()) as traced:
                held = traced.held()
                assert held["thread"].startswith("fc_vcpu"), held
                machine = evidence.machine_hex()
                installed = evidence.wait(lifecycle.GENERATION_INSTALLED, timeout=30)
                expired = evidence.wait(lifecycle.GENERATION_EXPIRED, timeout=30)
                assert expired.realtime_ns - installed.realtime_ns >= 4_950_000_000, (installed, expired)
                assert silo.info(child)["state"] in {"restoring", "activating"}, "held child is not nonterminal"
                if ack == "late":
                    traced.release()
                result = traced.manager_result()
                traced.finish()
            found = assert_failed_closed(silo, child, evidence, sampler, result, machine)
            lifecycle.assert_not_logged(found, lifecycle.GENERATION_ACKNOWLEDGED, lifecycle.ACTIVATE_SENDING,
                                        lifecycle.LISTENER_BOUND, lifecycle.THAW_SENDING)
            ordered(found, lifecycle.PREPARED, lifecycle.GENERATION_INSTALLED, lifecycle.GENERATION_EXPIRED)
            if ack == "late":
                failed = lifecycle.failure(found)
                assert failed.fields.get("stage") == "acknowledgement", failed.line
                assert failed.fields.get("code") == "clock-generation-failed", failed.line
            assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")
            source.unchanged(silo)
            if ack == "late":
                # The checkpoint stays restorable under a new run.
                retry = f"{child}-retry"
                restore.restore(silo, source.saved.reference, retry, expect=0)
                assert silo.wait_ready(retry)["run_id"] != source.info["run_id"]
                silo.stop(retry)
        finally:
            evidence.close()


@pytest.mark.slow
def test_restore_undelivered_activate_fails_closed(
    silo: Silo, restore_network_image: str,  # noqa: F811
) -> None:
    """The worker's vsock muxer is held once Activate is about to be sent: the
    30s Activate bound expires with the workload still frozen and fenced."""
    child = "restore-activate-lost"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        machine = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-guest-transport", lifecycle.ACTIVATE_SENDING,
                                          evidence.trace.ignored_paths()) as traced:
                assert traced.held()["thread"] == "vsock muxer"
                machine = evidence.machine_hex()
                time.sleep(WIRE_FREE)
                assert silo.info(child)["state"] == "activating", "held Activate is not reported as activating"
                result = traced.manager_result(timeout=120)
                traced.finish()
            found = assert_failed_closed(silo, child, evidence, sampler, result, machine)
            terminal = lifecycle.FAILED if lifecycle.named(found, lifecycle.FAILED) else lifecycle.REAPING
            ordered(found, lifecycle.GENERATION_ACKNOWLEDGED, lifecycle.ACTIVATE_SENDING, terminal)
            lifecycle.assert_not_logged(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.LISTENER_BOUND,
                                        lifecycle.THAW_SENDING)
            settled = lifecycle.first(found, terminal)
            sent = lifecycle.first(found, lifecycle.ACTIVATE_SENDING)
            assert settled.realtime_ns - sent.realtime_ns >= 29_900_000_000, (sent.line, settled.line)
            assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")
            source.unchanged(silo)
        finally:
            evidence.close()


@pytest.mark.slow
def test_restore_listener_conflict_fails_closed_without_taking_the_source_listener(
    silo: Silo, restore_network_image: str,  # noqa: F811
) -> None:
    """A machine forward whose host TCP port the paused source still owns:
    the child's fenced bind fails, the source keeps its listener, and after
    the source stops the same checkpoint rebinds that port in a new child."""
    port = procs.free_port()
    tcp_forward = f"host:tcp:127.0.0.1:{port}=guest:tcp:127.0.0.1:{lifecycle.LISTEN_PORT}"
    child = "restore-listener-conflict"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", tcp_forward) as source:
        monitor = shutdown.holder(silo, SOURCE)[0]
        owner = next(entry["pid"] for entry in monitor["holders"] if entry["role"] == "monitor")
        before = listening_owner(port)
        assert before is not None and before[1] == owner, (before, owner)
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        try:
            restored = restore.restore(silo, source.saved.reference, child)
            machine = evidence.machine_hex() if evidence.trace.only() is not None else None
            found = assert_failed_closed(silo, child, evidence, sampler,
                                         (restored.returncode, restored.stdout, restored.stderr), machine)
            failed = lifecycle.failure(found)
            assert (failed.fields.get("stage"), failed.fields.get("code")) == ("exposure", "bind-failed"), failed.line
            ordered(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.FAILED)
            lifecycle.assert_not_logged(found, lifecycle.LISTENER_BOUND, lifecycle.THAW_SENDING)
            assert_fenced_wire(evidence, None, silo.ws.evidence / f"{child}-wire.json")
            assert listening_owner(port) == before, "failed child took or closed the source listener"
            source.unchanged(silo)
        finally:
            evidence.close()
        silo.stop(SOURCE)
        rebound = "restore-listener-rebound"
        restore.restore(silo, source.saved.reference, rebound, expect=0)
        silo.wait_ready(rebound)
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            reply = connection.recv(4096)
        assert reply.startswith(f"SILO-RN-SVC pid={source.workload['pid']} ".encode()), reply
        silo.stop(rebound)


def listening_owner(port: int) -> tuple[int, int] | None:
    """(socket inode, owning pid) of the host's listening 127.0.0.1:port."""
    inode = None
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == f"0100007F:{port:04X}" and fields[3] == "0A":
            inode = int(fields[9])
    if inode is None:
        return None
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            for descriptor in (process / "fd").iterdir():
                if descriptor.readlink() == Path(f"socket:[{inode}]"):
                    return inode, int(process.name)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return inode, -1


@pytest.mark.slow
@pytest.mark.parametrize("hook", ["exit", "timeout"])
def test_restore_failed_activation_hook_fails_closed(
    silo: Silo, restore_network_image: str, hook: str,  # noqa: F811
) -> None:
    """The selected hook fails inside Activate: no listener, Thaw or release."""
    script = {"exit": ("exit 7", 5000), "timeout": ("exec sleep 30", 500)}[hook]
    selected = json.dumps({"argv": ["/bin/sh", "-c", script[0]], "environment": [],
                           "workingDirectory": "/", "timeoutMs": script[1]})
    child = f"restore-hook-{hook}"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        try:
            restored = restore.restore(silo, source.saved.reference, child, "--activation-hook", selected)
            machine = evidence.machine_hex() if evidence.trace.only() is not None else None
            found = assert_failed_closed(silo, child, evidence, sampler,
                                         (restored.returncode, restored.stdout, restored.stderr), machine)
            ordered(found, lifecycle.ACTIVATE_SENDING, lifecycle.FAILED)
            lifecycle.assert_not_logged(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.LISTENER_BOUND,
                                        lifecycle.THAW_SENDING)
            assert_fenced_wire(evidence, None, silo.ws.evidence / f"{child}-wire.json")
            source.unchanged(silo)
        finally:
            evidence.close()


@pytest.mark.slow
@pytest.mark.parametrize("recovery", ["refrozen", "reaped"])
def test_restore_lost_thaw_acknowledgement_refreezes_or_reaps(
    silo: Silo, restore_network_image: str, recovery: str,  # noqa: F811
) -> None:
    """The guest thaws but its real THAWED reply is held at the native socket
    write, whether the virtio event owner or muxer forwards it. After the Thaw
    bound the monitor re-freezes (released hold) or, unable to deliver
    FreezeWorkloads (kept hold), reaps the child. No thawed traffic reaches wire."""
    child = f"restore-thaw-{recovery}"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        machine = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-transport-reply", lifecycle.THAW_SENDING,
                                          evidence.trace.ignored_paths()) as traced:
                traced.held_thaw_reply(evidence.wait(lifecycle.THAW_SENDING, timeout=180))
                machine = evidence.machine_hex()
                freezing = evidence.wait(lifecycle.THAW_RECOVERY_FREEZING, timeout=60)
                sent = lifecycle.first(evidence.events(), lifecycle.THAW_SENDING)
                assert freezing.realtime_ns - sent.realtime_ns >= 14_900_000_000, (sent.line, freezing.line)
                assert silo.info(child)["state"] == "activating", "held Thaw is not reported as activating"
                if recovery == "refrozen":
                    traced.release()
                result = traced.manager_result(timeout=120)
                traced.finish()
            found = assert_failed_closed(silo, child, evidence, sampler, result, machine)
            lifecycle.assert_not_logged(found, lifecycle.THAW_ACKNOWLEDGED)
            ordered(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.LISTENER_BOUND, lifecycle.THAW_SENDING,
                    lifecycle.THAW_RECOVERY_FREEZING)
            if recovery == "refrozen":
                ordered(found, lifecycle.THAW_RECOVERY_FREEZING, lifecycle.THAW_RECOVERY_FROZEN, lifecycle.FAILED)
                failed = lifecycle.failure(found)
                assert (failed.fields.get("stage"), failed.fields.get("code")) == ("exposure", "thaw-unacknowledged"), failed.line
            else:
                lifecycle.assert_not_logged(found, lifecycle.THAW_RECOVERY_FROZEN)
                ordered(found, lifecycle.THAW_RECOVERY_FREEZING, lifecycle.REAPING)
            assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")
            source.unchanged(silo)
        finally:
            evidence.close()


@pytest.mark.slow
def test_restore_refrozen_activation_failed_is_stop_only_with_manager_suspended(
    silo: Silo, restore_network_image: str,  # noqa: F811
) -> None:
    """Suspend (not kill) the restore owner so it cannot clean up FAILED.

    The real lost THAWED reply triggers the production recovery deadline;
    the refrozen child must remain inspectable, fenced and strictly stop-only
    until a separate CLI stop reaps it. Manager death is a different gate.
    """
    child = "restore-stop-only-failed"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        children = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-transport-reply", lifecycle.THAW_SENDING,
                                          evidence.trace.ignored_paths()) as traced:
                try:
                    # Keep the pidfd until cleanup; even a failed assertion must
                    # resume/kill this exact owner before finishing the tracer.
                    manager = traced.manager()
                    with shutdown.owned_processes(manager):
                        sent = evidence.wait(lifecycle.THAW_SENDING, timeout=180)
                        traced.held_thaw_reply(sent)
                        # Ordinary tracing consumes SIGSTOP. Opt only this
                        # retained manager into real group-stop detachment;
                        # the held child reply and native wire remain traced.
                        (traced.evidence / "restore-manager-detach.json").write_text(
                            json.dumps({"pid": manager.pid}) + "\n")
                        manager.send(signal.SIGSTOP)
                        shutdown.until(manager.stopped, description="restore manager did not stop")
                        machine = evidence.machine_hex()
                        children = lifecycle.ChildProcesses.observe(silo, machine)
                        freezing = evidence.wait(lifecycle.THAW_RECOVERY_FREEZING, timeout=60)
                        assert freezing.realtime_ns - sent.realtime_ns >= 14_900_000_000, (
                            sent.line, freezing.line)
                        assert silo.info(child)["state"] == "activating"
                        traced.release()
                        evidence.wait(lifecycle.THAW_RECOVERY_FROZEN, timeout=60)
                        evidence.wait(lifecycle.FAILED, timeout=30)
                        shutdown.until(lambda: silo.info(child)["state"] == "activation-failed",
                                       description="refrozen child did not publish ActivationFailed")
                        assert manager.stopped() and not manager.terminal()
                        assert all(not process.terminal() for process in children.processes.values())
                        found = evidence.events()
                        lifecycle.single_activation(found)
                        ordered(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.LISTENER_BOUND,
                                lifecycle.THAW_SENDING, lifecycle.THAW_RECOVERY_FREEZING,
                                lifecycle.THAW_RECOVERY_FROZEN, lifecycle.FAILED)
                        failed = lifecycle.failure(found)
                        assert (failed.fields.get("stage"), failed.fields.get("code")) == (
                            "exposure", "thaw-unacknowledged"), failed.line
                        assert sorted(event.fields.get("listener")
                                      for event in lifecycle.named(found, lifecycle.LISTENER_BOUND)) == sorted(BOUND_LISTENERS)

                        # Compare entire rows, not counts: rejection must neither
                        # insert an intent nor mutate an already recorded command.
                        def command_rows() -> list[tuple]:
                            with closing(sqlite3.connect(
                                f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=1,
                            )) as connection:
                                return connection.execute("SELECT * FROM live_command ORDER BY rowid").fetchall()

                        commands = command_rows()
                        for action in ("start", "resume", "pause"):
                            refused = silo.run(action, child, expect=None)
                            assert refused.returncode != 0, (action, refused.stdout, refused.stderr)
                            assert command_rows() == commands, action
                            assert silo.info(child)["state"] == "activation-failed", action
                            assert manager.stopped() and not manager.terminal()
                            for endpoint in ("svc.sock", "vsock.sock"):
                                assert lifecycle.unix_refused(lifecycle.runtime_socket(silo, machine, endpoint)), endpoint
                        time.sleep(WIRE_FREE)
                        lifecycle.assert_not_logged(evidence.events(), *AFTER_FAILURE,
                                                    lifecycle.THAW_ACKNOWLEDGED, lifecycle.REAPING)
                        assert sampler.first("running") is None, sampler.samples
                        assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")

                        with (silo.ws.evidence / f"{child}-stop.stdout").open("wb") as output, \
                                (silo.ws.evidence / f"{child}-stop.stderr").open("wb") as errors:
                            stopper = silo.popen("stop", child, "--timeout", "20s",
                                                 stdout=output, stderr=errors)
                        with shutdown.owned_processes(shutdown.Process(stopper.pid)):
                            # Admission must terminate both child processes
                            # without the restore manager making any progress.
                            # Its launch lease remains owned until startup ends.
                            for process in children.processes.values():
                                process.wait(timeout=60)
                            assert manager.stopped() and not manager.terminal()
                            lifecycle.assert_not_logged(evidence.events(), *AFTER_FAILURE,
                                                        lifecycle.THAW_ACKNOWLEDGED)
                            assert sampler.first("running") is None, sampler.samples
                            assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-stop-wire.json")
                            manager.send(signal.SIGCONT)
                            assert stopper.wait(timeout=60) == 0, (
                                silo.ws.evidence / f"{child}-stop.stderr").read_text(errors="replace")
                            manager.wait(timeout=60)
                            children.reaped()
                except BaseException:
                    # A refrozen failed monitor can outlive its restore owner.
                    # Kill only retained child identities before waiting for
                    # the tracer; the outer finally alone closes these pidfds.
                    if children is not None:
                        for process in children.processes.values():
                            if not process.terminal():
                                try:
                                    process.send(signal.SIGCONT)
                                    process.send(signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                        children.reaped()
                    raise
                finally:
                    # The driver owns waitpid: its result proves the manager was
                    # reaped, while finish drains the native syscall controller.
                    try:
                        code, stdout, stderr = traced.manager_result(timeout=60)
                        assert code != 0 and not stdout.strip(), (code, stdout, stderr)
                    finally:
                        traced.finish()
            sampler.close()
            assert sampler.first("running") is None, sampler.samples
            lifecycle.assert_not_logged(evidence.events(), *AFTER_FAILURE, lifecycle.THAW_ACKNOWLEDGED)
            assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire-final.json")
            source.unchanged(silo)
        finally:
            sampler.close()
            evidence.close()
            if children is not None:
                children.close()


@pytest.mark.slow
def test_restore_manager_death_during_unacknowledged_thaw_reaps_child(
    silo: Silo, restore_network_image: str,  # noqa: F811
) -> None:
    """Manager death cancels startup during an uncertain Thaw. The monitor
    reaps rather than leaving an unowned, potentially thawed child running."""
    child = "restore-orphan-failed"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        sealed = source.sealed_progress()
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        children = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-transport-reply", lifecycle.THAW_SENDING,
                                          evidence.trace.ignored_paths()) as traced:
                traced.held_thaw_reply(evidence.wait(lifecycle.THAW_SENDING, timeout=180))
                machine = evidence.machine_hex()
                children = lifecycle.ChildProcesses.observe(silo, machine)
                manager = traced.manager()
                manager.send(signal.SIGKILL)
                manager.wait()
                manager.close()
                assert traced.manager_result()[0] == -signal.SIGKILL
                evidence.wait(lifecycle.REAPING, timeout=60)
                children.reaped()
                found = evidence.events()
                ordered(found, lifecycle.LISTENER_BOUND, lifecycle.THAW_SENDING, lifecycle.REAPING)
                lifecycle.assert_not_logged(found, *AFTER_FAILURE)
                assert lifecycle.unix_refused(lifecycle.runtime_socket(silo, machine, "svc.sock"))
                time.sleep(WIRE_FREE)
                assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")

                traced.finish()
            assert sampler.first("running") is None, sampler.samples
            ran = lifecycle.disk_progress(stopped.writable_paths(silo, child)["root"])
            assert ran["pid"] == sealed["pid"] and ran["udpSeq"] > sealed["udpSeq"] + 10, (
                "thawed workload made no durable progress while fenced", sealed, ran)
            assert silo.info(child)["state"] == "error"
            silo.rm(child)
            source.unchanged(silo)
        finally:
            sampler.close()
            evidence.close()
            if children is not None:
                children.close()


@pytest.mark.slow
@pytest.mark.parametrize("victim", ["manager", "monitor", "krun-worker"])
def test_restore_crash_while_activating(
    silo: Silo, restore_network_image: str, victim: str,  # noqa: F811
) -> None:
    """Kill one startup owner while Activate is held in flight. Manager death
    cancels startup; every victim leaves the child reaped and unexposed."""
    child = f"restore-crash-{victim}"
    with lifecycle.networked_source(silo, restore_network_image, SOURCE, "--forward", UNIX_FORWARD) as source:
        evidence = lifecycle.ChildEvidence(silo, child)
        sampler = lifecycle.StateSampler(silo, child, silo.ws.evidence / f"{child}-states.json")
        children = None
        machine = None
        try:
            with lifecycle.traced_restore(silo, source.saved.reference, source.ram(silo), child,
                                          "restore-guest-transport", lifecycle.ACTIVATE_SENDING,
                                          evidence.trace.ignored_paths()) as traced:
                held = traced.held()
                machine = evidence.machine_hex()
                children = lifecycle.ChildProcesses.observe(silo, machine)
                assert held["pid"] == children.processes["krun-worker"].pid, held
                if victim == "manager":
                    manager = traced.manager()
                    manager.send(signal.SIGKILL)
                    manager.wait()
                    manager.close()
                    assert traced.manager_result()[0] == -signal.SIGKILL
                    traced.release()
                    evidence.wait(lifecycle.REAPING, timeout=90)
                    children.reaped()
                    traced.finish()
                    assert sampler.first("running") is None, sampler.samples
                    lifecycle.assert_not_logged(evidence.events(), *AFTER_FAILURE)
                    assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")
                    assert silo.info(child)["state"] == "error"
                    silo.rm(child)
                else:
                    children.processes[victim].send(signal.SIGKILL)
                    traced.release()
                    result = traced.manager_result(timeout=120)
                    children.reaped()
                    traced.finish()
            if victim != "manager":
                found = assert_failed_closed(silo, child, evidence, sampler, result, machine,
                                             monitor_alive=victim != "monitor")
                lifecycle.assert_not_logged(found, lifecycle.ACTIVATE_ACKNOWLEDGED, lifecycle.LISTENER_BOUND,
                                            lifecycle.THAW_SENDING)
                assert_fenced_wire(evidence, traced, silo.ws.evidence / f"{child}-wire.json")
            source.unchanged(silo)
        finally:
            sampler.close()
            evidence.close()
            if children is not None:
                children.close()
