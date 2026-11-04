"""Actual-netd wire evidence for restored guest activation, never a network backend.

The owner supplies a datagram socket facing the native NIC and another bound,
connected datagram socket facing the real netd. The relay forwards every datagram
unchanged, including VFKT. Only explicitly labelled probe stimuli are generated.
Sockets belong to the relay after construction; processes and socket paths do not.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import selectors
import socket
import shlex
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path


def compile_probe(output: Path) -> Path:
    """Build the standalone static probe, only when called by the smoke owner."""
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2",
               "-Wall", "-Wextra", "-std=c11",
               str(Path(__file__).resolve().parents[2] / "virt/vmm/tests/guest/activation_network.c"),
               "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return output


@dataclass(frozen=True)
class NetworkIdentity:
    mac: str
    ipv4: str
    gateway: str
    prefix_length: int = 24

    def __post_init__(self) -> None:
        _mac(self.mac)
        address = ipaddress.IPv4Address(self.ipv4)
        gateway = ipaddress.IPv4Address(self.gateway)
        network = ipaddress.IPv4Network(f"{address}/{self.prefix_length}", strict=False)
        if address == gateway or gateway not in network:
            raise ValueError("guest and gateway must be distinct addresses in the fixture subnet")
        if address in (network.network_address, network.broadcast_address):
            raise ValueError("guest must be a usable unicast address")
        if gateway in (network.network_address, network.broadcast_address):
            raise ValueError("gateway must be a usable unicast address")


def _mac(value: str) -> bytes:
    fields = value.split(":")
    if len(fields) != 6 or any(len(field) != 2 for field in fields):
        raise ValueError(f"invalid Ethernet MAC: {value!r}")
    result = bytes(int(field, 16) for field in fields)
    if result[0] & 1 or result == bytes(6):
        raise ValueError("fixture MAC must be nonzero unicast")
    return result


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _arp(destination: bytes, peer: bytes, peer_ip: bytes, target_ip: bytes) -> bytes:
    return destination + peer + b"\x08\x06" + struct.pack(
        "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, peer, peer_ip, bytes(6), target_ip)


def _echo(destination: bytes, peer: bytes, peer_ip: bytes, target_ip: bytes,
          identifier: int, sequence: int, nonce: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence) + nonce
    icmp = icmp[:2] + struct.pack("!H", _checksum(icmp)) + icmp[4:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), sequence,
                         0x4000, 64, 1, 0, peer_ip, target_ip)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return destination + peer + b"\x08\x00" + header + icmp


def _ipv4(frame: bytes) -> tuple[bytes, bytes] | None:
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    packet = frame[14:]
    length = (packet[0] & 15) * 4
    total = int.from_bytes(packet[2:4], "big")
    if (packet[0] >> 4 != 4 or length < 20 or total < length or total > len(packet)
            or _checksum(packet[:length]) != 0):
        return None
    return packet[:length], packet[length:total]


@dataclass(frozen=True)
class _Frame:
    sequence: int
    monotonic_ns: int
    direction: str
    tag: str
    data: bytes

    def json(self) -> dict[str, object]:
        return {"sequence": self.sequence, "monotonic_ns": self.monotonic_ns,
                "direction": self.direction, "tag": self.tag,
                "frame_hex": self.data.hex()}


class DatagramRelay:
    """Bounded, loss-intolerant transparent relay with synchronous packet oracles.

    Call start() before starting the native worker. If the native provider does
    not originate VFKT itself, handshake() sends the real handshake to netd.
    Any overflow/truncation/I/O failure invalidates evidence rather than silently
    dropping frames. close() leaves all evidence and process ownership intact.
    """

    def __init__(self, guest: socket.socket, backend: socket.socket, evidence: Path,
                 max_frames: int = 65536, max_bytes: int = 64 * 1024 * 1024) -> None:
        if max_frames < 1 or max_bytes < 65536:
            raise ValueError("relay evidence limits are too small")
        if any(sock.family != socket.AF_UNIX or sock.type != socket.SOCK_DGRAM
               for sock in (guest, backend)):
            raise ValueError("relay requires two Unix datagram sockets")
        self.guest, self.backend = guest, backend
        self.evidence = evidence
        self._output = evidence.open("x", encoding="utf-8", buffering=1)
        self._frames: list[_Frame] = []
        self._byte_count = 0
        self._max_frames, self._max_bytes = max_frames, max_bytes
        self._condition = threading.Condition(threading.RLock())
        self._failure: BaseException | None = None
        self._closed = False
        self._handshake_sent = False
        self._thread: threading.Thread | None = None
        self._wake_read, self._wake_write = socket.socketpair()
        for sock in (guest, backend):
            sock.settimeout(0.5)

    def __enter__(self) -> DatagramRelay:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _healthy(self) -> None:
        if self._failure is not None:
            raise RuntimeError(f"network relay failed; raw evidence: {self.evidence}") from self._failure
        if self._closed:
            raise RuntimeError("network relay is closed")

    def _record(self, direction: str, tag: str, data: bytes) -> _Frame:
        if len(self._frames) >= self._max_frames or self._byte_count + len(data) > self._max_bytes:
            raise RuntimeError("network evidence limit exceeded, capture is incomplete")
        frame = _Frame(len(self._frames) + 1, time.monotonic_ns(), direction, tag, data)
        self._output.write(json.dumps(frame.json(), separators=(",", ":")) + "\n")
        self._frames.append(frame)
        self._byte_count += len(data)
        self._condition.notify_all()
        return frame

    def start(self) -> None:
        with self._condition:
            self._healthy()
            if self._thread is not None:
                raise RuntimeError("relay already started")
            self._thread = threading.Thread(target=self._run, name="guest-netd-relay", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.guest, selectors.EVENT_READ, "guest-to-netd")
                selector.register(self.backend, selectors.EVENT_READ, "netd-to-guest")
                selector.register(self._wake_read, selectors.EVENT_READ, "stop")
                while True:
                    for key, _ in selector.select():
                        if key.data == "stop":
                            return
                        incoming = self.guest if key.data == "guest-to-netd" else self.backend
                        outgoing = self.backend if key.data == "guest-to-netd" else self.guest
                        data, _, flags, _ = incoming.recvmsg(65536)
                        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                            raise RuntimeError("truncated native/netd datagram")
                        with self._condition:
                            if self._closed:
                                return
                            self._record(str(key.data), "transparent", data)
                            if data == b"VFKT" and key.data == "guest-to-netd":
                                self._handshake_sent = True
                            if outgoing.send(data) != len(data):
                                raise RuntimeError("short datagram relay send")
        except BaseException as error:
            with self._condition:
                self._failure = error
                self._output.write(json.dumps({"monotonic_ns": time.monotonic_ns(),
                                               "relay_error": repr(error)}) + "\n")
                self._condition.notify_all()

    def handshake(self) -> None:
        with self._condition:
            self._healthy()
            if self._handshake_sent:
                raise RuntimeError("VFKT handshake already sent")
            self._record("host-to-netd", "vfkit-handshake", b"VFKT")
            if self.backend.send(b"VFKT") != 4:
                raise RuntimeError("short VFKT handshake send")
            self._handshake_sent = True

    def mark(self, label: str) -> int:
        with self._condition:
            self._healthy()
            sequence = len(self._frames)
            self._output.write(json.dumps({"mark": label, "sequence": sequence,
                                           "monotonic_ns": time.monotonic_ns()}) + "\n")
            return sequence

    def inject(self, frame: bytes, tag: str) -> int:
        """Inject explicitly tagged ingress at the child, never through netd policy."""
        if not 14 <= len(frame) <= 65535 or not tag:
            raise ValueError("stimulus requires a bounded Ethernet frame and nonempty tag")
        with self._condition:
            self._healthy()
            recorded = self._record("stimulus-to-guest", tag, frame)
            if self.guest.send(frame) != len(frame):
                raise RuntimeError("short stimulus datagram send")
            return recorded.sequence

    def frames(self, since: int = 0) -> list[dict[str, object]]:
        with self._condition:
            self._healthy()
            return [frame.json() for frame in self._frames if frame.sequence > since]

    def _probe(self, destination: NetworkIdentity, target_ip: str, peer_ip: str,
               peer_mac: bytes, identifier: int, sequence: int, timeout: float,
               label: str, expect_reply: bool) -> dict[str, object]:
        mac = _mac(destination.mac)
        peer = ipaddress.IPv4Address(peer_ip).packed
        target = ipaddress.IPv4Address(target_ip).packed
        nonce = b"silo-activation-" + secrets.token_bytes(24)
        since = self.mark(label)
        arp_sent = self.inject(_arp(b"\xff" * 6, peer_mac, peer, target), label + "/arp")
        icmp_sent = self.inject(_echo(mac, peer_mac, peer, target, identifier, sequence, nonce),
                                label + "/unicast-icmp")
        deadline = time.monotonic() + timeout
        arp_replies: list[int] = []
        icmp_replies: list[int] = []
        cursor = since
        with self._condition:
            while True:
                self._healthy()
                for frame in self._frames[cursor:]:
                    cursor = frame.sequence
                    if frame.direction != "guest-to-netd":
                        continue
                    data = frame.data
                    if (len(data) >= 42 and data[:6] == peer_mac and data[6:12] == mac
                            and data[12:22] == b"\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02"
                            and data[22:28] == mac and data[28:32] == target
                            and data[32:38] == peer_mac and data[38:42] == peer):
                        arp_replies.append(frame.sequence)
                    decoded = _ipv4(data)
                    if decoded is not None:
                        header, payload = decoded
                        if (data[:6] == peer_mac and data[6:12] == mac
                                and header[9] == 1 and header[12:16] == target
                                and header[16:20] == peer and int.from_bytes(header[6:8], "big") & 0x3fff == 0
                                and len(payload) == 8 + len(nonce) and _checksum(payload) == 0
                                and payload[:2] == b"\0\0"
                                and payload[4:8] == struct.pack("!HH", identifier, sequence)
                                and payload[8:] == nonce):
                            icmp_replies.append(frame.sequence)
                if expect_reply and arp_replies and icmp_replies:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
        result = {"label": label, "target_ipv4": target_ip, "peer_ipv4": peer_ip,
                  "destination_mac": destination.mac, "identifier": identifier,
                  "icmp_sequence": sequence, "nonce_hex": nonce.hex(),
                  "arp_sent": arp_sent, "icmp_sent": icmp_sent,
                  "arp_replies": arp_replies, "icmp_replies": icmp_replies,
                  "expect_reply": expect_reply, "completed_monotonic_ns": time.monotonic_ns()}
        with self._condition:
            self._output.write(json.dumps({"probe": result}) + "\n")
        if expect_reply and not (arp_replies and icmp_replies):
            raise AssertionError(f"paired destination positive failed: {result}; {self.evidence}")
        if not expect_reply and (arp_replies or icmp_replies):
            raise AssertionError(f"child still answers old address: {result}; {self.evidence}")
        return result

    @staticmethod
    def _peer(destination: NetworkIdentity, peer_ipv4: str | None) -> tuple[str, bytes]:
        network = ipaddress.IPv4Network(f"{destination.ipv4}/{destination.prefix_length}", strict=False)
        peer_ipv4 = peer_ipv4 or str(network.broadcast_address - 1)
        peer_address = ipaddress.IPv4Address(peer_ipv4)
        if (peer_address not in network or peer_address in
                (network.network_address, network.broadcast_address,
                 ipaddress.IPv4Address(destination.ipv4), ipaddress.IPv4Address(destination.gateway))):
            raise ValueError("test peer must be a distinct usable address in destination subnet")
        peer_mac = bytes.fromhex("0253494c4ffe")
        if peer_mac == _mac(destination.mac):
            raise ValueError("test peer MAC conflicts with destination")
        return peer_ipv4, peer_mac

    def probe_address(self, destination: NetworkIdentity, peer_ipv4: str | None = None,
                      timeout: float = 0.35, label: str = "source-positive") -> dict[str, object]:
        """Establish actual source ARP and unicast-ICMP positives before capture."""
        if not 0.2 <= timeout <= 2:
            raise ValueError("positive probe timeout must be 0.2..2 seconds")
        peer_ipv4, peer_mac = self._peer(destination, peer_ipv4)
        return self._probe(destination, destination.ipv4, peer_ipv4, peer_mac,
                           secrets.randbelow(65535) + 1, 1, timeout, label, True)

    def paired_address_probes(self, destination: NetworkIdentity, old_ipv4: str,
                              peer_ipv4: str | None = None, trials: int = 5,
                              timeout: float = 0.35) -> dict[str, object]:
        """Interleave positive/negative/positive on one wire, at least five trials/one second."""
        if not 5 <= trials <= 32 or not 0.2 <= timeout <= 2:
            raise ValueError("require 5..32 trials with bounded 0.2..2 second observation windows")
        if ipaddress.IPv4Address(old_ipv4) == ipaddress.IPv4Address(destination.ipv4):
            raise ValueError("old and destination IP must differ")
        peer_ipv4, peer_mac = self._peer(destination, peer_ipv4)
        if ipaddress.IPv4Address(peer_ipv4) == ipaddress.IPv4Address(old_ipv4):
            raise ValueError("test peer must differ from old address")
        identifier = secrets.randbelow(65535) + 1
        started = time.monotonic_ns()
        probes: list[dict[str, object]] = []
        for trial in range(trials):
            for phase, target, positive in (("before", destination.ipv4, True),
                                            ("old", old_ipv4, False),
                                            ("after", destination.ipv4, True)):
                probes.append(self._probe(destination, target, peer_ipv4, peer_mac, identifier,
                                          len(probes) + 1, timeout, f"trial-{trial}/{phase}", positive))
        elapsed = time.monotonic_ns() - started
        if elapsed < 1_000_000_000:
            raise AssertionError("old-address observation window was less than one second")
        return {"elapsed_ns": elapsed, "trials": trials, "probes": probes,
                "raw_evidence": str(self.evidence)}

    def assert_no_source_identity(self, source: NetworkIdentity, since: int = 0) -> dict[str, object]:
        """Inspect all child output, not injected ingress or the backend's output."""
        old_mac, old_ip = _mac(source.mac), ipaddress.IPv4Address(source.ipv4).packed
        violations: list[dict[str, object]] = []
        count = 0
        with self._condition:
            self._healthy()
            for frame in self._frames:
                if frame.sequence <= since or frame.direction != "guest-to-netd" or frame.data == b"VFKT":
                    continue
                count += 1
                data = frame.data
                reasons: list[str] = []
                if len(data) < 14:
                    reasons.append("malformed Ethernet output")
                else:
                    if data[6:12] == old_mac:
                        reasons.append("source Ethernet MAC")
                    if data[12:14] == b"\x08\x06" and len(data) >= 42:
                        if data[22:28] == old_mac:
                            reasons.append("source ARP sender MAC")
                        if data[28:32] == old_ip:
                            reasons.append("source ARP sender IPv4")
                    if data[12:14] == b"\x08\x00" and len(data) >= 34 and data[26:30] == old_ip:
                        reasons.append("source IPv4")
                if reasons:
                    violations.append({"sequence": frame.sequence, "reasons": reasons})
        result = {"since": since, "guest_egress_frames": count, "violations": violations,
                  "raw_evidence": str(self.evidence)}
        with self._condition:
            self._output.write(json.dumps({"source_identity_check": result}) + "\n")
        if violations:
            raise AssertionError(f"source network identity escaped on child wire: {result}")
        return result

    def gateway_evidence(self, identity: NetworkIdentity, nonce: str, since: int = 0) -> dict[str, object]:
        """Correlate guest `gateway` probe with actual gateway nonce echo on netd wire."""
        encoded = nonce.encode("ascii")
        if not 1 <= len(encoded) <= 64:
            raise ValueError("gateway nonce must be 1..64 ASCII bytes")
        source, gateway = ipaddress.IPv4Address(identity.ipv4).packed, ipaddress.IPv4Address(identity.gateway).packed
        requests: list[tuple[_Frame, bytes]] = []
        replies: list[tuple[_Frame, bytes]] = []
        with self._condition:
            self._healthy()
            for frame in self._frames:
                if frame.sequence <= since:
                    continue
                decoded = _ipv4(frame.data)
                if decoded is None:
                    continue
                header, payload = decoded
                if (header[9] != 1 or len(payload) != 8 + len(encoded)
                        or int.from_bytes(header[6:8], "big") & 0x3fff
                        or payload[8:] != encoded or _checksum(payload) != 0):
                    continue
                if (frame.direction == "guest-to-netd" and header[12:16] == source
                        and header[16:20] == gateway and payload[:2] == b"\x08\0"
                        and frame.data[6:12] == _mac(identity.mac)):
                    requests.append((frame, payload[4:8]))
                if (frame.direction == "netd-to-guest" and header[12:16] == gateway
                        and header[16:20] == source and payload[:2] == b"\0\0"
                        and frame.data[:6] == _mac(identity.mac)):
                    replies.append((frame, payload[4:8]))
        pairs = [{"request_sequence": request.sequence, "reply_sequence": reply.sequence,
                  "identifier": int.from_bytes(key[:2], "big"), "icmp_sequence": int.from_bytes(key[2:], "big")}
                 for request, key in requests for reply, reply_key in replies
                 if key == reply_key and request.sequence < reply.sequence]
        result = {"gateway": identity.gateway, "source_ipv4": identity.ipv4, "source_mac": identity.mac,
                  "nonce": nonce, "pairs": pairs, "raw_evidence": str(self.evidence)}
        with self._condition:
            self._output.write(json.dumps({"gateway_check": result}) + "\n")
        if not pairs:
            raise AssertionError(f"no actual netd gateway nonce reply: {result}")
        return result

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._wake_write.send(b"x")
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("network relay did not stop within two seconds")
            if self._failure is not None:
                raise RuntimeError(f"network relay failed: {self.evidence}") from self._failure
        finally:
            for sock in (self.guest, self.backend, self._wake_read, self._wake_write):
                sock.close()
            self._output.close()
