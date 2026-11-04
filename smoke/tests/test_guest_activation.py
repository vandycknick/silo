"""Host-only unit tests for restored-guest helpers: real sockets and bytes, no VM."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct

import pytest

from silo_smoke import guest_activation_network as network
from silo_smoke import guest_restored, guest_restored_session

DESTINATION = network.NetworkIdentity("02:00:00:00:00:02", "192.168.128.2", "192.168.128.1")
PEER_MAC = bytes.fromhex("0253494c4ffe")


def _line(stream: socket.socket) -> bytes:
    stream.settimeout(5)
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = stream.recv(1)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def test_network_identity_rejects_invalid_fixture_addresses() -> None:
    for arguments in (("01:00:00:00:00:02", "192.168.128.2", "192.168.128.1"),
                      ("00:00:00:00:00:00", "192.168.128.2", "192.168.128.1"),
                      ("02:00:00:00:00", "192.168.128.2", "192.168.128.1"),
                      ("02:00:00:00:00:02", "192.168.128.2", "192.168.1.1"),
                      ("02:00:00:00:00:02", "192.168.128.1", "192.168.128.1"),
                      ("02:00:00:00:00:02", "192.168.128.0", "192.168.128.1"),
                      ("02:00:00:00:00:02", "192.168.128.255", "192.168.128.1"),
                      ("02:00:00:00:00:02", "192.168.128.2", "192.168.128.255")):
        with pytest.raises(ValueError):
            network.NetworkIdentity(*arguments)


def test_internet_checksum_matches_rfc1071_vector() -> None:
    assert network._checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220d
    assert network._checksum(b"\x01") == 0xfeff


def test_probe_frames_are_well_formed_and_corruption_is_rejected() -> None:
    peer = ipaddress.IPv4Address("192.168.128.254").packed
    target = ipaddress.IPv4Address(DESTINATION.ipv4).packed
    destination = network._mac(DESTINATION.mac)
    frame = network._echo(destination, PEER_MAC, peer, target, 0x1234, 7, b"nonce")
    assert frame[:6] == destination and frame[6:12] == PEER_MAC and frame[12:14] == b"\x08\x00"
    decoded = network._ipv4(frame)
    assert decoded is not None
    header, payload = decoded
    assert network._checksum(header) == 0 and header[9] == 1
    assert header[12:16] == peer and header[16:20] == target
    assert int.from_bytes(header[6:8], "big") == 0x4000
    assert payload[0] == 8 and network._checksum(payload) == 0
    assert payload[4:8] == struct.pack("!HH", 0x1234, 7) and payload[8:] == b"nonce"
    corrupted = bytearray(frame)
    corrupted[24] ^= 0xff
    assert network._ipv4(bytes(corrupted)) is None
    assert network._ipv4(frame[:30]) is None
    arp = network._arp(b"\xff" * 6, PEER_MAC, peer, target)
    assert len(arp) == 42 and arp[:6] == b"\xff" * 6 and arp[12:14] == b"\x08\x06"
    assert struct.unpack("!HHBBH6s4s6s4s", arp[14:]) == (1, 0x0800, 6, 4, 1, PEER_MAC, peer, bytes(6), target)


def test_relay_forwards_unchanged_and_tags_every_direction(tmp_path: Path) -> None:
    native, guest = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    netd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    backend = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        netd.bind(str(tmp_path / "netd.sock"))
        backend.bind(str(tmp_path / "guest.sock"))
        backend.connect(str(tmp_path / "netd.sock"))
        relay = network.DatagramRelay(guest, backend, tmp_path / "wire.jsonl")
        relay.handshake()
        netd.settimeout(2)
        native.settimeout(2)
        assert netd.recv(65536) == b"VFKT"
        with pytest.raises(RuntimeError):
            relay.handshake()
        relay.start()
        outbound = bytes(range(60))
        native.send(outbound)
        data, address = netd.recvfrom(65536)
        assert data == outbound and address == str(tmp_path / "guest.sock")
        inbound = b"\x01" * 64
        netd.sendto(inbound, str(tmp_path / "guest.sock"))
        assert native.recv(65536) == inbound
        mark = relay.mark("stimulus")
        stimulus = b"\x02" * 60
        sequence = relay.inject(stimulus, "unit-stimulus")
        assert native.recv(65536) == stimulus
        with pytest.raises(ValueError):
            relay.inject(b"short", "unit-stimulus")
        frames = relay.frames()
        assert [(frame["direction"], frame["tag"]) for frame in frames] == [
            ("host-to-netd", "vfkit-handshake"), ("guest-to-netd", "transparent"),
            ("netd-to-guest", "transparent"), ("stimulus-to-guest", "unit-stimulus")]
        assert [frame["frame_hex"] for frame in frames[1:]] == [outbound.hex(), inbound.hex(), stimulus.hex()]
        assert [frame["sequence"] for frame in relay.frames(since=mark)] == [sequence]
        relay.close()
        with pytest.raises(RuntimeError):
            relay.mark("closed")
        records = [json.loads(line) for line in (tmp_path / "wire.jsonl").read_text().splitlines()]
        assert any(record.get("mark") == "stimulus" and record["sequence"] == mark for record in records)
        assert sum("frame_hex" in record for record in records) == 4
    finally:
        for value in (native, netd):
            value.close()


def test_forward_peer_requires_exact_token_and_records_only_digests(tmp_path: Path) -> None:
    peer = guest_restored_session.ForwardPeer(tmp_path / "forward.jsonl")
    token = "00112233445566778899aabbccddeeff"
    peer.register("svc", token)
    with pytest.raises(ValueError):
        peer.register("bad", "00112233")
    replies = []
    for line, payload in ((f"CONNECT {token}\n".encode(), b"nonce-1\n"),
                          (b"CONNECT ffeeddccbbaa99887766554433221100\n", None),
                          (b"CONNECT short\n", None)):
        host, guest = socket.socketpair()
        try:
            peer.serve(len(replies) + 1, 4000, host)
            guest.sendall(line)
            reply = [_line(guest)]
            if payload is not None:
                guest.sendall(payload)
                reply.append(_line(guest))
            replies.append(reply)
        finally:
            guest.close()
    assert replies == [[b"OK\n", b"ECHO nonce-1\n"], [b"ERR not-found\n"], [b"ERR invalid\n"]]
    assert not peer.join(5)
    events = sorted(peer.events(), key=lambda event: event["connection_id"])
    assert [event["listener"] for event in events] == ["svc", None, None]
    assert events[0]["nonce"] == "nonce-1"
    assert events[0]["token_sha256"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in (tmp_path / "forward.jsonl").read_text()



def test_guest_observation_parsers() -> None:
    stat = b"123 (odd) name) S " + b" ".join(str(field).encode() for field in range(4, 23))
    assert guest_restored.proc_starttime(stat) == 22
    tcp = (b"  sl  local_address rem_address   st\n"
           b"   0: 00000000:1BBD 00000000:0000 0A\n"
           b"   1: 0100007F:1C21 00000000:0000 01\n")
    tcp6 = (b"  sl  local_address rem_address   st\n"
            b"   0: 00000000000000000000000000000000:1C22 00000000000000000000000000000000:0000 0A\n")
    assert guest_restored.listening(tcp, 7101)
    assert not guest_restored.listening(tcp, 7201)
    assert guest_restored.listening(tcp + tcp6, 7202)
    assert guest_restored.content_bytes({"encoding": "utf8", "data": "x"}) == b"x"
    assert guest_restored.content_bytes({"encoding": "hex", "data": "00ff"}) == b"\x00\xff"
    with pytest.raises(ValueError):
        guest_restored.content_bytes({"encoding": "base64", "data": ""})
    with pytest.raises(ValueError):
        guest_restored.content_bytes(None)
