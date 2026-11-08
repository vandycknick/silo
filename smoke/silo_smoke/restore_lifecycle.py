"""Real-CLI restore activation, fence and crash-boundary evidence.

Every observation comes from the production path: `silo restore`, the monitor's
own vm.trace.log events, netd's own packet capture (`networking.drivers.netd.pcap`),
real worker syscalls held or recorded by `silo_smoke.stopped_trace`, the catalog
and the guest's durable witness. Nothing here reaches into a monitor or worker,
grants a capability or synthesizes an acknowledgement, packet or state.

Activation events (monitor contract, field `activation=<id>`; "-ing" events are
logged immediately before their action). The lost-Thaw gate waits beyond the
send event for the real guest THAWED response, then holds its native socket write:

    restore prepared -> generation installed -> generation acknowledged
    -> activate sending -> activate acknowledged -> listener bound (per forward)
    -> thaw sending -> thaw acknowledged -> exposure committing
    -> exposure committed -> activation started

Failures: "restore activation failed" stage=<stage> code=<code>, lost-thaw
recovery "restore thaw recovery freezing"/"restore thaw recovery frozen",
ack expiry "restore generation acknowledgement expired", and
"restore activation reaping child" when pause/freeze cannot be re-established.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shlex
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid
from typing import Iterator

import pytest

from . import images, restore, shutdown, stopped
from .cli import Silo
from .config import REPO, SmokeConfig
from .registry import LoopbackRegistry

PROBE = "/usr/local/bin/restore-network"
STATE = "/var/lib/restore-network"
# The upper ext4 keeps the guest-visible tree below this directory.
UPPER = "/upper"
LISTEN_PORT = 7301
# netd's fixed gateway MAC (net/netd/internal/config stackConfig): every frame
# with any other Ethernet source in a netd capture was emitted by the guest.
GATEWAY_MAC = "5a:94:ef:e4:0c:dd"

PREPARED = "restore prepared"
GENERATION_INSTALLED = "restore generation installed"
GENERATION_ACKNOWLEDGED = "restore generation acknowledged"
GENERATION_EXPIRED = "restore generation acknowledgement expired"
ACTIVATE_SENDING = "restore activate sending"
ACTIVATE_ACKNOWLEDGED = "restore activate acknowledged"
LISTENER_BOUND = "restore listener bound"
THAW_SENDING = "restore thaw sending"
THAW_ACKNOWLEDGED = "restore thaw acknowledged"
THAW_RECOVERY_FREEZING = "restore thaw recovery freezing"
THAW_RECOVERY_FROZEN = "restore thaw recovery frozen"
EXPOSURE_COMMITTING = "restore exposure committing"
EXPOSURE_COMMITTED = "restore exposure committed"
STARTED = "restore activation started"
FAILED = "restore activation failed"
REAPING = "restore activation reaping child"
EVENTS = (PREPARED, GENERATION_INSTALLED, GENERATION_ACKNOWLEDGED, GENERATION_EXPIRED,
          ACTIVATE_SENDING, ACTIVATE_ACKNOWLEDGED, LISTENER_BOUND, THAW_SENDING,
          THAW_ACKNOWLEDGED, THAW_RECOVERY_FREEZING, THAW_RECOVERY_FROZEN,
          EXPOSURE_COMMITTING, EXPOSURE_COMMITTED, STARTED, FAILED, REAPING)
SUCCESS_ORDER = (PREPARED, GENERATION_INSTALLED, GENERATION_ACKNOWLEDGED, ACTIVATE_SENDING,
                 ACTIVATE_ACKNOWLEDGED, THAW_SENDING, THAW_ACKNOWLEDGED, EXPOSURE_COMMITTING,
                 EXPOSURE_COMMITTED, STARTED)


def compile_probe(output: Path) -> Path:
    command = [*shlex.split(os.environ.get("CC", "cc")), "-static", "-O2",
               "-Wall", "-Wextra", "-Werror", "-std=c11",
               str(REPO / "virt/vmm/tests/guest/restore_network.c"), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return output


@pytest.fixture(scope="session")
def restore_network_image(config: SmokeConfig, registry: LoopbackRegistry,
                          tmp_path_factory: pytest.TempPathFactory) -> str:
    probe = compile_probe(tmp_path_factory.mktemp("restore-network-probe") / "restore-network")
    spec = replace(images.BASIC, name="restore-network", files={
        **images.BASIC.files, PROBE.lstrip("/"): images.GuestFile(probe.read_bytes(), mode=0o755),
        # Keep namespace and extent mappings in the image, not only in the
        # live ext4 journal: the independent stopped-disk oracle never replays it.
        f"{STATE.lstrip('/')}/progress": images.GuestFile(b" " * 512, mode=0o600),
    })
    return registry.publish(images.build(spec, images.fetch_alpine(config.cache_dir)), "restore-network")


def enable_packet_capture(silo: Silo) -> Path:
    """Select netd's own capture through the ordinary user configuration file."""
    directory = silo.ws.config_home / "silo"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / "config.yaml"
    assert not path.exists(), "packet capture must be selected before any other configuration"
    path.write_text("networking:\n  drivers:\n    netd:\n      pcap: true\n")
    return path


# -- trace events ---------------------------------------------------------------

_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z\s+(\w+)\s+(.*)$")
_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|.*?)(?=\s+\w+=|$)')


@dataclass(frozen=True)
class Event:
    name: str
    realtime_ns: int
    fields: dict[str, str]
    line: str


def _realtime_ns(seconds: str, fraction: str | None) -> int:
    whole = datetime.strptime(seconds, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(whole.timestamp()) * 1_000_000_000 + int((fraction or "0").ljust(9, "0"))


def events(text: str) -> list[Event]:
    """Restore activation events in log order; unknown lines are ignored."""
    found: list[Event] = []
    for line in text.splitlines():
        match = _LINE.match(line)
        if match is None:
            continue
        body = match.group(4)
        for name in EVENTS:
            if body != name and not body.startswith(name + " "):
                continue
            rest = body[len(name):].strip()
            if rest and "=" not in rest.split(" ", 1)[0]:
                continue
            fields = {key: value[1:-1] if value.startswith('"') else value
                      for key, value in _FIELD.findall(rest)}
            found.append(Event(name, _realtime_ns(match.group(1), match.group(2)), fields, line))
            break
    return found


def single_activation(found: list[Event]) -> str:
    activations = {event.fields.get("activation") for event in found}
    assert len(activations) == 1 and None not in activations, (
        f"restore events must name exactly one activation: {[event.line for event in found]}")
    return next(iter(activations))


def named(found: list[Event], name: str) -> list[Event]:
    return [event for event in found if event.name == name]


def first(found: list[Event], name: str) -> Event:
    matches = named(found, name)
    assert matches, f"monitor never logged {name!r}: {[event.line for event in found]}"
    return matches[0]


def failure(found: list[Event]) -> Event:
    failures = named(found, FAILED)
    assert len(failures) == 1, f"expected exactly one activation failure: {[event.line for event in found]}"
    return failures[0]


def assert_not_logged(found: list[Event], *names: str) -> None:
    logged = [event.line for event in found if event.name in names]
    assert not logged, f"activation reached forbidden steps after failing closed: {logged}"


# -- evidence followers ---------------------------------------------------------

class Follower:
    """Copy every newly created matching file as it grows.

    The descriptor is held from first sight, so a restore cleanup that removes
    the child's run or log directory cannot erase evidence written before it.
    Files present at construction (the source's) are never followed.
    """

    def __init__(self, root: Path, pattern: str, evidence: Path) -> None:
        self.root, self.pattern = root, pattern
        self.evidence = evidence
        evidence.mkdir(parents=True, exist_ok=False)
        self._ignored = {self._identity(path) for path in root.glob(pattern)}
        self._ignored.discard(None)
        self._files: dict[tuple[int, int], tuple[str, int, bytearray]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name=f"follow-{pattern}", daemon=True)
        self._thread.start()

    @staticmethod
    def _identity(path: Path) -> tuple[int, int] | None:
        try:
            metadata = path.stat()
        except FileNotFoundError:
            return None
        return metadata.st_dev, metadata.st_ino

    def ignored_paths(self) -> list[str]:
        return [str(path) for path in self.root.glob(self.pattern) if self._identity(path) in self._ignored]

    def _poll(self) -> None:
        for path in self.root.glob(self.pattern):
            identity = self._identity(path)
            if identity is None or identity in self._ignored or identity in self._files:
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except FileNotFoundError:
                continue
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != identity:
                os.close(fd)
                continue
            with self._lock:
                self._files[identity] = (str(path.relative_to(self.root)), fd, bytearray())
        for identity, (relative, fd, buffer) in list(self._files.items()):
            while chunk := os.read(fd, 1 << 20):
                with self._lock:
                    buffer.extend(chunk)
                copy = self.evidence / relative.replace("/", "__")
                with copy.open("ab") as output:
                    output.write(chunk)

    def _run(self) -> None:
        try:
            while not self._stop.wait(0.02):
                self._poll()
        except BaseException as error:  # retained for the owner, never swallowed
            self._failure = error

    def files(self) -> dict[str, bytes]:
        if self._failure is not None:
            raise AssertionError(f"evidence follower failed: {self.evidence}") from self._failure
        with self._lock:
            return {relative: bytes(buffer) for relative, _, buffer in self._files.values()}

    def only(self) -> tuple[str, bytes] | None:
        files = self.files()
        assert len(files) <= 1, f"more than one new {self.pattern}: {sorted(files)}"
        return next(iter(files.items()), None)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        assert not self._thread.is_alive(), "evidence follower did not stop"
        self._poll()
        for _, fd, _ in self._files.values():
            os.close(fd)
        if self._failure is not None:
            raise AssertionError(f"evidence follower failed: {self.evidence}") from self._failure


class ChildEvidence:
    """The restored child's own trace log and netd capture, followed live."""

    def __init__(self, silo: Silo, label: str) -> None:
        base = silo.ws.evidence / f"restore-{label}"
        self.trace = Follower(silo.ws.silo_home / "logs/machines", "*/vm.trace.log", base / "trace")
        self.pcap = Follower(silo.ws.run_root / "networks", "*/capture.pcap", base / "pcap")

    def events(self) -> list[Event]:
        """Complete lines only: a line still being written is not yet an event."""
        found = self.trace.only()
        if found is None:
            return []
        complete = found[1][:found[1].rfind(b"\n") + 1]
        return events(complete.decode(errors="replace"))

    def machine_hex(self) -> str:
        found = self.trace.only()
        assert found is not None, "restore child has no trace log"
        return found[0].split("/", 1)[0]

    def wait(self, name: str, timeout: float) -> Event:
        def logged() -> Event | None:
            matches = named(self.events(), name)
            return matches[0] if matches else None

        return shutdown.until(logged, timeout=timeout, description=f"monitor did not log {name!r}")

    def frames(self) -> list[Frame]:
        found = self.pcap.only()
        return pcap_frames(found[1]) if found is not None else []

    def close(self) -> None:
        try:
            self.trace.close()
        finally:
            self.pcap.close()


# -- netd packet capture --------------------------------------------------------

@dataclass(frozen=True)
class Frame:
    index: int
    realtime_ns: int
    data: bytes

    @property
    def source_mac(self) -> str:
        return ":".join(f"{byte:02x}" for byte in self.data[6:12])

    @property
    def destination_mac(self) -> str:
        return ":".join(f"{byte:02x}" for byte in self.data[:6])

    def ipv4(self) -> tuple[str, str, int, bytes] | None:
        """(source, destination, protocol, payload) for a well-formed IPv4 frame."""
        if len(self.data) < 34 or self.data[12:14] != b"\x08\x00":
            return None
        packet = self.data[14:]
        header = (packet[0] & 15) * 4
        total = int.from_bytes(packet[2:4], "big")
        if packet[0] >> 4 != 4 or header < 20 or total < header or total > len(packet):
            return None
        return (str(ipaddress.IPv4Address(packet[12:16])), str(ipaddress.IPv4Address(packet[16:20])),
                packet[9], packet[header:total])

    def arp(self) -> tuple[str, str, str] | None:
        """(sender MAC, sender IPv4, target IPv4) for an Ethernet/IPv4 ARP frame."""
        if len(self.data) < 42 or self.data[12:14] != b"\x08\x06":
            return None
        body = self.data[14:42]
        return (":".join(f"{byte:02x}" for byte in body[8:14]),
                str(ipaddress.IPv4Address(body[14:18])), str(ipaddress.IPv4Address(body[24:28])))

    def ipv6_interface_ids(self) -> set[bytes]:
        """Low 64 bits of an IPv6 frame's source and destination addresses."""
        if len(self.data) < 54 or self.data[12:14] != b"\x86\xdd" or self.data[14] >> 4 != 6:
            return set()
        return {self.data[30:38], self.data[46:54]}

    def udp_payload(self) -> bytes | None:
        decoded = self.ipv4()
        if decoded is None or decoded[2] != 17 or len(decoded[3]) < 8:
            return None
        return decoded[3][8:]

    def json(self) -> dict[str, object]:
        return {"index": self.index, "realtimeNs": self.realtime_ns, "hex": self.data.hex()}


def pcap_frames(data: bytes) -> list[Frame]:
    """Complete Ethernet records from netd's vfkit datagram capture.

    A torn live tail is not yet a frame. LINKTYPE_RAW cannot prove MAC identity
    and must not be accepted as a substitute for this wire-boundary capture.
    """
    if len(data) < 24:
        return []
    magic = struct.unpack("<I", data[:4])[0]
    assert magic in (0xA1B2C3D4, 0xA1B23C4D), f"not a little-endian pcap: {data[:4].hex()}"
    scale = 1000 if magic == 0xA1B2C3D4 else 1
    assert struct.unpack("<I", data[20:24])[0] == 1, "netd capture is not Ethernet"
    frames, offset = [], 24
    while offset + 16 <= len(data):
        seconds, fraction, included, _ = struct.unpack("<IIII", data[offset:offset + 16])
        if offset + 16 + included > len(data):
            break
        frames.append(Frame(len(frames), seconds * 1_000_000_000 + fraction * scale,
                            data[offset + 16:offset + 16 + included]))
        offset += 16 + included
    return frames


def guest_frames(frames: list[Frame]) -> list[Frame]:
    return [frame for frame in frames if frame.source_mac != GATEWAY_MAC]


def _eui64(mac: str) -> bytes:
    """The modified EUI-64 interface identifier a kernel derives from a MAC."""
    octets = bytes.fromhex(mac.replace(":", ""))
    return bytes([octets[0] ^ 2, octets[1], octets[2], 0xFF, 0xFE, octets[3], octets[4], octets[5]])


@dataclass(frozen=True)
class Datagram:
    realtime_ns: int
    pid: int
    sequence: int
    uuid: str


_UDP = re.compile(rb"^SILO-RN-UDP pid=(\d+) seq=(\d+) uuid=([0-9a-f-]{36})\n$")


def datagrams(frames: list[Frame], *, source_ip: str | None = None) -> list[Datagram]:
    found = []
    for frame in guest_frames(frames):
        payload = frame.udp_payload()
        decoded = frame.ipv4()
        if payload is None or decoded is None:
            continue
        match = _UDP.match(payload)
        if match is None or (source_ip is not None and decoded[0] != source_ip):
            continue
        found.append(Datagram(frame.realtime_ns, int(match.group(1)), int(match.group(2)),
                              match.group(3).decode()))
    return found


def assert_identity_only(frames: list[Frame], *, allowed: Identity, forbidden: Identity,
                         record: Path) -> dict[str, object]:
    """Every guest frame uses the destination identity; nothing in either
    direction carries the source MAC, a source-MAC-derived IPv6 address or,
    when the isolated networks assigned different addresses, the source IPv4."""
    distinct_ipv4 = forbidden.ipv4 != allowed.ipv4
    violations = []
    for frame in frames:
        reasons = []
        if forbidden.mac in (frame.source_mac, frame.destination_mac):
            reasons.append("source MAC")
        decoded, arp = frame.ipv4(), frame.arp()
        if distinct_ipv4 and decoded is not None and forbidden.ipv4 in decoded[:2]:
            reasons.append("source IPv4")
        if arp is not None and (arp[0] == forbidden.mac or (distinct_ipv4 and forbidden.ipv4 in arp[1:])):
            reasons.append("source ARP identity")
        if frame.ipv6_interface_ids() & {_eui64(forbidden.mac)}:
            reasons.append("source MAC-derived IPv6 address")
        if frame.source_mac != GATEWAY_MAC:
            if frame.source_mac != allowed.mac:
                reasons.append("guest frame with foreign MAC")
            if decoded is not None and decoded[0] not in (allowed.ipv4, "0.0.0.0"):
                reasons.append("guest IPv4 not the destination")
            if arp is not None and (arp[0] != allowed.mac or arp[1] not in (allowed.ipv4, "0.0.0.0")):
                reasons.append("guest ARP not the destination")
        if reasons:
            violations.append({**frame.json(), "reasons": reasons})
    result = {"frames": len(frames), "guestFrames": len(guest_frames(frames)),
              "sourceIpv4Distinct": distinct_ipv4, "violations": violations}
    record.write_text(json.dumps(result, indent=2) + "\n")
    assert not violations, f"wrong network identity on the child wire: {record}"
    return result


# -- guest network identity ------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    mac: str
    ipv4: str
    prefix_length: int
    gateway: str

    @property
    def host(self) -> str:
        """netd's host-loopback address: the subnet's last usable address."""
        network = ipaddress.IPv4Network(f"{self.ipv4}/{self.prefix_length}", strict=False)
        return str(network.broadcast_address - 1)


def catalog_mac(silo: Silo, name: str) -> str:
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=5) as connection:
        rows = connection.execute(
            "SELECT a.guest_mac FROM network_attachments a JOIN machine_config c ON c.id=a.machine_id"
            " WHERE c.name=?", (name,)).fetchall()
    assert len(rows) == 1, f"{name} has no single netd attachment"
    return str(rows[0][0]).lower()


def requested_network(silo: Silo, machine_hex: str) -> Identity:
    """The destination identity libvm reserved with netd and bound into the
    child's authenticated restore request (its launch generation record)."""
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=5) as connection:
        rows = connection.execute(
            "SELECT json_extract(json(record_json),'$.restore.request.network') FROM storage_operation"
            " WHERE kind='launch' AND replace(machine_id,'-','')=?", (machine_hex,)).fetchall()
    assert len(rows) == 1 and rows[0][0] is not None, f"child {machine_hex} has no bound restore network: {rows}"
    network = json.loads(rows[0][0])
    return Identity(network["mac"].lower(), network["ipv4"], network["prefixLength"], network["gateway"])


def guest_identity(silo: Silo, name: str) -> Identity:
    """The guest kernel's own view, cross-checked against the catalog's netd MAC."""
    script = ("ip -o -4 addr show scope global; echo ---; ip route show default; echo ---; "
              "for link in /sys/class/net/*; do echo \"${link##*/} $(cat $link/address)\"; done")
    output = silo.exec(name, "sh", "-c", script, user="root").stdout
    addresses, routes, links = (part.strip().splitlines() for part in output.split("---\n"))
    assert len(addresses) == 1, f"expected one global IPv4 address: {addresses}"
    fields = addresses[0].split()
    interface, cidr = fields[1], fields[fields.index("inet") + 1]
    address = ipaddress.IPv4Interface(cidr)
    default = [route.split() for route in routes if route.startswith("default via")]
    assert len(default) == 1 and default[0][default[0].index("dev") + 1] == interface, routes
    mac = dict(line.split() for line in links if len(line.split()) == 2)[interface].lower()
    identity = Identity(mac, str(address.ip), address.network.prefixlen, default[0][2])
    assert identity.mac == catalog_mac(silo, name), "guest MAC differs from the netd reservation"
    silo.ws.record("restore-guest-identity", json.dumps({"machine": name, **identity.__dict__}) + "\n")
    return identity


# -- host peers -------------------------------------------------------------------

class HostPeers:
    """Real host endpoints the guest reaches through netd's host-loopback NAT."""

    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self.tcp = socket.create_server(("127.0.0.1", 0))
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp_port, self.udp_port = self.tcp.getsockname()[1], self.udp.getsockname()[1]
        self.tcp.settimeout(0.2)
        self.udp.settimeout(0.2)
        self.connections: list[dict] = []
        self.received: list[tuple[int, bytes]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._accept, daemon=True),
                         threading.Thread(target=self._receive, daemon=True)]
        for thread in self._threads:
            thread.start()

    def _log(self, value: dict) -> None:
        with self._lock, self.evidence.open("a") as output:
            output.write(json.dumps(value) + "\n")

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, peer = self.tcp.accept()
            except TimeoutError:
                continue
            record = {"acceptedNs": time.time_ns(), "peer": list(peer), "data": "", "closedNs": None}
            with self._lock:
                self.connections.append(record)
            threading.Thread(target=self._read, args=(connection, record), daemon=True).start()

    def _read(self, connection: socket.socket, record: dict) -> None:
        connection.settimeout(0.2)
        with connection:
            while not self._stop.is_set():
                try:
                    data = connection.recv(4096)
                except TimeoutError:
                    continue
                except OSError as error:
                    record["error"] = repr(error)
                    break
                if not data:
                    break
                with self._lock:
                    record["data"] += data.decode(errors="replace")
        record["closedNs"] = time.time_ns()
        self._log({"tcp": record})

    def _receive(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.udp.recv(65536)
            except TimeoutError:
                continue
            now = time.time_ns()
            with self._lock:
                self.received.append((now, data))
            self._log({"udpNs": now, "payload": data.decode(errors="replace")})

    def datagrams(self, since_ns: int = 0) -> list[Datagram]:
        with self._lock:
            received = [(when, data) for when, data in self.received if when >= since_ns]
        found = []
        for when, data in received:
            match = _UDP.match(data)
            assert match is not None, f"unexpected host datagram: {data!r}"
            found.append(Datagram(when, int(match.group(1)), int(match.group(2)), match.group(3).decode()))
        return found

    def tcp_records(self) -> list[dict]:
        with self._lock:
            return [dict(record) for record in self.connections]

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=5)
        self.tcp.close()
        self.udp.close()


# -- networked source ---------------------------------------------------------------

def create_source(silo: Silo, image: str, name: str, *flags: str) -> dict:
    """One vCPU, so a single held vCPU thread withholds every guest instruction.

    The ordinary OCI create gives the default layered root; its writable
    upper holds the guest's durable witness under `UPPER`.
    """
    silo.create(name, image, "--cpus", "1", "--memory", "512mib", "--disk-size", "512mib",
                "--vsock", "--network", "private", *flags)
    silo.start(name)
    info = silo.wait_ready(name)
    restore.require_restore_candidate(info)
    assert stopped.record(silo, name)["root"]["kind"] == "linux-overlay"
    return info


def network_capture(silo: Silo, name: str) -> Path:
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=5) as connection:
        rows = connection.execute(
            "SELECT a.network_instance_id FROM network_attachments a JOIN machine_config c"
            " ON c.id=a.machine_id WHERE c.name=?", (name,)).fetchall()
    assert len(rows) == 1, f"{name} has no single netd instance"
    path = silo.ws.run_root / "networks" / str(rows[0][0]) / "capture.pcap"
    assert path.is_file(), f"netd did not open its configured capture: {path}"
    return path


def runtime_socket(silo: Silo, machine_hex: str, relative: str) -> Path:
    return silo.ws.run_root / "machines" / machine_hex / relative


class SessionStream:
    """A captured `silo exec` session; its host CLI stays bound to the source."""

    _LINE = re.compile(rb"^SILO-RN-STREAM pid=(\d+) seq=(\d+)$")

    def __init__(self, silo: Silo, name: str, directory: str) -> None:
        self.silo, self.directory = silo, directory
        self.process = silo.popen("exec", name, "--user", "root", "--", PROBE, "stream", directory,
                                  stdin=subprocess.DEVNULL)
        assert self.process.stdout is not None
        self.fd = self.process.stdout.fileno()
        self.pending = b""
        self.pid: int | None = None
        self.values: list[int] = []

    def receive(self, timeout: float) -> bool:
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        data = os.read(self.fd, 65536)
        assert data, f"session stream ended, CLI exit={self.process.poll()}"
        self.pending += data
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            match = self._LINE.match(line)
            assert match is not None, line
            pid, value = int(match.group(1)), int(match.group(2))
            assert self.pid in (None, pid), "stream session changed process"
            assert value == (self.values[-1] + 1 if self.values else 1), (self.values[-1:], value)
            self.pid = pid
            self.values.append(value)
        return True

    def advances(self, count: int = 3) -> None:
        initial = len(self.values)
        deadline = time.monotonic() + 20
        while len(self.values) < initial + count:
            assert time.monotonic() < deadline, "session stream made no progress"
            self.receive(min(0.2, max(0, deadline - time.monotonic())))

    def stationary(self, seconds: float = 1.0) -> None:
        deadline = time.monotonic() + 3
        while self.receive(0.2):
            assert time.monotonic() < deadline, "paused source session kept streaming"
        end = time.monotonic() + seconds
        while (remaining := end - time.monotonic()) > 0:
            assert not self.receive(remaining), "source session received output while paused"

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            output, errors = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            output, errors = self.process.communicate(timeout=10)
        self.silo.ws.record("restore-session-stream", json.dumps({
            "values": self.values, "remainingHex": (self.pending + output).hex(),
            "stderr": errors.decode(errors="replace"), "exit": self.process.returncode,
        }) + "\n")


@dataclass
class Source:
    name: str
    info: dict
    hex: str
    identity: Identity
    workload: dict
    peers: HostPeers
    saved: restore.Checkpoint
    paused_ns: int
    cut_floor: int

    def ram(self, silo: Silo) -> Path:
        """The authenticated RAM stream: an existing identity for the tracer."""
        stream = self.saved.seal["memory"]["ramStream"]
        assert stream.startswith("sha256:")
        return silo.ws.silo_home / "images/streams/sha256" / stream[7:]

    def sealed_progress(self) -> dict:
        disks = list((self.saved.staging / "disks").glob("*.raw"))
        assert len(disks) == 1, "layered networked source seals exactly one writable upper"
        return disk_progress(disks[0])

    def unchanged(self, silo: Silo) -> None:
        current = silo.info(self.name)
        assert current["state"] == "paused" and current["run_id"] == self.info["run_id"], current
        assert current["lifecycle"]["lifecycle"]["currentPause"] is not None, current


@contextmanager
def networked_source(silo: Silo, image: str, name: str, *flags: str,
                     before_capture=None) -> Iterator[Source]:
    """Running workload on a netd network with packet capture, then a real
    preserving live checkpoint; the source stays paused for the caller."""
    enable_packet_capture(silo)
    peers = HostPeers(silo.ws.evidence / "host-peers.jsonl")
    try:
        info = create_source(silo, image, name, *flags)
        machine = uuid_hex(info["id"])
        identity = guest_identity(silo, name)
        workload = start_workload(silo, name, identity, peers)
        if before_capture is not None:
            before_capture(machine, workload)
        saved = restore.checkpoint(silo, name, alias=f"{name}-checkpoint")
        paused = time.time_ns()
        # Sent strictly before the cut is observable at the host; anything a
        # child sends must have a larger sequence than every one of these.
        floor = max(datagram.sequence for datagram in peers.datagrams())
        yield Source(name, info, machine, identity, workload, peers, saved, paused, floor)
    finally:
        peers.close()


def uuid_hex(identifier: str) -> str:
    return uuid.UUID(identifier).hex


# -- guest witness ----------------------------------------------------------------

def start_workload(silo: Silo, name: str, identity: Identity, peers: HostPeers) -> dict:
    result = silo.exec(name, PROBE, "start", STATE, identity.host, str(peers.tcp_port),
                       str(peers.udp_port), str(LISTEN_PORT), user="root")
    started = json.loads(result.stdout)
    shutdown.until(lambda: any(record["data"].startswith(f"SILO-RN-TCP pid={started['pid']}\n")
                               for record in peers.tcp_records()),
                   timeout=20, description="guest TCP stream did not reach the host peer")
    shutdown.until(lambda: len(peers.datagrams()) >= 10, timeout=20,
                   description="guest UDP sender did not reach the host peer")
    return started


def progress(silo: Silo, name: str) -> dict:
    return json.loads(silo.exec(name, PROBE, "status", STATE, user="root").stdout)


def disk_progress(disk: Path, *, path: str = f"{UPPER}{STATE}/progress") -> dict:
    """Read the durable witness from a stopped layered upper without mounting it."""
    result = subprocess.run(["debugfs", "-R", f"cat {path}", str(disk)],
                            capture_output=True, check=True, timeout=30)
    assert len(result.stdout) == 512, f"durable progress record missing: {result.stderr!r}"
    return json.loads(result.stdout.rstrip(b" \n"))


def forward_reply(path: Path, *, timeout: float = 5) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        data = bytearray()
        while chunk := client.recv(4096):
            data.extend(chunk)
        return bytes(data)


def unix_refused(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        try:
            client.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return True
        return False


# -- catalog observation ----------------------------------------------------------

class StateSampler:
    """Samples the child's durable catalog status; never a substitute for the
    monitor's event order, only independent evidence of what was published."""

    def __init__(self, silo: Silo, name: str, evidence: Path) -> None:
        self.db, self.name, self.evidence = silo.ws.state_db(), name, evidence
        self.samples: list[tuple[int, str | None]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"sample-{name}", daemon=True)
        self._thread.start()

    def _status(self) -> str | None:
        try:
            with sqlite3.connect(f"file:{self.db}?mode=ro", uri=True, timeout=1) as connection:
                row = connection.execute(
                    "SELECT s.status FROM machine_state s JOIN machine_config c ON c.id=s.machine_id"
                    " WHERE c.name=?", (self.name,)).fetchone()
        except sqlite3.OperationalError:
            return None
        return row[0] if row else None

    def _run(self) -> None:
        while not self._stop.wait(0.02):
            status = self._status()
            if not self.samples or self.samples[-1][1] != status:
                self.samples.append((time.time_ns(), status))

    def statuses(self) -> list[str | None]:
        return [status for _, status in self.samples]

    def current(self) -> str | None:
        return self.samples[-1][1] if self.samples else None

    def first(self, status: str) -> int | None:
        return next((when for when, value in self.samples if value == status), None)

    def close(self) -> None:
        if not self._stop.is_set():
            self._stop.set()
            self._thread.join(timeout=5)
            assert not self._thread.is_alive(), "state sampler did not stop"
        self.evidence.write_text(json.dumps(self.samples) + "\n")


def child_exists(silo: Silo, name: str) -> bool:
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=5) as connection:
        return connection.execute("SELECT COUNT(*) FROM machine_config WHERE name=?", (name,)).fetchone()[0] > 0


def assert_destroyed(silo: Silo, name: str, machine_hex: str | None) -> None:
    """A failed restore leaves no child: catalog, netd attachment and runtime gone."""
    assert not child_exists(silo, name), f"failed restore left child {name} in the catalog"
    assert name not in {machine["name"] for machine in silo.ls()}
    with sqlite3.connect(f"file:{silo.ws.state_db()}?mode=ro", uri=True, timeout=5) as connection:
        if machine_hex is not None:
            rows = connection.execute(
                "SELECT COUNT(*) FROM network_attachments WHERE replace(machine_id,'-','')=?",
                (machine_hex,)).fetchone()[0]
            assert rows == 0, "failed restore retained the child's netd reservation"
            pending = connection.execute(
                "SELECT COUNT(*) FROM storage_operation WHERE replace(machine_id,'-','')=?"
                " AND state NOT IN ('committed','aborted')", (machine_hex,)).fetchone()[0]
            assert pending == 0, "failed restore retained an unfinished generation/launch operation"
            charged = connection.execute(
                "SELECT COUNT(*) FROM restore_memory_reservation r JOIN storage_operation o"
                " ON o.operation_id=r.operation_id WHERE replace(o.machine_id,'-','')=?",
                (machine_hex,)).fetchone()[0]
            assert charged == 0, "failed restore retained its memory reservation"
    if machine_hex is not None:
        assert not (silo.ws.run_root / "machines" / machine_hex / "vm.pid").exists()


@dataclass
class ChildProcesses:
    holder: dict
    lease: Path
    processes: dict[str, shutdown.Process] = field(default_factory=dict)

    @classmethod
    def observe(cls, silo: Silo, machine_hex: str) -> ChildProcesses:
        path = silo.ws.run_root / "machines" / machine_hex / "vm.storage-holder.json"
        value = shutdown.until(lambda: path.is_file() and json.loads(path.read_bytes()),
                               timeout=60, description="restore child published no storage holders")
        assert {entry["role"] for entry in value["holders"]} == {"monitor", "krun-worker"}, value
        lease = silo.ws.silo_home / "images/locks/leases" / (value["operationId"] + ".lease")
        silo.ws.record("restore-child-holder", json.dumps(value, sort_keys=True) + "\n")
        return cls(value, lease, {entry["role"]: shutdown.Process(entry["pid"]) for entry in value["holders"]})

    def reaped(self) -> None:
        for process in self.processes.values():
            process.wait(timeout=60)
        assert not shutdown.lease_busy(self.lease), "child generation lease survived its processes"

    def close(self) -> None:
        for process in self.processes.values():
            process.close()


# -- traced restore -----------------------------------------------------------------

def drive() -> None:
    """Child of the syscall controller: run the real restore CLI once."""
    request = json.loads(Path(sys.argv[2]).read_text())
    evidence = Path(request["evidence"])

    def record(name: str, value: object) -> None:
        target = evidence / name
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        temporary.replace(target)

    with (evidence / "restore-manager.stdout").open("wb") as output, \
            (evidence / "restore-manager.stderr").open("wb") as errors:
        process = subprocess.Popen([request["silo"], *request["argv"]], stdout=output, stderr=errors)
        record("restore-manager-process.json", {"pid": process.pid})
        try:
            code = process.wait(timeout=230)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    record("restore-manager-result.json", {"code": code})


class Traced:
    def __init__(self, silo: Silo, evidence: Path, controller: subprocess.Popen[bytes]) -> None:
        self.silo, self.evidence, self.controller = silo, evidence, controller

    def _record(self, name: str) -> dict | None:
        path = self.evidence / name
        if path.exists():
            return json.loads(path.read_text())
        assert self.controller.poll() is None, f"restore tracer ended before {name}; see {self.evidence}"
        return None

    def wait(self, name: str, timeout: float = 180) -> dict:
        return shutdown.until(lambda: self._record(name), timeout=timeout,
                              description=f"restore trace did not produce {name}")

    def held(self) -> dict:
        receipt = self.wait("boundary-held.json")
        assert receipt["injectedReturn"] is False, receipt
        return receipt

    def held_thaw_reply(self, sent: Event) -> dict:
        receipt = self.held()
        assert receipt["afterLog"] == THAW_SENDING, receipt
        reply = receipt["thawReply"]
        assert reply["state"] == "thawed", receipt
        assert reply["activation"] == sent.fields["activation"], receipt
        assert reply["machine"] and reply["run"] and reply["grpcMessageHex"], receipt
        return receipt

    def release(self) -> None:
        (self.evidence / "boundary-release").touch(exist_ok=True)

    def manager(self) -> shutdown.Process:
        return shutdown.Process(self.wait("restore-manager-process.json")["pid"])

    def manager_result(self, timeout: float = 180) -> tuple[int, str, str]:
        code = self.wait("restore-manager-result.json", timeout=timeout)["code"]
        return (code, (self.evidence / "restore-manager.stdout").read_text(errors="replace"),
                (self.evidence / "restore-manager.stderr").read_text(errors="replace"))

    def net_egress(self) -> list[dict]:
        path = self.evidence / "net-egress.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def finish(self, timeout: float = 240) -> None:
        self.release()
        assert self.controller.wait(timeout=timeout) == 0, f"restore tracer failed; see {self.evidence}"
        assert json.loads((self.evidence / "boundary-result.json").read_text())["returncode"] == 0


@contextmanager
def traced_restore(silo: Silo, reference: str, target: Path, child: str, boundary: str,
                   after: str, ignore_logs: list[str], *extra: str) -> Iterator[Traced]:
    """Run `silo restore` under the syscall controller, holding `boundary`
    only after the monitor logged `after`; every native NIC send is recorded."""
    assert boundary != "restore-transport-reply" or after == THAW_SENDING
    evidence = silo.ws.evidence / f"traced-{child}"
    evidence.mkdir()
    silo.ws.register_machine(child)
    driver = evidence / "driver.json"
    driver.write_text(json.dumps({"silo": str(silo.ws.config.silo), "evidence": str(evidence),
                                  "argv": ["restore", reference, "--name", child, *extra]}) + "\n")
    request = evidence / "request.json"
    request.write_text(json.dumps({
        "command": [sys.executable, "-m", "silo_smoke.restore_lifecycle", "drive", str(driver)],
        "target": str(target), "boundary": boundary,
        "machines": str(silo.ws.silo_home / "machines"),
        "evidence": str(evidence), "release": str(evidence / "boundary-release"),
        "afterLog": {"directory": str(silo.ws.silo_home / "logs/machines"), "glob": "*/vm.trace.log",
                     "needle": after, "ignore": ignore_logs},
        "observeNetEgress": True,
    }) + "\n")
    with (evidence / "controller.log").open("wb") as output:
        controller = subprocess.Popen([sys.executable, "-m", "silo_smoke.stopped_trace", str(request)],
                                      env=silo.ws.env(PYTHONPATH=str(REPO / "smoke")),
                                      stdout=output, stderr=subprocess.STDOUT)
    traced = Traced(silo, evidence, controller)
    try:
        yield traced
    finally:
        traced.release()
        if controller.poll() is None:
            controller.terminate()
            try:
                controller.wait(timeout=15)
            except subprocess.TimeoutExpired:
                controller.kill()
                controller.wait(timeout=5)


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "drive":
        drive()
        return
    raise SystemExit("usage: python -m silo_smoke.restore_lifecycle drive REQUEST")


if __name__ == "__main__":
    main()
