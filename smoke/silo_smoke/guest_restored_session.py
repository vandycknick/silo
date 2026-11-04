"""Focused real-Silo native session over the frozen standalone native owner.

Reuses native_live_api's ApiSession command/capture/seal/stop/close machinery and
replaces only resource construction and guest-facing servicing. It never sends a
diagnostic console command, echo datagram or vsock echo stream to the VM.

    native stdout ── pump() ────────────────> replies (caller thread only)
    PTY hvc0 + probe2 output ─┐
    mux control (guest CONNECT)┴─> _Servicer ─> logs, ForwardPeer threads
    native NIC <─socketpair─> DatagramRelay <─unixgram─> real netd

Each role gets its own netd subnet/static lease and native MAC. The cold binding's
source-run bytes are the actual Silo source run UUID and are never rewritten.
Restores keep the captured binding unchanged; the destination fixture only carries
destination MAC/runtime identity. Process ownership stays with this session; the
native owner is the sole VM reaper.
"""
from __future__ import annotations

import array
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pty
import select
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tty
import uuid

from .guest_activation_network import DatagramRelay, NetworkIdentity
from .native_live_api import make_session_type, require

AGENT_PORT = 1027  # forward_spec::GUEST_CONTROL_VSOCK_PORT
FORWARD_PORT = 1028  # forward_spec::FORWARD_VSOCK_PORT
SSH_PORT = 22  # agent_spec::SSH_VSOCK_PORT
MAX_CONTROL_LINE = 64
MAX_FORWARD_LINE = 512  # forward_spec::MAX_TARGET_LINE_BYTES
WAIT = 30
BINDING_FIELDS = ("silo-producer", "profile", "topology", "ram-layout", "source-run", "capture")
READY = "READY whole-machine-production"
PREPARED = "PREPARED native-parked-fenced, not BackendStarted"


def load_native(native_root: Path) -> type:
    """Import the frozen validators read-only and return the native ApiSession type."""
    examples = (native_root / "src/libkrun/examples").resolve(strict=True)
    if str(examples) not in sys.path:
        sys.path.insert(0, str(examples))
    previous = sys.dont_write_bytecode
    # The native checkout is read-only evidence; never drop __pycache__ into it.
    sys.dont_write_bytecode = True
    try:
        return make_session_type()
    finally:
        sys.dont_write_bytecode = previous


@dataclass(frozen=True)
class NativeInputs:
    native_root: Path
    entry: Path
    launcher: Path
    netd: Path


@dataclass(frozen=True)
class SessionRole:
    label: str
    machine_id: str
    run_id: str
    network: NetworkIdentity

    def __post_init__(self) -> None:
        for value in (self.machine_id, self.run_id):
            require(str(uuid.UUID(value)) == value, "role identities must be canonical UUIDs")

    @property
    def subnet(self) -> str:
        return str(ipaddress.IPv4Network(f"{self.network.ipv4}/{self.network.prefix_length}", strict=False))

    @property
    def mac_bytes(self) -> list[int]:
        return list(bytes.fromhex(self.network.mac.replace(":", "")))


@dataclass
class CohortArgs:
    """The attribute surface ApiSession/Session methods read from `self.args`."""
    inputs: NativeInputs
    kernel: Path
    initramfs: Path
    binding_material: bytes
    sessions: list = field(default_factory=list)
    case: str = "silo-restored-guest"


def write_cold_binding(binding: Path, material: bytes, run_id: str) -> None:
    binding.mkdir(mode=0o700)
    for name in ("silo-producer", "profile", "topology", "ram-layout"):
        (binding / name).write_bytes(hashlib.sha256(name.encode() + material).digest())
    (binding / "source-run").write_bytes(uuid.UUID(run_id).bytes)
    (binding / "capture").write_bytes(os.urandom(16))


def _append_json(path: Path, value: dict) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")


def _read_line(stream: socket.socket, bound: int) -> bytes:
    line = bytearray()
    while not line.endswith(b"\n"):
        if len(line) >= bound:
            raise ValueError("forward line exceeded its bound")
        chunk = stream.recv(1)
        if not chunk:
            raise ConnectionError("forward stream closed before a complete line")
        line.extend(chunk)
    return bytes(line)


class ForwardPeer:
    """Host end of the guest forward return port: exact token check and a nonce echo.

    This is the smoke stand-in for the host relay target, not monitor listener
    policy. Tokens are recorded only as SHA256 digests.
    """

    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self._lock = threading.Lock()
        self._tokens: dict[str, str] = {}
        self._events: list[dict] = []
        self._threads: list[threading.Thread] = []

    def register(self, name: str, token_hex: str) -> None:
        require(len(token_hex) == 32 and all(c in "0123456789abcdef" for c in token_hex),
                "forward token must be 16 lowercase hex bytes")
        with self._lock:
            self._tokens[token_hex] = name

    def _record(self, value: dict) -> None:
        with self._lock:
            value["sequence"] = len(self._events) + 1
            self._events.append(value)
            _append_json(self.evidence, value)

    def events(self) -> list[dict]:
        with self._lock:
            return [dict(value) for value in self._events]

    def serve(self, connection_id: int, source_port: int, stream: socket.socket) -> None:
        thread = threading.Thread(target=self._serve, args=(connection_id, source_port, stream),
                                  name=f"forward-return-{connection_id}", daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()

    def _serve(self, connection_id: int, source_port: int, stream: socket.socket) -> None:
        record: dict = {"connection_id": connection_id, "guest_source_port": source_port,
                        "accepted_monotonic_ns": time.monotonic_ns(), "token_sha256": None,
                        "listener": None, "reply": None, "nonce": None, "error": None}
        try:
            stream.setblocking(True)
            stream.settimeout(5)
            line = _read_line(stream, MAX_FORWARD_LINE)
            record["connect_line_bytes"] = len(line)
            if not line.startswith(b"CONNECT ") or len(line) != len(b"CONNECT \n") + 32:
                stream.sendall(b"ERR invalid\n")
                record["reply"] = "ERR invalid"
                return
            token = line[len(b"CONNECT "):-1].decode("ascii")
            record["token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
            with self._lock:
                listener = self._tokens.get(token)
            if listener is None:
                stream.sendall(b"ERR not-found\n")
                record["reply"] = "ERR not-found"
                return
            record["listener"] = listener
            stream.sendall(b"OK\n")
            record["reply"] = "OK"
            nonce = _read_line(stream, MAX_FORWARD_LINE)
            record["nonce"] = nonce[:-1].decode("ascii", errors="replace")
            stream.sendall(b"ECHO " + nonce)
        except (OSError, ValueError, ConnectionError) as error:
            record["error"] = repr(error)
        finally:
            record["finished_monotonic_ns"] = time.monotonic_ns()
            stream.close()
            self._record(record)

    def join(self, timeout: float) -> list[str]:
        deadline = time.monotonic() + timeout
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
        return [f"forward return thread {thread.name} still running" for thread in threads if thread.is_alive()]


class _Servicer(threading.Thread):
    """Drains console ports and answers guest-initiated mux CONNECT frames.

    The guest kernel/agent write hvc0 continuously; an undrained PTY would block
    guest console writers while the caller waits on an attach subprocess.
    """

    def __init__(self, session) -> None:
        super().__init__(name=f"silo-servicer-{session.role.label}", daemon=True)
        self.session = session
        self.failure: BaseException | None = None
        self._wake_read, self._wake_write = socket.socketpair()
        self._control = bytearray()
        self._fds: list[int] = []
        self.control_eof = False

    def run(self) -> None:
        session = self.session
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(session.console, selectors.EVENT_READ, "console")
                selector.register(session.output_host, selectors.EVENT_READ, "output")
                selector.register(session.mux, selectors.EVENT_READ, "mux")
                selector.register(self._wake_read, selectors.EVENT_READ, "stop")
                while True:
                    for key, _ in selector.select():
                        if key.data == "stop":
                            return
                        if key.data == "console":
                            try:
                                data = os.read(session.console, 65536)
                            except BlockingIOError:
                                continue
                            except OSError:
                                data = b""  # EIO: every slave closed after native exit.
                            if not data:
                                selector.unregister(session.console)
                                continue
                            session.guest_log.write(data)
                            session.guest_log.flush()
                        elif key.data == "output":
                            try:
                                data = session.output_host.recv(65536)
                            except BlockingIOError:
                                continue
                            if not data:
                                selector.unregister(session.output_host)
                                continue
                            session.output_log.write(data)
                            session.output_log.flush()
                        elif not self._mux():
                            selector.unregister(session.mux)
        except BaseException as error:
            self.failure = error
            _append_json(self.session.directory / "servicer-failure.jsonl",
                         {"monotonic_ns": time.monotonic_ns(), "error": repr(error)})

    def _mux(self) -> bool:
        try:
            data, ancillary, flags, _ = self.session.mux.recvmsg(
                MAX_CONTROL_LINE, socket.CMSG_SPACE(16 * array.array("i").itemsize))
        except BlockingIOError:
            return True
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("truncated native mux control frame")
        for level, kind, payload in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, "unexpected mux ancillary data")
            descriptors = array.array("i")
            descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
            self._fds.extend(descriptors)
        if not data:
            self.control_eof = True
            _append_json(self.session.directory / "mux-control.jsonl",
                         {"monotonic_ns": time.monotonic_ns(), "event": "control-eof"})
            return False
        self._control.extend(data)
        while b"\n" in self._control:
            line, _, rest = bytes(self._control).partition(b"\n")
            self._control = bytearray(rest)
            self._connect(line)
        require(len(self._control) <= MAX_CONTROL_LINE, "oversized native mux control line")
        return True

    def _connect(self, line: bytes) -> None:
        fields = line.split(b" ")
        require(len(fields) == 4 and fields[0] == b"CONNECT" and all(value.isdigit() for value in fields[1:]),
                f"unexpected native mux control line {line!r}")
        require(self._fds, "guest CONNECT omitted its stream descriptor")
        connection, port, source = (int(value) for value in fields[1:])
        stream = socket.socket(fileno=self._fds.pop(0))
        accepted = port == FORWARD_PORT
        record = {"monotonic_ns": time.monotonic_ns(), "event": "guest-connect", "id": connection,
                  "port": port, "source_port": source, "accepted": accepted}
        _append_json(self.session.directory / "mux-control.jsonl", record)
        self.session.send_control((b"OK " if accepted else b"REJECT ") + str(connection).encode() + b"\n")
        if accepted:
            self.session.forward.serve(connection, source, stream)
        else:
            stream.close()

    def stop(self) -> list[str]:
        if self.is_alive():
            self._wake_write.send(b"x")
            self.join(5)
        failures = ["servicer thread did not stop"] if self.is_alive() else []
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()
        self._wake_read.close()
        self._wake_write.close()
        if self.failure is not None:
            failures.append(f"servicer failed: {self.failure!r}")
        return failures


def silo_session_type(api_session_type: type) -> type:
    class SiloSession(api_session_type):
        """One native process: cold Silo boot (restore=None) or descriptor-fed restore."""

        def __init__(self, args: CohortArgs, directory: Path, disks: list[Path], role: SessionRole,
                     restore: Path | None = None):
            from native_device_controller import save
            # Every attribute close() reads exists before any fallible step.
            self.directory = directory
            self.args = args
            self.role = role
            self.restore_directory = restore
            self.restore_failure_evidence = None
            self.prepared = restore is not None
            self.partial = False
            self.stopping = False
            self.last_release = None
            self.releases = []
            self.replies = []
            self.control_buffer = bytearray()
            self.process = None
            self.netd = None
            self.relay = None
            self.servicer = None
            self.fds = []
            self.sockets = []
            self.relay_sockets = []
            self.mux_lock = threading.Lock()
            directory.mkdir(mode=0o700)
            args.sessions.append(self)
            self.forward = ForwardPeer(directory / "forward-return.jsonl")
            self.runtime = tempfile.TemporaryDirectory(prefix="silo-restored-")
            self.log = (directory / "driver.log").open("wb")
            self.guest_log = (directory / "console-hvc0.log").open("wb")
            self.output_log = (directory / "console-output.log").open("wb")
            self.binding = directory / "binding"
            if restore is not None:
                shutil.copytree(restore / "binding", self.binding)
            else:
                write_cold_binding(self.binding, args.binding_material, role.run_id)
            for name in BINDING_FIELDS:
                (self.binding / name).chmod(0o600)
            self.source_run_binding = (self.binding / "source-run").read_bytes()
            ram_fds: tuple[int, ...] = ()
            if restore is not None:
                from native_ram_image import authenticate_image
                ram_fd = os.open(restore / "memory.ram", os.O_RDONLY | os.O_NONBLOCK)
                self.fds.append(ram_fd)
                layout_fd = os.open(restore / "memory-layout.json", os.O_RDONLY | os.O_NONBLOCK)
                self.fds.append(layout_fd)
                authentication = authenticate_image(
                    restore / "memory.ram", restore / "memory-layout.json",
                    (self.binding / "ram-layout").read_bytes(), ram_fd=ram_fd, layout_fd=layout_fd)
                require((restore / "memory-authentication.bin").read_bytes()
                        == bytes.fromhex(authentication["layout_digest"] + authentication["stream_digest"]),
                        "restore RAM stream authentication mismatch")
                save(directory / "restore-ram-authentication.json", authentication)
                ram_fds = (ram_fd, layout_fd)
            master, slave = pty.openpty()
            tty.setraw(master)
            tty.setraw(slave)
            self.console = master
            self.fds.extend([master, slave])
            input_host, input_guest = socket.socketpair()
            output_host, output_guest = socket.socketpair()
            mux_host, mux_guest = socket.socketpair()
            net_native, net_relay = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            echo.bind(("127.0.0.1", 0))
            self.input_host, self.output_host, self.mux = input_host, output_host, mux_host
            self.sockets.extend([input_host, input_guest, output_host, output_guest, mux_host, mux_guest,
                                 net_native, echo])
            self.relay_sockets.append(net_relay)
            endpoint = Path(self.runtime.name) / "netd.sock"
            local = Path(self.runtime.name) / "guest.sock"
            logfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            self.fds.append(logfd)
            runtimefd = os.open(self.runtime.name, os.O_RDONLY | os.O_DIRECTORY)
            self.fds.append(runtimefd)
            netd_command = [str(args.inputs.netd), "--listen-vfkit", f"unixgram://{endpoint}",
                            "--subnet", role.subnet, "--static-lease", f"{role.network.ipv4}={role.network.mac}",
                            "--log-dir-fd", str(logfd), "--runtime-dir-fd", str(runtimefd),
                            "--log-file", "netd.log", "--audit-log-file", "netd-audit.jsonl",
                            "--vm-id", role.machine_id, "--run-id", role.run_id, "--network-id", directory.name]
            save(directory / "netd-command.json", netd_command)
            with (directory / "netd.stderr").open("wb") as error:
                self.netd = subprocess.Popen(netd_command, pass_fds=(logfd, runtimefd),
                                             stdout=subprocess.DEVNULL, stderr=error)
            deadline = time.monotonic() + WAIT
            while not endpoint.exists():
                require(self.netd.poll() is None and time.monotonic() < deadline,
                        "actual managed netd did not create its endpoint")
                time.sleep(.01)
            backend = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.relay_sockets.append(backend)
            backend.bind(str(local))
            backend.connect(str(endpoint))
            self.relay = DatagramRelay(net_relay, backend, directory / "wire.jsonl")
            self.relay_sockets.clear()  # The relay owns both sockets from here on.
            self.relay.handshake()
            self.relay.start()
            fixture = directory / "silo-fixture.json"
            with fixture.open("x", encoding="utf-8") as output:
                json.dump({"machine_id": role.machine_id, "run_id": role.run_id, "mac": role.mac_bytes}, output)
            fixture.chmod(0o600)
            command = [sys.executable, str(args.inputs.launcher),
                       "--disk0", str(disks[0]), "--disk1", str(disks[1]),
                       "--kernel", str(args.kernel), "--initramfs", str(args.initramfs),
                       "--binding", str(self.binding), "--echo-port", str(echo.getsockname()[1]),
                       "--console-fd", str(slave), "--console-input-fd", str(input_guest.fileno()),
                       "--console-output-fd", str(output_guest.fileno()), "--net-fd", str(net_native.fileno()),
                       "--mux-fd", str(mux_guest.fileno()), "--generation", "on", "--silo-fixture", str(fixture)]
            if restore is not None:
                command += ["--restore", str(restore), "--ram-image-fd", str(ram_fds[0]),
                            "--ram-layout-fd", str(ram_fds[1])]
            save(directory / "command.json", command)
            inherited = (slave, input_guest.fileno(), output_guest.fileno(), net_native.fileno(),
                         mux_guest.fileno(), *ram_fds)
            environment = {**os.environ, "SILO_NATIVE_API_EXECUTABLE": str(args.inputs.entry)}
            with (directory / "driver.stderr").open("wb") as error:
                self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                stderr=error, pass_fds=inherited, env=environment)
            save(directory / "process.json", {
                "native_pid": self.process.pid, "netd_pid": self.netd.pid, "role": role.label,
                "machine_id": role.machine_id, "run_id": role.run_id, "network": role.network.__dict__,
                "restore": str(restore) if restore else None,
                "source_run_binding_hex": self.source_run_binding.hex()})
            # Drop every parent duplicate of a transferred destination resource.
            for transferred in (input_guest, output_guest, mux_guest, net_native):
                transferred.close()
                self.sockets.remove(transferred)
            os.close(slave)
            self.fds.remove(slave)
            for fd in ram_fds:
                os.close(fd)
                self.fds.remove(fd)
            for endpoint_socket in (input_host, output_host, mux_host):
                endpoint_socket.setblocking(False)
            os.set_blocking(master, False)
            os.set_blocking(self.process.stdout.fileno(), False)
            self.servicer = _Servicer(self)
            self.servicer.start()
            self.until(lambda: READY in self.replies, "native driver readiness")
            self.ready_monotonic_ns = time.monotonic_ns()
            if restore is not None:
                require(PREPARED in self.replies, "restored native owner did not report parked/fenced preparation")
            require((self.binding / "source-run").read_bytes() == self.source_run_binding,
                    "source-run binding changed after native readiness")

        def pump(self, duration=.01, peers=True):
            """Service native replies only; guest-facing endpoints belong to the servicer."""
            deadline = time.monotonic() + duration
            descriptor = self.process.stdout.fileno()
            while True:
                ready, _, _ = select.select([descriptor], [], [], min(.01, max(0, deadline - time.monotonic())))
                if ready:
                    try:
                        data = os.read(descriptor, 65536)
                    except BlockingIOError:
                        data = None
                    if data:
                        self.log.write(data)
                        self.log.flush()
                        self.control_buffer.extend(data)
                        while b"\n" in self.control_buffer:
                            line, _, self.control_buffer = self.control_buffer.partition(b"\n")
                            self.replies.append(line.decode(errors="strict"))
                if self.servicer is not None and self.servicer.failure is not None:
                    raise RuntimeError(f"guest endpoint servicer failed: {self.servicer.failure!r}")
                if self.process.poll() is not None:
                    if self.stopping and self.process.returncode == 0:
                        return
                    raise RuntimeError(f"native process exited before stop: {self.process.returncode}")
                if time.monotonic() >= deadline:
                    return

        def record_network_state(self, event):
            value = {"event": event, "observed_monotonic_ns": time.monotonic_ns(),
                     "native_pid": self.process.pid if self.process else None,
                     "netd_pid": self.netd.pid if self.netd else None,
                     "netd_returncode": self.netd.poll() if self.netd else None,
                     "forward_return_events": len(self.forward.events()),
                     "relay_sequence": None, "relay_error": None}
            try:
                value["relay_sequence"] = self.relay.mark(event) if self.relay is not None else None
            except RuntimeError as error:
                value["relay_error"] = str(error)
            _append_json(self.directory / "native-transitions.jsonl", value)

        def send_control(self, frame: bytes, fd: int | None = None) -> None:
            rights = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
            deadline = time.monotonic() + 5
            with self.mux_lock:
                while True:
                    try:
                        sent = self.mux.sendmsg([frame], rights)
                        require(sent == len(frame), "short native mux control frame")
                        return
                    except BlockingIOError:
                        require(time.monotonic() < deadline, "native mux control send deadline")
                        select.select([], [self.mux], [], .01)

        def open_stream(self, port: int) -> socket.socket:
            """Fresh native CONNECT; the caller owns the returned end and its `OK` handshake."""
            local, remote = socket.socketpair()
            try:
                self.send_control(f"CONNECT {port}\n".encode(), remote.fileno())
            except BaseException:
                local.close()
                raise
            finally:
                remote.close()
            return local

        def close(self):
            failures = []
            if self.servicer is not None:
                failures.extend(self.servicer.stop())
            try:
                failures.extend(api_session_type.close(self))
            finally:
                if self.relay is not None:
                    try:
                        self.relay.close()
                    except BaseException as error:
                        failures.append(f"network relay close: {error!r}")
                for value in self.relay_sockets:
                    value.close()
                self.relay_sockets = []
                failures.extend(self.forward.join(2))
            self.cleanup_failures = list(dict.fromkeys([*self.cleanup_failures, *failures]))
            return failures

    return SiloSession
