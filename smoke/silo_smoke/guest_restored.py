"""Actual restored-Silo guest Freeze/Activate/Thaw proof over the standalone native owner.

One cold Silo source (AgentPid1, staged init/agent/kernel, populated private root
plus data disk, real netd) is frozen through the guest RPC, natively paused and
captured once. Fresh children restore that read-only cut sequentially. Barrier
order per child, every step independently observed:

    restorePrepared/fenced -> generation-fresh -> release CPUs -> exact timely
    native/driver ACK -> guest Activate (frozen) -> destination-bound Thaw
    -> native provider fence release (`activate` command) -> wire/RPC oracles

Native command `activate` is provider fence release only; no public Running state
is claimed. Every owned process (native, netd, attach helpers) is reaped on
every path; failure payloads and raw evidence are retained. Successful bulk
payload removal is Main-owned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import subprocess
import tempfile
import time
import uuid

from . import guest_lifecycle, overlay
from .cli import Silo
from .config import REPO
from .guest_activation_network import NetworkIdentity
from .guest_restored_session import (AGENT_PORT, FORWARD_PORT, SSH_PORT, CohortArgs, NativeInputs,
                                     SessionRole, load_native, silo_session_type)
from .native_live_api import assert_writers_closed, cleanup_session, lease_conflicts, require

MIB = 1024 * 1024
PROBE = "/usr/local/bin/guest-activation-network"
STATE = "/var/lib/silo-smoke"
WITNESS_COUNTER = f"{STATE}/witness-counter"
WITNESS_PID = f"{STATE}/witness.pid"
WITNESS_MEMBERSHIP = f"{STATE}/witness-membership"
USERDATA_INVOCATIONS = f"{STATE}/userdata-invocations"
USERDATA_MEMBERSHIP = f"{STATE}/userdata-membership"
EXEC_COUNTER = f"{STATE}/exec-counter"
SSH_COUNTER = f"{STATE}/ssh-counter"
HOOK_MARKER = f"{STATE}/hook-marker"
HOOK_OBSERVATION = f"{STATE}/hook-observation.json"
CONFLICT_PORT = 7101
FORWARD_GUEST_PORT = 7201
MANAGED_NAME = "silo-managed0"
SEEDED_NEIGHBOUR_MAC = "02:53:49:4c:4f:aa"
SOURCE = NetworkIdentity("02:00:00:00:00:01", "192.168.127.2", "192.168.127.1")
TOPOLOGY_ALIAS = "192.168.127.9"

# Persistent continuation witness: started once by cold userdata, not a captured
# exec/SSH session. Its parent exits; stdio is detached so provisioning returns.
USERDATA = f"""#!/bin/sh
set -eu
mkdir -p {STATE}
printf x >>{USERDATA_INVOCATIONS}
cat /proc/self/cgroup >{USERDATA_MEMBERSHIP}
/bin/sh -c 'echo $$ >{WITNESS_PID}; cat /proc/self/cgroup >{WITNESS_MEMBERSHIP}; while :; do printf x >>{WITNESS_COUNTER}; sleep 0.02; done' </dev/null >/dev/null 2>&1 &
nc -l -p {CONFLICT_PORT} </dev/null >/dev/null 2>&1 &
"""


def destination(index: int) -> NetworkIdentity:
    """Distinct per-child subnet/IP/MAC; the gateway is netd's first usable address."""
    require(0 <= index < 64, "bounded child index")
    return NetworkIdentity(f"02:00:00:00:00:{index + 2:02x}", f"192.168.{128 + index}.2", f"192.168.{128 + index}.1")


def content_bytes(content: dict | None) -> bytes:
    require(content is not None, "observation content missing")
    if content["encoding"] == "utf8":
        return content["data"].encode()
    require(content["encoding"] == "hex", "unknown observation content encoding")
    return bytes.fromhex(content["data"])


def proc_starttime(stat: bytes) -> int:
    # Field 22 of /proc/PID/stat, counted after the parenthesised command name.
    return int(stat.rsplit(b")", 1)[1].split()[19])


def listening(tcp: bytes, port: int) -> bool:
    for row in tcp.decode().splitlines()[1:]:
        fields = row.split()
        if len(fields) > 3 and fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port:
            return True
    return False


@dataclass(frozen=True)
class RestoredInputs:
    native: NativeInputs
    controller: Path
    kernel_config: Path
    assets: Path

    @classmethod
    def resolve(cls, silo: Silo) -> RestoredInputs:
        native_root = os.environ.get("SILO_NATIVE_ROOT")
        require(native_root is not None, "set SILO_NATIVE_ROOT to the frozen read-only native checkout")
        target = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "target")))
        entry = Path(os.environ.get("SILO_SMOKE_NATIVE_LIVE_API", str(target / "debug/examples/native-live-api")))
        require(entry.is_file() and os.access(entry, os.X_OK),
                "Main must build the explicit native entry: cargo build --locked -p silo-vmm --example native-live-api; "
                "set SILO_SMOKE_NATIVE_LIVE_API for another target/profile")
        config = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
        require(config is not None, "set SILO_SMOKE_KERNEL_CONFIG to the staged kernel's actual emitted .config")
        kernel_config = Path(config).resolve(strict=True)
        lines = set(kernel_config.read_text().splitlines())
        require({"CONFIG_VMGENID=y", "CONFIG_VIRTIO_SILO_VMGENID=y"} <= lines,
                "staged kernel config lacks the built-in Silo generation driver")
        netd = silo.ws.config.runtime_dir / "bin/netd"
        require(netd.is_file() and os.access(netd, os.X_OK), "staged runtime lacks netd; run make stage")
        return cls(NativeInputs(Path(native_root).resolve(strict=True), entry.resolve(),
                                (Path(__file__).with_name("native_live_launch.py")).resolve(strict=True), netd.resolve()),
                   guest_lifecycle.controller(), kernel_config, silo.ws.config.runtime_dir / "assets")


@dataclass
class SourceFixture:
    directory: Path
    root: Path
    data: Path
    manifest: dict
    role: SessionRole
    kernel: Path
    kernel_source: Path
    initramfs: Path


def build_fixture(silo: Silo, image: str) -> tuple[SourceFixture, Path]:
    disk, directory = guest_lifecycle.private_root(silo, image, "guest-restored-")
    root = Path(disk["path"])
    require(root.stat().st_size == disk["geometry"]["length"], "private root length differs from its geometry")
    data = directory / "data.raw"
    with data.open("xb") as output:
        output.truncate(64 * MIB)
    data.chmod(0o600)
    subprocess.run(["mkfs.ext4", "-F", "-q", "-L", "silo-restored", str(data)], check=True, timeout=60, capture_output=True)
    # Exact native inventory: the entry exposes disk0 (root) and disk1 (data), never
    # the catalog's original block ID.
    disks = [dict(disk, blockId="disk0"),
             {"path": str(data), "role": "data", "format": "raw",
              "geometry": {"length": data.stat().st_size, "logicalSectorSize": 512},
              "blockId": "disk1", "readOnly": False}]
    manifest = {"kind": "complete", "attachments": [guest_lifecycle.block_attachment(value) for value in disks]}
    role = SessionRole("source", str(uuid.uuid4()), str(uuid.uuid4()), SOURCE)
    agent_config = {
        "provision": {"enabled": True,
                      "network": {"interfaces": [{"mac_address": SOURCE.mac, "ipv4": {
                          "address": SOURCE.ipv4, "prefix_length": SOURCE.prefix_length, "gateway": SOURCE.gateway},
                          "dns": {"servers": [SOURCE.gateway]}}]},
                      "userdata": {"content": USERDATA, "content_type": "shell_script", "run": "once"}},
        "ssh": {"trusted_ca": guest_lifecycle.ssh_material(directory)},
        "storage_shutdown": {"version": 1, "machineId": role.machine_id, "runId": role.run_id, "manifest": manifest},
    }
    assets = silo.ws.config.runtime_dir / "assets"
    initramfs = guest_lifecycle.composite_initramfs(assets, directory, agent_config)
    kernel, kernel_source = guest_lifecycle.private_kernel(assets, directory)
    (directory / "agent-config.json").write_text(json.dumps(agent_config, indent=2, sort_keys=True) + "\n")
    return SourceFixture(directory, root, data, manifest, role, kernel, kernel_source, initramfs), directory


@dataclass
class Cut:
    directory: Path
    identity: dict
    freeze_ref: dict
    reseeds: int
    ifindex: int
    witness_pid: int
    witness_starttime: int
    source_setup: dict
    source_status: dict
    source_cursor: str
    source_listener: str
    capture: dict
    manifest: dict


@dataclass
class Child:
    session: object
    role: SessionRole
    native: dict
    guest: dict
    record: dict = field(default_factory=dict)


class AttachFailure(AssertionError):
    pass


class Held:
    """One `hold` attach helper keeping captured sessions live across pause/capture."""

    def __init__(self, process: subprocess.Popen, stem: Path, ready: dict) -> None:
        self.process, self.stem, self.ready = process, stem, ready
        self.result: dict | None = None

    def release(self) -> dict:
        self.process.stdin.write(b"release\n")
        self.process.stdin.flush()
        self.process.stdin.close()
        stdout, stderr = self.process.communicate(timeout=60)
        self.stem.with_suffix(".release.stdout").write_bytes(stdout)
        self.stem.with_suffix(".stderr").write_bytes(stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.startswith(b"{")]
        require(len(records) == 1 and records[0]["record"] == "result", "hold helper did not print one result")
        self.result = records[0]
        require(self.process.returncode == 0 and self.result["passed"], f"hold release failed: {self.stem}")
        return self.result

    def reap(self) -> dict:
        if self.process.poll() is None:
            self.process.kill()
        status = self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        return {"helper": str(self.stem), "pid": self.process.pid, "exit_status": status,
                "released": self.result is not None}


class Cohort:
    def __init__(self, silo: Silo, image: str, case: str, probe: Path) -> None:
        self.silo = silo
        self.case = case
        self.inputs = RestoredInputs.resolve(silo)
        parent = Path(os.environ.get("SILO_SMOKE_RESTORED_EVIDENCE", str(silo.ws.root)))
        parent.mkdir(parents=True, exist_ok=True)
        self.evidence = Path(tempfile.mkdtemp(prefix=f"guest-restored-{case}-", dir=parent))
        require(shutil.disk_usage(self.evidence).free >= 8 * 1024 * MIB, "restored cohort requires 8 GiB headroom")
        self.attach_root = self.evidence / "attach"
        self.attach_root.mkdir(mode=0o700)
        self.attach_sequence = 0
        self.timeline: list[dict] = []
        self.helpers: list[Held] = []
        self.cleanups: list[dict] = []
        self.fixture, fixture_directory = build_fixture(silo, image)
        material = json.dumps({"image": image, "fixture": str(fixture_directory),
                               "initramfs": overlay.digest(self.fixture.initramfs)}, sort_keys=True).encode()
        self.args = CohortArgs(self.inputs.native, self.fixture.kernel, self.fixture.initramfs, material)
        self.session_type = silo_session_type(load_native(self.inputs.native.native_root))
        self._record_inputs(image, probe)

    def _record_inputs(self, image: str, probe: Path) -> None:
        identities = {name: overlay.digest(path) for name, path in (
            ("controller", self.inputs.controller), ("entry", self.inputs.native.entry),
            ("launcher", self.inputs.native.launcher), ("netd", self.inputs.native.netd),
            ("kernel", self.fixture.kernel), ("kernel_config", self.inputs.kernel_config),
            ("agent", self.inputs.assets / "agent"), ("base_initramfs", self.inputs.assets / "initramfs"),
            ("composite_initramfs", self.fixture.initramfs), ("activation_probe", probe))}
        sources = ["smoke/silo_smoke/guest_restored.py", "smoke/silo_smoke/guest_restored_session.py",
                   "smoke/silo_smoke/guest_activation_network.py", "smoke/silo_smoke/guest_lifecycle.py",
                   "smoke/silo_smoke/native_live_api.py", "smoke/silo_smoke/native_live_launch.py",
                   "virt/vmm/tests/guest/activation_network.c", "virt/vmm/examples/guest_lifecycle_controller.rs",
                   "virt/vmm/examples/native_live_api/entry.rs",
                   "resources/kernels/patches/live/0001-virtio-silo-vmgenid.patch"]
        revisions = {name: subprocess.run(["git", "rev-parse", "HEAD"], cwd=checkout, check=True, text=True,
                                          capture_output=True, timeout=5).stdout.strip()
                     for name, checkout in (("silo", REPO), ("native", self.inputs.native.native_root))}
        shutil.copyfile(self.inputs.kernel_config, self.evidence / "kernel.config")
        record = {"case": self.case, "image": image, "identities": identities, "revisions": revisions,
                  "kernel_source": str(self.fixture.kernel_source), "kernel_config": str(self.inputs.kernel_config),
                  "source_sha256": {name: overlay.digest(REPO / name) for name in sources if (REPO / name).is_file()},
                  "fixture": str(self.fixture.directory), "manifest": self.fixture.manifest,
                  "source_role": {"machine_id": self.fixture.role.machine_id, "run_id": self.fixture.role.run_id,
                                  "network": SOURCE.__dict__},
                  "scope": "explicit restored-Silo guest proof; no public Phase 13-15 workflow, no capability change"}
        (self.evidence / "inputs.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.silo.ws.record("guest-restored-inputs", json.dumps(record, sort_keys=True) + "\n")

    # -- evidence -----------------------------------------------------------------

    def event(self, name: str, **detail) -> int:
        stamp = time.monotonic_ns()
        self.timeline.append({"event": name, "monotonic_ns": stamp, **detail})
        return stamp

    def create(self, label: str, disks: list[Path], role: SessionRole, restore: Path | None = None):
        session = self.session_type.create(self.args, self.evidence / label, disks, role, restore=restore)
        self.event("native-ready", role=label, pid=session.process.pid)
        return session

    def retire(self, session) -> dict:
        record = cleanup_session(session)
        self.cleanups.append(record)
        self.args.sessions.remove(session)
        require(record["native_stop_acknowledged"] and record["os_reaped"] and not record["errors"],
                f"native owner {session.directory} did not stop/reap cleanly: {record}")
        require(not lease_conflicts(session), "retired native owner still holds its closure lease")
        self.event("native-retired", role=session.role.label, pid=record["process_pid"])
        return record

    def close(self) -> dict:
        helpers = [helper.reap() for helper in self.helpers]
        sessions = [cleanup_session(owner) for owner in list(self.args.sessions)]
        self.cleanups.extend(sessions)
        return {"helpers": helpers, "sessions": self.cleanups,
                "all_reaped": all(value["terminal"] and not value["errors"] for value in self.cleanups)
                and all(helper["exit_status"] is not None for helper in helpers)}

    # -- guest RPC helper ---------------------------------------------------------

    def _stem(self, session, label: str) -> Path:
        self.attach_sequence += 1
        return self.attach_root / f"{self.attach_sequence:04d}-{session.role.label}-{label}"

    def _request(self, stem: Path, fd: int, operation: dict, deadline_ms: int) -> Path:
        path = stem.with_suffix(".request.json")
        with path.open("x", encoding="utf-8") as output:
            json.dump({"fd": fd, "deadline_ms": deadline_ms, "operation": operation}, output, sort_keys=True)
        return path

    def attach(self, session, operation: dict, label: str, *, deadline_ms: int = 60_000,
               required: bool = True) -> dict:
        """One bounded attach helper over a fresh native 1027 stream; result retained verbatim."""
        stem = self._stem(session, label)
        stream = session.open_stream(AGENT_PORT)
        try:
            path = self._request(stem, stream.fileno(), operation, deadline_ms)
            process = subprocess.Popen([str(self.inputs.controller), "--attach", str(path)],
                                       pass_fds=(stream.fileno(),), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            stream.close()
        try:
            stdout, stderr = process.communicate(timeout=deadline_ms / 1000 + 15)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        stem.with_suffix(".stdout").write_bytes(stdout)
        stem.with_suffix(".stderr").write_bytes(stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.startswith(b"{")]
        result = records[0] if len(records) == 1 and records[0].get("record") == "result" else None
        with (self.attach_root / "index.jsonl").open("a") as index:
            index.write(json.dumps({"stem": stem.name, "label": label, "kind": operation["kind"],
                                    "exit_status": process.returncode,
                                    "passed": result["passed"] if result else None}, sort_keys=True) + "\n")
        if required:
            failed = [check for check in (result or {}).get("checks", []) if not check["passed"]]
            if not (process.returncode == 0 and result is not None and result["passed"]):
                raise AttachFailure(f"attach {label} failed (exit {process.returncode}); failed checks {failed}; "
                                    f"harness_error {(result or {}).get('harness_error')}; evidence {stem}")
        return result or {"passed": False, "output": None, "checks": []}

    def hold(self, session, operation: dict, label: str, *, deadline_ms: int = 600_000) -> Held:
        stem = self._stem(session, label)
        streams = [session.open_stream(AGENT_PORT)]
        try:
            if operation.get("ssh") is not None:
                streams.append(session.open_stream(SSH_PORT))
                operation = dict(operation, ssh=dict(operation["ssh"], fd=streams[1].fileno()))
            path = self._request(stem, streams[0].fileno(), dict(operation, kind="hold"), deadline_ms)
            process = subprocess.Popen([str(self.inputs.controller), "--attach", str(path)],
                                       pass_fds=tuple(stream.fileno() for stream in streams),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            for stream in streams:
                stream.close()
        held = Held(process, stem, {})
        self.helpers.append(held)
        buffer = bytearray()
        deadline = time.monotonic() + 60
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"\n" not in buffer:
                require(time.monotonic() < deadline and process.poll() is None,
                        f"hold helper did not report ready: {stem}")
                if selector.select(timeout=.1):
                    chunk = os.read(process.stdout.fileno(), 65536)
                    require(bool(chunk), f"hold helper closed stdout before ready: {stem}")
                    buffer.extend(chunk)
        line, _, rest = bytes(buffer).partition(b"\n")
        require(not rest, "hold helper wrote beyond its ready record before release")
        stem.with_suffix(".ready.stdout").write_bytes(line + b"\n")
        held.ready = json.loads(line)
        require(held.ready.get("record") == "ready", f"hold helper did not report ready: {stem}")
        return held

    # -- guest RPC operations -----------------------------------------------------

    @staticmethod
    def status(result: dict) -> dict:
        observation = result["output"]["observation"]
        status = observation["status"]["status"]
        require(status is not None, "observation lacks agent status")
        return status

    def observe(self, session, label: str, *, expect: dict | None = None, **observe) -> dict:
        return self.attach(session, {"kind": "observe", "expect": expect or {}, "observe": observe}, label)

    def files(self, session, label: str, paths: list[str], **extra) -> dict[str, bytes]:
        result = self.observe(session, label, files=[{"path": path, "max_bytes": 65536} for path in paths], **extra)
        values = {}
        for entry in result["output"]["observation"]["files"]:
            require(entry["error"] is None, f"guest file read failed: {entry}")
            values[entry["path"]] = content_bytes(entry["content"])
        require(set(values) == set(paths), "every requested guest file must be observed")
        return values

    def execute(self, session, identity: dict, argv: list[str], label: str, *, expect_rpc="ok",
                expect_exit: int | None = 0, timeout_ms: int = 10_000, required: bool = True) -> dict:
        operation = {"kind": "exec", "start": {
            "execution_id": str(uuid.uuid4()), "expected_agent_instance_id": identity["agent_instance_id"],
            "expected_agent_boot_id": identity["boot_id"], "argv": argv, "working_directory": "/",
            "user": "root", "environment": []},
            "stdin_hex": None, "timeout_ms": timeout_ms, "max_output_bytes": 65536,
            "expect_rpc": expect_rpc, "expect_exit_code": expect_exit}
        return self.attach(session, operation, label, required=required)

    def probe_json(self, session, identity: dict, argv: list[str], label: str) -> dict:
        result = self.execute(session, identity, argv, label)
        return json.loads(content_bytes(result["output"]["process"]["stdout"]))

    def refused(self, session, identity: dict, argv: list[str], label: str) -> dict:
        """An admitted refusal: an RPC error or a typed launch failure, never a started process."""
        result = self.execute(session, identity, argv, label, expect_rpc="any", expect_exit=None, required=False)
        output = result["output"]
        require(output is not None and result.get("harness_error") is None, f"{label}: refusal probe did not run")
        process = output["process"]
        require(output["rpc"]["outcome"] == "error" or process["launch_failed"] is not None
                or not process["started"], f"{label}: process request was admitted: {output}")
        return output

    def wait_ready(self, session) -> dict:
        deadline = time.monotonic() + 120
        while True:
            result = self.attach(session, {"kind": "observe", "expect": {"ready": True, "agent_pid1": True},
                                           "observe": {}}, "ready", deadline_ms=10_000, required=False)
            if result["passed"]:
                status = self.status(result)
                identity = status["expected_identity"]
                require(identity["machine_id"] == session.role.machine_id and identity["run_id"] == session.role.run_id,
                        "cold Silo guest identity differs from the fixture launch identity")
                return status
            require(time.monotonic() < deadline, f"Silo agent did not become Ready; inspect {session.directory}")
            time.sleep(1)

    def interface_index(self, session, mac: str) -> tuple[int, str]:
        names, cursor = [], None
        while True:
            page = self.attach(session, {"kind": "list_directory", "path": "/sys/class/net", "limit": 64,
                                         "cursor_hex": cursor}, "list-net")["output"]["page"]
            names.extend(entry["name"] for entry in page["entries"])
            cursor = page["next_cursor_hex"]
            if cursor is None:
                break
        values = self.files(session, "net-addresses", [f"/sys/class/net/{name}/{leaf}" for name in names
                                                        for leaf in ("address", "ifindex")])
        matches = [name for name in names if values[f"/sys/class/net/{name}/address"].strip().decode() == mac]
        require(len(matches) == 1, f"exactly one guest interface must carry {mac}: {names}")
        return int(values[f"/sys/class/net/{matches[0]}/ifindex"]), matches[0]

    def generation(self, session, label: str, **expect) -> dict:
        result = self.observe(session, label, expect=expect, generation={})
        observed = result["output"]["observation"]["generation"]
        require(observed is not None and observed["error"] is None and not observed["absent"]
                and observed["fields"] is not None, f"Silo generation_state unavailable: {observed}")
        return observed

    # -- native barriers ----------------------------------------------------------

    def generation_ack(self, session, expected: dict) -> dict:
        session.command("generation-wait", timeout=6)
        native = session.native()
        for key in ("sequence", "id", "flags", "deadline", "config_generation"):
            require(native[key] == expected[key], f"native request {key} replaced or renewed before ACK")
        require(native["outcome"] == "acknowledged" and native["timely"],
                f"no exact timely native generation ACK: {native}")
        return native

    def fenced(self, session, label: str) -> dict:
        value = session.live()
        require(not value["activation_released"] and not value["activation_failed"] and all(
            entry["activation_fenced"] is True for entry in value["providers"]
            if entry["activation_fenced"] is not None), f"{label}: native provider fences opened early")
        stream = session.open_stream(FORWARD_PORT)
        rejected = bytearray()
        try:
            stream.settimeout(.1)
            until = time.monotonic() + 2
            while time.monotonic() < until and b"ERR" not in rejected:
                try:
                    chunk = stream.recv(4096)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                rejected.extend(chunk)
        finally:
            stream.close()
        require(not rejected.startswith(b"OK") and (b"ERR" in rejected or not rejected),
                f"{label}: non-control mux service opened while fenced")
        self.event("fenced-observed", role=session.role.label, label=label)
        return {"live": value, "non_control_refusal_hex": bytes(rejected).hex()}

    def prepared(self, child, cut: Path) -> dict:
        value = child.live()
        require(value["state"].startswith("RestorePrepared") and value["backing"] == "RestoredPrivate"
                and value["tracking"] == "Some(Capture)" and value["coverage_valid"]
                and value["native_commands_reconciled"] and not value["activation_released"]
                and not value["activation_failed"], "actual parked/fenced/private/tracked native restore required")
        facts = value["restore_installation"]
        require(facts is not None and facts["tracking_before_install"] and facts["complete"]
                and facts["dirty_pages"] > 0, "native install effects must follow tracking and enter dirty coverage")
        info = (cut / "memory.ram").stat()
        require(value["file_backings"] and all(pair == [info.st_dev, info.st_ino] for pair in value["file_backings"]),
                "every child region must use the exact inherited immutable inode")
        fenced = {entry["configured_id"]: entry["activation_fenced"] for entry in value["providers"]
                  if entry["activation_fenced"] is not None}
        require(fenced.get("net0") is True and fenced.get("vsock") is True,
                "actual destination network and non-control mux gates must remain closed")
        require(lease_conflicts(child), "prepared child lost closure lease")
        egress = [frame for frame in child.relay.frames() if frame["direction"] == "guest-to-netd"]
        require(not egress, "parked restored guest emitted network frames before CPU release")
        return value

    # -- source -------------------------------------------------------------------

    def source_cut(self, *, alias: bool, continuation: bool) -> tuple[Cut, dict]:
        fixture = self.fixture
        source = self.create("source", [fixture.root, fixture.data], fixture.role)
        record: dict = {"pid": source.process.pid}
        status = self.wait_ready(source)
        identity = status["expected_identity"]
        require(status["boot"]["agent_is_pid1"] is True and status["boot"]["mode"] == "agent_pid1",
                "positive restored proof requires the admitted AgentPid1 profile")
        record["ready_status"] = status
        witness = self.observe(source, "witness-advancing", counters=[WITNESS_COUNTER], cgroups=["workloads"],
                               samples={"count": 40, "interval_ms": 25, "expect": "advancing"})
        record["witness_advancing"] = witness["output"]["observation"]["counters"]
        values = self.files(source, "witness-provenance",
                            [USERDATA_INVOCATIONS, USERDATA_MEMBERSHIP, WITNESS_PID, WITNESS_MEMBERSHIP])
        require(values[USERDATA_INVOCATIONS] == b"x", "cold userdata must run exactly once")
        for path in (USERDATA_MEMBERSHIP, WITNESS_MEMBERSHIP):
            require(b"0::/silo/workloads" in values[path].splitlines(), f"{path} escaped workload containment")
        witness_pid = int(values[WITNESS_PID])
        stat = self.files(source, "witness-stat", [f"/proc/{witness_pid}/stat", "/proc/net/tcp", "/proc/net/tcp6"])
        witness_starttime = proc_starttime(stat[f"/proc/{witness_pid}/stat"])
        require(listening(stat["/proc/net/tcp"] + stat["/proc/net/tcp6"], CONFLICT_PORT),
                "captured workload listener did not bind")
        record["witness"] = {"pid": witness_pid, "starttime": witness_starttime,
                             "userdata_membership": values[USERDATA_MEMBERSHIP].decode(),
                             "witness_membership": values[WITNESS_MEMBERSHIP].decode()}
        ifindex, name = self.interface_index(source, SOURCE.mac)
        network = ipaddress.IPv4Network(f"{SOURCE.ipv4}/{SOURCE.prefix_length}", strict=False)
        ordinary, proxy = str(network.network_address + 50), str(network.network_address + 51)
        setup = self.probe_json(source, identity, [PROBE, "setup", str(ifindex), MANAGED_NAME, ordinary, proxy,
                                                   SEEDED_NEIGHBOUR_MAC], "network-setup")
        require(setup["ifindex"] == ifindex and setup["name"] == MANAGED_NAME, "rename lost the retained ifindex")
        require(any(entry.get("destination") == ordinary for entry in setup["neighbours"])
                and any(entry.get("destination") == proxy for entry in setup["proxy_neighbours"]),
                "seeded ordinary/proxy neighbours absent on the managed NIC")
        require(any(route.get("dst_length") == 0 and route.get("gateway") == SOURCE.gateway
                    and route.get("oif") == ifindex for route in setup["routes_ipv4"]),
                "cold managed default route did not survive rename setup")
        if alias:
            self.execute(source, identity, ["/sbin/ip", "addr", "add", f"{TOPOLOGY_ALIAS}/24", "dev", MANAGED_NAME],
                         "topology-alias")
            setup = self.probe_json(source, identity, [PROBE, "observe", str(ifindex)], "topology-observe")
            require(any(entry.get("address") == TOPOLOGY_ALIAS for entry in setup["addresses"]),
                    "unsupported alias topology was not installed before capture")
        record["network_before_freeze"] = {"original_name": name, "setup": setup,
                                           "seeded": {"ordinary": ordinary, "proxy": proxy}}
        record["source_wire_positive"] = source.relay.probe_address(SOURCE, label="source-positive")
        nonce = secrets.token_hex(16)
        mark = source.relay.mark("source-gateway")
        record["source_gateway_probe"] = self.probe_json(source, identity, [PROBE, "gateway", SOURCE.gateway, nonce],
                                                         "source-gateway")
        record["source_gateway_wire"] = source.relay.gateway_evidence(SOURCE, nonce, since=mark)
        source_token = secrets.token_hex(16)
        held = self.hold(source, {
            "process": {"execution_id": str(uuid.uuid4()), "expected_agent_instance_id": identity["agent_instance_id"],
                        "expected_agent_boot_id": identity["boot_id"],
                        "argv": ["/bin/sh", "-c", f"while :; do printf x >>{EXEC_COUNTER}; sleep 0.02; done"],
                        "working_directory": "/", "user": "root", "environment": []},
            "ssh": {"fd": -1, "host_public_key": status["ssh"]["host_public_key"],
                    "private_key": str(fixture.directory / "client"),
                    "certificate": str(fixture.directory / "client-cert.pub"), "user": "root",
                    "command": f"while :; do printf x >>{SSH_COUNTER}; sleep 0.02; done"},
            "listen": {"listen": "tcp:127.0.0.1:0", "token_hex": source_token, "unix_mode": None}}, "captured-sessions")
        listener = held.ready["listen_bound"]
        require(listener is not None and held.ready["process_started"] and held.ready["ssh_exec_started"],
                "captured exec/SSH/forward sessions did not start")
        record["captured_sessions_ready"] = held.ready
        self.observe(source, "captured-sessions-advancing", counters=[EXEC_COUNTER, SSH_COUNTER],
                     samples={"count": 40, "interval_ms": 25, "expect": "advancing"})
        page = self.attach(source, {"kind": "list_directory", "path": "/", "limit": 1}, "source-cursor")
        cursor = page["output"]["page"]["next_cursor_hex"]
        require(cursor is not None, "source filesystem listing produced no retained cursor")
        generation = self.generation(source, "source-generation")
        reseeds = int(generation["fields"]["reseed_count"])
        record["source_generation"] = {"guest": generation, "native": source.native()}
        profile = source.directory / "profile"
        record["profile"] = self.attach(source, {"kind": "profile", "directory": str(profile),
                                                 "kernel_config": str(self.inputs.kernel_config)},
                                        "profile")["output"]
        source.command(f"profile {profile}")
        reference = {"machine_id": identity["machine_id"], "run_id": identity["run_id"],
                     "operation_id": str(uuid.uuid4()), "freeze_epoch": 1}
        freeze = {"kind": "freeze", "request": {"expected": identity, "freeze_ref": reference, "deadline_ms": 5000},
                  "expect_rpc": "ok", "observe": {"counters": [WITNESS_COUNTER, EXEC_COUNTER, SSH_COUNTER],
                                                  "samples": {"count": 5, "interval_ms": 80, "expect": "stationary"}}}
        first = self.attach(source, freeze, "freeze")
        self.event("source-frozen", pid=source.process.pid)
        repeat = self.attach(source, freeze, "freeze-repeat")
        require(repeat["output"]["rpc"]["response"] == first["output"]["rpc"]["response"],
                "repeated exact freeze changed its settled reference/root set")
        refusal = self.refused(source, identity, ["/bin/true"], "frozen-spawn")
        record["freeze"] = {"first": first["output"], "repeat": repeat["output"]["rpc"], "spawn_refusal": refusal}
        source.command("pause")
        self.event("source-paused", pid=source.process.pid)
        cut = self.evidence / "cut"
        captured = source.capture(cut, "full", accept=True)
        assert_writers_closed(source.process.pid, cut)
        require(bytes(captured["binding"]["source_run"]) == uuid.UUID(fixture.role.run_id).bytes,
                "captured source-run binding differs from the actual Silo source run")
        self.event("source-captured", pid=source.process.pid)
        record["capture"] = captured
        if continuation:
            record["continuation"] = self.continuation(source, identity, reference, reseeds)
        record["captured_sessions_released"] = held.release()
        self.retire(source)
        return Cut(cut, identity, reference, reseeds, ifindex, witness_pid, witness_starttime, setup, status,
                   cursor, listener, captured, fixture.manifest), record

    def continuation(self, source, identity: dict, reference: dict, reseeds: int) -> dict:
        """Ordinary source ClockOnly resume, observed through the real agent, then exact source Thaw."""
        from native_generation_controller import validate_ack
        previous = source.native()
        source.command("resume")
        until = time.monotonic() + 6
        while True:
            native = source.native()
            guest = self.generation(source, "source-resume-generation")["fields"]
            if (native["outcome"] == "acknowledged" and guest.get("ack_accessor_returned") == "1"
                    and int(guest["ack_sequence"]) == native["sequence"]):
                break
            require(time.monotonic() < until, "ordinary source resume did not complete its real ClockOnly ACK")
            time.sleep(.01)
        require(native["flags"] == 3 and native["id"] == previous["id"]
                and native["sequence"] == previous["sequence"] + 1,
                "source resume replaced its identity or failed to publish the next ClockOnly request")
        validate_ack(native, guest, reseeds, clock=True)
        frozen = self.observe(source, "source-resumed-frozen", expect={
            "identity": identity, "lifecycle_state": "frozen", "freeze_ref": reference})
        thaw = self.attach(source, {"kind": "thaw", "request": {"expected": identity, "freeze_ref": reference,
                                                                "rollback": False, "deadline_ms": 5000},
                                    "observe": {"counters": [WITNESS_COUNTER],
                                                "samples": {"count": 40, "interval_ms": 25, "expect": "advancing"}}},
                           "source-thaw")
        self.event("source-thawed")
        return {"native": native, "guest": guest, "frozen_after_resume": frozen["output"],
                "thaw": thaw["output"], "api": "ordinary Control::resume / native ClockOnly, no source Activate"}

    # -- children -----------------------------------------------------------------

    def restore(self, cut: Cut, label: str, network: NetworkIdentity) -> Child:
        from native_generation_controller import validate_ack
        disks = []
        for index in range(2):
            path = self.evidence / f"{label}-disk{index}.raw"
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(cut.directory / f"disk{index}.raw"), str(path)],
                           check=True, timeout=60, capture_output=True)
            path.chmod(0o600)
            disks.append(path)
        role = SessionRole(label, str(uuid.uuid4()), str(uuid.uuid4()), network)
        session = self.create(label, disks, role, restore=cut.directory)
        record: dict = {"pid": session.process.pid, "role": {"machine_id": role.machine_id, "run_id": role.run_id,
                                                              "network": network.__dict__}}
        record["prepared"] = self.prepared(session, cut.directory)
        session.command("generation-fresh")
        expected = session.native()
        self.event("generation-fresh", role=label)
        session.command("release")
        self.event("cpus-released", role=label)
        native = self.generation_ack(session, expected)
        record["ack_monotonic_ns"] = self.event("generation-acknowledged", role=label)
        record["after_ack"] = self.fenced(session, "after generation ACK")
        inherited = self.observe(session, "inherited-frozen", expect={
            "identity": cut.identity, "lifecycle_state": "frozen", "freeze_ref": cut.freeze_ref,
            "ready": False, "agent_pid1": True},
            generation={}, cgroups=["workloads"], counters=[WITNESS_COUNTER],
            files=[{"path": f"/proc/{cut.witness_pid}/stat", "max_bytes": 4096}],
            samples={"count": 5, "interval_ms": 80, "expect": "stationary"})
        observation = inherited["output"]["observation"]
        guest = observation["generation"]["fields"]
        validate_ack(native, guest, cut.reseeds, clock=False)
        stat = content_bytes(observation["files"][0]["content"])
        require(proc_starttime(stat) == cut.witness_starttime, "persistent witness is not the captured process")
        require(all(value["frozen"] for value in observation["cgroups"] if value["group"] == "workloads"),
                "restored workloads are not kernel-frozen")
        record["inherited"] = inherited["output"]
        record["generation"] = {"request": expected, "native": native, "guest": guest}
        return Child(session, role, native, guest, record)

    def activation_request(self, cut: Cut, child: Child, *, hook: dict | None, listeners: list[dict],
                           network: bool = True) -> dict:
        identity = child.role.network
        return {"activation_id": str(uuid.uuid4()), "expected": cut.identity, "freeze_ref": cut.freeze_ref,
                "destination_machine_id": child.role.machine_id, "destination_run_id": child.role.run_id,
                "network": {"mac": identity.mac, "ipv4": identity.ipv4, "prefix_length": identity.prefix_length,
                            "gateway": identity.gateway, "dns_servers": [identity.gateway], "dns_search": []}
                if network else None,
                "listeners": listeners, "hook": hook, "host_time": None,
                "shutdown_manifest_json": json.dumps(cut.manifest, separators=(",", ":")), "deadline_ms": 30000}

    def probe_hook(self, cut: Cut) -> dict:
        return {"argv": [PROBE, "hook", str(cut.ifindex), HOOK_OBSERVATION, HOOK_MARKER], "environment": [],
                "working_directory": "/", "timeout_ms": 5000}

    def activate(self, child: Child, request: dict, label: str, *, lost_reply: bool = False) -> dict:
        # A discarded reply has no RPC outcome to match; its own discard checks decide.
        return self.attach(child.session, {"kind": "activate", "request": request, "lost_reply": lost_reply,
                                           "expect_rpc": "any" if lost_reply else "ok",
                                           "observe": {"counters": [WITNESS_COUNTER]}}, label)

    def replaced_network(self, cut: Cut, child: Child, observed: dict) -> dict:
        """Kernel readback after activation: same object, destination identity only."""
        target, ifindex = child.role.network, cut.ifindex
        mac = target.mac.replace(":", "")
        require(observed["ifindex"] == ifindex and observed["name"] == MANAGED_NAME,
                "activation did not keep the retained renamed interface object")
        links = [link for link in observed["links"] if link["ifindex"] == ifindex]
        require(len(links) == 1 and links[0]["mac_hex"] == mac, "managed link MAC is not the destination override")
        addresses = [entry for entry in observed["addresses"] if entry["ifindex"] == ifindex
                     and isinstance(entry.get("address"), str) and ipaddress.ip_address(entry["address"]).version == 4]
        require([(entry["address"], entry["prefix_length"]) for entry in addresses]
                == [(target.ipv4, target.prefix_length)], f"managed IPv4 is not exactly the destination: {addresses}")
        source_network = ipaddress.IPv4Network(f"{SOURCE.ipv4}/{SOURCE.prefix_length}", strict=False)
        stale = {SOURCE.ipv4, SOURCE.gateway, TOPOLOGY_ALIAS, str(source_network.network_address),
                 str(source_network.broadcast_address)}
        for route in observed["routes_ipv4"]:
            require(not stale & {str(route.get(key)) for key in ("gateway", "destination", "preferred_source")},
                    f"source-derived IPv4 route survived activation: {route}")
        require(any(route.get("dst_length") == 0 and route.get("gateway") == target.gateway
                    and route.get("oif") == ifindex and route.get("table") == 254
                    for route in observed["routes_ipv4"]), "destination default route absent")
        seeded = {entry.get("destination") for entry in cut.source_setup["neighbours"]
                  + cut.source_setup["proxy_neighbours"] if entry.get("ifindex") == ifindex}
        remaining = {entry.get("destination") for entry in observed["neighbours"] + observed["proxy_neighbours"]
                     if entry.get("ifindex") == ifindex}
        require(seeded and not seeded & remaining, "seeded source neighbours survived activation")
        resolver = bytes.fromhex(observed["resolv_conf_hex"]).decode()
        require(f"nameserver {target.gateway}" in resolver.splitlines() and SOURCE.gateway not in resolver,
                "resolver is not exactly the destination configuration")
        return {"ifindex": ifindex, "addresses": addresses, "resolv_conf": resolver,
                "seeded_removed": sorted(seeded)}

    def positive_child(self, cut: Cut, index: int) -> dict:
        child = self.restore(cut, f"child-{index}", destination(index))
        session, record = child.session, child.record
        token = secrets.token_hex(16)
        session.forward.register("restored-forward", token)
        listeners = [{"name": "restored-forward", "registration": {
            "listen": f"tcp:127.0.0.1:{FORWARD_GUEST_PORT}", "token_hex": token, "unix_mode": None}}]
        request = self.activation_request(cut, child, hook=self.probe_hook(cut), listeners=listeners)
        activation_mark = session.relay.mark("activate")
        first = self.activate(child, request, "activate")
        rpc = first["output"]["rpc"]
        require(record["ack_monotonic_ns"] < rpc["started_monotonic_ns"], "guest Activate preceded the native ACK")
        self.event("guest-activated", role=child.role.label)
        resolved = first["output"]["resolved_request"]
        response = rpc["response"]
        destination_identity, destination_ref = response["identity"], response["freeze_ref"]
        replay = self.activate(child, resolved, "activate-replay")
        require(replay["output"]["rpc"]["response"] == response, "exact Activate replay changed its recorded result")
        conflicting = dict(resolved, network=dict(resolved["network"], dns_search=["conflict.invalid"]))
        conflict = self.attach(session, {"kind": "activate", "request": conflicting, "expect_rpc": {
            "error": {"code": "already_exists"}}}, "activate-conflict")
        stale_thaw = self.attach(session, {"kind": "thaw", "request": {
            "expected": cut.identity, "freeze_ref": cut.freeze_ref, "rollback": False, "deadline_ms": 5000},
            "expect_rpc": "any"}, "source-thaw-rejected")
        require(stale_thaw["output"]["rpc"]["outcome"] == "error", "source identity/epoch Thaw was admitted")
        activated = self.observe(session, "activated-frozen", expect={
            "identity": destination_identity, "lifecycle_state": "activated_frozen", "freeze_ref": destination_ref,
            "activation_id": request["activation_id"], "ready": False},
            cgroups=["workloads", "activation"], counters=[WITNESS_COUNTER],
            files=[{"path": HOOK_MARKER, "max_bytes": 64}, {"path": HOOK_OBSERVATION, "max_bytes": 65536},
                   {"path": USERDATA_INVOCATIONS, "max_bytes": 64}],
            samples={"count": 5, "interval_ms": 80, "expect": "stationary"})
        observation = activated["output"]["observation"]
        files = {entry["path"]: content_bytes(entry["content"]) for entry in observation["files"]}
        require(files[HOOK_MARKER].strip() == b"1", "selected hook ran other than exactly once across replay")
        require(files[USERDATA_INVOCATIONS] == b"x", "activation re-ran cold userdata")
        groups = {value["group"]: value for value in observation["cgroups"]}
        require(groups["workloads"]["frozen"] and groups["activation"]["populated"] is False,
                "workloads thawed or hook descendants survived activation")
        hook_observation = json.loads(files[HOOK_OBSERVATION])
        require(b"0::/silo/activation" in bytes.fromhex(hook_observation["self_cgroup_hex"]).splitlines(),
                "selected hook did not run in the activation sibling")
        record["network_after_activate"] = self.replaced_network(cut, child, hook_observation)
        status_addresses = observation["status"]["status"]["system"]["ip_addresses"]
        require(child.role.network.ipv4 in status_addresses and SOURCE.ipv4 not in status_addresses,
                f"activated guest status retained source network identity: {status_addresses}")
        require(destination_identity["boot_id"] == cut.identity["boot_id"]
                and destination_identity["agent_instance_id"] != cut.identity["agent_instance_id"]
                and destination_identity["machine_id"] == child.role.machine_id
                and destination_identity["run_id"] == child.role.run_id, "destination identity rotation is wrong")
        record["after_activate"] = self.fenced(session, "after guest Activate")
        thaw = self.attach(session, {"kind": "thaw", "request": {
            "expected": destination_identity, "freeze_ref": destination_ref, "rollback": False, "deadline_ms": 5000},
            "observe": {"counters": [WITNESS_COUNTER], "samples": {"count": 40, "interval_ms": 25, "expect": "advancing"}}},
            "thaw")
        thaw_rpc = thaw["output"]["rpc"]
        require(rpc["finished_monotonic_ns"] < thaw_rpc["started_monotonic_ns"], "Thaw preceded Activate completion")
        self.event("guest-thawed", role=child.role.label)
        retired = self.observe(session, "captured-sessions-retired", counters=[EXEC_COUNTER, SSH_COUNTER],
                               samples={"count": 5, "interval_ms": 80, "expect": "stationary"})
        record["after_thaw"] = self.fenced(session, "after destination Thaw")
        release_mark = session.relay.mark("fence-release")
        released_at = time.monotonic_ns()
        require(thaw_rpc["finished_monotonic_ns"] < released_at, "fence release preceded Thaw completion")
        session.command("activate")  # Native provider fence release only, NOT guest activation.
        self.event("provider-fences-released", role=child.role.label)
        released = session.live()
        require(released["activation_released"] and not released["activation_failed"] and all(
            entry["activation_fenced"] is False for entry in released["providers"]
            if entry["activation_fenced"] is not None), "native provider fence release acknowledgements missing")
        nonce = secrets.token_hex(16)
        gateway_mark = session.relay.mark("destination-gateway")
        gateway = self.probe_json(session, destination_identity,
                                  [PROBE, "gateway", child.role.network.gateway, nonce], "gateway")
        wire = session.relay.gateway_evidence(child.role.network, nonce, since=gateway_mark)
        paired = session.relay.paired_address_probes(child.role.network, SOURCE.ipv4)
        relay_nonce = secrets.token_hex(8)
        forward = self.execute(session, destination_identity, [
            "/bin/sh", "-c", f"printf '%s\\n' {relay_nonce} | nc -w 3 127.0.0.1 {FORWARD_GUEST_PORT}"],
            "listener-relay")
        require(content_bytes(forward["output"]["process"]["stdout"]) == f"ECHO {relay_nonce}\n".encode(),
                "selected activation listener did not relay with the destination token")
        old_host, old_port = cut.source_listener.removeprefix("tcp:").rsplit(":", 1)
        old_forward = self.execute(session, destination_identity, [
            "/bin/sh", "-c", f"printf 'old\\n' | nc -w 2 {old_host} {old_port}"], "old-listener",
            expect_exit=None)
        require(b"ECHO" not in content_bytes(old_forward["output"]["process"]["stdout"]),
                "captured source forward listener resurrected")
        events = session.forward.events()
        require([event["listener"] for event in events if event["reply"] == "OK"] == ["restored-forward"]
                and all(event["nonce"] == relay_nonce for event in events if event["reply"] == "OK"),
                f"forward return port saw unexpected relays: {events}")
        old_instance = self.refused(session, cut.identity, ["/bin/true"], "old-instance")
        cursor = self.attach(session, {"kind": "list_directory", "path": "/", "limit": 1,
                                       "cursor_hex": cut.source_cursor,
                                       "expect_rpc": {"error": {"code": "failed_precondition",
                                                                "error_code": "ERROR_CODE_CURSOR_EXPIRED"}}},
                             "old-cursor")
        after = self.probe_json(session, destination_identity, [PROBE, "observe", str(cut.ifindex)], "network-released")
        leak = session.relay.assert_no_source_identity(SOURCE, since=release_mark)
        final = self.files(session, "userdata-after", [USERDATA_INVOCATIONS])
        require(final[USERDATA_INVOCATIONS] == b"x", "userdata invocation count changed after thaw")
        record.update({
            "activate": first["output"], "replay": replay["output"]["rpc"], "conflict": conflict["output"]["rpc"],
            "source_thaw_rejected": stale_thaw["output"]["rpc"], "activated": activated["output"],
            "thaw": thaw["output"], "captured_sessions_retired": retired["output"], "released": released,
            "gateway": {"guest": gateway, "wire": wire}, "paired_old_address": paired,
            "listener_relay": forward["output"], "old_listener": old_forward["output"], "forward_events": events,
            "old_instance": old_instance, "old_cursor": cursor["output"]["rpc"],
            "network_after_release": after, "source_identity_egress": leak,
            "activation_wire_mark": activation_mark, "identity": destination_identity,
            "freeze_ref": destination_ref})
        self.retire(session)
        return record

    def failed_activation(self, cut: Cut, child: Child, request: dict, label: str, *,
                          markers: tuple[str, ...] = ()) -> dict:
        """Sticky ActivationFailed: exact retry returns the recorded failure, no thaw, fences closed."""
        session = child.session
        operation = {"kind": "activate", "request": request, "expect_rpc": "any",
                     "observe": {"counters": [WITNESS_COUNTER]}}
        first = self.attach(session, operation, label)
        rpc = first["output"]["rpc"]
        require(rpc["outcome"] == "error", f"{label}: activation unexpectedly succeeded")
        retry = self.attach(session, dict(operation, request=first["output"]["resolved_request"]), label + "-retry")
        require(retry["output"]["rpc"]["outcome"] == "error"
                and retry["output"]["rpc"]["error"]["code"] == rpc["error"]["code"]
                and retry["output"]["rpc"]["error"]["message"] == rpc["error"]["message"],
                f"{label}: exact retry did not return the recorded failure")
        failed = self.observe(session, label + "-status", expect={"lifecycle_state": "activation_failed",
                                                                  "activation_id": request["activation_id"]},
                              cgroups=["workloads", "activation"], counters=[WITNESS_COUNTER],
                              files=[{"path": "/proc/net/tcp", "max_bytes": 65536},
                                     {"path": "/proc/net/tcp6", "max_bytes": 65536},
                                     *({"path": path, "max_bytes": 64} for path in markers)],
                              samples={"count": 5, "interval_ms": 80, "expect": "stationary"})
        observation = failed["output"]["observation"]
        groups = {value["group"]: value for value in observation["cgroups"]}
        require(groups["workloads"]["frozen"] and groups["activation"]["populated"] is False,
                f"{label}: workloads thawed or activation descendants survived")
        status = self.status(failed)
        current = status["expected_identity"]
        thaws = []
        for expected, reference in ((cut.identity, cut.freeze_ref), (current, status["lifecycle"]["freeze_ref"])):
            result = self.attach(session, {"kind": "thaw", "request": {
                "expected": expected, "freeze_ref": reference, "rollback": False, "deadline_ms": 5000},
                "expect_rpc": "any"}, label + "-thaw-rejected")
            require(result["output"]["rpc"]["outcome"] == "error", f"{label}: normal Thaw admitted after failure")
            thaws.append(result["output"]["rpc"])
        files = {entry["path"]: content_bytes(entry["content"]) for entry in observation["files"]}
        for path in markers:
            require(files[path] == b"x", f"{label}: failing hook did not run exactly once")
        fenced = self.fenced(session, label + " after failure")
        return {"first": first["output"], "retry": retry["output"]["rpc"], "status": failed["output"],
                "thaw_rejections": thaws, "fenced": fenced,
                "tcp": (files["/proc/net/tcp"] + files["/proc/net/tcp6"]).decode()}

    def failure_children(self, cut: Cut) -> dict:
        results = {}
        offset = 2
        hooks = {
            "hook-exit": ("exit 7", None),
            "hook-timeout": ("exec sleep 30", 500),
            "hook-descendant": ("sleep 30 </dev/null >/dev/null 2>&1 & exit 0", None),
        }
        for name, (script, timeout) in hooks.items():
            child = self.restore(cut, name, destination(offset))
            offset += 1
            marker = f"{STATE}/{name}-marker"
            hook = {"argv": ["/bin/sh", "-c", f"printf x >>{marker}; {script}"], "environment": [],
                    "working_directory": "/", "timeout_ms": timeout if timeout is not None else 5000}
            request = self.activation_request(cut, child, hook=hook, listeners=[])
            child.record["failure"] = self.failed_activation(cut, child, request, name, markers=(marker,))
            self.retire(child.session)
            results[name] = child.record
        child = self.restore(cut, "listener-conflict", destination(offset))
        offset += 1
        token = secrets.token_hex(16)
        listeners = [{"name": "conflict", "registration": {"listen": f"tcp:127.0.0.1:{CONFLICT_PORT}",
                                                           "token_hex": token, "unix_mode": None}}]
        request = self.activation_request(cut, child, hook=None, listeners=listeners)
        failure = self.failed_activation(cut, child, request, "listener-conflict")
        require(listening(failure["tcp"].encode(), CONFLICT_PORT), "conflicting workload listener was removed")
        alive = self.files(child.session, "conflict-witness", [f"/proc/{cut.witness_pid}/stat"])
        require(proc_starttime(alive[f"/proc/{cut.witness_pid}/stat"]) == cut.witness_starttime,
                "failed activation killed the persistent workload")
        child.record["failure"] = failure
        self.retire(child.session)
        results["listener-conflict"] = child.record
        results["lost-activation-reply"] = self.lost_activation_reply(cut, destination(offset))
        offset += 1
        results["lost-thaw"] = self.lost_thaw(cut, destination(offset))
        return results

    def lost_activation_reply(self, cut: Cut, network: NetworkIdentity) -> dict:
        child = self.restore(cut, "lost-activation-reply", network)
        session, record = child.session, child.record
        request = self.activation_request(cut, child, hook=self.probe_hook(cut), listeners=[])
        lost = self.activate(child, request, "activate-lost", lost_reply=True)
        rpc = lost["output"]["rpc"]
        require(rpc["outcome"] == "discarded" and rpc["discard"]["effect_observed"] is True,
                "activation reply was not discarded after its terminal effect was observed")
        resolved = lost["output"]["resolved_request"]
        replay = self.activate(child, resolved, "activate-replay")
        again = self.activate(child, resolved, "activate-replay-2")
        response = replay["output"]["rpc"]["response"]
        require(again["output"]["rpc"]["response"] == response, "lost-reply replay was not exact")
        marker = self.files(session, "lost-reply-marker", [HOOK_MARKER])
        require(marker[HOOK_MARKER].strip() == b"1", "replay after a lost reply re-ran the hook")
        thaw = self.attach(session, {"kind": "thaw", "request": {
            "expected": response["identity"], "freeze_ref": response["freeze_ref"], "rollback": False,
            "deadline_ms": 5000}, "observe": {"counters": [WITNESS_COUNTER], "samples": {
                "count": 40, "interval_ms": 25, "expect": "advancing"}}}, "thaw")
        self.fenced(session, "lost-reply child after Thaw")
        session.command("activate")  # Native provider fence release only.
        nonce = secrets.token_hex(16)
        mark = session.relay.mark("destination-gateway")
        gateway = self.probe_json(session, response["identity"], [PROBE, "gateway", network.gateway, nonce], "gateway")
        record.update({"lost": lost["output"], "replay": replay["output"]["rpc"], "thaw": thaw["output"]["rpc"],
                       "gateway": {"guest": gateway, "wire": session.relay.gateway_evidence(network, nonce, since=mark)}})
        self.retire(session)
        return record

    def lost_thaw(self, cut: Cut, network: NetworkIdentity) -> dict:
        child = self.restore(cut, "lost-thaw", network)
        session, record = child.session, child.record
        request = self.activation_request(cut, child, hook=None, listeners=[])
        response = self.activate(child, request, "activate")["output"]["rpc"]["response"]
        identity, reference = response["identity"], response["freeze_ref"]
        thaw = {"expected": identity, "freeze_ref": reference, "rollback": False, "deadline_ms": 5000}
        lost = self.attach(session, {"kind": "thaw", "request": thaw, "lost_reply": True, "expect_rpc": "any"},
                           "thaw-lost")
        require(lost["output"]["rpc"]["outcome"] == "discarded", "thaw reply was not discarded after kernel thaw")
        recovery_ref = dict(reference, freeze_epoch=reference["freeze_epoch"] + 1)
        recovery = self.attach(session, {"kind": "freeze", "request": {
            "expected": identity, "freeze_ref": recovery_ref, "deadline_ms": 5000},
            "observe": {"counters": [WITNESS_COUNTER], "samples": {"count": 5, "interval_ms": 80,
                                                                  "expect": "stationary"}}}, "recovery-freeze")
        stale = self.attach(session, {"kind": "thaw", "request": thaw, "expect_rpc": "any",
                                      "observe": {"counters": [WITNESS_COUNTER], "samples": {
                                          "count": 5, "interval_ms": 80, "expect": "stationary"}}}, "stale-thaw")
        require(stale["output"]["rpc"]["outcome"] == "error", "stale-epoch Thaw released the recovery freeze")
        frozen = self.observe(session, "recovery-frozen", expect={"lifecycle_state": "frozen",
                                                                  "freeze_ref": recovery_ref}, cgroups=["workloads"])
        record.update({"lost_thaw": lost["output"]["rpc"], "recovery_freeze": recovery["output"],
                       "stale_thaw": stale["output"], "recovery_frozen": frozen["output"],
                       "fenced": self.fenced(session, "lost-thaw recovery")})
        self.retire(session)
        return record

    def topology_child(self, cut: Cut) -> dict:
        child = self.restore(cut, "network-topology", destination(0))
        mismatch = self.activation_request(cut, child, hook=None, listeners=[], network=False)
        rejected = self.attach(child.session, {"kind": "activate", "request": mismatch, "expect_rpc": {
            "error": {"code": "failed_precondition", "message_contains": "topology differs"}}}, "presence-mismatch")
        unchanged = self.observe(child.session, "presence-mismatch-no-effects", expect={
            "identity": cut.identity, "lifecycle_state": "frozen", "freeze_ref": cut.freeze_ref},
            cgroups=["workloads"])
        request = self.activation_request(cut, child, hook=None, listeners=[])
        failure = self.failed_activation(cut, child, request, "network-topology")
        child.record.update({"presence_mismatch": rejected["output"]["rpc"],
                             "presence_unchanged": unchanged["output"], "failure": failure})
        self.retire(child.session)
        return child.record


def run(silo: Silo, image: str, case: str, probe: Path) -> dict:
    """Run one bounded restored cohort; returns the passed report, raises with evidence otherwise."""
    require(case in ("positive", "failures", "topology"), "unknown restored cohort")
    cohort = Cohort(silo, image, case, probe)
    report: dict = {"schema": 1, "case": case, "status": "failed", "evidence": str(cohort.evidence),
                    "public_delivery": False, "native_activate_command": "provider fence release only"}
    failure: BaseException | None = None
    try:
        cut, source = cohort.source_cut(alias=case == "topology", continuation=case == "positive")
        report["source"] = source
        if case == "positive":
            children = [cohort.positive_child(cut, index) for index in range(2)]
            require(children[0]["generation"]["native"]["id"] != children[1]["generation"]["native"]["id"],
                    "sequential children reused a generation identity")
            require(children[0]["identity"]["agent_instance_id"] != children[1]["identity"]["agent_instance_id"]
                    and children[0]["identity"]["run_id"] != children[1]["identity"]["run_id"]
                    and children[0]["identity"]["boot_id"] == children[1]["identity"]["boot_id"] == cut.identity["boot_id"],
                    "children lack independent destination identities over the preserved boot")
            report["children"] = children
        elif case == "failures":
            report["children"] = cohort.failure_children(cut)
        else:
            report["children"] = {"network-topology": cohort.topology_child(cut)}
        report["status"] = "passed"
    except BaseException as error:
        failure = error
        report["error"] = repr(error)
    finally:
        cleanup = cohort.close()
        report["cleanup"] = cleanup
        report["timeline"] = cohort.timeline
        if not cleanup["all_reaped"]:
            report["status"] = "failed"
            report.setdefault("error", "native/helper cleanup not proven")
        text = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
        (cohort.evidence / "restored-report.json").write_text(text)
        silo.ws.record(f"guest-restored-{case}", json.dumps({"status": report["status"], "evidence": str(cohort.evidence),
                                                             "error": report.get("error")}) + "\n")
    if failure is not None:
        raise failure
    require(report["status"] == "passed", f"{report.get('error')}; evidence {cohort.evidence}")
    return report
