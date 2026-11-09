"""Controlled compatibility evidence through the shipped monitor/worker.

This creates disposable launch files without changing the shared runtime or
granting live capabilities. It does not replace normal production-path acceptance.
Bootstrap JSON starts from F1's independent current fixture, not a second
host/guest wire codec.
"""
from __future__ import annotations

import json
import fcntl
import hashlib
import platform
import shutil
import os
from pathlib import Path
import signal
import subprocess
import time
from uuid import UUID, uuid4

from . import overlay
from .cli import Silo
from .config import REPO

def bounded_log(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(2 * 1024**2 + 1)
    assert len(data) <= 2 * 1024**2, f"candidate log exceeds 2MiB fixture bound: {path}"
    return data.decode(errors="replace")



def cpio(entries: list[tuple[str, bytes, int]]) -> bytes:
    result = bytearray()
    for inode, (name, data, mode) in enumerate([*entries, ("TRAILER!!!", b"", 0)], 1):
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 2 if mode & 0o170000 == 0o040000 else 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        result.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded)
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(data)
        result.extend(b"\0" * (-len(result) % 4))
    return bytes(result)


class Candidate:
    def __init__(self, silo: Silo, reference: str | None = None, *, fault: str = "none", historical: bool = False, data: Path | None = None, range_request: str | None = None) -> None:
        self.silo = silo
        self.root = silo.ws.root / ("candidate-" + str(uuid4())[:8])
        self.root.mkdir(mode=0o700)
        self.serial = self.root / "serial.log"
        self.trace = self.root / "trace.log"
        self.process: subprocess.Popen | None = None
        self.closed = False
        self.lease_fd: int | None = None
        copied_native = fault in {"missing", "truncated", "swapped", "duplicate", "reordered", "writable-lower", "readonly-upper", "range-observer"}
        self.monitor = silo.ws.config.runtime_dir / "bin/silo-vmm"
        if copied_native:
            fixture_root = os.environ.get("SILO_SMOKE_FAULT_MONITORS")
            assert fixture_root, "Main must build isolated COPY-only native fault monitors"
            manifest = json.loads((Path(fixture_root) / fault / "fault-manifest.json").read_text())
            assert manifest["fault"] == fault
            assert manifest["validationUnchanged"] and manifest["uniqueAttachmentKeysUnchanged"]
            assert manifest["declaredNativeBaseline"] == overlay.APPROVED_NATIVE_REVISION
            revision = manifest["nativePin"]
            self.monitor = Path(manifest["binary"])
            assert overlay.digest(self.monitor) == manifest["binarySha256"]
            assert manifest["productionEngineSha256"] == overlay.digest(REPO / "virt/vmm/src/krun/engine.rs"), "fault fixture source stale"
            silo.ws.record("overlay-native-fault-build", json.dumps(manifest, sort_keys=True) + "\n")
        monitor_snapshot = self.root / "silo-vmm"
        shutil.copyfile(self.monitor, monitor_snapshot)
        monitor_snapshot.chmod(0o700)
        if copied_native:
            assert overlay.digest(monitor_snapshot) == manifest["binarySha256"]
        self.monitor = monitor_snapshot
        native_capabilities = overlay.native_capabilities(self.monitor)
        identity = overlay.native_source_identity(native_capabilities)
        if copied_native:
            assert native_capabilities["buildIdentity"] == manifest["nativeBuildIdentity"], "actual fault binary source/content identity mismatch"
        else:
            assert identity.kind == "path" and identity.state == "clean", "candidate requires a clean production-path native build"
            revision = identity.revision
        if not copied_native:
            stage = json.loads((silo.ws.config.runtime_dir / "runtime-manifest.json").read_text())
            assert stage["managedOverlayCandidate"]["nativeExecutableDigest"] == "sha256:" + overlay.digest(self.monitor)
        silo.ws.record("overlay-candidate-native-capabilities", json.dumps(native_capabilities, sort_keys=True) + "\n")
        self.mapping_only = historical
        produced = None
        if not historical:
            assert reference is not None, "root qualification requires an OCI reference"
            producer = silo.ws.config.bin_dir / "examples/overlay_candidate_lower"
            if not producer.is_file():
                producer = REPO / "target/debug/examples/overlay_candidate_lower"
            assert producer.is_file(), "Main must build cargo build -p libvm --example overlay_candidate_lower"
            result = subprocess.run([str(producer), reference, str(self.root / "composition")], env=silo.ws.env(), check=True, capture_output=True, text=True, timeout=300)
            silo.ws.record("overlay-candidate-composition", result.stdout + result.stderr)
            produced = json.loads(result.stdout)
            source_descriptor = Path(produced["descriptor"])
            self.occurrences = overlay.lower_occurrences(source_descriptor)
        else:
            assert reference is None, "byte-mapping qualification has no filesystem source"
            self.occurrences = []
        self.mapping_probes: list[tuple[int, int]] = []
        if historical:
            import random
            a = self.root / "a.bin"
            with a.open("w+b") as stream:
                stream.truncate(4_831_838_208)
                rng = random.Random(14)
                for offset in [0, overlay.SPLIT - 4096, overlay.SPLIT, overlay.SPLIT + 4096, 2 * overlay.SPLIT - 4096, 2 * overlay.SPLIT, 4_831_838_208 - 4096]:
                    stream.seek(offset)
                    stream.write(rng.randbytes(4096))
            empty = self.root / "empty.bin"
            empty.touch()
            b = self.root / "b.bin"
            b.write_bytes(random.Random(14).randbytes(1024**2))
            self.occurrences = [a, empty, b, b]
        self.logical_lower_bytes = sum(path.stat().st_size for path in self.occurrences)
        if historical:
            self.mapping_probes = sorted(set(overlay.probes(self.logical_lower_bytes) + [(4_831_838_208 - 2048, 4096), (4_831_838_208, 4096), (4_831_838_208 + 1024**2 - 2048, 4096)]))
            assert len(self.mapping_probes) <= 64
        lower = self.occurrences[0]
        self.lower = lower
        self.occurrence_digests = {path: overlay.digest(path) for path in dict.fromkeys(self.occurrences)}
        self.lower_digest = self.occurrence_digests[lower]
        upper = self.root / "upper.raw"
        self.upper = upper
        formatter = silo.ws.config.bin_dir / "examples/format_upper"
        if not formatter.is_file():
            formatter = REPO / "target/debug/examples/format_upper"
        result = subprocess.run([str(formatter), str(upper), str(256 * 1024**2)], check=True, capture_output=True, text=True, timeout=90)
        formatted = json.loads(result.stdout)
        silo.ws.record("overlay-candidate-formatter", result.stdout + result.stderr)
        if fault == "magic":
            with upper.open("r+b") as stream:
                stream.seek(1024 + 56)
                stream.write(b"\0\0")
        if fault in {"journal-inode", "journal-backup"}:
            with upper.open("r+b") as stream:
                stream.seek(1024 + 0x10c)
                backup = stream.read(68)
                stream.seek(4096 + 8)
                table = int.from_bytes(stream.read(4), "little")
                assert table > 0
                inode_offset = table * 4096 + 7 * 256
                stream.seek(inode_offset)
                inode = stream.read(256)
                assert backup[:60] == inode[40:100] and backup[60:64] == inode[108:112] and backup[64:68] == inode[4:8], "formatter backup must initially match actual journal inode"
                if fault == "journal-inode":
                    stream.seek(inode_offset + 40)
                    stream.write(b"\0\0\0\0")
                    stream.seek(1024 + 0x10c)
                    assert stream.read(68) == backup, "preserve valid backup while corrupting actual inode"
                else:
                    stream.seek(1024 + 0x10c)
                    stream.write(b"\0" * 68)
                    stream.seek(inode_offset)
                    assert stream.read(256) == inode, "preserve actual inode while corrupting obsolete backup"
                silo.ws.record("overlay-journal-authority", json.dumps({"fault": fault, "actualInodeSha256Before": hashlib.sha256(inode).hexdigest(), "initialMatchingBackupSha256": hashlib.sha256(backup).hexdigest(), "inodeOffset": inode_offset}) + "\n")
        if fault == "upper-symlink":
            for command in ["rmdir /upper", "symlink /upper /tmp"]:
                result = subprocess.run(["debugfs", "-w", "-R", command, str(upper)], check=True, capture_output=True, text=True, timeout=30)
                silo.ws.record("overlay-candidate-upper-fault", result.stdout + result.stderr)
            result = subprocess.run(["debugfs", "-R", "stat /upper", str(upper)], check=True, capture_output=True, text=True, timeout=30)
            assert "symlink" in result.stdout.lower()
        descriptor = self.root / "lower.vmdk"
        self.descriptor = descriptor
        # Arbitrary-byte mapping uses a standalone init and mounts no root.
        extents = overlay.records(source_descriptor) if produced is not None else []
        if historical:
            extents = [overlay.Record(4_194_304, lower, 0), overlay.Record(4_194_304, lower, 4_194_304), overlay.Record(1_048_576, lower, 8_388_608), overlay.Record(2048, b, 0), overlay.Record(2048, b, 0)]
        bootstrap = json.loads((REPO / "specs/rootfs-spec/fixtures/overlay.json").read_text())
        root = bootstrap["root"]
        root["lower"]["lengthBytes"] = self.logical_lower_bytes
        if produced is not None:
            assert produced["candidateOnly"] is True
            assert produced["logicalLowerBytes"] == self.logical_lower_bytes
            root["lower"]["filesystemUuid"] = produced["filesystemUuid"]
            assert root["lower"]["filesystemUuid"] == str(UUID(hex=overlay.erofs(lower)["uuid"]))
        if fault in {"lower-magic", "lower-device-range"}:
            assert produced is not None
            damaged = self.root / "damaged-fsmeta.erofs"
            shutil.copyfile(lower, damaged)
            with damaged.open("r+b") as stream:
                if fault == "lower-magic":
                    stream.seek(1024)
                    stream.write(b"\0\0\0\0")
                else:
                    assert overlay.erofs(lower)["devices"] > 0
                    stream.seek(4096 + 68)
                    stream.write((self.logical_lower_bytes // 4096 + 1).to_bytes(4, "little"))
            extents = [overlay.Record(record.sectors, damaged if record.path == lower else record.path, record.offset) for record in extents]
            self.occurrences = [damaged if path == lower else path for path in self.occurrences]
            lower = damaged
            self.lower = lower
            self.occurrence_digests = {path: overlay.digest(path) for path in dict.fromkeys(self.occurrences)}
            self.lower_digest = self.occurrence_digests[lower]
        if fault == "lower-uuid":
            root["lower"]["filesystemUuid"] = str(uuid4())
        root["upper"]["lengthBytes"] = formatted["backing_bytes"]
        root["upper"]["filesystemUuid"] = formatted["uuid"]
        if fault == "uuid":
            root["upper"]["filesystemUuid"] = str(uuid4())
        if fault == "length":
            root["lower"]["lengthBytes"] += 512
        descriptor.write_text('# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="twoGbMaxExtentFlat"\n\n' + "".join(f'RW {record.sectors} FLAT "{record.path}" {record.offset}\n' for record in extents))
        self.bootstrap = bootstrap
        assets = silo.ws.config.runtime_dir / "assets"
        base = assets / "initramfs"
        if fault == "effective-index-off":
            fixture_root = os.environ.get("SILO_SMOKE_FAULT_MONITORS")
            assert fixture_root, "Main must build isolated bad-request init fixture"
            manifest = json.loads((Path(fixture_root) / fault / "fault-manifest.json").read_text())
            assert manifest["verifierSourceSha256"] == overlay.digest(REPO / "guest/init/src/overlay_verify.rs")
            assert manifest["productionInitSourceSha256"] == overlay.digest(REPO / "guest/init/src/overlay.rs")
            base = Path(manifest["baseInitramfs"])
            silo.ws.record("overlay-native-init-fault-build", json.dumps(manifest, sort_keys=True) + "\n")
        composite = self.root / "initramfs"
        base_bytes = base.read_bytes()
        if fault == "effective-index-off":
            assert hashlib.sha256(base_bytes).hexdigest() == manifest["baseInitramfsSha256"]
        base_snapshot = self.root / "base-initramfs"
        base_snapshot.write_bytes(base_bytes)
        kernel_snapshot = self.root / "kernel"
        shutil.copyfile(assets / "kernel-default", kernel_snapshot)
        raw = base_bytes
        raw += b"\0" * (-len(raw) % 4)
        payload = json.dumps(bootstrap, separators=(",", ":")).encode()
        if fault == "malformed-bootstrap":
            payload = b'{"schemaVersion":1,"schemaVersion":1,"root":{}}'
        entries = [("silo", b"", 0o040700)]
        if fault != "missing-bootstrap":
            entries.append(("silo/rootfs.json", payload, 0o100600))
        raw += cpio(entries)
        composite.write_bytes(raw)
        disks = [
            {"path": str(descriptor), "role": "root-lower", "format": "vmdk", "geometry": {"length": self.logical_lower_bytes, "logicalSectorSize": 512}, "blockId": "silo-root-lower", "readOnly": True},
            {"path": str(upper), "role": "root-upper", "format": "raw", "geometry": {"length": formatted["backing_bytes"], "logicalSectorSize": 512}, "blockId": "silo-root-upper", "readOnly": False},
        ]
        if fault == "duplicate":
            # Unique host/native key. The isolated native response mutation maps
            # ONLY this extra real block device's GET_ID to silo-root-lower.
            duplicate = self.root / "duplicate-lower.raw"
            with duplicate.open("xb") as output:
                for occurrence in self.occurrences:
                    with occurrence.open("rb") as source:
                        shutil.copyfileobj(source, output)
            assert duplicate.stat().st_size == self.logical_lower_bytes
            disks.append({"path": str(duplicate), "role": "data", "format": "raw", "geometry": {"length": self.logical_lower_bytes, "logicalSectorSize": 512}, "blockId": "silo-data-0", "readOnly": True})
        if data is not None:
            assert fault == "range-observer" and range_request is not None
            assert data.stat().st_size == 4 * 1024**2
            disks.append({"path": str(data), "role": "data", "format": "raw", "geometry": {"length": data.stat().st_size, "logicalSectorSize": 512}, "blockId": "silo-data-0", "readOnly": False})
        self.spec = {"specVersion": "0.2.0", "boot": {"kernel": {"path": str(kernel_snapshot), "initramfs": str(composite), "cmdline": ["loglevel=6", "silo.rootfs=" + overlay.PROFILE, "init=/sbin/candidate-init"]}}, "hardware": {"cpus": 1, "memory": 512, "rosetta": False, "nestedVirtualization": False}, "storage": {"disks": disks}}
        if self.mapping_probes:
            self.spec["boot"]["kernel"]["cmdline"].append("silo.smoke_probes=" + ",".join(f"{offset}:{length}" for offset, length in self.mapping_probes))
        if range_request is not None:
            assert fault == "range-observer" and data is not None
            self.spec["boot"]["kernel"]["cmdline"].append("silo.smoke_range=" + range_request)
        if historical:
            mapping_init = self.root / "mapping-init"
            subprocess.run([os.environ.get("CC", "cc"), "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(mapping_init), str(REPO / "smoke/fixtures/vmdk_mapping.c")], check=True, capture_output=True, timeout=90)
            composite.write_bytes(cpio([("init", mapping_init.read_bytes(), 0o100755)]))
            self.spec["boot"]["kernel"]["cmdline"] = ["loglevel=6", "rdinit=/init", "silo.smoke_probes=" + ",".join(f"{offset}:{length}" for offset, length in self.mapping_probes)]
        self.config = self.root / "spec.json"
        self.config.write_text(json.dumps(self.spec))
        self.identities = {"kernelSha256": overlay.digest(kernel_snapshot), "initramfsSha256": hashlib.sha256(base_bytes).hexdigest(), "compositeInitramfsSha256": overlay.digest(composite), "monitorWorkerSha256": overlay.digest(self.monitor), "hostSystem": platform.system(), "hostArchitecture": platform.machine(), "hostKernelRelease": platform.release(), "hostLane": "linux-kvm" if platform.system() == "Linux" else "macos-hvf", "rootProfile": overlay.PROFILE, "upperProfile": "silo-upper-ext4-v1", "renderingAbi": "linux-overlayfs-mountinfo-v1", "attachmentFamily": "krun-virtio-blk-v1", "candidateOnly": True}
        self.identities["nativeRevision"] = revision
        self.identities["actualNativeCapabilities"] = native_capabilities
        self.identities["logicalLowerBytes"] = self.logical_lower_bytes
        self.identities["lowerOccurrences"] = [{"path": str(path), "lengthBytes": path.stat().st_size, "sha256": self.occurrence_digests[path]} for path in self.occurrences]
        if produced is not None:
            self.identities["compositionResult"] = produced["compositionResult"]
            self.identities["fsmetaObject"] = produced["fsmetaObject"]
        if historical:
            self.identities["rootProfile"] = "none"
            self.identities["experiment"] = "arbitrary-byte-vmdk-mapping"
            self.identities["initramfsSha256"] = overlay.digest(composite)
            self.identities["compositeInitramfsSha256"] = overlay.digest(composite)
        config_input = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
        if config_input:
            config_snapshot = self.root / "resolved.config"
            shutil.copyfile(Path(config_input), config_snapshot)
            self.identities["resolvedConfigDigest"] = "sha256:" + overlay.digest(config_snapshot)
            self.identities["resolvedConfigSourcePath"] = config_input
            self.identities["configEvidence"] = "local-build-supplied-requires-independent-build-provenance"

    def start(self) -> None:
        machine_id, run_id, operation_id = str(uuid4()), str(uuid4()), str(uuid4())
        self.lease_fd = os.open(self.root / (operation_id + ".lease"), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.lease_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        metadata = os.fstat(self.lease_fd)
        context = {"version": 1, "machineId": machine_id, "runId": run_id, "manifest": {"kind": "complete", "attachments": [
            {"kind": "block", **{key: disk[key] for key in ("blockId", "role", "format", "geometry", "readOnly")}, "exclusiveWriter": disk["readOnly"] or Path(disk["path"]).is_relative_to(self.root)}
            for disk in self.spec["storage"]["disks"]
        ]}}
        request = {"version": 1, "machineId": machine_id, "machineRunId": run_id, "startupCommand": None,
                   "storageLease": {"operationId": operation_id, "fileDevice": metadata.st_dev, "fileInode": metadata.st_ino},
                   "storageShutdown": context}
        reader, writer = os.pipe()
        environment = self.silo.ws.env(RUST_LOG="info,silo_vmm::virt::backend::krun::owner=debug")
        environment.update(_VM_STARTPIPE=str(reader), _VM_STORAGE_LEASES=json.dumps([self.lease_fd]))
        args = [str(self.monitor), "--foreground", "--id", machine_id, "--run-id", run_id, "--name", "overlay-candidate"]
        for flag, path in [("--data-dir", self.root), ("--runtime-dir", self.root), ("--config", self.config), ("--socket", self.root / "vm.sock"), ("--pidfile", self.root / "vm.pid"), ("--exit-status", self.root / "vm.exit.json"), ("--serial-log", self.serial), ("--trace-log", self.trace)]:
            args.extend([flag, str(path)])
        try:
            with (self.root / "monitor-output.log").open("ab") as sink:
                self.process = subprocess.Popen(args, env=environment, pass_fds=(reader, self.lease_fd), stdin=subprocess.DEVNULL, stdout=sink, stderr=sink, start_new_session=True)
            os.close(reader)
            reader = -1
            with os.fdopen(writer, "wb") as stream:
                writer = -1
                stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        finally:
            if reader >= 0:
                os.close(reader)
            if writer >= 0:
                os.close(writer)

    def wait(self, *, rejected: bool = False) -> str:
        deadline = time.monotonic() + 90
        while True:
            text = bounded_log(self.serial) if self.serial.exists() else ""
            if self.mapping_only:
                assert not rejected
                assert "SILO_VMDK_MAPPING_FAIL" not in text, text
                if "SILO_VMDK_MAPPING_PASS" in text:
                    self.observe_worker()
                    return text
            if rejected:
                assert "SILO_OVERLAY_WORKLOAD_REACHED" not in text
                assert "starting rescue shell" not in text
                if "init: overlay: boot failed; workload prohibited" in text:
                    self.observe_worker()
                    return text
            elif "SILO_OVERLAY_WORKLOAD_REACHED" in text:
                assert "SILO_OVERLAY_CANDIDATE_BEGIN" in text
                assert '"effectiveOverlayProfile":"silo-overlay-v1"' in text.replace(" ", "")
                assert '"kind":"' + overlay.PROFILE + '"' in text.replace(" ", "")
                assert '"filesystem":"erofs"' in text.replace(" ", "")
                self.observe_worker()
                return text
            if self.process is None or self.process.poll() is not None:
                raise AssertionError(f"candidate monitor exited before guest evidence; serial={text}; trace={bounded_log(self.trace) if self.trace.exists() else ''}")
            if time.monotonic() >= deadline:
                raise AssertionError(f"candidate did not produce explicit {'guest rejection' if rejected else 'success'} evidence: {text}")
            time.sleep(0.05)

    def logs(self) -> str:
        return "\n".join(bounded_log(path) for path in self.root.glob("*.log"))

    def observe_worker(self) -> None:
        assert self.process is not None
        self.identities["monitorPid"] = self.process.pid
        if platform.system() == "Linux":
            pid = overlay.worker_pid_of_monitor(self.process.pid)
            actual = overlay.digest(Path(f"/proc/{pid}/exe"))
            assert actual == self.identities["monitorWorkerSha256"], "worker did not execute captured monitor bytes"
            self.identities["workerPid"] = pid
            self.identities["actualWorkerSha256"] = actual

    def close(self) -> None:
        if self.closed:
            return
        if self.process is not None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=20)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=10)
        for label, path in [("candidate-serial", self.serial), ("candidate-trace", self.trace), ("candidate-monitor-output", self.root / "monitor-output.log")]:
            if path.exists():
                self.silo.ws.record(label, bounded_log(path))
        assert all(overlay.digest(path) == expected for path, expected in self.occurrence_digests.items())
        if self.lease_fd is not None:
            os.close(self.lease_fd)
            self.lease_fd = None
        self.closed = True

    def native_diagnostic(self) -> str:
        assert self.closed, "native request evidence requires finalized actual worker diagnostic"
        event = json.loads((self.root / "vm.exit.json").read_text())
        assert event["pid"] == self.identities["monitorPid"]
        assert event["backend"]["process"]["pid"] == self.identities["workerPid"]
        text = event["backend"]["diagnostic"]["tail"]
        self.silo.ws.record("overlay-native-raw-diagnostic", text)
        return text
