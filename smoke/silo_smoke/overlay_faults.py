"""Prepare/build explicitly approved isolated COPY-only native fault monitors.

No production source, Cargo cache, dependency pin, staged binary, config/env
bypass or feature is changed. Main invokes this module after handoffs. Each
binary has one immutable fault baked into its copied native GET_ID construction.
Unique native attachment keys and both strict validators remain untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from .config import REPO
from .overlay import APPROVED_NATIVE_REVISION, digest, native_capabilities, native_source_identity

FAULTS = ("missing", "truncated", "swapped", "duplicate", "reordered", "writable-lower", "readonly-upper", "effective-index-off", "range-observer")


def replace_once(path: Path, original: str, replacement: str) -> dict:
    source = path.read_text()
    if source.count(original) != 1:
        raise ValueError(f"Source anchor changed in {path}: expected exactly one {original!r}")
    changed = source.replace(original, replacement, 1)
    path.write_text(changed)
    return {"path": str(path), "originalSha256": hashlib.sha256(source.encode()).hexdigest(), "mutatedSha256": hashlib.sha256(changed.encode()).hexdigest(), "original": original, "replacement": replacement}


def prepare(destination: Path, native_source: Path, production_monitor: Path, fault: str, *, build: bool) -> dict:
    if fault not in FAULTS:
        raise ValueError(f"Unknown immutable fault {fault}")
    if destination.exists():
        raise FileExistsError(f"Refuse to overwrite isolated fixture {destination}")
    if destination.is_relative_to(REPO) or destination.is_relative_to(native_source) or native_source.is_relative_to(destination):
        raise ValueError("Fault builds must not overwrite production/staged inputs")
    destination.mkdir(parents=True, mode=0o700)
    source = destination / "silo"
    native = destination / "native"
    excluded = shutil.ignore_patterns("target", ".git", ".tmp", ".codegraph", ".venv", "node_modules", "__pycache__", ".pytest_cache")
    shutil.copytree(REPO, source, symlinks=True, ignore=excluded)
    production_snapshot = destination / "production-monitor"
    shutil.copyfile(production_monitor, production_snapshot)
    production_snapshot.chmod(0o700)
    production_report = native_capabilities(production_snapshot, diagnostic=destination / "production-capabilities.log")
    identity = native_source_identity(production_report)
    if identity.kind != "path" or identity.state != "clean":
        raise ValueError("Fault preparation requires a clean production-path native build")
    revision = identity.revision
    head = subprocess.run(["git", "-C", str(native_source), "rev-parse", "--verify", "HEAD"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    status = subprocess.run(["git", "-C", str(native_source), "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"], check=True, capture_output=True, text=True, timeout=30).stdout
    if head != revision or status:
        raise ValueError("Fault source must be the unchanged clean production HEAD observed by the monitor")
    subprocess.run(["git", "-C", str(native_source), "verify-commit", revision], check=True, capture_output=True, text=True, timeout=30)
    subprocess.run(["git", "-C", str(native_source), "merge-base", "--is-ancestor", APPROVED_NATIVE_REVISION, revision], check=True, capture_output=True, text=True, timeout=30)
    provenance = {"nativePin": revision, "declaredNativeBaseline": APPROVED_NATIVE_REVISION, "productionMonitorSha256": digest(production_snapshot), "productionMonitorCapabilities": production_report}
    if fault == "effective-index-off":
        mutation = replace_once(source / "guest/init/src/overlay.rs", "    options.extend_from_slice(rootfs_spec::OVERLAY_OPTIONS.as_bytes());", '    options.extend_from_slice(b"index=off,metacopy=off,redirect_dir=nofollow,xino=on,nfs_export=off,uuid=null");')
        verifier = REPO / "guest/init/src/overlay_verify.rs"
        assert digest(source / "guest/init/src/overlay_verify.rs") == digest(verifier)
        target = destination / "target"
        command = ["cargo", "run", "--offline", "--manifest-path", str(source / "xtask/Cargo.toml"), "--target-dir", str(target), "--", "--target-dir", str(target), "component", "initramfs", "--profile", "debug"]
        proof = {"fault": fault, "mutations": [mutation], "command": command, "verifierSourceSha256": digest(verifier), "productionInitSourceSha256": digest(REPO / "guest/init/src/overlay.rs"), "productionStageModified": False}
        proof.update(provenance)
        evidence = destination / "fault-manifest.json"
        evidence.write_text(json.dumps(proof, indent=2) + "\n")
        if build:
            with (destination / "build.log").open("wb") as output:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=1800)
            if result.returncode:
                raise RuntimeError(f"Fault init build failed ({result.returncode}); see {destination / 'build.log'}")
            base = target / "debug/assets/initramfs"
            proof["baseInitramfs"] = str(base)
            proof["baseInitramfsSha256"] = digest(base)
            evidence.write_text(json.dumps(proof, indent=2) + "\n")
        return proof
    native.mkdir()
    with tempfile.TemporaryFile() as archive:
        result = subprocess.run(["git", "-C", str(native_source), "archive", "--format=tar", revision], stdout=archive, stderr=subprocess.PIPE, timeout=60)
        if result.returncode:
            raise RuntimeError(f"Cannot archive exact corrected native commit {revision}: {result.stderr.decode(errors='replace')}")
        archive.seek(0)
        archive_sha256 = hashlib.file_digest(archive, "sha256").hexdigest()
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as files:
            files.extractall(native, filter="data")
    native_manifest = native / "src/libkrun/Cargo.toml"
    if not native_manifest.is_file():
        raise FileNotFoundError("Expected complete pinned libkrun source checkout")
    mutations = []
    if fault in {"missing", "truncated", "swapped", "duplicate"}:
        mapping = {
            "missing": '"silo-root-lower" => "absent-lower",',
            "truncated": '"silo-root-lower" => "silo-root-lowe",',
            "swapped": '"silo-root-lower" => "silo-root-upper", "silo-root-upper" => "silo-root-lower",',
            "duplicate": '"silo-data-0" => "silo-root-lower",',
        }[fault]
        replacement = f'(match block_id {{ {mapping} _ => block_id }}).to_string()'
        mutations.append(replace_once(native / "src/devices/src/virtio/block/device.rs", "            block_id.to_string()", "            " + replacement))
    elif fault == "reordered":
        # Reverse only the disk slice after unchanged host/private validation;
        # console/network device planning and identities remain production code.
        mutations.append(replace_once(source / "virt/vmm/src/krun/engine.rs", "    for device in device_plan(config) {", "    let mut smoke_config = config.clone();\n    smoke_config.disks.reverse();\n    for device in device_plan(&smoke_config) {"))
    elif fault in {"writable-lower", "readonly-upper"}:
        identity = "silo-root-lower" if fault == "writable-lower" else "silo-root-upper"
        access = "false" if fault == "writable-lower" else "true"
        mutations.append(replace_once(source / "virt/vmm/src/krun/engine.rs", "                device.set_read_only(disk.read_only);", f'                device.set_read_only(if disk.block_id.as_str() == "{identity}" {{ {access} }} else {{ disk.read_only }});'))
    mutations.append(replace_once(native / "src/devices/src/virtio/block/worker.rs", "                let disk_id = self.disk.image_id();", '                let disk_id = self.disk.image_id();\n                eprintln!("SILO_SMOKE_GET_ID device={:p} sectors={} reply={}", &self.disk, self.disk.nsectors(), std::str::from_utf8(disk_id).unwrap_or("<invalid>").trim_end_matches(\'\\0\'));'))
    if fault == "range-observer":
        for opcode in ("DISCARD", "WRITE_ZEROES"):
            anchor = f"            VIRTIO_BLK_T_{opcode} => {{\n                let discard_write_data: DiscardWriteData = reader\n                    .read_obj()\n                    .map_err(RequestError::ReadingFromDescriptor)?;"
            receipt = f'\n                eprintln!("SILO_SMOKE_BLOCK_REQUEST device={{:p}} op={opcode} offset={{}} length={{}} flags={{}}", &self.disk, discard_write_data.sector * 512, u64::from(discard_write_data.num_sectors) * 512, discard_write_data.flags);'
            mutations.append(replace_once(native / "src/devices/src/virtio/block/worker.rs", anchor, anchor + receipt))
    manifest = source / "Cargo.toml"
    text = manifest.read_text()
    patches = re.findall(r'(?m)^\[patch\."https://github\.com/vandycknick/libkrun\.git"\]\nlibkrun = \{ path = "[^"\n]+" \}$', text)
    if len(patches) != 1:
        raise ValueError("Expected the explicit production native path patch")
    mutations.append(replace_once(manifest, patches[0], '[patch."https://github.com/vandycknick/libkrun.git"]\nlibkrun = { path = ' + json.dumps(str(native / "src/libkrun")) + ' }'))
    target = destination / "target"
    command = ["cargo", "build", "--offline", "--manifest-path", str(manifest), "--target-dir", str(target), "-p", "silo-vmm", "--bin", "silo-vmm"]
    proof = {"fault": fault, "nativePin": revision, "nativeArchiveSha256": archive_sha256, "nativeSource": str(native_source), "productionSource": str(REPO), "productionEngineSha256": digest(REPO / "virt/vmm/src/krun/engine.rs"), "mutations": mutations, "command": command, "validationUnchanged": True, "uniqueAttachmentKeysUnchanged": True, "productionStageModified": False}
    proof.update(provenance)
    evidence = destination / "fault-manifest.json"
    evidence.write_text(json.dumps(proof, indent=2) + "\n")
    if build:
        with (destination / "build.log").open("wb") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=1800)
        if result.returncode:
            raise RuntimeError(f"Fault build failed ({result.returncode}); see {destination / 'build.log'}")
        binary = target / "debug/silo-vmm"
        proof["binary"] = str(binary)
        proof["binarySha256"] = digest(binary)
        evidence.write_text(json.dumps(proof, indent=2) + "\n")
        report = native_capabilities(binary, diagnostic=destination / "capabilities.log")
        identity = native_source_identity(report)
        if identity.kind != "path" or identity.state != "unknown" or identity.revision != "unknown" or identity.content == "unknown":
            raise ValueError("Archived fault source must expose content-bound, Git-unattested native provenance")
        proof["actualCapabilities"] = report
        proof["nativeBuildIdentity"] = report["buildIdentity"]
        evidence.write_text(json.dumps(proof, indent=2) + "\n")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--native-source", type=Path, required=True)
    parser.add_argument("--production-monitor", type=Path, required=True, help="Actual corrected staged monitor; private snapshot capabilities bind native revision")
    parser.add_argument("--fault", choices=(*FAULTS, "all"), default="all")
    parser.add_argument("--build", action="store_true", help="Main-only explicit bounded build after handoffs")
    args = parser.parse_args()
    faults = FAULTS if args.fault == "all" else (args.fault,)
    for fault in faults:
        print(json.dumps(prepare(args.destination.resolve() / fault, args.native_source.resolve(), args.production_monitor.resolve(), fault, build=args.build), sort_keys=True))


if __name__ == "__main__":
    main()
