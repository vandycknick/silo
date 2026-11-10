from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from silo_smoke.config import SmokeConfig
from silo_smoke import irq_fixture
from silo_smoke.overlay import digest, native_capabilities, monitor_build_identity


def snapshot(root: Path) -> dict:
    entries = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        entries[str(path.relative_to(root))] = (
            metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_mtime_ns,
            os.readlink(path) if stat.S_ISLNK(metadata.st_mode) else None,
            path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None,
        )
    return entries


@pytest.mark.parametrize("mode", ["ordinary", "launch-environment", "mutable-grants"])
def test_native_capabilities_machine_less_binding_and_no_mutable_grants(config: SmokeConfig, tmp_path: Path, mode: str) -> None:
    """Real system-fd queries belong to smoke, never to a Cargo test process."""
    monitor = config.runtime_dir / "bin/silo-vmm"
    (tmp_path / "sentinel").write_bytes(b"preserve")
    (tmp_path / "sentinel-link").symlink_to("missing-target")
    environment = os.environ.copy()
    environment.update(SILO_HOME=str(tmp_path / "absent-home"), SILO_RUN_ROOT=str(tmp_path / "absent-run"))
    if mode == "launch-environment":
        environment.update(_VM_STARTPIPE="not-a-descriptor", _VM_SYNCPIPE="-1", _VM_MACHINE_LOG_DIR="2147483648", _VM_MACHINE_LOCK="closed-descriptor", _VM_NETD_EXIT="invalid")
    if mode == "mutable-grants":
        home = tmp_path / "grant-home"
        home.mkdir()
        grant = home / "qualification.json"
        grant.write_text(json.dumps({"revision": "*", "operations": ["pause", "capture", "restore", "fork", "incremental"], "qualified": True}))
        environment.update(SILO_HOME=str(home), SILO_LIVE_QUALIFICATION=str(grant), SILO_LIVE_QUALIFIED="1")
    before = snapshot(tmp_path)
    result = subprocess.run([str(monitor), "capabilities", "--backend", "krun", "--json"], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["schemaVersion"] == 1 and report["scope"] == "host" and report["backend"] == "krun"
    assert report["scenarioDigest"] is None
    assert report["lane"] in ("kvm-x86_64", "kvm-arm64-gicv3", "hvf-arm64")
    for operation in ("pause", "capture", "restore", "fork", "incremental"):
        capability = report["live"][operation]
        assert capability["native"] is (report["lane"] == "kvm-x86_64" or operation == "pause")
        expected = ({"status": "supported"} if capability["native"] else
                    {"status": "unsupported", "reason": {"code": "build-excluded", "subject": None}})
        assert capability["availability"] == expected
    identity = monitor_build_identity(report)
    assert identity.target and identity.version
    assert snapshot(tmp_path) == before, "query created or modified runtime state"


@pytest.mark.parametrize("target,version", [
    ("x86_64-unknown-linux-gnu", "1.2.3"), ("aarch64-apple-darwin", "1.2.3-dev"),
])
def test_native_source_identity_is_informational_silo_metadata(target: str, version: str) -> None:
    identity = monitor_build_identity({"buildIdentity": f"v1:silo:{target}:{version}"})
    assert (identity.target, identity.version) == (target, version)


@pytest.mark.parametrize("identity", [
    "58253c00580bda34f5ea9fc4e0fccaf1e09a83d4:old-build",
    "unqualified:archive:old-build",
    f"v2:path:clean:{'a' * 40}:content={'d' * 64}:inputs={'e' * 64}",
    f"v2:other:{'a' * 40}:content={'d' * 64}:inputs={'e' * 64}",
    f"v2:path:invalid:content={'d' * 64}:inputs={'e' * 64}",
    f"v2:git:{'a' * 40}:content=invalid:inputs={'e' * 64}",
    f"v2:git:{'a' * 40}:content={'d' * 64}:inputs=invalid",
])
def test_native_source_identity_refuses_old_or_inconsistent_bindings(identity: str) -> None:
    with pytest.raises(ValueError):
        monitor_build_identity({"buildIdentity": identity})


@pytest.mark.linux_only
@pytest.mark.slow
def test_irq_fixture_binds_resolved_source_and_staged_monitor(config: SmokeConfig, tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "assets").mkdir(parents=True)
    (runtime / "bin").symlink_to(config.runtime_dir / "bin", target_is_directory=True)
    directory = irq_fixture.stage(runtime)
    manifest = json.loads((directory / "fixture-manifest.json").read_text())
    assert directory == runtime / "assets/restore-irq-witness"
    assert manifest["monitorSha256"] == digest(config.runtime_dir / "bin/silo-vmm")
    assert manifest["buildIdentity"] == native_capabilities(config.runtime_dir / "bin/silo-vmm")["buildIdentity"]
    assert Path(manifest["libkrunManifest"]).is_file()
    assert manifest["sourceSha256"] == digest(Path(manifest["assembly"])) == digest(directory / "witness.S")
    assert manifest["binarySha256"] == digest(directory / "witness.bin")
    assert manifest["symbolsSha256"] == digest(directory / "witness.nm")
    assert 0 < (directory / "witness.bin").stat().st_size <= 0x3000
    assert 0 < (directory / "witness.nm").stat().st_size <= 65536
