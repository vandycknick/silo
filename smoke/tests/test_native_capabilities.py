from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from silo_smoke.config import SmokeConfig
from silo_smoke.overlay import native_source_identity


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
        assert capability["availability"] == {"status": "unsupported", "reason": {"code": "not-delivered", "subject": None}}
    identity = native_source_identity(report)
    assert identity.kind == "path"
    assert identity.content != "unknown"
    qualification = report["qualificationIdentity"]
    assert qualification.startswith("v2:native=") and "native=unobserved" not in qualification
    assert qualification.endswith(":empty") and len(qualification) <= 256
    assert snapshot(tmp_path) == before, "query created or modified runtime state"


@pytest.mark.parametrize("kind,state,revision", [
    ("path", "clean", "a" * 40), ("path", "dirty", "b" * 40),
    ("path", "unknown", "unknown"), ("git", "revision-bound", "c" * 40),
])
def test_native_source_identity_preserves_observed_source_states(kind: str, state: str, revision: str) -> None:
    identity = native_source_identity({"buildIdentity": f"v2:{kind}:{state}:{revision}:content={'d' * 64}:inputs={'e' * 64}"})
    assert (identity.kind, identity.state, identity.revision) == (kind, state, revision)
    assert identity.content == "d" * 64 and identity.inputs == "e" * 64


@pytest.mark.parametrize("identity", [
    "58253c00580bda34f5ea9fc4e0fccaf1e09a83d4:old-build",
    "unqualified:archive:old-build",
    f"v2:path:clean:unknown:content={'d' * 64}:inputs={'e' * 64}",
    f"v2:path:clean:{'a' * 40}:content=unknown:inputs={'e' * 64}",
    f"v2:git:dirty:{'a' * 40}:content={'d' * 64}:inputs={'e' * 64}",
])
def test_native_source_identity_refuses_old_or_inconsistent_bindings(identity: str) -> None:
    with pytest.raises(ValueError):
        native_source_identity({"buildIdentity": identity})
