"""Explicit candidate-only EROFS qualification, not a production admission grant."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from silo_smoke import overlay
from silo_smoke.cli import Silo
from silo_smoke.config import REPO
from silo_smoke.overlay_candidate import Candidate, bounded_log, cpio


@pytest.fixture(scope="session")
def erofs_probe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not os.environ.get("SILO_SMOKE_EROFS_KERNELS"):
        pytest.skip("explicit EROFS candidate kernel paths required")
    output = tmp_path_factory.mktemp("erofs-probe") / "init"
    subprocess.run(
        [os.environ.get("CC", "cc"), "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(output), str(REPO / "smoke/fixtures/erofs_mount.c")],
        check=True, capture_output=True, timeout=90,
    )
    return output


@pytest.mark.linux_only
@pytest.mark.parametrize("track", ["stable", "longterm"])
@pytest.mark.parametrize("fixture", ["empty", "metadata", "rich", "many", "split"])
def test_erofs_native_vmdk_mount(
    silo: Silo, basic_image: str, erofs_probe: Path, track: str, fixture: str,
) -> None:
    kernels = json.loads(os.environ.get("SILO_SMOKE_EROFS_KERNELS", "{}"))
    if track not in kernels:
        pytest.skip("explicit EROFS candidate kernel paths required in SILO_SMOKE_EROFS_KERNELS")
    kernel = Path(kernels[track])
    config = kernel.parent / ".config"
    text = config.read_text()
    for feature in ["EROFS_FS", "EROFS_FS_XATTR", "EROFS_FS_POSIX_ACL", "EROFS_FS_SECURITY", "EXPORTFS"]:
        assert f"CONFIG_{feature}=y\n" in text, feature
    producer = REPO / "target/debug/examples/erofs_qualification"
    assert producer.is_file(), "build libvm example erofs_qualification before qualification"
    fixture_dir = silo.ws.root / "erofs"
    generated = subprocess.run([str(producer), str(fixture_dir), fixture], check=True, capture_output=True, text=True, timeout=300)
    silo.ws.record("erofs-producer", generated.stdout + generated.stderr)
    summary = json.loads(generated.stdout)
    first = fixture_dir / "fsmeta.erofs"
    assert first.read_bytes() == (fixture_dir / "fsmeta-second.erofs").read_bytes(), "double-build byte determinism"
    tools = Path(os.environ.get("SILO_SMOKE_EROFS_UTILS", str(REPO / ".tmp/tools/erofs-utils-1.9.4")))
    args = [str(tools / "fsck/fsck.erofs")]
    if fixture != "many":
        args.extend(["--extract", "--device=" + str(fixture_dir / "payload.pack")])
    # erofs-utils admits at most 256 external CLI devices. For 1024 slots,
    # structural fsck plus actual flattened-device guest reads are mandatory.
    args.append(str(first))
    checked = subprocess.run(args, capture_output=True, text=True, timeout=180)
    silo.ws.record("erofs-fsck", checked.stdout + checked.stderr)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    dumped = subprocess.run([str(tools / "dump/dump.erofs"), "-s", str(first)], check=True, capture_output=True, text=True, timeout=30)
    silo.ws.record("erofs-dump", dumped.stdout + dumped.stderr)
    candidate = Candidate(silo, basic_image)
    try:
        shutil.copyfile(fixture_dir / "lower.vmdk", candidate.descriptor)
        candidate.logical_lower_bytes = summary["logicalLowerBytes"]
        candidate.spec["storage"]["disks"][0]["geometry"]["length"] = candidate.logical_lower_bytes
        kernel_snapshot = Path(candidate.spec["boot"]["kernel"]["path"])
        shutil.copyfile(kernel, kernel_snapshot)
        initramfs = Path(candidate.spec["boot"]["kernel"]["initramfs"])
        raw = cpio([("init", erofs_probe.read_bytes(), 0o100755)])
        initramfs.write_bytes(raw)
        candidate.spec["boot"]["kernel"]["cmdline"] = ["loglevel=6", "rdinit=/init", "silo.erofs_fixture=" + fixture]
        candidate.config.write_text(json.dumps(candidate.spec))
        candidate.occurrences = [record.path for record in overlay.records(candidate.descriptor)]
        candidate.occurrence_digests = {path: overlay.digest(path) for path in dict.fromkeys(candidate.occurrences)}
        candidate.identities.update(
            kernelSha256=overlay.digest(kernel_snapshot),
            initramfsSha256=hashlib.sha256(raw).hexdigest(),
            compositeInitramfsSha256=hashlib.sha256(raw).hexdigest(),
            resolvedConfigDigest="sha256:" + overlay.digest(config),
            rootProfile="silo-erofs-v1-candidate-only", fixture=fixture, kernelTrack=track,
            logicalLowerBytes=candidate.logical_lower_bytes,
            lowerOccurrences=[{"path": str(path), "sha256": digest} for path, digest in candidate.occurrence_digests.items()],
        )
        candidate.start()
        deadline = time.monotonic() + 180
        while True:
            serial = bounded_log(candidate.serial) if candidate.serial.exists() else ""
            assert "SILO_EROFS_FAIL" not in serial, serial
            if "SILO_EROFS_PASS" in serial:
                candidate.observe_worker()
                break
            assert candidate.process is not None and candidate.process.poll() is None, candidate.logs()
            assert time.monotonic() < deadline, candidate.logs()
            time.sleep(0.05)
        silo.ws.record("erofs-native-qualification", json.dumps(candidate.identities, sort_keys=True) + "\n")
    finally:
        candidate.close()
