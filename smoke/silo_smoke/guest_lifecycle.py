"""Explicit real-guest controller fixtures, with no production sidechannel."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from uuid import uuid4

from . import overlay, shutdown, stopped
from .cli import Silo
from .config import REPO
from .overlay_candidate import cpio


def controller() -> Path:
    override = os.environ.get("SILO_SMOKE_GUEST_LIFECYCLE_CONTROLLER")
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "target")))
    path = Path(override) if override else target / "debug/examples/guest-lifecycle-controller"
    assert path.is_file() and os.access(path, os.X_OK), (
        "Main must build the explicit helper first: cargo build -p silo-vmm "
        "--example guest-lifecycle-controller; set SILO_SMOKE_GUEST_LIFECYCLE_CONTROLLER "
        "when using a different target/profile"
    )
    return path.resolve()


def _run_controller(silo: Silo, executable: Path, fixture: Path, directory: Path) -> subprocess.CompletedProcess:
    command = [str(executable), str(fixture)]
    worker = None
    output = errors = ""
    with shutdown.subreaper():
        process = subprocess.Popen(command, env=silo.ws.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            holder = directory / "vm.storage-holder.json"
            identity = json.loads(fixture.read_text())
            def observed_worker():
                if holder.is_file():
                    record = json.loads(holder.read_text())
                    assert record["machineId"] == identity["machine_id"] and record["runId"] == identity["run_id"]
                    entry = next((item for item in record["holders"] if item["role"] == "krun-worker"), None)
                    if entry is not None:
                        return entry
                return {"completed": True} if process.poll() is not None else None
            entry = shutdown.until(observed_worker, timeout=30, description="controller did not publish its owned worker")
            if "pid" in entry:
                try:
                    candidate = shutdown.Process(entry["pid"])
                except (ProcessLookupError, FileNotFoundError):
                    candidate = None
                if candidate is not None:
                    try:
                        status = Path(f"/proc/{candidate.pid}/status").read_text()
                        parent = int(next(line.split()[1] for line in status.splitlines() if line.startswith("PPid:")))
                        assert parent in (process.pid, os.getpid()), "holder no longer names the controller's child"
                        boot = int(next(line.split()[1] for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime ")))
                        assert boot + candidate.start_ticks // os.sysconf("SC_CLK_TCK") == entry["startedAt"]
                    except FileNotFoundError:
                        candidate.close()
                    except BaseException:
                        candidate.close()
                        raise
                    else:
                        worker = candidate
            output, errors = process.communicate(timeout=180)
        finally:
            if process.poll() is None:
                process.kill()
                output, errors = process.communicate(timeout=10)
            silo.ws.record("guest-lifecycle-controller", f"exit={process.returncode}\n{output}\n[stderr]\n{errors}\n")
            if worker is not None:
                # If the helper died, its watchdog child is adopted and reaped
                # here. A pidfd fences cleanup against PID reuse.
                with shutdown.owned_processes(worker):
                    pass
    return subprocess.CompletedProcess(command, process.returncode, output, errors)


def private_root(silo: Silo, image: str, prefix: str) -> tuple[dict, Path]:
    """Create a stopped machine and return a private copy of its populated root.

    The fixture boots a whole-disk ext4 bootstrap, so the root is explicitly
    converted to the opaque raw family. The catalog's stopped root is never
    booted or mutated; only private bytes are.
    """
    name = "guest-freezer-" + uuid4().hex[:8]
    silo.create(name, silo.raw_image(image), "--cpus", "2", "--memory", "512mib", "--disk-size", "512mib", "--network", "none", "--vsock")
    configuration = stopped.configuration(silo, name)
    disk = dict(configuration["spec"]["storage"]["disks"][0])
    source = Path(disk["path"])
    if not source.is_absolute():
        source = overlay.machine_dir(silo, name) / source
    directory = silo.ws.root / (prefix + uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    root = directory / "root.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(source), str(root)], check=True, capture_output=True, timeout=120)
    root.chmod(0o600)
    disk["path"] = str(root)
    return disk, directory


def block_attachment(disk: dict) -> dict:
    """Exact shutdown-manifest block entry for one resolved launch disk."""
    return {"kind": "block", **{key: disk[key] for key in ("blockId", "role", "format", "geometry", "readOnly")},
            "exclusiveWriter": True}


def ssh_material(directory: Path) -> str:
    """Fresh CA plus `client`/`client-cert.pub` for root; returns the trusted CA line."""
    ca = directory / "ca"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca)], check=True, capture_output=True, timeout=30)
    subject = directory / "client"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(subject)], check=True, capture_output=True, timeout=30)
    subprocess.run(["ssh-keygen", "-q", "-s", str(ca), "-I", "guest-freezer-smoke", "-n", "root", "-V", "-1m:+5m", str(subject.with_suffix(".pub"))], check=True, capture_output=True, timeout=30)
    return ca.with_suffix(".pub").read_text().strip()


def whole_disk_bootstrap(root: dict) -> dict:
    """Schema-2 launch bootstrap selecting the `silo-root` attachment as an ext4 whole disk."""
    assert root["blockId"] == "silo-root", root
    geometry = root["geometry"]
    return {"schemaVersion": 2, "rosetta": "disabled", "root": {
        "kind": "opaque-raw-v1", "discovery": "virtio-block-serial",
        "device": {"serial": "silo-root", "lengthBytes": geometry["length"],
                   "logicalSectorSize": geometry["logicalSectorSize"], "readOnly": root["readOnly"]},
        "selector": {"kind": "whole-disk"}, "filesystem": "ext4"}}


def composite_initramfs(assets: Path, directory: Path, agent_config: dict, root: dict) -> Path:
    """Staged Silo init initramfs plus the staged agent, this fixture's config and its root bootstrap."""
    base = (assets / "initramfs").read_bytes()
    composite = directory / "initramfs"
    composite.write_bytes(base + b"\0" * (-len(base) % 4) + cpio([
        ("agent", b"", 0o040700),
        ("agent/silo-agent", (assets / "agent").read_bytes(), 0o100700),
        ("agent/config.json", json.dumps(agent_config, separators=(",", ":")).encode(), 0o100600),
        ("silo", b"", 0o040700),
        ("silo/rootfs.json", json.dumps(whole_disk_bootstrap(root), separators=(",", ":")).encode(), 0o100600),
    ]))
    composite.chmod(0o600)
    return composite


def private_kernel(assets: Path, directory: Path) -> tuple[Path, Path]:
    """Private snapshot of the staged (or explicitly overridden) kernel and its source."""
    kernel = directory / "kernel"
    kernel_source = Path(os.environ.get("SILO_SMOKE_GUEST_LIFECYCLE_KERNEL", str(assets / "kernel-default"))).resolve()
    shutil.copyfile(kernel_source, kernel)
    kernel.chmod(0o600)
    return kernel, kernel_source


def run(silo: Silo, image: str, *, unsupported: bool = False) -> dict:
    executable = controller()
    disk, directory = private_root(silo, image, "guest-lifecycle-")
    machine, run_id = str(uuid4()), str(uuid4())
    manifest = {"kind": "complete", "attachments": [block_attachment(disk)]}
    agent_config = {
        "provision": {"enabled": True, "userdata": {"content": "#!/bin/sh\ncat /proc/self/cgroup >/lifecycle-userdata-membership\n", "content_type": "shell_script", "run": "always"}},
        "ssh": {"trusted_ca": ssh_material(directory)},
        "storage_shutdown": {"version": 1, "machineId": machine, "runId": run_id, "manifest": manifest},
    }
    assets = silo.ws.config.runtime_dir / "assets"
    composite = composite_initramfs(assets, directory, agent_config, disk)
    kernel, kernel_source = private_kernel(assets, directory)
    fixture = {"kernel": str(kernel), "initramfs": str(composite), "directory": str(directory),
               "machine_id": machine, "run_id": run_id, "root": disk, "expect_unsupported": unsupported}
    fixture_path = directory / "fixture.json"
    fixture_path.write_text(json.dumps(fixture))
    identities = {"controllerSha256": overlay.digest(executable), "kernelSha256": overlay.digest(kernel),
                  "agentSha256": overlay.digest(assets / "agent"), "baseInitramfsSha256": overlay.digest(assets / "initramfs"),
                  "compositeInitramfsSha256": overlay.digest(composite), "machineId": machine, "runId": run_id,
                  "scope": "real cold guest API, not native pause/capture/restore/generation qualification"}
    identities["kernelSource"] = str(kernel_source)
    resolved = kernel_source.parent / ".config"
    if resolved.is_file():
        shutil.copyfile(resolved, directory / "resolved.config")
        identities["resolvedConfigSha256"] = overlay.digest(resolved)
    silo.ws.record("guest-lifecycle-inputs", json.dumps(identities, sort_keys=True) + "\n")
    result = _run_controller(silo, executable, fixture_path, directory)
    assert result.returncode == 0, f"guest lifecycle controller failed; inspect {directory}/serial.log and retained controller evidence: {result.stderr}"
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert len(records) == 1, records
    record = records[0]
    assert record["result"] == ("unsupported-profile-refused" if unsupported else "cold-freeze-thaw"), record
    if not unsupported:
        assert record["recoveryEpoch"] == 3
        assert record["counterAdvancing"] > record["counterBefore"]
        assert record["counterResumed"] > record["counterFrozen"]
        assert record["counterFinal"] > record["counterRecoveryFrozen"]
        assert record["restoreGenerationEvidence"] == "not-exercised"
    return record
