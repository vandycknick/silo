"""Build an explicit isolated Phase14 capture candidate, never a production grant.

Only copied compiled qualification tables change. Native provenance, provider
admission, guest evidence and capture verification remain the production code.
The matching private CLI admits the exact candidate monitor boot tuple only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from .config import REPO
from .overlay import digest, native_capabilities, native_source_identity
from .overlay_faults import replace_once


def build(destination: Path, runtime: Path) -> dict:
    if destination.exists():
        raise FileExistsError(destination)
    for protected in (REPO, runtime):
        if destination.is_relative_to(protected) or protected.is_relative_to(destination):
            raise ValueError("candidate must not overlap production source or runtime")
    if (runtime / "bin").is_symlink():
        raise ValueError("candidate runtime bin directory must not be a shared symlink")
    destination.mkdir(mode=0o700, parents=True)
    production = runtime / "bin/silo-vmm"
    production_hash = digest(production)
    original = native_capabilities(production, diagnostic=destination / "production-capabilities.log")
    if original["live"]["capture"]["availability"]["status"] != "unsupported":
        raise ValueError("Phase14 production capture must remain unqualified")
    source = destination / "source"
    shutil.copytree(REPO, source, symlinks=True, ignore=shutil.ignore_patterns(
        "target", ".git", ".tmp", ".codegraph", ".venv", "node_modules", "__pycache__", ".pytest_cache",
    ))
    target = destination / "target"
    command = ["cargo", "build", "--locked", "--offline", "--manifest-path", str(source / "Cargo.toml"),
               "--target-dir", str(target)]
    manifest = destination / "candidate-manifest.json"
    proof = {"scope": "isolated Phase14 test-only capture candidate, not production qualification",
             "productionMonitorSha256": production_hash, "productionCapabilities": original,
             "commands": [], "mutations": []}

    def compile_candidate(label: str, arguments: list[str]) -> None:
        invocation = command + arguments
        proof["commands"].append(invocation)
        manifest.write_text(json.dumps(proof, indent=2) + "\n")
        with (destination / (label + ".log")).open("wb") as log:
            result = subprocess.run(invocation, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        if result.returncode:
            raise RuntimeError(f"candidate build failed ({result.returncode}): {label}.log")

    compile_candidate("unqualified-build", ["-p", "silo-vmm", "--bin", "silo-vmm"])
    binary = target / "debug/silo-vmm"
    unqualified = native_capabilities(binary, diagnostic=destination / "unqualified-capabilities.log")
    identity = native_source_identity(unqualified)
    binding = unqualified["qualificationIdentity"]
    if identity.kind != "path" or identity.state != "clean" or unqualified["lane"] != "kvm-x86_64":
        raise ValueError("candidate requires clean real native KVM x86_64 provenance")
    if not binding.endswith(":eligible=true") or len(binding) > 256:
        raise ValueError("candidate lacks a complete eligible native/build binding")
    if binding != original["qualificationIdentity"]:
        raise ValueError("candidate build inputs differ from production; align environment/configuration")
    capabilities = source / "virt/vmm/src/capabilities.rs"
    text = capabilities.read_text()
    qualifications = re.findall(r"const QUALIFICATIONS: &\[Qualification<'static>\] = &\[.*?\];", text, re.DOTALL)
    if len(qualifications) != 1:
        raise ValueError("expected exactly one compiled qualification table")
    if unqualified["live"]["capture"]["availability"] != {
        "status": "unsupported", "reason": {"code": "lane-not-qualified", "subject": None},
    }:
        raise ValueError("production must deliver capture without qualifying it")
    proof["mutations"].append(replace_once(
        capabilities, qualifications[0],
        "const QUALIFICATIONS: &[Qualification<'static>] = &[Qualification { binding: "
        + json.dumps(binding)
        + ', lane: LiveLane::KvmX86_64, operations: &[LiveOperation::Pause, LiveOperation::Capture], evidence: "isolated-phase14-candidate-not-shipped" }];'))
    proof["unqualifiedCapabilities"] = unqualified
    compile_candidate("candidate-monitor-build", ["-p", "silo-vmm", "--bin", "silo-vmm"])
    candidate = native_capabilities(binary, diagnostic=destination / "candidate-capabilities.log")
    if candidate["qualificationIdentity"] != binding:
        raise ValueError("candidate changed its native/build binding")
    for operation in ("pause", "capture"):
        if candidate["live"][operation] != {"native": True, "availability": {"status": "supported"}}:
            raise ValueError(f"candidate did not admit exact native {operation}")
    for operation in ("restore", "fork", "incremental"):
        if candidate["live"][operation] != unqualified["live"][operation]:
            raise ValueError(f"candidate changed undelivered operation {operation}")
    monitor_hash = digest(binary)
    boot = source / "runtime/libvm/src/boot_qualification.rs"
    boot_text = boot.read_text()
    admitted = re.search(r"const ADMITTED_BOOTS:.*?\];", boot_text, re.DOTALL)
    if admitted is None:
        raise ValueError("missing existing compiled overlay boot tuple")
    native = re.findall(r"native_sha256:\s*\[.*?\]", admitted.group(), re.DOTALL)
    if len(native) != 1:
        raise ValueError("expected one admitted native monitor digest")
    replacement = "native_sha256: [" + ", ".join("0x" + monitor_hash[index:index + 2]
                                                   for index in range(0, 64, 2)) + "]"
    proof["mutations"].append(replace_once(boot, native[0], replacement))
    compile_candidate("candidate-consumers-build", ["-p", "cli", "--bin", "silo",
                                                     "-p", "libvm", "--examples"])
    private_runtime = destination / "runtime"
    shutil.copytree(runtime, private_runtime, symlinks=True)
    replacement_path = private_runtime / "bin/silo-vmm"
    if replacement_path.is_symlink():
        replacement_path.unlink()
    shutil.copyfile(binary, replacement_path)
    replacement_path.chmod(0o700)
    private_bin = destination / "bin"
    private_bin.mkdir(mode=0o700)
    shutil.copyfile(target / "debug/silo", private_bin / "silo")
    (private_bin / "silo").chmod(0o700)
    (private_bin / "examples").mkdir(mode=0o700)
    for name in ("live_acceptance", "storage_acceptance"):
        executable = private_bin / "examples" / name
        shutil.copyfile(target / "debug/examples" / name, executable)
        executable.chmod(0o700)
    if digest(production) != production_hash:
        raise ValueError("production stage changed while building the candidate")
    proof.update({"candidateCapabilities": candidate, "candidateMonitorSha256": monitor_hash,
                  "candidateCliSha256": digest(private_bin / "silo"), "runtime": str(private_runtime),
                  "bin": str(private_bin), "productionStageUnchanged": True})
    manifest.write_text(json.dumps(proof, indent=2) + "\n")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.destination.resolve(), args.runtime.resolve()), sort_keys=True))


if __name__ == "__main__":
    main()
