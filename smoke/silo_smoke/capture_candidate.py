"""Build an isolated capture/restore/fork candidate, never a production grant.

Copied compiled qualification tables admit only the exact private build. An
explicit IRQ candidate additionally enables source-only diagnostic witness
transport; its build identity is retained separately, never called production.
An explicit fork candidate admits delivered-but-unqualified live fork in the
same private copy only; production qualification tables stay untouched.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

from .config import REPO
from .overlay import digest, native_capabilities, native_source_identity
from .overlay_faults import replace_once


def build(destination: Path, runtime: Path, *, restore: bool = False, irq_probe: bool = False,
          fork: bool = False, profile: str = "debug") -> dict:
    if profile not in ("debug", "release"):
        raise ValueError("candidate profile must be debug or release")
    if irq_probe and not restore:
        raise ValueError("IRQ probe requires the isolated restore candidate")
    if fork and (not restore or irq_probe):
        raise ValueError("fork requires the ordinary isolated restore candidate, never the IRQ probe")
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
        raise ValueError("production capture must remain unqualified")
    source = destination / "source"
    shutil.copytree(REPO, source, symlinks=True, ignore=shutil.ignore_patterns(
        "target", ".git", ".tmp", ".codegraph", ".venv", "node_modules", "__pycache__", ".pytest_cache",
    ))
    target = destination / "target"
    command = ["cargo", "build", "--locked", "--offline", "--manifest-path", str(source / "Cargo.toml"),
               "--target-dir", str(target)]
    if profile == "release":
        command.append("--release")
    manifest = destination / "candidate-manifest.json"
    operations = ("pause", "capture", "restore", "fork") if fork else (
        ("pause", "capture", "restore") if restore else ("pause", "capture"))
    phase = 16 if fork else (15 if restore else 14)
    proof = {"scope": f"isolated Phase{phase} test-only candidate, not production qualification",
             "productionMonitorSha256": production_hash, "productionCapabilities": original,
             "commands": [], "mutations": []}
    proof["profile"] = profile
    proof["irqProbe"] = irq_probe
    monitor_features = ["--features", "restore-irq-probe"] if irq_probe else []
    if irq_probe:
        configure_irq_candidate(source, proof)

    def compile_candidate(label: str, arguments: list[str]) -> None:
        invocation = command + arguments
        proof["commands"].append(invocation)
        manifest.write_text(json.dumps(proof, indent=2) + "\n")
        with (destination / (label + ".log")).open("wb") as log:
            result = subprocess.run(invocation, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        if result.returncode:
            raise RuntimeError(f"candidate build failed ({result.returncode}): {label}.log")

    compile_candidate("unqualified-build", ["-p", "silo-vmm", "--bin", "silo-vmm", *monitor_features])
    binary = target / profile / "silo-vmm"
    unqualified = native_capabilities(binary, diagnostic=destination / "unqualified-capabilities.log")
    identity = native_source_identity(unqualified)
    binding = unqualified["qualificationIdentity"]
    if identity.kind != "path" or identity.state != "clean" or unqualified["lane"] != "kvm-x86_64":
        raise ValueError("candidate requires clean real native KVM x86_64 provenance")
    expected_eligibility = ":eligible=false" if irq_probe else ":eligible=true"
    if not binding.endswith(expected_eligibility) or len(binding) > 256:
        raise ValueError("candidate native/build eligibility differs from its declared scope")
    if irq_probe:
        production_identity = native_source_identity(original)
        if (identity.kind, identity.state, identity.revision, identity.content) != (
                production_identity.kind, production_identity.state,
                production_identity.revision, production_identity.content):
            raise ValueError("IRQ candidate must use the exact clean production native source")
        proof["diagnosticQualificationIdentity"] = binding
    elif binding != original["qualificationIdentity"]:
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
    if restore and unqualified["live"]["restore"] != {
        "native": True,
        "availability": {"status": "unsupported",
                         "reason": {"code": "lane-not-qualified", "subject": None}},
    }:
        raise ValueError("production must deliver restore without qualifying it")
    if fork and unqualified["live"]["fork"] != {
        "native": True,
        "availability": {"status": "unsupported",
                         "reason": {"code": "lane-not-qualified", "subject": None}},
    }:
        raise ValueError("production must deliver fork without qualifying it")
    admitted_operations = ", ".join("LiveOperation::" + operation.capitalize()
                                    for operation in operations)
    proof["mutations"].append(replace_once(
        capabilities, qualifications[0],
        "const QUALIFICATIONS: &[Qualification<'static>] = &[Qualification { binding: "
        + json.dumps(binding)
        + ", lane: LiveLane::KvmX86_64, operations: &[" + admitted_operations
        + f'], evidence: "isolated-phase{phase}-candidate-not-shipped" }}];'))
    proof["unqualifiedCapabilities"] = unqualified
    compile_candidate("candidate-monitor-build", ["-p", "silo-vmm", "--bin", "silo-vmm", *monitor_features])
    candidate = native_capabilities(binary, diagnostic=destination / "candidate-capabilities.log")
    if candidate["qualificationIdentity"] != binding:
        raise ValueError("candidate changed its native/build binding")
    for operation in operations:
        if candidate["live"][operation] != {"native": True, "availability": {"status": "supported"}}:
            raise ValueError(f"candidate did not admit exact native {operation}")
    for operation in ("pause", "capture", "restore", "fork", "incremental"):
        if operation in operations:
            continue
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
    if restore:
        compile_candidate("candidate-native-helper-build",
                          ["-p", "silo-vmm", "--example", "native-live-api", *monitor_features])
    private_runtime = destination / "runtime"
    shutil.copytree(runtime, private_runtime, symlinks=True)
    replacement_path = private_runtime / "bin/silo-vmm"
    if replacement_path.is_symlink():
        replacement_path.unlink()
    shutil.copyfile(binary, replacement_path)
    replacement_path.chmod(0o700)
    private_bin = destination / "bin"
    private_bin.mkdir(mode=0o700)
    shutil.copyfile(target / profile / "silo", private_bin / "silo")
    (private_bin / "silo").chmod(0o700)
    (private_bin / "examples").mkdir(mode=0o700)
    examples = ("live_acceptance", "storage_acceptance")
    if restore:
        examples += ("native-live-api",)
    for name in examples:
        executable = private_bin / "examples" / name
        shutil.copyfile(target / profile / "examples" / name, executable)
        executable.chmod(0o700)
    if irq_probe:
        stage_irq_fixture(source, private_runtime, candidate, monitor_hash, proof)
    if digest(production) != production_hash:
        raise ValueError("production stage changed while building the candidate")
    proof.update({"candidateCapabilities": candidate, "candidateMonitorSha256": monitor_hash,
                  "candidateCliSha256": digest(private_bin / "silo"), "runtime": str(private_runtime),
                  "bin": str(private_bin), "productionStageUnchanged": True})
    manifest.write_text(json.dumps(proof, indent=2) + "\n")
    return proof


def configure_irq_candidate(source: Path, proof: dict) -> None:
    """Adapt only the isolated source copy, retaining production ineligibility."""
    capabilities = source / "virt/vmm/src/capabilities.rs"
    proof["mutations"].append(replace_once(
        capabilities,
        "let qualification_ready = build.qualification_ready();",
        'let diagnostic_producer = native::diagnostic_execution_producer()'
        '.map_err(eyre::Report::msg)?;\n'
        '        eyre::ensure!(diagnostic_producer.starts_with("diagnostic-only;"), '
        '"IRQ candidate requires a diagnostic producer");\n'
        '        let qualification_ready = '
        'native::diagnostic_lane(native::compiled_live_build()).is_some();'))
    proof["mutations"].append(replace_once(
        capabilities, ".then(native::query_live_host)",
        ".then(native::query_diagnostic_live_host)"))
    # qualification_identity still computes ordinary production eligibility.
    # Only this copy's table matching uses the explicit diagnostic admission.
    inspect = source / "virt/vmm/src/restore/inspect.rs"
    proof["mutations"].append(replace_once(
        inspect,
        "libkrun::capabilities::compiled_live_build()\n        .execution_producer()",
        "libkrun::capabilities::diagnostic_execution_producer()"))
    proof["scope"] = (
        "isolated Phase15 IRQ diagnostic candidate, production-ineligible; "
        "not ordinary restore or production qualification")


def stage_irq_fixture(source: Path, runtime: Path, candidate: dict, monitor_hash: str, proof: dict) -> None:
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    native = Path(manifest["patch"]["https://github.com/vandycknick/libkrun.git"]["libkrun"]["path"])
    assembly = native / "examples/native_device_witness.S"
    output = runtime / "assets/restore-irq-witness"
    output.mkdir(mode=0o700)
    shutil.copyfile(assembly, output / "witness.S")
    commands = [
        ["as", "--64", str(output / "witness.S"), "-o", str(output / "witness.o")],
        ["ld", "--build-id=none", "-nostdlib", "-Ttext=0x1c001000", str(output / "witness.o"),
         "-o", str(output / "witness.elf")],
        ["objcopy", "-O", "binary", str(output / "witness.elf"), str(output / "witness.bin")],
        ["nm", "-n", str(output / "witness.elf")],
    ]
    for command in commands:
        result = subprocess.run(command, check=True, capture_output=True, timeout=60)
        proof["commands"].append(command)
        if command[0] == "nm":
            (output / "witness.nm").write_bytes(result.stdout)
    fixture = {
        "sourceSha256": digest(output / "witness.S"),
        "binarySha256": digest(output / "witness.bin"),
        "symbolsSha256": digest(output / "witness.nm"),
        "nativeSourceIdentity": candidate["buildIdentity"],
        "candidateMonitorSha256": monitor_hash,
        "commands": commands,
    }
    (output / "fixture-manifest.json").write_text(json.dumps(fixture, indent=2) + "\n")
    proof["irqFixture"] = fixture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--profile", choices=("debug", "release"), default="debug",
                        help="build profile; must match the supplied production runtime")
    parser.add_argument("--restore", action="store_true",
                        help="admit delivered restore in this isolated Phase15 candidate")
    parser.add_argument("--irq-probe", action="store_true",
                        help="build a separate restore candidate with source-only native IRQ witness transport")
    parser.add_argument("--fork", action="store_true",
                        help="also admit delivered live fork in this isolated Phase16 restore candidate")
    args = parser.parse_args()
    print(json.dumps(build(args.destination.resolve(), args.runtime.resolve(),
                           restore=args.restore, irq_probe=args.irq_probe, fork=args.fork,
                           profile=args.profile),
                     sort_keys=True))


if __name__ == "__main__":
    main()
