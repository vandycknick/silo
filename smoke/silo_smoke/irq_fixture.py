"""Stage the IRQ witness from Cargo's resolved libkrun checkout."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess

from .config import REPO
from .overlay import digest, native_capabilities


def stage(runtime: Path) -> Path:
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
         "--manifest-path", str(REPO / "Cargo.toml")],
        check=True, capture_output=True, text=True, timeout=60,
    )
    packages = [package for package in json.loads(metadata.stdout)["packages"]
                if package["name"] == "libkrun"]
    if len(packages) != 1:
        raise ValueError("Cargo must resolve exactly one libkrun package")
    manifest = Path(packages[0]["manifest_path"]).resolve(strict=True)
    assembly = next((root / "examples/native_device_witness.S"
                     for root in manifest.parents
                     if (root / "examples/native_device_witness.S").is_file()), None)
    if assembly is None:
        raise FileNotFoundError(f"Resolved libkrun checkout has no IRQ witness: {manifest}")
    monitor = runtime / "bin/silo-vmm"
    capabilities = native_capabilities(monitor)
    output = runtime / "assets/restore-irq-witness"
    output.mkdir(mode=0o700)
    try:
        shutil.copyfile(assembly, output / "witness.S")
        commands = [
            ["as", "--64", str(output / "witness.S"), "-o", str(output / "witness.o")],
            ["ld", "--build-id=none", "-nostdlib", "-Ttext=0x1c001000",
             str(output / "witness.o"), "-o", str(output / "witness.elf")],
            ["objcopy", "-O", "binary", str(output / "witness.elf"), str(output / "witness.bin")],
            ["nm", "-n", str(output / "witness.elf")],
        ]
        for command in commands:
            result = subprocess.run(command, check=True, capture_output=True, timeout=60)
            if command[0] == "nm":
                (output / "witness.nm").write_bytes(result.stdout)
        fixture = {
            "sourceSha256": digest(output / "witness.S"),
            "binarySha256": digest(output / "witness.bin"),
            "symbolsSha256": digest(output / "witness.nm"),
            "buildIdentity": capabilities["buildIdentity"],
            "monitorSha256": digest(monitor),
            "libkrunManifest": str(manifest),
            "assembly": str(assembly),
            "commands": commands,
        }
        (output / "fixture-manifest.json").write_text(json.dumps(fixture, indent=2) + "\n")
    except BaseException:
        shutil.rmtree(output)
        raise
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    print(stage(args.runtime.resolve(strict=True)))


if __name__ == "__main__":
    main()
