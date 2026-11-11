#!/usr/bin/env python3
"""Collect notices from the exact target-specific Go dependency graph."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True)
class Module:
    name: str
    version: str | None
    directory: Path


def modules_from_packages(data: str) -> list[Module]:
    decoder = json.JSONDecoder()
    modules: dict[str, Module] = {}
    while data.strip():
        item, end = decoder.raw_decode(data.lstrip())
        data = data.lstrip()[end:]
        module = item.get("Module")
        if module is None or module.get("Main"):
            continue
        source = module.get("Replace", module)
        modules[module["Path"]] = Module(module["Path"], source.get("Version", module.get("Version")), Path(source["Dir"]))
    return sorted(modules.values(), key=lambda module: module.name)


def safe_path(value: str) -> Path:
    if not value or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/")) or Path(value).is_absolute():
        raise ValueError(f"unsafe module notice path: {value!r}")
    return Path(value)


def collect(modules: list[Module], output: Path) -> None:
    inventory = []
    material: list[tuple[Path, Path]] = []
    for module in modules:
        version = safe_path(module.version or "local")
        if len(version.parts) != 1:
            raise ValueError(f"invalid module version: {module.version!r}")
        destination = safe_path(module.name) / version
        notices = sorted(p for p in module.directory.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")) and p.suffix.lower() not in {".go", ".rs", ".py", ".sh"})
        if not notices:
            raise RuntimeError(f"missing license material for {module.name} {module.version or 'local'}")
        for notice in notices:
            material.append((notice, destination / notice.name))
        inventory.append({"module": module.name, "version": module.version, "notices": [str(destination / p.name) for p in notices]})
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for source, relative in material:
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
    manifest = output / "modules.json"
    manifest.write_text(json.dumps(inventory, indent=2) + "\n")
    manifest.chmod(0o644)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--package", default="./cmd/tsgate")
    args = parser.parse_args()
    data = subprocess.check_output([args.go, "list", "-mod=readonly", "-deps", "-json", args.package], cwd=args.module, text=True)
    collect(modules_from_packages(data), args.output)


if __name__ == "__main__":
    main()
