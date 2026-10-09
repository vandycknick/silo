#!/usr/bin/env python3
"""Fail-closed native Linux ELF/ABI/dependency audit, independent of build closure."""
import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import subprocess


# ADR0012's GNU/Linux floor is glibc 2.39, not a new baseline selected by this tool.
GLIBC_FLOOR = (2, 39)
SYSTEM_ROOTS = (Path("/usr/lib"), Path("/usr/lib64"), Path("/lib"), Path("/lib64"))


@dataclass(frozen=True)
class Elf:
    path: Path
    interpreter: str | None
    needed: tuple[str, ...]
    search_paths: tuple[str, ...]
    glibc: tuple[int, int]


def environment() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LD_", "DYLD_", "SILO_", "TS_"))}
    env.pop("GODEBUG", None)
    env["LC_ALL"] = "C"
    return env


def native_path(path: Path) -> Path:
    actual = path.resolve(strict=True)
    if not any(actual.is_relative_to(root.resolve(strict=True)) for root in SYSTEM_ROOTS if root.is_dir()):
        raise RuntimeError(f"dependency outside native system library directories: {path} -> {actual}")
    if str(actual).startswith("/nix/"):
        raise RuntimeError(f"Nix dependency: {actual}")
    return actual


def inspect(path: Path) -> Elf:
    output = subprocess.check_output(["/usr/bin/readelf", "-l", "-d", "--version-info", str(path)], text=True, env=environment())
    interpreter = re.search(r"Requesting program interpreter: ([^\]]+)\]", output)
    needed = tuple(re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", output))
    searches = tuple(re.findall(r"\((?:RUNPATH|RPATH)\).*\[([^\]]*)\]", output))
    needs = output.split("Version needs section", 1)[-1] if "Version needs section" in output else ""
    versions = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", needs)]
    return Elf(path, interpreter[1] if interpreter else None, needed, searches, max(versions, default=(0, 0)))


def validate(elf: Elf, loader: Path, *, system_dependency: bool = False) -> None:
    correct = elf.interpreter == str(loader)
    if system_dependency and elf.interpreter is not None:
        correct = native_path(Path(elf.interpreter)) == native_path(loader)
    if elf.interpreter is not None and not correct:
        raise RuntimeError(f"nonstandard ELF interpreter: {elf.path}: {elf.interpreter}")
    if any(elf.search_paths):
        raise RuntimeError(f"ELF search paths are not permitted in this system-library archive: {elf.path}: {elf.search_paths}")
    if any(not re.fullmatch(r"[A-Za-z0-9_+.\-]+", name) for name in elf.needed):
        raise RuntimeError(f"non-basename DT_NEEDED: {elf.path}: {elf.needed}")
    if elf.glibc > GLIBC_FLOOR:
        raise RuntimeError(f"glibc requirement {elf.glibc} exceeds ADR0012 floor {GLIBC_FLOOR}: {elf.path}")


def loader_for(target: str) -> Path:
    expected = {"linux-amd64-gnu": ("x86_64", "/lib64/ld-linux-x86-64.so.2"), "linux-arm64-gnu": ("aarch64", "/lib/ld-linux-aarch64.so.1")}
    machine, path = expected[target]
    if platform.machine() != machine:
        raise RuntimeError(f"native audit requires {machine}, current host is {platform.machine()}")
    loader = Path(path)
    native_path(loader)
    return loader


def library_path() -> str:
    paths = [str(root) for root in SYSTEM_ROOTS if root.is_dir()]
    paths.extend(str(root / triplet) for root in SYSTEM_ROOTS for triplet in ("x86_64-linux-gnu", "aarch64-linux-gnu") if (root / triplet).is_dir())
    for path in paths:
        native_path(Path(path))
    return ":".join(paths)


def loader_command(loader: Path, path: Path, *args: str) -> list[str]:
    return [str(loader), "--inhibit-cache", "--library-path", library_path(), str(path), *args]


def audit(path: Path, target: str) -> Elf:
    loader = loader_for(target)
    elf = inspect(path)
    validate(elf, loader)
    if not elf.needed:
        print(f"ELF {path}: static, glibc imports={elf.glibc}")
        return elf
    output = subprocess.check_output([str(loader), "--inhibit-cache", "--library-path", library_path(), "--list", str(path)], text=True, stderr=subprocess.STDOUT, env=environment())
    if "not found" in output:
        raise RuntimeError(f"unresolved dependency: {path}\n{output}")
    dependencies: dict[str, Path] = {}
    for line in output.splitlines():
        match = re.search(r"([^\s]+) => (/[^\s]+)", line)
        if match:
            dependencies[match[1]] = native_path(Path(match[2]))
        elif line.strip().startswith("/"):
            native_path(Path(line.strip().split()[0]))
    if not set(elf.needed).issubset(dependencies.keys() | {loader.name}):
        raise RuntimeError(f"incomplete dependency resolution: {path}: {elf.needed}\n{output}")
    for name, dependency in dependencies.items():
        validate(inspect(dependency), loader, system_dependency=True)
        print(f"  dependency {name}: {dependency}")
    print(f"ELF {path}: interpreter={elf.interpreter}, glibc imports={elf.glibc}, native closure passed")
    return elf


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("linux-amd64-gnu", "linux-arm64-gnu"))
    parser.add_argument("files", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.files:
        audit(path.resolve(strict=True), args.target)


if __name__ == "__main__":
    main()
