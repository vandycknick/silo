"""Resolve smoke inputs from the same Cargo outputs and kernel provenance as stage."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib

from .config import REPO
from .errors import SmokeEnvironmentError


def target_dir() -> Path:
    return Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "target"))).expanduser().resolve()


def bin_dir() -> Path:
    return Path(os.environ.get("SILO_SMOKE_BIN_DIR", str(target_dir() / os.environ.get("PROFILE", "release")))).expanduser().resolve()


def example(name: str, directory: Path | None = None, override: str | None = None) -> Path:
    value = os.environ.get(override) if override else None
    path = Path(value).expanduser() if value else (directory or bin_dir()) / "examples" / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SmokeEnvironmentError(f"Missing smoke helper {path}; run make smoke-prereqs with the matching PROFILE and CARGO_TARGET_DIR")
    return path.resolve()


def native_root() -> Path:
    override = os.environ.get("SILO_NATIVE_ROOT")
    if override:
        root = Path(override).expanduser().resolve(strict=True)
    else:
        metadata = subprocess.run(
            ["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", str(REPO / "Cargo.toml")],
            check=True, capture_output=True, text=True, timeout=120,
        )
        pin = tomllib.loads((REPO / "Cargo.toml").read_text())["workspace"]["dependencies"]["libkrun"]
        packages = [package for package in json.loads(metadata.stdout)["packages"]
                    if package["name"] == "libkrun" and package.get("source")
                    and package["source"].endswith("#" + pin["rev"])]
        if len(packages) != 1:
            raise SmokeEnvironmentError("Cargo must resolve exactly the workspace-pinned git libkrun package")
        manifest = Path(packages[0]["manifest_path"]).resolve(strict=True)
        root = next((parent for parent in manifest.parents
                     if (parent / "src/libkrun/examples/native_generation_controller.py").is_file()), None)
        if root is None:
            raise SmokeEnvironmentError(f"Pinned libkrun checkout lacks the native validators: {manifest}")
    if not (root / "src/libkrun/examples/native_generation_controller.py").is_file():
        raise SmokeEnvironmentError(f"Native checkout lacks read-only validator sources: {root}")
    return root


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def registry_repository(reference: str) -> str:
    repository = reference.split("@", 1)[0]
    colon = repository.rfind(":")
    return repository[:colon] if colon > repository.rfind("/") else repository


def kernel_config(runtime: Path, local_kernel: Path | None = None) -> Path:
    override = os.environ.get("SILO_SMOKE_KERNEL_CONFIG")
    if override:
        return Path(override).expanduser().resolve(strict=True)
    kernel = runtime / "assets/kernel-default"
    local = target_dir() / "smoke/kernel-config" / runtime.parent.name / (runtime.name + ".json")
    if local_kernel is not None:
        kernel_file = local_kernel.resolve(strict=True)
        # `make kernel` publishes `<image>.config`; a KERNEL_PATH into a kernel
        # build directory has its `.config` beside the image.
        for candidate in (kernel_file.with_name(kernel_file.name + ".config"), kernel_file.parent / ".config"):
            if candidate.is_file() and _digest(kernel_file) == _digest(kernel):
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_text(json.dumps({"kernel": _digest(kernel), "config": str(candidate)}) + "\n")
                return candidate
    if local.is_file():
        record = json.loads(local.read_text())
        if record["kernel"] == _digest(kernel):
            return Path(record["config"]).resolve(strict=True)
    stage = json.loads((runtime / "runtime-manifest.json").read_text())
    artifact = stage["managedOverlayCandidate"].get("kernelArtifact")
    if artifact is None or artifact["kernel"]["digest"] != _digest(kernel):
        raise SmokeEnvironmentError("Staged local kernel has no resolved config; set SILO_SMOKE_KERNEL_CONFIG to its actual emitted .config")
    descriptor = artifact["resolvedConfig"]
    digest = descriptor["digest"]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise SmokeEnvironmentError(f"Invalid resolved kernel config digest: {digest!r}")
    destination = target_dir() / "kernel-cache/sha256" / digest[7:]
    if not destination.is_file():
        provenance = target_dir() / "kernel-provenance" / runtime.parent.name / (runtime.name + ".json")
        reference = json.loads(provenance.read_text())["reference"]
        repository = registry_repository(reference)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="kconfig-", dir=destination.parent) as temporary:
            fetched = Path(temporary) / "config"
            subprocess.run(["oras", "blob", "fetch", "--no-tty", "--output", str(fetched), repository + "@" + digest],
                           check=True, timeout=120)
            if fetched.stat().st_size != descriptor["size"] or _digest(fetched) != digest:
                raise SmokeEnvironmentError("Downloaded resolved kernel config does not match staged provenance")
            os.replace(fetched, destination)
    if destination.stat().st_size != descriptor["size"] or _digest(destination) != digest:
        raise SmokeEnvironmentError(f"Cached resolved kernel config does not match staged provenance: {destination}")
    return destination


def evidence_parent(variable: str = "SILO_SMOKE_EVIDENCE") -> Path:
    parent = Path(os.environ.get(variable) or os.environ.get("SILO_SMOKE_EVIDENCE") or str(target_dir() / "smoke/evidence")).expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    return parent


def workspace_parent() -> Path:
    # Durable storage (reflinks, no RAM-backed multi-GiB files) at a short,
    # canonical path: Unix socket paths under it must fit SUN_LEN, and the
    # repo's target dir is too deep for that. TMPDIR stays an override.
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    parent = Path(os.environ.get("TMPDIR", str(cache / "silo/smoke"))).expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    return parent


def extractor_skip_reason() -> str | None:
    override = os.environ.get("SILO_SMOKE_FILESYSTEM_OBSERVER")
    if override:
        path = Path(override).expanduser()
        return None if path.is_file() and os.access(path, os.X_OK) else f"SILO_SMOKE_FILESYSTEM_OBSERVER is not executable: {path}"
    go = shutil.which("go")
    if go is None:
        return "independent guest collector requires Go >=1.26.6 on PATH; install Go, then run make smoke SMOKE_MARK="
    result = subprocess.run([go, "env", "GOVERSION"], env={**os.environ, "GOTOOLCHAIN": "local"}, capture_output=True, text=True, timeout=15, check=True)
    match = re.fullmatch(r"go(\d+)\.(\d+)(?:\.(\d+))?\s*", result.stdout)
    if match is None or tuple(int(value or 0) for value in match.groups()) < (1, 26, 6):
        return f"independent guest collector requires Go >=1.26.6 on PATH, found {result.stdout.strip()!r}; install Go, then run make smoke SMOKE_MARK="
    return None


def includes_slow(marker: str) -> bool:
    from _pytest.mark.expression import Expression

    return not marker or Expression.compile(marker).evaluate(lambda name, **kwargs: name in {"slow", "linux_only"})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--local-kernel", type=Path)
    parser.add_argument("--marker", default="not slow")
    args, pytest_args = parser.parse_known_args()
    native_root()
    print(f"Smoke kernel config: {kernel_config(args.runtime, args.local_kernel)}", flush=True)
    # The final -m supplied by the caller overrides the Makefile default, as in pytest.
    marker = args.marker
    for index, argument in enumerate(pytest_args):
        if argument == "-m" and index + 1 < len(pytest_args):
            marker = pytest_args[index + 1]
        elif argument.startswith("-m") and len(argument) > 2:
            marker = argument[2:]
    slow = includes_slow(marker)
    if slow and platform.system() == "Linux":
        if platform.machine().lower() in {"x86_64", "amd64"}:
            subprocess.run(["make", "-C", str(REPO), "smoke-diagnostic", f"SMOKE_PROFILE={os.environ.get('PROFILE', 'release')}",
                            f"SMOKE_RUNTIME_SOURCE={args.runtime.resolve()}"], check=True)
        reason = extractor_skip_reason()
        if reason is not None:
            print(f"Smoke collector skip: {reason}", flush=True)
        elif not os.environ.get("SILO_SMOKE_FILESYSTEM_OBSERVER"):
            subprocess.run(["make", "-C", str(REPO), "changeset-extractor"],
                           env={**os.environ, "CGO_ENABLED": "0"}, check=True)


if __name__ == "__main__":
    main()
