from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform

import pytest

from .errors import SmokeEnvironmentError

RUN_ROOT_PARENT = "/private/tmp" if platform.system() == "Darwin" else "/tmp"
REPO = Path(__file__).resolve().parents[2]
# Published multi-arch images every lane can rely on: the appliance comes from
# .github/workflows/system-image.yml (the same dev default silod uses), the Arch
# image is the README quickstart image (systemd init, no OpenSSH, so the agent's
# native SSH backend serves logins).
DEFAULT_SYSTEM_IMAGE = "ghcr.io/vandycknick/silo/system:dev"
DEFAULT_DISTRO_IMAGES = f"arch=ghcr.io/vandycknick/archlinux:latest,system={DEFAULT_SYSTEM_IMAGE}"


def runtime_target() -> str:
    system, machine = platform.system(), platform.machine().lower()
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-amd64-gnu"
    if system == "Linux" and machine in {"aarch64", "arm64"}:
        return "linux-arm64-gnu"
    if system == "Darwin" and machine in {"aarch64", "arm64"}:
        return "darwin-arm64"
    raise SmokeEnvironmentError(f"Unsupported smoke host: {system} {machine}")


def go_ffi_library() -> str:
    return "libsilo_go_ffi.dylib" if platform.system() == "Darwin" else "libsilo_go_ffi.so"


@dataclass(frozen=True)
class SmokeConfig:
    bin_dir: Path
    runtime_dir: Path
    backend: str
    cache_dir: Path
    keep: bool
    system_image: str | None
    distro_images: dict[str, str]
    systemd_image: str | None
    curl_image: str | None

    @property
    def silo(self) -> Path:
        return self.bin_dir / "silo"

    @property
    def silod(self) -> Path:
        return self.bin_dir / "silod"


def add_options(parser: pytest.Parser) -> None:
    group = parser.getgroup("silo smoke")
    group.addoption("--silo-bin-dir", default=None)
    group.addoption("--silo-runtime-dir", default=None)
    group.addoption("--backend", choices=("krun", "vz"), default=None)
    group.addoption("--cache-dir", default=None)
    group.addoption("--keep", action="store_true", default=None)


def _path(config: pytest.Config, option: str, variable: str, default: Path) -> Path:
    value = config.getoption(option) or os.environ.get(variable)
    return Path(value).expanduser().resolve() if value else default.resolve()


def _published(variable: str, default: str) -> str | None:
    """Published image references default on; an empty value opts out."""
    value = os.environ.get(variable)
    if value is None:
        return default
    return value.strip() or None


def resolve(pytestconfig: pytest.Config) -> SmokeConfig:
    backend = pytestconfig.getoption("--backend") or os.environ.get("SILO_SMOKE_BACKEND", "krun")
    if backend not in {"krun", "vz"}:
        raise SmokeEnvironmentError(f"Invalid backend {backend!r}; use krun or vz")
    if backend == "vz" and platform.system() != "Darwin":
        raise SmokeEnvironmentError("The vz backend requires macOS; use --backend krun on Linux")
    distro_images: dict[str, str] = {}
    for entry in filter(None, (_published("SILO_SMOKE_DISTRO_IMAGES", DEFAULT_DISTRO_IMAGES) or "").split(",")):
        label, separator, reference = entry.partition("=")
        label, reference = label.strip(), reference.strip()
        if not separator or not label or not reference or label in distro_images:
            raise SmokeEnvironmentError("SILO_SMOKE_DISTRO_IMAGES must contain unique label=reference entries")
        distro_images[label] = reference
    keep = pytestconfig.getoption("--keep")
    return SmokeConfig(
        bin_dir=_path(pytestconfig, "--silo-bin-dir", "SILO_SMOKE_BIN_DIR", REPO / "target/debug"),
        runtime_dir=_path(pytestconfig, "--silo-runtime-dir", "SILO_SMOKE_RUNTIME_DIR", REPO / "target/silo-runtime" / runtime_target() / "debug"),
        backend=backend,
        cache_dir=_path(pytestconfig, "--cache-dir", "SILO_SMOKE_CACHE", Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "silo-smoke"),
        keep=bool(keep) if keep is not None else os.environ.get("SILO_SMOKE_KEEP") == "1",
        system_image=_published("SILO_SMOKE_SYSTEM_IMAGE", DEFAULT_SYSTEM_IMAGE),
        distro_images=distro_images,
        systemd_image=os.environ.get("SILO_SMOKE_SYSTEMD_IMAGE") or None,
        curl_image=os.environ.get("SILO_SMOKE_CURL_IMAGE") or None,
    )
