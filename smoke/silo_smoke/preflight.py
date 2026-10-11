from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import warnings

from .config import RUN_ROOT_PARENT, SmokeConfig
from .errors import SmokeEnvironmentError


@dataclass(frozen=True)
class LiveDaemonMark:
    path: Path
    inode: int
    mtime_ns: int


def _macos_checks(config: SmokeConfig) -> None:
    checks = [
        (["sysctl", "-n", "kern.hv_support"], ("1",)),
        (["codesign", "-d", "--entitlements", "-", str(config.runtime_dir / "bin/silo-vmm")],
         ("com.apple.security.hypervisor", "com.apple.security.virtualization")),
    ]
    for command, required in checks:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            if result.returncode or not all(value in output for value in required):
                warnings.warn(f"macOS virtualization check failed: {shlex.join(command)}\n{output}", stacklevel=2)
        except (OSError, subprocess.TimeoutExpired) as error:
            warnings.warn(f"macOS virtualization check unavailable: {error}", stacklevel=2)
    from .registry import ensure_ca

    ca, _ = ensure_ca(config.cache_dir)
    try:
        result = subprocess.run(["security", "verify-cert", "-c", str(ca)], capture_output=True, timeout=15)
        trusted = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        trusted = False
    if not trusted:
        warnings.warn(
            "Trust the smoke registry CA in the login keychain before VM pulls: "
            "security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db "
            + shlex.quote(str(ca)), stacklevel=2,
        )


def check(config: SmokeConfig) -> LiveDaemonMark | None:
    if os.geteuid() == 0:
        raise SmokeEnvironmentError("Run smoke as a non-root user: silod refuses root")
    for binary in (config.silo, config.silod):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SmokeEnvironmentError(f"Missing executable {binary}; run make stage first")
    for relative in ("bin/silo-vmm", "bin/netd", "assets/kernel-default", "assets/initramfs", "assets/agent"):
        path = config.runtime_dir / relative
        if not path.is_file():
            raise SmokeEnvironmentError(f"Missing staged runtime file {path}; run make stage first")
    for program in ("openssl", "sqlite3"):
        if shutil.which(program) is None:
            raise SmokeEnvironmentError(f"{program} is not on PATH; enter the development shell")
    if platform.system() == "Linux" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SmokeEnvironmentError("/dev/kvm must be readable and writable; enable KVM and grant your user access")
    if platform.system() == "Darwin":
        _macos_checks(config)
    path = Path(RUN_ROOT_PARENT) / f"silo-{os.geteuid()}" / "silod/control.sock"
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return LiveDaemonMark(path, stat.st_ino, stat.st_mtime_ns)


def live_daemon_unchanged(mark: LiveDaemonMark | None) -> bool:
    if mark is None:
        return True
    try:
        stat = mark.path.stat()
    except FileNotFoundError:
        return False
    return stat.st_ino == mark.inode and stat.st_mtime_ns == mark.mtime_ns
