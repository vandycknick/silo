from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import time
import warnings

from . import procs
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
        raise SmokeEnvironmentError("Run smoke as a non-root user: the daemon refuses root")
    if not config.silo.is_file() or not os.access(config.silo, os.X_OK):
        raise SmokeEnvironmentError(f"Missing executable {config.silo}; run make stage first")
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


def _orphaned_processes() -> list[tuple[int, str]]:
    """Processes still referencing a `silo-smoke-*` workspace that no longer exists.

    A run killed mid-test (Ctrl-C twice, a crashed runner) skips workspace cleanup, so
    its silo-vmm and netd outlive the directory they were started for. A living
    workspace is never touched: another smoke session may own it.
    """
    listing = subprocess.run(["ps", "-axo", "pid=,args="], capture_output=True, text=True, check=False)
    prefix = f"{RUN_ROOT_PARENT}/silo-smoke-"
    orphans: list[tuple[int, str]] = []
    for line in listing.stdout.splitlines():
        pid_text, _, args = line.strip().partition(" ")
        if not pid_text.isdigit() or int(pid_text) == os.getpid() or prefix not in args:
            continue
        roots = {token[: token.index("/", len(prefix))] for token in args.split() if token.startswith(prefix) and "/" in token[len(prefix):]}
        if roots and not any(Path(root).exists() for root in roots):
            orphans.append((int(pid_text), args))
    return orphans


def sweep_orphans() -> list[int]:
    """Terminate VM processes left behind by interrupted runs; returns the pids swept."""
    orphans = _orphaned_processes()
    for pid, _ in orphans:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    survivors = [pid for pid, _ in orphans]
    while survivors and time.monotonic() < deadline:
        time.sleep(0.1)
        survivors = [pid for pid in survivors if procs.alive(pid)]
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid, args in orphans:
        print(f"swept orphaned smoke process {pid}: {args[:120]}")
    return [pid for pid, _ in orphans]


def live_daemon_unchanged(mark: LiveDaemonMark | None) -> bool:
    if mark is None:
        return True
    try:
        stat = mark.path.stat()
    except FileNotFoundError:
        return False
    return stat.st_ino == mark.inode and stat.st_mtime_ns == mark.mtime_ns
