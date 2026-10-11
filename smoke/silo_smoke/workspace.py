from __future__ import annotations

import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
from typing import TYPE_CHECKING

from .config import RUN_ROOT_PARENT, SmokeConfig

if TYPE_CHECKING:
    from .daemon import Silod


def _system_trust_bundle() -> bytes:
    """The host's CA bundle, so netd and SDK builds can still reach public TLS endpoints.

    The suite CA is appended to it: `SSL_CERT_FILE` replaces the trust store for Go and
    rustls-native-certs consumers instead of extending it.
    """
    cafile = ssl.get_default_verify_paths().cafile
    for candidate in (cafile, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"):
        if candidate and Path(candidate).is_file():
            return Path(candidate).read_bytes().rstrip(b"\n") + b"\n"
    return b""


class Workspace:
    def __init__(self, config: SmokeConfig, registry_ca: Path) -> None:
        self.config = config
        self.root = Path(tempfile.mkdtemp(prefix="silo-smoke-", dir=RUN_ROOT_PARENT))
        self.root.chmod(0o700)
        self.user_home = self.root / "user"
        self.silo_home = self.root / "state"
        self.config_home = self.root / "config"
        self.run_root = self.root / "run"
        self.evidence = self.root / "evidence"
        self._trust_bundle = self.root / "ca-bundle.pem"
        self._machines: list[str] = []
        self._daemons: list[Silod] = []
        self._record_lock = threading.Lock()
        assert len(os.fsencode(self.run_root / "machines" / ("x" * 36) / "vsock.sock")) < 100
        for directory in (self.user_home, self.silo_home, self.config_home, self.run_root, self.evidence):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self._trust_bundle.write_bytes(_system_trust_bundle() + registry_ca.read_bytes())

    def env(self, **overrides: str) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.user_home),
            "SILO_HOME": str(self.silo_home),
            "XDG_CONFIG_HOME": str(self.config_home),
            "SILO_RUN_ROOT": str(self.run_root),
            "SILO_RUNTIME_DIR": str(self.config.runtime_dir),
            "SILO_VIRT_BACKEND": self.config.backend,
            "SSL_CERT_FILE": str(self._trust_bundle),
            "TERM": "dumb", "NO_COLOR": "1", "RUST_LOG": "info",
        }
        for key, value in overrides.items():
            if value:
                environment[key] = value
            else:
                environment.pop(key, None)
        return environment

    def register_machine(self, name: str) -> None:
        if name not in self._machines:
            self._machines.append(name)

    def register_daemon(self, daemon: Silod) -> None:
        if daemon not in self._daemons:
            self._daemons.append(daemon)

    def evidence_path(self, label: str) -> Path:
        relative = Path(label + ".log")
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Evidence labels must stay within the evidence directory")
        path = self.evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def record(self, label: str, text: str) -> None:
        with self._record_lock:
            with self.evidence_path(label).open("a", encoding="utf-8") as log:
                log.write(text)

    def _cleanup_command(self, *args: str) -> None:
        try:
            result = subprocess.run([str(self.config.silo), *args], env=self.env(), capture_output=True, text=True, errors="replace", timeout=30)
            self.record("cleanup", f"silo {args}: exit {result.returncode}\n{result.stdout}{result.stderr}\n")
        except (OSError, subprocess.TimeoutExpired) as error:
            self.record("cleanup", f"silo {args}: {error}\n")
            if isinstance(error, subprocess.TimeoutExpired):
                for output in (error.stdout, error.stderr):
                    if output:
                        self.record("cleanup", output.decode(errors="replace") if isinstance(output, bytes) else output)

    def cleanup(self, failed: bool) -> None:
        for name in reversed(self._machines):
            self._cleanup_command("stop", name, "--force", "--timeout", "10s")
            self._cleanup_command("rm", name, "--force")
        for daemon in reversed(self._daemons):
            try:
                daemon.terminate(timeout=15)
            except Exception as error:
                self.record("cleanup", f"Daemon termination failed: {error}\n")
                try:
                    daemon.kill()
                except Exception as kill_error:
                    self.record("cleanup", f"Daemon kill failed: {kill_error}\n")
        if failed or self.config.keep:
            print(f"Evidence retained at {self.root}")
        else:
            shutil.rmtree(self.root)

    def machine_secrets(self, machine_id: str) -> Path:
        return self.silo_home / "machines" / machine_id / "secrets.json"

    def known_host(self, machine_id: str) -> Path:
        return self.silo_home / "machines" / machine_id / "ssh/known_host"

    def state_db(self) -> Path:
        return self.silo_home / "state.db"
