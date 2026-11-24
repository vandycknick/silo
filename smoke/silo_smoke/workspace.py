from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import TYPE_CHECKING

from .config import RUN_ROOT_PARENT, SmokeConfig
from .errors import SmokeAssertion
from .prereqs import workspace_parent

if TYPE_CHECKING:
    from .daemon import Daemon


type ConfigValue = str | int | float | bool | None | list[ConfigValue] | ConfigMapping
type ConfigMapping = dict[str, ConfigValue]


def _merge_config(document: ConfigMapping, updates: ConfigMapping) -> None:
    for key, value in updates.items():
        existing = document.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            _merge_config(existing, value)
        else:
            document[key] = value


class Workspace:
    def __init__(self, config: SmokeConfig, registry_address: str, registry_ca: Path, *, parent: Path | None = None, runtime_parent: Path | None = None) -> None:
        self.config = config
        if parent is None:
            parent = workspace_parent()
        self.root = Path(tempfile.mkdtemp(prefix="silo-smoke-", dir=parent))
        self.root.chmod(0o700)
        self.user_home = self.root / "user"
        self.silo_home = self.root / "state"
        self.config_home = self.root / "config"
        # Durable mounted state may have a long path. Generated sockets/locks
        # can live in a separately owned short runtime tree, never disk bytes.
        if runtime_parent is None and len(os.fsencode(self.root / "run" / "machines" / ("x" * 36) / "vsock.sock")) >= 100:
            runtime_parent = Path(RUN_ROOT_PARENT)
        self._runtime_directory = Path(tempfile.mkdtemp(prefix="silo-run-", dir=runtime_parent)) if runtime_parent is not None else None
        self.run_root = (self._runtime_directory or self.root) / "run"
        self.evidence = self.root / "evidence"
        self._machines: list[str] = []
        self._daemons: list[Daemon] = []
        self._record_lock = threading.Lock()
        assert len(os.fsencode(self.run_root / "machines" / ("x" * 36) / "vsock.sock")) < 100
        for directory in (self.user_home, self.silo_home, self.config_home, self.run_root, self.evidence):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self.trust_registry(registry_address, registry_ca)
        if self._runtime_directory is not None:
            self.record("runtime-placement", f"persistent={self.silo_home}\nruntime={self.run_root}\n")

    def trust_registry(self, address: str, ca: Path) -> None:
        self.update_config({"images": {"registries": {address: {"ca": str(ca.resolve())}}}})

    def update_config(self, updates: ConfigMapping) -> None:
        """Merge into the suite-owned Silo config, written as JSON-compatible YAML."""
        directory = self.config_home / "silo"
        path = directory / "config.yaml"
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raw = None
        try:
            document: ConfigMapping = json.loads(raw) if raw is not None else {}
        except json.JSONDecodeError as error:
            raise SmokeAssertion(f"Expected JSON-compatible YAML in workspace config {path}: {error}") from error
        if not isinstance(document, dict):
            raise SmokeAssertion(f"Expected a mapping in workspace config {path}")
        _merge_config(document, updates)
        rendered = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        if rendered == raw:
            return
        # Changes to registry roots (including the CA digest) change daemon identity.
        # Configure before startup, or stop and explicitly restart the private daemon.
        if any(daemon.proc is not None and daemon.proc.poll() is None for daemon in self._daemons):
            raise SmokeAssertion("Stop the private daemon before changing its workspace config")
        directory.mkdir(mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as temporary:
            staged = Path(temporary.name)
            try:
                temporary.write(rendered)
                temporary.close()
                staged.replace(path)
            finally:
                staged.unlink(missing_ok=True)

    def env(self, **overrides: str) -> dict[str, str]:
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.user_home),
            "SILO_HOME": str(self.silo_home),
            "XDG_CONFIG_HOME": str(self.config_home),
            "SILO_RUN_ROOT": str(self.run_root),
            "SILO_RUNTIME_DIR": str(self.config.runtime_dir),
            "SILO_VIRT_BACKEND": self.config.backend,
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

    def unregister_machine(self, name: str) -> None:
        if name in self._machines:
            self._machines.remove(name)

    def register_daemon(self, daemon: Daemon) -> None:
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
        retain = failed or self.config.keep
        for name in reversed(self._machines):
            self._cleanup_command("stop", name, "--force", "--timeout", "10s")
            if not retain:
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
        if retain:
            print(f"Evidence retained at {self.root}")
            if self._runtime_directory is not None:
                print(f"Generated runtime evidence retained at {self._runtime_directory}")
        else:
            shutil.rmtree(self.root)
            if self._runtime_directory is not None:
                shutil.rmtree(self._runtime_directory)

    def machine_secrets(self, machine_id: str) -> Path:
        return self.silo_home / "machines" / machine_id / "secrets.json"

    def known_host(self, machine_id: str) -> Path:
        return self.silo_home / "machines" / machine_id / "ssh/known_host"

    def state_db(self) -> Path:
        return self.silo_home / "state.db"
