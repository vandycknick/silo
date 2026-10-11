from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from silo_smoke.cli import Silo
from silo_smoke.config import REPO, go_ffi_library
from silo_smoke.workspace import Workspace

pytestmark = pytest.mark.sdk


def _run(workspace: Workspace, command: list[str], env: dict[str, str], expected: int, label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
    workspace.record(label, f"$ {command}\n{result.stdout}\n[stderr]\n{result.stderr}")
    assert result.returncode == expected, result.stderr
    return result


def test_go_and_node_examples_against_vm(silo: Silo, workspace: Workspace, basic_image: str) -> None:
    for tool in ("go", "node"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not on PATH")
    if not (REPO / "sdk/node/dist").is_dir():
        pytest.skip("sdk/node/dist absent; build the Node SDK first")
    bridge = workspace.config.bin_dir / go_ffi_library()
    if not bridge.is_file():
        pytest.skip(f"{bridge} absent; build the Go FFI bridge first")
    for source in ("sdk/go/examples/shell/main.go", "sdk/node/examples/shell.mjs", "sdk/node/tests/integration/shell-smoke.mjs"):
        assert (REPO / source).is_file(), source
    name = "sdk-vm"
    silo.create(name, basic_image, "--cpus", "1", "--memory", "512mb", "--vsock", "--network", "none", "--provision-user=silo:1000:1000:/home/silo")
    silo.start(name)
    machine_id = silo.wait_ready(name)["id"]
    env = workspace.env(SILO_GO_FFI_PATH=str(bridge))
    example: Path = workspace.root / "shell-example"
    # Reuse the host's module/build caches instead of filling the throwaway HOME.
    modcache, gocache = subprocess.run(["go", "env", "GOMODCACHE", "GOCACHE"], capture_output=True, text=True, check=True, timeout=30).stdout.split()
    build_env = workspace.env(SILO_GO_FFI_PATH=str(bridge), GOMODCACHE=modcache, GOCACHE=gocache)
    _run(workspace, ["go", "-C", "sdk/go", "build", "-o", str(example), "./examples/shell"], build_env, 0, "go-build")
    go_result = _run(workspace, [str(example), machine_id], env, 7, "go-shell")
    assert "embedded:silo" in go_result.stdout
    assert "SSH exit: 7" in go_result.stdout
    node_result = _run(workspace, ["node", "sdk/node/examples/shell.mjs", machine_id], env, 7, "node-shell")
    assert "embedded:silo" in node_result.stdout
    assert "SSH exit: 7" in node_result.stdout
    qualification = _run(workspace, ["node", "sdk/node/tests/integration/shell-smoke.mjs", str(workspace.silo_home), machine_id, "all"], env, 0, "node-qualification")
    assert "Node all execution/SSH qualification passed" in qualification.stdout
