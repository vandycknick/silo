"""Unit coverage of actual input files, path resolution and marker selection."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from silo_smoke import areas, prereqs, toolchain
from silo_smoke.config import REPO
from silo_smoke.errors import SmokeEnvironmentError


@pytest.mark.parametrize(("marker", "expected"), [
    ("", True), ("not slow", False), ("slow", True),
    ("linux_only", True), ("slow and not linux_only", False),
    ("slow and serial", False), ("not daemon", True),
    ("slow or daemon", True), ("not (slow or live)", False),
])
def test_slow_prerequisites_follow_the_actual_case_markers(marker: str, expected: bool) -> None:
    assert prereqs.includes_slow(marker) is expected


@pytest.mark.parametrize(("reference", "expected"), [
    ("ghcr.io/owner/kernel:stable", "ghcr.io/owner/kernel"),
    ("ghcr.io/owner/kernel@sha256:" + "a" * 64, "ghcr.io/owner/kernel"),
    ("localhost:5000/kernel:stable", "localhost:5000/kernel"),
    ("localhost:5000/kernel@sha256:" + "a" * 64, "localhost:5000/kernel"),
    ("localhost:5000/kernel", "localhost:5000/kernel"),
])
def test_kernel_config_blob_uses_the_staged_repository(reference: str, expected: str) -> None:
    assert prereqs.registry_repository(reference) == expected


def _run(code: str, target: Path, *arguments: Path) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("SILO_SMOKE_") and key != "SILO_NATIVE_ROOT"}
    environment.update(CARGO_TARGET_DIR=str(target), PROFILE="release", PYTHONPATH=str(REPO / "smoke"))
    return subprocess.run([sys.executable, "-c", code, *map(str, arguments)], cwd=REPO,
                          env=environment, capture_output=True, text=True, timeout=30)


def _kernel_fixture(target: Path) -> tuple[Path, Path]:
    runtime = target / "silo-runtime/linux-amd64-gnu/release"
    (runtime / "assets").mkdir(parents=True)
    kernel = b"actual kernel fixture bytes"
    (runtime / "assets/kernel-default").write_bytes(kernel)
    config = b"CONFIG_VMGENID=y\nCONFIG_VIRTIO_SILO_VMGENID=y\n"
    digest = "sha256:" + hashlib.sha256(config).hexdigest()
    cached = target / "kernel-cache/sha256" / digest[7:]
    cached.parent.mkdir(parents=True)
    cached.write_bytes(config)
    (runtime / "runtime-manifest.json").write_text(json.dumps({"managedOverlayCandidate": {
        "kernelArtifact": {"kernel": {"digest": "sha256:" + hashlib.sha256(kernel).hexdigest()},
                           "resolvedConfig": {"digest": digest, "size": len(config)}}}}))
    return runtime, cached


def test_staged_kernel_resolves_authenticated_cached_config_without_env(tmp_path: Path) -> None:
    runtime, cached = _kernel_fixture(tmp_path)
    result = _run("import sys; from pathlib import Path; from silo_smoke import prereqs; print(prereqs.kernel_config(Path(sys.argv[1])))", tmp_path, runtime)
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()) == cached


@pytest.mark.parametrize("mutation", ["config-bytes", "config-length", "kernel-bytes"])
def test_staged_kernel_config_refuses_mismatched_actual_bytes(tmp_path: Path, mutation: str) -> None:
    runtime, cached = _kernel_fixture(tmp_path)
    if mutation == "config-bytes":
        cached.write_bytes(b"X" * cached.stat().st_size)
    elif mutation == "config-length":
        cached.write_bytes(cached.read_bytes() + b"\n")
    else:
        (runtime / "assets/kernel-default").write_bytes(b"a different kernel")
    result = _run("import sys; from pathlib import Path; from silo_smoke import prereqs; prereqs.kernel_config(Path(sys.argv[1]))", tmp_path, runtime)
    assert result.returncode != 0
    assert "SmokeEnvironmentError" in result.stderr


def test_local_kernel_uses_adjacent_emitted_config_and_remembers_exact_kernel(tmp_path: Path) -> None:
    runtime, _ = _kernel_fixture(tmp_path)
    (runtime / "runtime-manifest.json").write_text(json.dumps({"managedOverlayCandidate": {"kernelArtifact": None}}))
    build = tmp_path / "local-build"
    build.mkdir()
    local = build / "vmlinux"
    local.write_bytes((runtime / "assets/kernel-default").read_bytes())
    config = build / ".config"
    config.write_text("CONFIG_VMGENID=y\n")
    code = "import sys; from pathlib import Path; from silo_smoke import prereqs; runtime, local = map(Path, sys.argv[1:]); print(prereqs.kernel_config(runtime, local)); print(prereqs.kernel_config(runtime))"
    result = _run(code, tmp_path, runtime, local)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [str(config), str(config)]
    (runtime / "assets/kernel-default").write_bytes(b"replacement kernel")
    result = _run("import sys; from pathlib import Path; from silo_smoke import prereqs; prereqs.kernel_config(Path(sys.argv[1]))", tmp_path, runtime)
    assert result.returncode != 0 and "no resolved config" in result.stderr


def test_release_paths_and_evidence_do_not_need_manual_environment(tmp_path: Path) -> None:
    code = "from silo_smoke import prereqs; from silo_smoke.evidence import evidence_directory; print(prereqs.bin_dir()); print(prereqs.workspace_parent()); print(evidence_directory('first')); print(evidence_directory('first'))"
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr
    binary, workspace, first, second = map(Path, result.stdout.splitlines())
    assert binary == tmp_path / "release"
    # An explicit TMPDIR remains a supported scratch override; otherwise a short
    # durable cache directory keeps socket paths under SUN_LEN.
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    assert workspace == Path(os.environ.get("TMPDIR", str(cache / "silo/smoke"))).resolve()
    assert first.parent == second.parent == tmp_path / "smoke/evidence"
    assert first != second and first.is_dir() and second.is_dir()


def test_example_resolution_never_falls_back_to_another_profile(tmp_path: Path) -> None:
    with pytest.raises(SmokeEnvironmentError, match="make smoke-prereqs"):
        prereqs.example("storage_acceptance", tmp_path / "release")
    directory = tmp_path / "release/examples"
    directory.mkdir(parents=True)
    executable = directory / "storage_acceptance"
    executable.symlink_to(sys.executable)
    assert prereqs.example("storage_acceptance", directory.parent) == Path(sys.executable).resolve()


def test_native_sources_come_from_cargos_exact_pinned_checkout(tmp_path: Path) -> None:
    code = (
        "import subprocess, tomllib; from silo_smoke import prereqs; from silo_smoke.config import REPO; "
        "root = prereqs.native_root(); "
        "pin = tomllib.loads((REPO / 'Cargo.toml').read_text())['workspace']['dependencies']['libkrun']['rev']; "
        "revision = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip(); "
        "assert revision == pin, (root, revision, pin); "
        "assert (root / 'src/libkrun/examples/native_generation_controller.py').is_file()"
    )
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_kernel_config_override_remains_an_explicit_input(tmp_path: Path) -> None:
    supplied = tmp_path / "owner.config"
    supplied.write_text("CONFIG_VMGENID=y\n")
    code = (
        "import os, sys; from pathlib import Path; from silo_smoke import prereqs; "
        "os.environ['SILO_SMOKE_KERNEL_CONFIG'] = sys.argv[1]; "
        "print(prereqs.kernel_config(Path('no-staged-runtime')))"
    )
    result = _run(code, tmp_path, supplied)
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()) == supplied


def test_every_smoke_module_has_an_area_and_every_area_names_real_modules() -> None:
    modules = {path.stem for path in (REPO / "smoke/tests").glob("test_*.py")}
    mapped = {module for area in areas.AREAS.values() for module in area.modules}
    assert modules - mapped == set(), "unmapped smoke modules"
    assert mapped - modules == set(), "areas name missing modules"


def test_static_cc_autodetects_a_compiler_that_links_static(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CC", raising=False)
    toolchain.static_cc.cache_clear()
    try:
        assert toolchain.links_static(list(toolchain.static_cc()))
    finally:
        toolchain.static_cc.cache_clear()


def test_static_cc_prefers_cc_but_falls_back_when_it_cannot_link_static(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC", "false")
    toolchain.static_cc.cache_clear()
    try:
        compiler = toolchain.static_cc()
        assert compiler != ("false",) and toolchain.links_static(list(compiler))
    finally:
        toolchain.static_cc.cache_clear()


@pytest.mark.linux_only
def test_scratch_refuses_tmpfs_and_defaults_to_durable_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TMPDIR", "/dev/shm")
    with pytest.raises(SmokeEnvironmentError, match="tmpfs"):
        prereqs.workspace_parent()
    monkeypatch.delenv("TMPDIR")
    assert prereqs.workspace_parent().is_relative_to(Path.home())
