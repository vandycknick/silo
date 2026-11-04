from __future__ import annotations

from pathlib import Path
import sqlite3

from silo_smoke import image_cache
from silo_smoke.cli import Silo
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


def test_image_catalog_snapshot_seeds_cache_without_private_machine_state(
    silo: Silo, workspace: Workspace, basic_image: str, registry: LoopbackRegistry,
    tmp_path: Path,
) -> None:
    """Exercise actual staged acquisition, SQLite backup and offline private cloning."""
    silo.create("catalog-source", basic_image, "--network", "none")
    cache = tmp_path / "cache"
    assert image_cache.persist(cache, workspace.silo_home)
    assert not image_cache.persist(cache, workspace.silo_home)

    destination = tmp_path / "destination"
    destination.mkdir(mode=0o700)
    carried = image_cache.seed(cache, destination)
    assert basic_image in carried
    assert not (destination / "machines").exists()
    assert not (destination / "images/tmp").exists()
    assert not (destination / "images/locks").exists()
    assert not (destination / "images/index.json").exists()
    with sqlite3.connect(destination / "state.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM machine_config").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM storage_operation").fetchone() == (0,)
        for table in ("storage_operation_stream", "storage_operation_object", "storage_operation_layer"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        paths = connection.execute("SELECT rootfs_path FROM image_rootfs_artifact").fetchall()
    assert paths
    assert all(Path(path).is_relative_to(destination / "images/streams/sha256") for (path,) in paths)
    assert all(Path(path).is_file() for (path,) in paths)

    environment = workspace.env(SILO_HOME=str(destination))
    assert silo.json("ls", env=environment) == []
    requests = registry.requests
    silo.run("create", basic_image, "--name", "catalog-clone", "--pull", "never", "--network", "none", env=environment)
    try:
        assert registry.requests == requests
        assert silo.json("info", "catalog-clone", env=environment)["state"] == "stopped"
    finally:
        silo.run("rm", "catalog-clone", "--force", env=environment)
