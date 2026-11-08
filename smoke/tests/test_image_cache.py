from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from silo_smoke import image_cache, procs, stopped
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
    assert carried == {basic_image}
    assert not (destination / "machines").exists()
    assert not (destination / "images/tmp").exists()
    assert not (destination / "images/locks").exists()
    assert not (destination / "images/index.json").exists()
    with sqlite3.connect(destination / "state.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM machine_config").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM storage_operation").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM storage_snapshot").fetchone() == (0,)
        for table in ("storage_operation_stream", "storage_operation_object", "storage_operation_layer",
                      "storage_operation_lower", "machine_lower_dependency"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        lowers = connection.execute("SELECT lower_id FROM image_composition_artifact").fetchall()
        fsmeta = connection.execute(
            "SELECT r.fsmeta_digest FROM composition_result r JOIN image_composition_artifact a ON a.lower_id=r.id").fetchall()
        packs = connection.execute(
            "SELECT l.pack_stream FROM image_composition_artifact a JOIN composition_layer c ON c.result_id=a.lower_id "
            "JOIN layer_result l ON l.id=c.layer_result_id").fetchall()
    assert lowers and len(fsmeta) == len(lowers) and packs
    assert all((destination / "images/objects/sha256" / digest.removeprefix("sha256:")).is_file() for (digest,) in fsmeta)
    assert all((destination / "images/streams/sha256" / stream.removeprefix("sha256:")).is_file() for (stream,) in packs)

    environment = workspace.env(SILO_HOME=str(destination))
    assert silo.json("ls", env=environment) == []
    requests = registry.requests
    silo.run("create", basic_image, "--name", "catalog-clone", "--pull", "never", "--network", "none", env=environment)
    try:
        assert registry.requests == requests
        assert silo.json("info", "catalog-clone", env=environment)["state"] == "stopped"
        rows = procs.query(destination / "state.db", """
SELECT c.id, json(s.record_json) FROM machine_config c
JOIN machine_storage s ON s.machine_id=c.id WHERE c.name='catalog-clone'
""")
        assert len(rows) == 1, rows
        machine_id, encoded = rows[0]
        root = json.loads(encoded)["root"]
        # The offline clone selects the seeded composition as its lower.
        assert root["kind"] == "linux-overlay" and root["lower"]["kind"] == "erofs-composition", root
        assert (root["lower"]["record"],) in lowers, (root["lower"], lowers)
        relative = root["upper"]
        cloned = destination / "machines" / machine_id / relative
        original = stopped.writable_paths(silo, "catalog-source")["root"]
        assert (cloned.stat().st_dev, cloned.stat().st_ino) != (original.stat().st_dev, original.stat().st_ino)
    finally:
        silo.run("rm", "catalog-clone", "--force", env=environment)
