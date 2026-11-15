"""Real-file unit coverage for independent harness observations and ownership."""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sqlite3

import pytest

from silo_smoke import procs
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.errors import SmokeAssertion
from silo_smoke.registry import LoopbackRegistry
from silo_smoke.workspace import Workspace


def test_catalog_matches_independent_sqlite_cli_with_full_schema_and_typed_rows(tmp_path: Path) -> None:
    db = tmp_path / "catalog ?#.sqlite"
    with sqlite3.connect(db) as connection:
        connection.executescript('''
            CREATE TABLE empty (value TEXT);
            CREATE TABLE "odd""table" (text TEXT, number INTEGER, real_value REAL, binary BLOB, absent TEXT);
            CREATE UNIQUE INDEX by_number ON "odd""table" (number);
            CREATE VIEW numbers AS SELECT number FROM "odd""table";
            CREATE TRIGGER untouched AFTER DELETE ON empty BEGIN SELECT 1; END;
        ''')
        connection.executemany('INSERT INTO "odd""table" VALUES (?,?,?,?,?)', [
            ("z\n\x1f雪", -2, 1.25, b"\x00\xff", None),
            ("a", 9, -0.5, b"", ""),
        ])
    before = db.read_bytes()
    expected = {"schema": procs.query(db, "SELECT quote(type),quote(name),quote(tbl_name),quote(sql) FROM sqlite_schema ORDER BY type,name")}
    for (table,) in procs.query(db, "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
        identifier = '"' + table.replace('"', '""') + '"'
        columns = procs.query(db, f"PRAGMA table_info({identifier})")
        names = ['"' + column[1].replace('"', '""') + '"' for column in columns]
        expressions = [f"typeof({name}) || ':' || hex({name})" for name in names]
        expected[table] = sorted(procs.query(db, f"SELECT {','.join(expressions)} FROM {identifier}"))
    observed = procs.catalog(db)
    assert observed == expected
    assert observed["empty"] == []
    assert observed['odd"table'] == [
        ("text:61", "integer:39", "real:2D302E35", "blob:", "text:"),
        ("text:7A0A1FE99BAA", "integer:2D32", "real:312E3235", "blob:00FF", "null:"),
    ]
    assert db.read_bytes() == before


def test_catalog_keeps_multiline_schema_as_one_entry(tmp_path: Path) -> None:
    db = tmp_path / "multiline.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE multiline (\n value TEXT\n)")
        expected = connection.execute("SELECT quote(type),quote(name),quote(tbl_name),quote(sql) FROM sqlite_schema ORDER BY type,name").fetchall()
    assert procs.catalog(db) == {"schema": expected, "multiline": []}


def test_catalog_empty_database_and_missing_or_malformed_input(tmp_path: Path) -> None:
    empty = tmp_path / "empty.sqlite"
    sqlite3.connect(empty).close()
    assert procs.catalog(empty) == {"schema": []}
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(SmokeAssertion, match="Catalog observation failed"):
        procs.catalog(missing)
    assert not missing.exists()
    malformed = tmp_path / "malformed.sqlite"
    malformed.write_bytes(b"not a SQLite database")
    with pytest.raises(SmokeAssertion, match="Catalog observation failed"):
        procs.catalog(malformed)
    assert malformed.read_bytes() == b"not a SQLite database"


def test_workspace_long_durable_path_keeps_runtime_sockets_short(config: SmokeConfig, registry: LoopbackRegistry, tmp_path: Path) -> None:
    parent = tmp_path / ("durable-" + "x" * 100)
    parent.mkdir()
    workspace = Workspace(replace(config, keep=False), registry.ca_path, parent=parent)
    runtime = workspace.run_root.parent
    try:
        assert workspace.silo_home.is_relative_to(parent)
        assert not workspace.run_root.is_relative_to(parent)
        assert len(os.fsencode(workspace.run_root / "machines" / ("x" * 36) / "vsock.sock")) < 100
        workspace.register_machine("removed")
        workspace.unregister_machine("removed")
        workspace.unregister_machine("removed")
        assert workspace._machines == []
        workspace.register_machine("removed")
        workspace.register_machine("removed")
        assert workspace._machines == ["removed"]
        workspace.unregister_machine("removed")
    finally:
        workspace.cleanup(failed=False)
    assert not workspace.root.exists()
    assert not runtime.exists()


def test_successful_remove_unregisters_and_recreate_registers(silo: Silo, basic_image: str) -> None:
    name = "recreated-owner"
    assert silo.create(name, basic_image, "--network", "none") is None
    assert name in silo.ws._machines
    silo.rm(name)
    assert name not in silo.ws._machines
    silo.ws.register_machine(name)
    with pytest.raises(SmokeAssertion):
        silo.rm(name)
    assert name in silo.ws._machines
    silo.ws.unregister_machine(name)
    assert silo.create(name, basic_image, "--network", "none") is None
    assert name in silo.ws._machines
    refused = silo.run("rm", "never-created", expect=1)
    assert refused.returncode == 1 and name in silo.ws._machines
    silo.rm(name)
    assert name not in silo.ws._machines
