"""Real-file unit coverage for independent harness observations and ownership."""
from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess

import pytest

from silo_smoke import fork, procs
from silo_smoke.cli import Silo
from silo_smoke.config import SmokeConfig
from silo_smoke.errors import SmokeAssertion
from silo_smoke.overlay_candidate import spawned_worker_pid
from silo_smoke.registry import LoopbackRegistry, ensure_ca
from silo_smoke.workspace import Workspace


def test_krun_worker_observation_reads_real_process_and_file_modes(tmp_path: Path) -> None:
    yes = shutil.which("yes")
    assert yes is not None
    executable = tmp_path / ("silo-vmm" if platform.system() == "Darwin" else "krun")
    shutil.copyfile(yes, executable)
    executable.chmod(0o700)
    lower = tmp_path / "read only.extent"
    upper = tmp_path / "read write.raw"
    lower.touch()
    upper.touch()
    with lower.open("rb") as reader, upper.open("r+b") as writer, subprocess.Popen(
        ["krun"], executable=executable, stdout=subprocess.PIPE,
        pass_fds=(reader.fileno(), writer.fileno()),
    ) as child, subprocess.Popen(
        [yes], stdout=subprocess.PIPE,
    ) as other_child:
        try:
            assert procs.krun_workers(os.getpid()) == [child.pid]
            assert procs.executable_path(child.pid).resolve(strict=True) == executable.resolve(strict=True)
            assert {
                (reader.fileno(), str(lower.resolve()), os.O_RDONLY),
                (writer.fileno(), str(upper.resolve()), os.O_RDWR),
            }.issubset(procs.file_access_modes(child.pid))
        finally:
            child.terminate()
            other_child.terminate()
    assert procs.krun_workers(os.getpid()) == []


def test_timeout_thread_states_observe_owned_process_without_logging_its_environment(workspace: Workspace) -> None:
    yes = shutil.which("yes")
    assert yes is not None
    witness = "must-not-appear-in-thread-evidence"
    with subprocess.Popen([yes], stdout=subprocess.PIPE, env=workspace.env(WITNESS=witness)) as child:
        try:
            text = procs.thread_states(workspace, "exec timeout-probe")
            first, second = text.split("sample 1\n")
            assert str(child.pid) in first and str(child.pid) in second, text
            assert witness not in text
        finally:
            child.terminate()


def test_candidate_worker_spawn_pid_requires_one_monitor_record() -> None:
    spawn = "2026-11-24T14:17:16.804943Z  INFO krun worker spawned worker_pid=67926\n"
    diagnostics = (
        "2026-11-24T14:17:16.831100Z DEBUG krun diagnostic worker_pid=67926 "
        "diagnostic=INFO krun worker spawned worker_pid=67926\n"
    )
    assert spawned_worker_pid(spawn + diagnostics) == 67926
    for trace in (diagnostics, spawn + spawn, spawn.replace("67926", "0")):
        with pytest.raises(AssertionError, match="expected one krun worker spawn record"):
            spawned_worker_pid(trace)


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
    workspace = Workspace(replace(config, keep=False), registry.address, registry.ca_path, parent=parent)
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


def test_workspace_merges_registry_ca_with_existing_config(config: SmokeConfig, tmp_path: Path) -> None:
    ca, _ = ensure_ca(tmp_path / 'CA "with spaces"')
    workspace = Workspace(replace(config, keep=False), "127.0.0.1:5043", ca, parent=tmp_path)
    try:
        workspace.update_config({
            "default_machine": "smoke",
            "images": {
                "default": "deny",
                "search_registries": ["127.0.0.1:5043"],
                "rules": [{"prefix": "127.0.0.1:5043/smoke", "action": "allow"}],
            },
            "networking": {"drivers": {"netd": {"subnet": "192.168.86.0/24"}}},
        })
        workspace.trust_registry("127.0.0.1:6043", ca)
        workspace.update_config({"networking": {"drivers": {"netd": {"pcap": True}}}})
        path = workspace.config_home / "silo/config.yaml"
        assert json.loads(path.read_text(encoding="utf-8")) == {
            "default_machine": "smoke",
            "images": {
                "default": "deny",
                "search_registries": ["127.0.0.1:5043"],
                "rules": [{"prefix": "127.0.0.1:5043/smoke", "action": "allow"}],
                "registries": {
                    "127.0.0.1:5043": {"ca": str(ca.resolve())},
                    "127.0.0.1:6043": {"ca": str(ca.resolve())},
                },
            },
            "networking": {"drivers": {"netd": {"subnet": "192.168.86.0/24", "pcap": True}}},
        }
        assert "SSL_CERT_FILE" not in workspace.env()
    finally:
        workspace.cleanup(failed=False)


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


@pytest.mark.parametrize("names", [["child"], ["first", "second"]])
def test_live_fork_argv_explicitly_selects_json(names: list[str]) -> None:
    operation = "ac615223-973b-4b60-b839-d339f976bbd4"
    args = fork.create_argv("source", names, "--preserve", operation=operation)
    assert args == [
        "fork", "source", "--live", "--format", "json",
        *(argument for name in names for argument in ("--name", name)),
        "--operation-id", operation, "--preserve",
    ]


def test_old_format_home_is_refused_without_conversion_or_deletion(silo: Silo) -> None:
    home = silo.ws.root / "old-format-home"
    home.mkdir(mode=0o700)
    database = home / "state.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript("""
            CREATE TABLE _sqlx_migrations (
                version BIGINT PRIMARY KEY, description TEXT NOT NULL,
                installed_on TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL, checksum BLOB NOT NULL, execution_time BIGINT NOT NULL
            );
            INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time)
                VALUES(1,'initial',TRUE,X'00',1);
            CREATE TABLE old_stream_map (record BLOB NOT NULL);
            INSERT INTO old_stream_map VALUES('old-format-home-marker');
        """)
    marker = home / "old-artifact"
    marker.write_bytes(b'{"schema":1,"kind":"stream","chunks":[]}')
    before = procs.catalog(database)
    failed = silo.run("ls", expect=1, env=silo.ws.env(SILO_HOME=str(home)))
    assert "incompatible state database" in failed.stderr.lower(), failed
    assert "cannot be read or converted" in failed.stderr.lower(), failed
    assert procs.catalog(database) == before
    assert marker.read_bytes() == b'{"schema":1,"kind":"stream","chunks":[]}'


@pytest.mark.parametrize("layered", [False, True], ids=["raw", "layered"])
@pytest.mark.parametrize("data_count", [1, 3])
def test_managed_fixture_inventory_tracks_writable_attachment_indices(layered: bool, data_count: int) -> None:
    from silo_smoke import stopped

    root_index = int(layered)
    disks = ([{"blockId": "silo-root-lower", "readOnly": True}] if layered else [])
    disks.append({"blockId": "silo-root-upper" if layered else "silo-root", "readOnly": False})
    root_identity = {
        "attachmentIndex": root_index, "blockId": disks[root_index]["blockId"],
        "identity": {"kind": "identified", "root": "sha256:" + "ab" * 32},
    }
    storage = {"diskIdentities": [root_identity]}
    for number in range(data_count):
        disks.append({"blockId": f"silo-data-{number}", "readOnly": False})
    disks.append({"blockId": "external-read-only", "readOnly": True})
    disks.append({"blockId": "external-writable", "readOnly": False})
    config = {"spec": {"storage": {"disks": disks}}}

    stopped.bind_fixture_disk_identity_inventory(config, storage)
    expected = [(index, disk["blockId"]) for index, disk in enumerate(disks) if not disk["readOnly"]]
    assert [(entry["attachmentIndex"], entry["blockId"]) for entry in storage["diskIdentities"]] == expected
    assert storage["diskIdentities"][0] == root_identity
    assert all(entry["identity"] == {"kind": "unknown"} for entry in storage["diskIdentities"][1:])
    before = list(storage["diskIdentities"])
    stopped.bind_fixture_disk_identity_inventory(config, storage)
    assert storage["diskIdentities"] == before


def test_managed_fixture_inventory_rejects_existing_mismatched_binding() -> None:
    from silo_smoke import stopped

    config = {"spec": {"storage": {"disks": [{"blockId": "silo-root", "readOnly": False}]}}}
    storage = {"diskIdentities": [{
        "attachmentIndex": 0, "blockId": "different-root", "identity": {"kind": "unknown"},
    }]}
    with pytest.raises(AssertionError):
        stopped.bind_fixture_disk_identity_inventory(config, storage)


@pytest.mark.parametrize(("reason", "kind"), [
    (None, None),
    ({"kind": "external"}, "external"),
    ({"kind": "copy-lane"}, "copy-lane"),
    ({"kind": "invalid-receipt", "reason": "never-armed"}, "invalid-receipt"),
])
def test_disk_full_scan_reason_reads_tagged_variant(reason: dict | None, kind: str | None) -> None:
    from silo_smoke.incremental import disk_full_scan_reason

    assert disk_full_scan_reason({"fullScanReason": reason}) == kind
