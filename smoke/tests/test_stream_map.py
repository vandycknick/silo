"""Real-file independent format evidence, no VM or production decoder."""
from __future__ import annotations

from pathlib import Path
from contextlib import closing
import sqlite3
import random
import struct

import pytest

from silo_smoke import stream_map as oracle


def test_empty_and_zero_root_exact_bytes() -> None:
    for shift in range(12, 24):
        for length in (0, 1, 30 << 30, 500 << 30, 1 << 40):
            root = oracle.from_leaves(length, 1 << shift, {})
            encoded = b"silo:stream:v2\n" + struct.pack("<BQB", shift, length, 0)
            assert root.encode() == encoded and len(encoded) == 25
            assert oracle.decode_root(encoded) == root
    assert oracle.Root(0, oracle.RAM_CHUNK, None).identity != oracle.Root(1, oracle.RAM_CHUNK, None).identity
    assert oracle.Root(1, oracle.RAM_CHUNK, None).identity != oracle.Root(1, oracle.DISK_CHUNK, None).identity
    assert oracle.Root(0, oracle.RAM_CHUNK, None).identity == (
        "sha256:8105ecb94483de323a5b839ea425e11e2270d9b5ae54fe5ab72ee75beed03f02")
    assert oracle.Root(1, oracle.RAM_CHUNK, None).identity == (
        "sha256:0471c42fb5674f3d0950b535aebe6712afd9b09ca40891364a9042e0b2c9a23a")


@pytest.mark.parametrize(("size", "expected"), [
    (oracle.RAM_CHUNK, "sha256:71e80b10f3466f6c8004110a61078629142623039973613bdaf5c687a7f9ee18"),
    (oracle.DISK_CHUNK, "sha256:8baf9f891e9598b23cdd74e9cad57c07fadd8f7e382917be95a9a1aa67235996"),
])
def test_nonzero_short_tail_literal_root(tmp_path: Path, size: int, expected: str) -> None:
    path = tmp_path / "one-byte"
    path.write_bytes(b"A")
    root, leaves = oracle.from_file(path, size)
    assert root.identity == expected and root.length == 1
    assert leaves == {0: oracle.digest(b"A")}
    assert root.tree == "sha256:b9498cd4ac4155f3cafb234fd53c1037c8f0daa85564dcc7b038bb2f1910dcb9"


def test_sparse_boundary_indices_and_closure_corruption(tmp_path: Path) -> None:
    length = 1 << 40
    indices = (0, 63, 64, 4095, 4096, length // oracle.RAM_CHUNK - 1)
    leaves = {index: oracle.digest(str(index).encode()) for index in indices}
    objects = tmp_path / "objects"
    objects.mkdir()

    def sink(identity: str, encoded: bytes) -> None:
        (objects / identity[7:]).write_bytes(encoded)

    def source(identity: str) -> bytes:
        return (objects / identity[7:]).read_bytes()

    root = oracle.from_leaves(length, oracle.RAM_CHUNK, leaves, sink)
    assert dict(oracle.present_chunks(root, source)) == leaves
    for path in objects.iterdir():
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with pytest.raises(ValueError, match="hash mismatch"):
            dict(oracle.present_chunks(root, source))
        path.write_bytes(original)
        path.unlink()
        with pytest.raises(FileNotFoundError):
            dict(oracle.present_chunks(root, source))
        path.write_bytes(original)
    assert len(list(objects.iterdir())) <= 5 * len(indices)
    with pytest.raises(ValueError, match="outside"):
        oracle.from_leaves(1, oracle.RAM_CHUNK, {1: oracle.digest(b"x")})


def test_random_writes_zeroes_and_short_tail_rebuild(tmp_path: Path) -> None:
    path = tmp_path / "ram"
    size = oracle.RAM_CHUNK
    path.write_bytes(bytes(size * 65 + 17))
    generator = random.Random(30)
    leaves: dict[int, str] = {}
    for _ in range(25):
        index = generator.randrange(66)
        count = min(size, path.stat().st_size - index * size)
        data = bytes(count) if generator.randrange(3) == 0 else generator.randbytes(count)
        with path.open("r+b") as output:
            output.seek(index * size)
            output.write(data)
        if any(data):
            leaves[index] = oracle.digest(data)
        else:
            leaves.pop(index, None)
        root, actual = oracle.from_file(path, size)
        assert actual == leaves
        assert root == oracle.from_leaves(path.stat().st_size, size, leaves)
    with path.open("r+b") as output:
        output.truncate(size)
    root, actual = oracle.from_file(path, size)
    assert root == oracle.from_leaves(size, size, {i: v for i, v in leaves.items() if i == 0})


@pytest.mark.parametrize("encoded", [b"{}", b"silo:stream:v1\n", oracle.ROOT + bytes(11)])
def test_old_or_malformed_roots_refused(encoded: bytes) -> None:
    with pytest.raises(ValueError):
        oracle.decode_root(encoded)


@pytest.mark.parametrize("height", range(5))
def test_empty_trailing_wrong_height_and_explicit_defaults_refused(height: int) -> None:
    prefix = oracle.LEAF if height == 0 else oracle.BRANCH + bytes([height])
    with pytest.raises(ValueError):
        oracle.decode_node(prefix + bytes(8), height)
    data = prefix + struct.pack("<Q", 1) + bytes.fromhex("11" * 32)
    assert len(oracle.decode_node(data, height)) == 1
    with pytest.raises(ValueError):
        oracle.decode_node(data + b"x", height)
    with pytest.raises(ValueError):
        oracle.decode_node(data, (height + 1) % 5)
    if height:
        with pytest.raises(ValueError, match="default"):
            oracle.decode_node(prefix + struct.pack("<Q", 1) + oracle.default_digest(height - 1), height)


def test_change_file_empty_full_and_incremental_runs(tmp_path: Path) -> None:
    path = tmp_path / "memory.changes"
    header = b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, 1, 0)
    data = struct.pack("<QQB7s32s", 3, 1, 1, bytes(7), bytes.fromhex("12" * 32))
    zero = struct.pack("<QQB7s32s", 4, 3, 0, bytes(7), bytes(32))
    path.write_bytes(header + data + zero)
    changes = oracle.read_changes(path, 7 * oracle.RAM_CHUNK)
    assert changes.mode == "incremental" and changes.affected() == {3, 4, 5, 6}
    assert changes.byte_length == 128 and len(changes.records) == 2
    assert changes.identity == oracle.digest(path.read_bytes())
    full_header = b"KRUNRAM\0" + struct.pack("<HBBI", 1, 16, 0, 0)
    path.write_bytes(full_header)
    assert oracle.read_changes(path, 1 << 40).records == ()
    for malformed in (header + data + data, header + zero + zero, header + data[:-1],
                      full_header + zero, header + zero + struct.pack("<QQB7s32s", 7, 1, 0, bytes(7), bytes(32))):
        path.write_bytes(malformed)
        with pytest.raises(ValueError):
            oracle.read_changes(path, 8 * oracle.RAM_CHUNK)


def test_catalog_root_allows_no_representation_but_rejects_conflicting_rows(tmp_path: Path) -> None:
    objects = tmp_path / "images/objects/sha256"
    objects.mkdir(parents=True)
    payload = b"real sparse root bytes"
    leaves = {0: oracle.digest(payload)}
    root = oracle.from_leaves(len(payload), oracle.RAM_CHUNK, leaves,
        lambda identity, encoded: (objects / identity[7:]).write_bytes(encoded))
    (objects / root.identity[7:]).write_bytes(root.encode())
    binding = {"stream": root.identity, "map": root.identity,
               "length": root.length, "chunkSize": root.chunk_size}
    with closing(sqlite3.connect(tmp_path / "state.db")) as connection:
        connection.executescript("""
            CREATE TABLE stream_map_root (
                root_digest TEXT PRIMARY KEY, length INTEGER NOT NULL, chunk_shift INTEGER NOT NULL
            );
            CREATE TABLE storage_stream (
                stream_id TEXT PRIMARY KEY, length INTEGER NOT NULL,
                map_digest TEXT NOT NULL CHECK(map_digest=stream_id),
                chunk_shift INTEGER NOT NULL CHECK(chunk_shift IN (16,23)),
                flat_state TEXT NOT NULL CHECK(flat_state IN ('present','evicting','absent'))
            );
        """)
        connection.execute("INSERT INTO stream_map_root VALUES(?,?,?)", (root.identity, root.length, 16))
        connection.commit()
        assert oracle.catalog_root(tmp_path, binding) == (root, leaves)
        connection.execute("INSERT INTO storage_stream VALUES(?,?,?,?,?)",
                           (root.identity, root.length, root.identity, 16, "present"))
        connection.commit()
        assert oracle.catalog_root(tmp_path, binding) == (root, leaves)
        connection.execute("UPDATE storage_stream SET chunk_shift=23")
        connection.commit()
        with pytest.raises(ValueError, match="rows mismatch"):
            oracle.catalog_root(tmp_path, binding)
        connection.execute("DELETE FROM storage_stream")
        connection.execute("DELETE FROM stream_map_root")
        connection.commit()
        with pytest.raises(ValueError, match="rows mismatch"):
            oracle.catalog_root(tmp_path, binding)


def test_completed_disk_node_files_authenticates_exact_new_closure(tmp_path: Path) -> None:
    from silo_smoke.capture import completed_disk_node_files

    home = tmp_path / "home"
    directory = home / "capture"
    nodes = directory / "map-nodes"
    nodes.mkdir(parents=True)
    (directory / "disks").mkdir()
    pool = home / "images/objects/sha256"
    pool.mkdir(parents=True)
    (directory / "disks/root.raw").write_bytes(b"A")
    root = oracle.from_leaves(1, oracle.DISK_CHUNK, {0: oracle.digest(b"A")},
                             lambda identity, encoded: (nodes / identity[7:]).write_bytes(encoded))
    encoded_root = root.encode()
    (directory / "disks/root.root").write_bytes(encoded_root)
    seal = {"inventory": [{"role": "disks/root.root", "length": len(encoded_root), "sha256": root.identity}]}
    expected = {"map-nodes/" + path.name for path in nodes.iterdir()}
    assert len(expected) == 5
    assert completed_disk_node_files(home, directory, seal) == expected
    orphan_bytes = oracle.LEAF + struct.pack("<Q", 1) + bytes.fromhex("12" * 32)
    orphan = nodes / oracle.digest(orphan_bytes)[7:]
    orphan.write_bytes(orphan_bytes)
    assert completed_disk_node_files(home, directory, seal) == expected
    assert "map-nodes/" + orphan.name not in expected
    shared_name = next(iter(expected))
    shared = directory / shared_name
    original = shared.read_bytes()
    retained = pool / shared.name
    retained.write_bytes(original)
    shared.unlink()
    assert completed_disk_node_files(home, directory, seal) == expected - {shared_name}
    retained.write_bytes(original[:-1] + bytes([original[-1] ^ 0x80]))
    with pytest.raises(ValueError, match="hash mismatch"):
        completed_disk_node_files(home, directory, seal)
    retained.unlink()
    with pytest.raises(FileNotFoundError):
        completed_disk_node_files(home, directory, seal)
