"""Independent stream-map v2 and native RAM-change decoders (stdlib only).

This deliberately shares no implementation with the Rust codec. Full-byte scans
are evidence, never part of a timed local capture/restore operation.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import closing
from dataclasses import dataclass
import hashlib
import sqlite3
from pathlib import Path
import struct

RAM_CHUNK = 1 << 16
DISK_CHUNK = 1 << 23
ROOT = b"silo:stream:v2\n"
LEAF = b"silo:stream-map:leaf:v2\n"
BRANCH = b"silo:stream-map:branch:v2\n"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def raw_digest(value: str) -> bytes:
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError("invalid SHA-256 identity")
    raw = bytes.fromhex(value[7:])
    if value[7:] != raw.hex():
        raise ValueError("noncanonical SHA-256 identity")
    return raw


def default_digest(height: int) -> bytes:
    prefix = LEAF if height == 0 else BRANCH + bytes([height])
    return hashlib.sha256(prefix + bytes(8)).digest()


@dataclass(frozen=True)
class Root:
    length: int
    chunk_size: int
    tree: str | None

    @property
    def count(self) -> int:
        return (self.length + self.chunk_size - 1) // self.chunk_size

    def encode(self) -> bytes:
        shift = self.chunk_size.bit_length() - 1
        if not 12 <= shift <= 23 or self.chunk_size != 1 << shift:
            raise ValueError("invalid identity profile")
        if not 0 <= self.length <= 4 << 40 or self.count > 1 << 30:
            raise ValueError("stream length exceeds format bounds")
        if self.length == 0 and self.tree is not None:
            raise ValueError("empty stream has a tree")
        if self.tree is not None and raw_digest(self.tree) in (bytes(32), default_digest(4)):
            raise ValueError("explicit default or zero digest")
        return (ROOT + struct.pack("<BQB", shift, self.length, int(self.tree is not None))
                + (raw_digest(self.tree) if self.tree is not None else b""))

    @property
    def identity(self) -> str:
        return digest(self.encode())


def decode_root(encoded: bytes) -> Root:
    if not encoded.startswith(ROOT) or len(encoded) not in (len(ROOT) + 10, len(ROOT) + 42):
        raise ValueError("invalid stream-map v2 root")
    shift, length, present = struct.unpack_from("<BQB", encoded, len(ROOT))
    if present not in (0, 1) or len(encoded) != len(ROOT) + 10 + 32 * present:
        raise ValueError("invalid tree flag or root length")
    root = Root(length, 1 << shift, digest_text(encoded[-32:]) if present else None)
    if root.encode() != encoded:
        raise ValueError("noncanonical root")
    return root


def digest_text(raw: bytes) -> str:
    return "sha256:" + raw.hex()


def decode_node(encoded: bytes, height: int) -> dict[int, str]:
    if not 0 <= height <= 4:
        raise ValueError("invalid node height")
    prefix = LEAF if height == 0 else BRANCH + bytes([height])
    if not encoded.startswith(prefix) or len(encoded) < len(prefix) + 8:
        raise ValueError("wrong node domain or height")
    bitmap, = struct.unpack_from("<Q", encoded, len(prefix))
    if not bitmap or len(encoded) != len(prefix) + 8 + 32 * bitmap.bit_count():
        raise ValueError("empty or malformed node")
    offset = len(prefix) + 8
    entries = {}
    for slot in range(64):
        if bitmap & (1 << slot):
            raw = encoded[offset:offset + 32]
            offset += 32
            if raw == bytes(32) or (height and raw == default_digest(height - 1)):
                raise ValueError("explicit default or zero digest")
            entries[slot] = digest_text(raw)
    return entries


def present_chunks(root: Root, source: Callable[[str], bytes]) -> Iterator[tuple[int, str]]:
    """Authenticate the full node closure, including position and tail bounds."""
    def walk(identity: str, height: int, first: int) -> Iterator[tuple[int, str]]:
        encoded = source(identity)
        if digest(encoded) != identity:
            raise ValueError(f"map node hash mismatch: {identity}, height {height}")
        for slot, child in decode_node(encoded, height).items():
            index = first + (slot << (6 * height))
            if index >= root.count:
                raise ValueError("map entry outside stream length")
            if height:
                yield from walk(child, height - 1, index)
            else:
                yield index, child
    if root.tree is not None:
        yield from walk(root.tree, 4, 0)


def from_leaves(length: int, chunk_size: int, leaves: Mapping[int, str],
                sink: Callable[[str, bytes], None] | None = None) -> Root:
    """Build canonical nodes from nonzero identities, absent entries stay zero."""
    root = Root(length, chunk_size, None)
    root.encode()
    current = dict(leaves)
    if any(not 0 <= index < root.count for index in current):
        raise ValueError("leaf outside stream length")
    for height in range(5):
        groups: dict[int, dict[int, str]] = {}
        for index, value in sorted(current.items()):
            groups.setdefault(index // 64, {})[index % 64] = value
        current = {}
        for index, entries in groups.items():
            prefix = LEAF if height == 0 else BRANCH + bytes([height])
            encoded = prefix + struct.pack("<Q", sum(1 << slot for slot in entries))
            encoded += b"".join(raw_digest(value) for value in entries.values())
            decode_node(encoded, height)
            identity = digest(encoded)
            current[index] = identity
            if sink is not None:
                sink(identity, encoded)
    return Root(length, chunk_size, current.get(0))


def from_file(path: Path, chunk_size: int) -> tuple[Root, dict[int, str]]:
    """Read every byte, including zeros, and independently rebuild its root."""
    leaves = {}
    length = path.stat().st_size
    Root(length, chunk_size, None).encode()
    with path.open("rb") as source:
        index = 0
        while data := source.read(chunk_size):
            if any(data):
                leaves[index] = digest(data)
            index += 1
        if source.tell() != length:
            raise ValueError("stream changed during oracle scan")
    return from_leaves(length, chunk_size, leaves), leaves


@dataclass(frozen=True)
class Change:
    first: int
    count: int
    value: str | None


@dataclass(frozen=True)
class Changes:
    mode: str
    records: tuple[Change, ...]
    identity: str
    byte_length: int

    def affected(self) -> set[int]:
        return {index for record in self.records for index in range(record.first, record.first + record.count)}


def read_changes(path: Path, length: int) -> Changes:
    """Decode sorted, disjoint native records without expanding zero runs."""
    if not 0 <= length <= 1 << 40:
        raise ValueError("native RAM-change length exceeds bounds")
    hasher = hashlib.sha256()
    records = []
    end = 0
    previous_zero = False
    count = (length + RAM_CHUNK - 1) // RAM_CHUNK
    with path.open("rb") as source:
        header = source.read(16)
        hasher.update(header)
        if (len(header) != 16 or header[:11] != b"KRUNRAM\0\x01\0\x10"
                or header[11] not in (0, 1) or header[12:] != bytes(4)):
            raise ValueError("invalid native RAM-change header")
        mode = "incremental" if header[11] else "full"
        while encoded := source.read(56):
            hasher.update(encoded)
            if len(encoded) != 56:
                raise ValueError("truncated native RAM-change record")
            first, run, kind, reserved, raw = struct.unpack("<QQB7s32s", encoded)
            if reserved != bytes(7) or not run or first < end or first + run > count:
                raise ValueError("invalid native RAM-change range")
            if kind == 0:
                if raw != bytes(32) or mode == "full" or (previous_zero and first == end):
                    raise ValueError("noncanonical native zero run")
                value = None
            elif kind == 1 and run == 1 and raw != bytes(32):
                value = digest_text(raw)
            else:
                raise ValueError("invalid native RAM-change kind or data count")
            records.append(Change(first, run, value))
            previous_zero = kind == 0
            end = first + run
        byte_length = source.tell()
    return Changes(mode, tuple(records), digest_text(hasher.digest()), byte_length)


def object_source(home: Path) -> Callable[[str], bytes]:
    return lambda identity: (home / "images/objects/sha256" / raw_digest(identity).hex()).read_bytes()


def catalog_root(home: Path, binding: dict) -> tuple[Root, dict[int, str]]:
    with closing(sqlite3.connect((home / "state.db").resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        roots = connection.execute(
            "SELECT root_digest,length,chunk_shift FROM stream_map_root WHERE root_digest=?",
            (binding["map"],)).fetchall()
        representations = connection.execute(
            "SELECT stream_id,map_digest,length,chunk_shift FROM storage_stream WHERE stream_id=?",
            (binding["stream"],)).fetchall()
    shift = binding["chunkSize"].bit_length() - 1
    expected_root = (binding["map"], binding["length"], shift)
    expected_representation = (binding["stream"], *expected_root)
    # Local publication admits roots without creating a retained transport
    # representation. If a representation exists, its binding must still agree.
    if roots != [expected_root] or representations not in ([], [expected_representation]):
        raise ValueError(f"catalog stream/root rows mismatch: roots={roots}, representations={representations}")
    source = object_source(home)
    encoded = source(binding["map"])
    root = decode_root(encoded)
    if root.identity != binding["stream"] or root.identity != binding["map"]:
        raise ValueError("catalog stream/root binding mismatch")
    if root.length != binding["length"] or root.chunk_size != binding["chunkSize"]:
        raise ValueError("catalog geometry mismatch")
    return root, dict(present_chunks(root, source))
