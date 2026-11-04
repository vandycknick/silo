"""Reuse immutable image bytes and a SQLite-only image catalog across workspaces.

Snapshots use SQLite's backup API, never copy an active state.db/WAL/SHM. No
machine, operation, network, private root, lock or temporary state is seeded.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import fcntl
import hashlib
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
from typing import Iterator
import uuid

CACHE_NAME = "image-catalog"
POOL_DIRECTORIES = ("objects", "streams", "source-blobs", "transport")
CATALOG_TABLES = {
    "_sqlx_migrations", "db_config", "image_manifest", "image_ref", "image_config",
    "image_layer", "image_manifest_layer", "image_rootfs_artifact",
}


def _cache_home(cache_dir: Path) -> Path:
    # Staged binaries are built from this checkout. Never seed a Home carrying
    # another embedded schema's migration checksum after a hard-breaking edit.
    schema = Path(__file__).resolve().parents[2] / "runtime/libvm/migrations/0001_initial.sql"
    return cache_dir / CACHE_NAME / hashlib.sha256(schema.read_bytes()).hexdigest()


@contextmanager
def _cache_lock(cache_dir: Path) -> Iterator[None]:
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (cache_dir / "image-catalog.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


@contextmanager
def _pool_lock(home: Path) -> Iterator[None]:
    # Production creates this stable slot before publishing any retained stream.
    with (home / "images/locks/roots.lock").open("r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        yield


def _catalog(home: Path) -> set[tuple[str, str, str]]:
    database = home / "state.db"
    if not database.is_file():
        return set()
    try:
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
            return set(connection.execute(
                "SELECT r.requested_reference, r.manifest_digest, a.stream_id "
                "FROM image_ref r JOIN image_rootfs_artifact a ON a.manifest_digest = r.manifest_digest"
            ))
    except sqlite3.DatabaseError:
        # A cache from an incompatible schema is not reusable after a hard break.
        return set()


def _copy_pool(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in POOL_DIRECTORIES:
        path = source / name
        if not path.is_dir():
            continue
        command = (["cp", "-Rc"] if platform.system() == "Darwin" else ["cp", "-R", "--reflink=auto"])
        subprocess.run([*command, str(path), str(destination / name)], check=True, capture_output=True, text=True, timeout=300)


def _snapshot(source: Path, destination: Path, final_home: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = destination / "state.db"
    with closing(sqlite3.connect((source / "state.db").as_uri() + "?mode=ro", uri=True)) as original:
        with closing(sqlite3.connect(database)) as copy:
            original.backup(copy)
            copy.execute("PRAGMA foreign_keys = OFF")
            copy.execute("PRAGMA secure_delete = ON")
            tables = [row[0] for row in copy.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            for table in tables:
                if table not in CATALOG_TABLES and not table.startswith("sqlite_"):
                    copy.execute('DELETE FROM "' + table.replace('"', '""') + '"')
            for image_id, stream_id in copy.execute("SELECT image_id, stream_id FROM image_rootfs_artifact").fetchall():
                algorithm, separator, digest = stream_id.partition(":")
                if algorithm != "sha256" or separator != ":" or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError(f"Invalid cached stream identity: {stream_id!r}")
                copy.execute("UPDATE image_rootfs_artifact SET rootfs_path = ? WHERE image_id = ?", (str(final_home / "images/streams/sha256" / digest), image_id))
            copy.commit()
            copy.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            copy.execute("PRAGMA journal_mode = DELETE")
            copy.execute("VACUUM")
    database.chmod(0o600)
    (destination / "catalog.lock").touch(mode=0o600, exist_ok=False)


def seed(cache_dir: Path, silo_home: Path) -> set[str]:
    """Seed an unopened fresh Home from a sanitized image-only snapshot."""
    with _cache_lock(cache_dir):
        cached = _cache_home(cache_dir)
        entries = _catalog(cached)
        if not entries:
            return set()
        if (silo_home / "state.db").exists():
            raise ValueError("Image cache seeding requires an unopened fresh Silo Home")
        _copy_pool(cached / "images", silo_home / "images")
        _snapshot(cached, silo_home, silo_home)
        return {reference for reference, _, _ in entries}


def persist(cache_dir: Path, silo_home: Path) -> bool:
    """Publish immutable bytes with a sanitized, transactionally backed-up catalog."""
    with _cache_lock(cache_dir):
        learned = _catalog(silo_home)
        cached = _cache_home(cache_dir)
        if not learned or learned == _catalog(cached):
            return False
        staging = cache_dir / f"image-catalog.new-{uuid.uuid4()}"
        retired = cache_dir / f"image-catalog.old-{uuid.uuid4()}"
        cached.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with _pool_lock(silo_home):
                _snapshot(silo_home, staging, cached)
                _copy_pool(silo_home / "images", staging / "images")
            if cached.exists():
                cached.rename(retired)
            try:
                staging.rename(cached)
            except OSError:
                if retired.exists():
                    retired.rename(cached)
                raise
            return True
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(retired, ignore_errors=True)
