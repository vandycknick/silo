"""Reuse registry pulls across the per-test Silo Homes.

Every workspace starts with an empty ``SILO_HOME``, so each test that boots a
published image (the appliance, the distro images) would pull it again. The
store under ``<SILO_HOME>/images`` is content addressed (``index.json``, ``blobs``,
``manifests`` and one directory per manifest digest), so a whole-directory copy
is a valid store. Workspaces are seeded from ``<cache>/images`` before the test
and the cache is replaced by the workspace store afterwards when it learned new
tags; the next run then pulls nothing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

STORE_NAME = "images"
# In-flight pulls land here; never carry them between stores.
SCRATCH_DIR = "tmp"


def _tags(store: Path) -> set[str]:
    index = store / "index.json"
    if not index.is_file():
        return set()
    try:
        document = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    tags = document.get("tags") if isinstance(document, dict) else None
    return set(tags) if isinstance(tags, dict) else set()


def _copy_store(source: Path, destination: Path) -> None:
    """Copy a store directory, cloning blocks where the filesystem allows it."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Darwin":
        command = ["cp", "-Rc", str(source), str(destination)]
    else:
        command = ["cp", "-R", "--reflink=auto", str(source), str(destination)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=600)
    shutil.rmtree(destination / SCRATCH_DIR, ignore_errors=True)


def seed(cache_dir: Path, silo_home: Path) -> set[str]:
    """Populate ``<silo_home>/images`` from the cache; returns the tags it carried."""
    cached = cache_dir / STORE_NAME
    if not _tags(cached):
        return set()
    _copy_store(cached, silo_home / STORE_NAME)
    return _tags(cached)


def persist(cache_dir: Path, silo_home: Path) -> bool:
    """Replace the cache with the workspace store when it learned new tags."""
    store = silo_home / STORE_NAME
    cached = cache_dir / STORE_NAME
    learned = _tags(store)
    if not learned or learned <= _tags(cached):
        return False
    staging = cache_dir / f"{STORE_NAME}.new-{os.getpid()}"
    retired = cache_dir / f"{STORE_NAME}.old-{os.getpid()}"
    shutil.rmtree(staging, ignore_errors=True)
    _copy_store(store, staging)
    if cached.exists():
        cached.rename(retired)
    staging.rename(cached)
    shutil.rmtree(retired, ignore_errors=True)
    return True
