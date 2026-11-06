"""Owned-input page-cache eviction and mincore(2) residency evidence.

Cold budget samples never drop global caches and never use sudo. Each owned
regular input file is fsynced and then `POSIX_FADV_DONTNEED` is applied to that
file alone, before the timed operation is dispatched. mincore(2) records the
pages that remain resident afterwards. Pages that a live process still maps or
dirties (a running monitor's executable, a running source's upper) cannot be
evicted this way, so such a sample is labelled `partial-cold`, never `cold`.
Nothing is evicted again inside a timed window.
"""
from __future__ import annotations

import ctypes
import mmap
import os
from pathlib import Path
import stat

PAGE = os.sysconf("SC_PAGE_SIZE")
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.mmap.restype = ctypes.c_void_p
_LIBC.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
_LIBC.munmap.restype = ctypes.c_int
_LIBC.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_LIBC.mincore.restype = ctypes.c_int
_LIBC.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
_MAP_FAILED = ctypes.c_void_p(-1).value
# SQLite's shared-memory index is a coordination mapping, not an input.
_SKIPPED_SUFFIXES = ("-shm",)


def inputs(*roots: Path) -> list[Path]:
    """Every regular file below the given owned roots (or the files themselves)."""
    found: set[Path] = set()
    for root in roots:
        metadata = root.lstat()
        if stat.S_ISREG(metadata.st_mode):
            found.add(root)
            continue
        for directory, _, names in os.walk(root, followlinks=False):
            for name in names:
                path = Path(directory) / name
                try:
                    regular = stat.S_ISREG(path.lstat().st_mode)
                except FileNotFoundError:
                    continue
                if regular and not name.endswith(_SKIPPED_SUFFIXES):
                    found.add(path)
    return sorted(found)


def _resident(fd: int, length: int) -> int:
    if length == 0:
        return 0
    address = _LIBC.mmap(None, length, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
    if address is None or address == _MAP_FAILED:
        raise OSError(ctypes.get_errno(), "mmap for mincore")
    try:
        pages = (length + PAGE - 1) // PAGE
        vector = (ctypes.c_ubyte * pages)()
        if _LIBC.mincore(address, length, vector) != 0:
            raise OSError(ctypes.get_errno(), "mincore")
        resident = sum(1 for value in bytes(vector) if value & 1)
    finally:
        if _LIBC.munmap(address, length) != 0:
            raise OSError(ctypes.get_errno(), "munmap after mincore")
    return min(length, resident * PAGE)


def _observe(paths: list[Path], *, evict: bool) -> dict:
    files = []
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            # An owned run file may be retired between enumeration and open.
            continue
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                continue
            before = _resident(fd, metadata.st_size)
            after = before
            if evict:
                os.fsync(fd)
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                after = _resident(fd, os.fstat(fd).st_size)
            files.append({"path": str(path), "device": metadata.st_dev, "inode": metadata.st_ino,
                          "logicalBytes": metadata.st_size, "allocatedBytes": metadata.st_blocks * 512,
                          "residentBefore": before, "residentAfter": after})
        finally:
            os.close(fd)
    logical = sum(entry["logicalBytes"] for entry in files)
    resident = sum(entry["residentAfter"] for entry in files)
    if evict:
        label = "cold" if resident == 0 else "partial-cold"
    else:
        label = "warm-observed"
    return {
        "method": ("per-file fsync + POSIX_FADV_DONTNEED, then mincore" if evict
                   else "mincore only, no eviction"),
        "label": label, "files": len(files), "logicalBytes": logical,
        "residentBytesBefore": sum(entry["residentBefore"] for entry in files),
        "residentBytesAfter": resident,
        "residualFiles": [entry for entry in files if entry["residentAfter"]],
        "inventory": files,
    }


def evict(paths: list[Path]) -> dict:
    """Evict each owned input's clean pages and record what stayed resident."""
    return _observe(paths, evict=True)


def residency(paths: list[Path]) -> dict:
    """Record residency without changing it (warm-cohort evidence)."""
    return _observe(paths, evict=False)
