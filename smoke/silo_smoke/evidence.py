"""Durable, unique text-evidence directories for harness consumers."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile

from . import prereqs


def evidence_directory(label: str, *, variable: str = "SILO_SMOKE_EVIDENCE") -> Path:
    parent = prereqs.evidence_parent(variable)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    return Path(tempfile.mkdtemp(prefix=f"{label}-{stamp}-{worker}-", dir=parent))
