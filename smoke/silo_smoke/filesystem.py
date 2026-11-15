"""Independent host filesystem capability probes."""
from __future__ import annotations

import errno
import fcntl
from pathlib import Path
import tempfile
from typing import TypedDict


class ReflinkProbe(TypedDict):
    method: str
    directory: str
    reflink: bool
    errno: int | None


def reflink_probe(directory: Path) -> ReflinkProbe:
    error_number = None
    with tempfile.NamedTemporaryFile(dir=directory, prefix="reflink-source-") as source, \
            tempfile.NamedTemporaryFile(dir=directory, prefix="reflink-destination-") as destination:
        source.write(b"\xa5" * 4096)
        source.flush()
        try:
            fcntl.ioctl(destination.fileno(), 0x40049409, source.fileno())
        except OSError as error:
            if error.errno not in {errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL}:
                raise
            error_number = error.errno
    return {"method": "FICLONE", "directory": str(directory),
            "reflink": error_number is None, "errno": error_number}
