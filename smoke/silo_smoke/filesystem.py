"""Independent host filesystem capability probes."""
from __future__ import annotations

import ctypes
import errno
import fcntl
from pathlib import Path
import subprocess
import sys
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


def disk_clone_probe(directory: Path) -> ReflinkProbe:
    if sys.platform != "darwin":
        return reflink_probe(directory)
    clonefile = ctypes.CDLL(None, use_errno=True).clonefile
    clonefile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
    clonefile.restype = ctypes.c_int
    with tempfile.TemporaryDirectory(dir=directory, prefix="clonefile-") as work:
        source, destination = Path(work) / "source", Path(work) / "clone"
        source.write_bytes(b"\xa5" * 4096)
        error_number = ctypes.get_errno() if clonefile(bytes(source), bytes(destination), 0) else None
        if error_number not in {None, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL}:
            raise OSError(error_number, "clonefile probe", str(directory))
    return {"method": "clonefile", "directory": str(directory),
            "reflink": error_number is None, "errno": error_number}


def copy_sparse(source: Path, destination: Path, *, timeout: float) -> None:
    command = ["/bin/cp", "-c"] if sys.platform == "darwin" else ["cp", "--reflink=auto", "--sparse=always"]
    subprocess.run([*command, str(source), str(destination)], check=True, capture_output=True, timeout=timeout)
