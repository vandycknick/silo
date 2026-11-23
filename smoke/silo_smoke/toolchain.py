"""Host C compiler for the statically linked guest probes."""
from __future__ import annotations

from functools import cache
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from silo_smoke.errors import SmokeEnvironmentError

# `cc` first so a working default stays the default. Toolchains such as Nix's
# clang wrapper link dynamically only, so the distribution compilers follow.
_CANDIDATES = ("cc", "gcc", "/usr/bin/cc", "/usr/bin/gcc", "clang", "musl-gcc")
_PROGRAM = b"#include <pthread.h>\nint main(void) { return pthread_self() == 0; }\n"


def links_static(compiler: list[str]) -> bool:
    with tempfile.TemporaryDirectory(prefix="silo-smoke-cc-") as directory:
        source = Path(directory) / "probe.c"
        source.write_bytes(_PROGRAM)
        try:
            result = subprocess.run([*compiler, "-static", "-pthread", str(source), "-o", str(Path(directory) / "probe")],
                                    capture_output=True, timeout=60)
        except (FileNotFoundError, PermissionError):
            return False
        return result.returncode == 0


@cache
def static_cc() -> tuple[str, ...]:
    """The first of `CC` and the candidates that links a static pthread program.

    `CC` is only a preference: development shells export a dynamic-only `CC`
    (Nix sets `CC=clang`) for host builds, which must not break guest probes.
    """
    explicit = os.environ.get("CC")
    candidates = ([shlex.split(explicit)] if explicit else []) + [[candidate] for candidate in _CANDIDATES]
    for compiler in candidates:
        if links_static(compiler):
            return tuple(compiler)
    tried = ", ".join(" ".join(compiler) for compiler in candidates)
    raise SmokeEnvironmentError(
        f"No C compiler links static guest probes (tried {tried}); "
        "install static libc (glibc-static or musl) or set CC to one that does")
