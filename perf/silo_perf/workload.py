from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
import time
from typing import Iterator

from silo_perf.model import Workload

MIB = 1024 * 1024
FILL = "/fill/ram"
INPUT = "/fill/.perf-workload-input"
MARKER = "/perf-snapshot-marker"


@dataclass(frozen=True)
class Write:
    script: str
    size: int
    seed: int
    destination: str = INPUT

    def chunks(self) -> Iterator[bytes]:
        """Independent seeded bytes, never a repeated compressible seed block."""
        generator = random.Random(self.seed)
        remaining = self.size
        while remaining:
            size = min(MIB, remaining)
            yield generator.randbytes(size)
            remaining -= size

    def save(self, path: Path) -> None:
        deadline = time.monotonic() + 300
        with path.open("xb") as stream:
            for chunk in self.chunks():
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"generating workload payload {path} exceeded 300 seconds")
                stream.write(chunk)


def dirty_offsets(workload: Workload, generation: int) -> tuple[int, ...]:
    chunks = workload.memory_mib * 1024 // workload.dirty_chunk_kib
    count = chunks * workload.dirty_percent // 100
    generator = random.Random(workload.seed + generation)
    return tuple(index * (workload.dirty_chunk_kib // 4)
                 for index in generator.sample(range(chunks), count))


def writes(workload: Workload, generation: int, *, initialize: bool) -> tuple[Write, ...]:
    seed = workload.seed + generation * 3
    steps: list[Write] = []
    if initialize:
        size = workload.memory_mib * MIB
        steps.append(Write(f"test \"$(wc -c < {FILL})\" -eq {size}", size, seed, FILL))
    offsets = dirty_offsets(workload, generation)
    offset_list = " ".join(str(offset) for offset in offsets)
    pages = workload.dirty_chunk_kib // 4
    size = len(offsets) * workload.dirty_chunk_kib * 1024
    steps.append(Write(
        f"test \"$(wc -c < {INPUT})\" -eq {size}; read_offset=0; "
        f"for offset in {offset_list}; do "
        f"dd if={INPUT} of={FILL} bs=4096 skip=\"$read_offset\" seek=\"$offset\" count={pages} "
        f"iflag=fullblock conv=notrunc; read_offset=$((read_offset + {pages})); done", size, seed + 1))
    per_file = workload.disk_mib // workload.disk_files
    steps.append(Write(
        f"test \"$(wc -c < {INPUT})\" -eq {workload.disk_mib * MIB}; "
        "mkdir -p /perf-workload; i=0; "
        f"while [ \"$i\" -lt {workload.disk_files} ]; do "
        f"dd if={INPUT} of=/perf-workload/data-$i bs=1M skip=\"$((i * {per_file}))\" "
        f"count={per_file} iflag=fullblock; "
        f"test \"$(wc -c < /perf-workload/data-$i)\" -eq {per_file * MIB}; "
        "i=$((i + 1)); done; i=0; "
        f"while [ \"$i\" -lt {workload.small_files} ]; do "
        f"printf '%s\\n' '{seed}:{generation}' \"$i\" > /perf-workload/small-$i; "
        "i=$((i + 1)); done; sync", workload.disk_mib * MIB, seed + 2))
    return tuple(steps)


def marker_write(value: str) -> str:
    if value not in {"before-snapshot", "after-snapshot"}:
        raise ValueError("invalid snapshot marker")
    return f"printf '%s\\n' '{value}' > {MARKER}; sync"


def marker_check(value: str) -> str:
    if value not in {"before-snapshot", "after-snapshot"}:
        raise ValueError("invalid snapshot marker")
    return f"test \"$(cat {MARKER})\" = '{value}'"
