from __future__ import annotations

from dataclasses import replace
import random
from pathlib import Path

import pytest

from silo_perf.drivers import Action, INFORMATIONAL_METRICS, MsbDriver, copy_command, raw_conversion_command
from silo_perf.model import Cohort, Workload, image_source, load_cohorts, load_targets
from silo_perf.scenario import SCENARIO
from silo_perf.workload import FILL, INPUT, MIB, Write, dirty_offsets, marker_check, marker_write, writes


def workload() -> Workload:
    return Workload(memory_mib=16, disk_mib=8, disk_files=2, small_files=8,
                    dirty_percent=10, dirty_chunk_kib=64, seed=3001)


def test_parse_workload_and_raw_cohort(tmp_path: Path) -> None:
    path = tmp_path / "cohorts.toml"
    path.write_text('''[busy]
image = "alpine"
cpus = 2
memory_gib = 2
informational = true
[busy.workload]
memory_mib = 16
disk_mib = 8
disk_files = 2
small_files = 8
dirty_percent = 10
dirty_chunk_kib = 64
seed = 3001
[raw]
image = "alpine"
cpus = 2
memory_gib = 2
raw_root = true
informational = true
''')
    parsed = load_cohorts(path)
    assert parsed["busy"].workload == workload()
    assert parsed["busy"].informational
    assert parsed["raw"].raw_root
    assert parsed["raw"].disks == ("",)
    assert parsed["raw"].workload is None


def test_realistic_cohorts_change_execution_plan() -> None:
    cohorts = load_cohorts()
    idle, raw, busy = (cohorts[name] for name in ("alpine-2g", "alpine-2g-raw", "alpine-8g-busy"))
    assert raw_conversion_command(idle) == ()
    assert raw_conversion_command(raw) == ("image", "convert", raw.image, "--disk-format", "raw", "--format", "json")
    assert idle.workload is None and busy.workload is not None
    assert writes(busy.workload, 0, initialize=True)
    assert not MsbDriver.supports(raw)
    assert MsbDriver.supports(busy)
    arch, arch_busy = cohorts["arch-30g"], cohorts["arch-30g-busy"]
    assert (arch.image, arch.cpus, arch.memory_gib, arch.disks) == (
        arch_busy.image, arch_busy.cpus, arch_busy.memory_gib, arch_busy.disks)
    assert arch_busy.workload is not None
    assert arch_busy.workload.memory_mib == 4096
    assert busy.workload.memory_mib == 2048
    targets = load_targets()
    for cohort in (raw, busy, arch_busy):
        assert cohort.informational
        assert all(key[1] != cohort.name for key in targets)


@pytest.mark.parametrize(("field", "value"), [
    ("memory_mib", 0), ("disk_mib", -1), ("disk_files", 3), ("small_files", 0),
    ("dirty_percent", 0), ("dirty_percent", 101), ("dirty_chunk_kib", 3),
    ("dirty_chunk_kib", 12), ("dirty_chunk_kib", 32768), ("seed", True),
])
def test_invalid_workload_parameters(field: str, value: int) -> None:
    with pytest.raises(ValueError, match="workload"):
        replace(workload(), **{field: value})


def test_invalid_cohort_memory_and_raw_comparison() -> None:
    with pytest.raises(ValueError, match="memory"):
        Cohort("busy", "alpine", 2, 1, workload=replace(workload(), memory_mib=1024))
    with pytest.raises(ValueError, match="Silo only"):
        Cohort("raw", "alpine", 2, 2, raw_root=True, msb_image="alpine")


def test_dirty_offsets_are_unique_scattered_aligned_and_bounded() -> None:
    config = workload()
    offsets = dirty_offsets(config, 0)
    chunk_pages = config.dirty_chunk_kib // 4
    assert len(offsets) == (config.memory_mib * 1024 // config.dirty_chunk_kib) * config.dirty_percent // 100
    assert len(set(offsets)) == len(offsets)
    assert all(offset % chunk_pages == 0 and 0 <= offset <= config.memory_mib * 256 - chunk_pages
               for offset in offsets)
    assert max(offsets) - min(offsets) > config.memory_mib * 256 // 2
    assert offsets == dirty_offsets(config, 0)
    assert offsets != dirty_offsets(config, 1)


def test_payload_chunks_are_seeded_bounded_and_not_repeated() -> None:
    step = Write("unused", MIB * 2 + 17, 3001)
    chunks = list(step.chunks())
    assert [len(chunk) for chunk in chunks] == [MIB, MIB, 17]
    assert chunks == list(step.chunks())
    assert chunks[0] != chunks[1]
    assert chunks[0] == random.Random(3001).randbytes(MIB)
    assert b"".join(chunks) != b"".join(Write("unused", step.size, 3002).chunks())
    assert list(Write("unused", 0, 1).chunks()) == []


def test_initial_and_incremental_workload_commands() -> None:
    config = workload()
    initial = writes(config, 0, initialize=True)
    incremental = writes(config, 1, initialize=False)
    assert len(initial) == 3 and len(incremental) == 2
    assert initial[0].size == config.memory_mib * MIB
    assert initial[0].destination == FILL
    assert initial[0].script.startswith("test ")
    assert "wc -c" in initial[0].script
    dirty = incremental[0]
    assert "seek=\"$offset\"" in dirty.script
    assert dirty.destination == INPUT
    assert f"if={INPUT}" in dirty.script and "skip=\"$read_offset\"" in dirty.script
    assert "read_offset=$((read_offset + 16))" in dirty.script
    assert "iflag=fullblock conv=notrunc" in dirty.script
    assert dirty.size == len(dirty_offsets(config, 1)) * config.dirty_chunk_kib * 1024
    planned_offsets = dirty.script.split("for offset in ", 1)[1].split(";", 1)[0].split()
    assert planned_offsets == [str(offset) for offset in dirty_offsets(config, 1)]
    disk = incremental[-1]
    assert disk.size == config.disk_mib * MIB
    assert "of=/perf-workload/data-$i" in disk.script
    assert disk.destination == INPUT and f"if={INPUT}" in disk.script
    assert 'skip="$((i * 4))"' in disk.script
    assert "/perf-workload/small-$i" in disk.script
    assert disk.script.endswith("; sync")
    assert initial[-1].seed != disk.seed
    assert all("/dev/urandom" not in step.script and "openssl" not in step.script for step in initial)


def test_correctness_commands_propagate_missing_or_wrong_markers() -> None:
    before = marker_write("before-snapshot")
    after = marker_write("after-snapshot")
    assert before != after and before.endswith("; sync")
    assert "test " in marker_check("before-snapshot")
    assert marker_check("before-snapshot") != marker_check("after-snapshot")
    with pytest.raises(ValueError, match="marker"):
        marker_write("untrusted shell input")
    with pytest.raises(ValueError, match="marker"):
        marker_check("")


def test_scenario_first_create_precedes_warm_run_and_new_capture_cases() -> None:
    assert SCENARIO.index(Action.IMAGE_CONVERT_RAW) < SCENARIO.index(Action.CREATE_FIRST)
    assert SCENARIO.index(Action.CREATE_FIRST) < SCENARIO.index(Action.RUN) < SCENARIO.index(Action.CREATE)
    assert SCENARIO.index(Action.FORK_FIRST) < SCENARIO.index(Action.FORK_OF_FORK) < SCENARIO.index(Action.SNAPSHOT_FULL)
    assert SCENARIO.index(Action.RESTORE_SECOND_EXEC) < SCENARIO.index(Action.SNAPSHOT_OF_RESTORED)
    assert SCENARIO.index(Action.SNAPSHOT_OF_RESTORED) < SCENARIO.index(Action.SNAPSHOT_AFTER_RESTART)
    assert {"create_first", "image_convert_raw", "fork_of_fork", "snapshot_of_restored",
            "snapshot_after_restart"} <= INFORMATIONAL_METRICS


@pytest.mark.parametrize(("reference", "source"), [
    ("docker.io/library/alpine:latest", "remote"),
    ("ghcr.io/vandycknick/archlinux:20260831.150324", "remote"),
    ("127.0.0.1:5000/smoke/alpine:latest", "local"),
    ("localhost:5000/smoke/alpine:latest", "local"),
    ("[::1]:5000/smoke/alpine:latest", "local"),
    ("image:converted-id", "local"), ("disk:/tmp/root.raw", "local"),
])
def test_image_source_records_acquisition_origin(reference: str, source: str) -> None:
    assert image_source(reference) == source


def test_raw_verification_is_separate_and_informational() -> None:
    assert SCENARIO.index(Action.SNAPSHOT_INCREMENTAL) < SCENARIO.index(Action.SNAPSHOT_VERIFY)
    assert SCENARIO.index(Action.SNAPSHOT_VERIFY) < SCENARIO.index(Action.RESTORE_FIRST)
    assert Action.SNAPSHOT_VERIFY.value in INFORMATIONAL_METRICS


def test_payload_file_is_generated_without_overwriting(tmp_path: Path) -> None:
    step = Write("unused", MIB * 2 + 17, 3001)
    path = tmp_path / "payload"
    step.save(path)
    assert path.stat().st_size == step.size
    with path.open("rb") as stream:
        for expected in step.chunks():
            assert stream.read(len(expected)) == expected
        assert stream.read(1) == b""
    with pytest.raises(FileExistsError):
        step.save(path)


def test_copy_command_uses_large_file_rpcs() -> None:
    source = Path("/workspace/payload")
    assert copy_command("silo", source, "source", INPUT) == (
        "cp", "--owner", "0:0", "--mode", "600", str(source), f"source:{INPUT}")
    assert copy_command("msb", source, "source", INPUT) == ("copy", str(source), f"source:{INPUT}")
    with pytest.raises(ValueError, match="unsupported"):
        copy_command("unknown", source, "source", INPUT)


def test_tmpfs_budget_includes_only_one_staging_payload() -> None:
    config = workload()
    assert config.tmpfs_mib == config.memory_mib + config.disk_mib + 256
    for name in ("arch-30g-busy", "alpine-8g-busy"):
        selected = load_cohorts()[name].workload
        assert selected is not None
        for step in writes(selected, 0, initialize=True):
            if step.destination == INPUT:
                assert selected.memory_mib * MIB + step.size <= selected.tmpfs_mib * MIB
