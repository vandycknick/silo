"""Smoke areas: named groups of test modules, selectable as markers or with `--area`.

Every module under tests/ belongs to at least one area; collection fails for an
unmapped module so new suites cannot fall outside every selection.

    make smoke SMOKE_AREAS=restore,fork
    make smoke-areas
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Area:
    description: str
    modules: tuple[str, ...]


AREAS: dict[str, Area] = {
    "host": Area("host-only unit coverage, no VM", (
        "test_guest_activation", "test_harness", "test_prereqs", "test_stopped_trace", "test_stream_map")),
    "lifecycle": Area("create, start, stop, pause, shutdown and guest init", (
        "test_lifecycle", "test_guest_lifecycle", "test_shutdown", "test_pause", "test_contained_init")),
    "access": Area("exec, shell, terminal, cp, forwards, logs and ssh", (
        "test_exec_shell", "test_exec_stdin", "test_terminal", "test_cp", "test_forward_logs",
        "test_ssh_distros", "test_ssh_systemd_owned")),
    "network": Area("network policy, netd and secret providers", (
        "test_network_policy", "test_netd_lifetime", "test_secret_provider")),
    "daemon": Area("silod user and system daemons", ("test_daemon", "test_daemon_system")),
    "image": Area("OCI pulls, image cache, overlay/EROFS roots, raw import and conversion", (
        "test_registry", "test_image_cache", "test_overlay", "test_erofs", "test_cloud_disk",
        "test_flatten_export")),
    "artifact": Area("Silo VM artifact push and pull through a registry", (
        "test_artifact_stopped", "test_distribution_registry")),
    "snapshot": Area("disk-only snapshots, stopped storage and handoff", (
        "test_stopped", "test_raw_live", "test_handoff")),
    "capture": Area("snapshots with memory: capture, incremental RAM and multi-disk cuts", (
        "test_capture", "test_capture_lifecycle", "test_capture_multidisk", "test_incremental")),
    "restore": Area("restoring snapshots with memory and activation", (
        "test_restore", "test_restore_lifecycle", "test_guest_activation")),
    "fork": Area("live and stopped forks", ("test_fork", "test_unhashed_fork")),
    "native": Area("native VMM capabilities and live API", ("test_native_capabilities", "test_native_live_api")),
    "memory": Area("host memory reclaim", ("test_reclaim",)),
}


def areas_of(module: str) -> tuple[str, ...]:
    return tuple(name for name, area in AREAS.items() if module in area.modules)


def main() -> None:
    width = max(map(len, AREAS))
    for name, area in AREAS.items():
        print(f"{name:<{width}}  {area.description}")
        print(f"{'':<{width}}  {' '.join(area.modules)}")


if __name__ == "__main__":
    main()
